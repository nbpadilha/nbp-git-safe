# SPDX-License-Identifier: MIT
"""Agent protocol, mutual handshake and server behaviour (the server runs in a thread here so
that it is measured; ``tests/integration/test_agent_process.py`` covers the real process)."""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from multiprocessing.connection import Client, Connection, Listener, Pipe
from pathlib import Path

import pytest

from nbp_git_safe import agent, crypto
from tests.helpers import ThreadAgent, make_info

KEY = bytes(range(64))


def _address() -> tuple[str, str]:
    if sys.platform == "win32":
        return rf"\\.\pipe\nbp-test-{secrets.token_hex(6)}", "AF_PIPE"
    import atexit
    import shutil
    import tempfile

    # a SHORT directory (sun_path is ~104 bytes; the per-test TMPDIR is long); removed at exit
    short = tempfile.mkdtemp(prefix="nbp-t-", dir="/tmp")
    atexit.register(shutil.rmtree, short, ignore_errors=True)
    return str(Path(short) / "s"), "AF_UNIX"


@pytest.fixture
def agent_thread(tmp_path: Path) -> Callable[..., ThreadAgent]:
    started: list[ThreadAgent] = []

    def make(master: bytes | None = KEY, **kwargs: object) -> ThreadAgent:
        ta = ThreadAgent(tmp_path / f"state{len(started)}", master, **kwargs)  # type: ignore[arg-type]
        started.append(ta)
        return ta

    yield make  # type: ignore[misc]
    for ta in started:
        ta.stop()


# ------------------------------------------------------------------------- framing


def test_pack_unpack_roundtrip() -> None:
    data = agent.pack_args(b"abc", b"", b"\x00" * 10)
    assert agent.unpack_args(data, 3) == [b"abc", b"", b"\x00" * 10]


@pytest.mark.parametrize(
    ("data", "count"),
    [
        (b"", 1),  # missing length
        (b"\x00\x00\x00\x05abc", 1),  # length beyond the data
        (agent.pack_args(b"a", b"b"), 1),  # trailing bytes
        (agent.pack_args(b"a"), 2),  # missing part
    ],
)
def test_unpack_rejects_malformed(data: bytes, count: int) -> None:
    with pytest.raises(agent.ProtocolError):
        agent.unpack_args(data, count)


# ------------------------------------------------------------------- handshake (Pipe)


def _run_server_side(conn: Connection, authkey: bytes, errors: list[Exception]) -> None:
    try:
        agent.server_handshake(conn, authkey, timeout=3)
    except Exception as exc:
        errors.append(exc)
        conn.close()  # like the real server: a failed handshake hangs up


def test_mutual_handshake_succeeds() -> None:
    a, b = Pipe()
    authkey = os.urandom(32)
    errors: list[Exception] = []
    t = threading.Thread(target=_run_server_side, args=(b, authkey, errors))
    t.start()
    agent.client_handshake(a, authkey, timeout=3)
    t.join()
    assert errors == []


def test_client_rejects_impostor_server() -> None:
    """A server that does not know the authkey cannot authenticate itself to the client."""
    a, b = Pipe()
    errors: list[Exception] = []
    t = threading.Thread(target=_run_server_side, args=(b, os.urandom(32), errors))
    t.start()
    with pytest.raises(agent.HandshakeError, match="agent failed authentication"):
        agent.client_handshake(a, os.urandom(32), timeout=3)
    a.close()  # the client hangs up without ever sending its proof
    t.join()
    assert len(errors) == 1
    assert isinstance(errors[0], agent.HandshakeError)


def test_server_rejects_impostor_client() -> None:
    """A client that does not know the authkey is rejected by the server."""
    a, b = Pipe()
    errors: list[Exception] = []
    t = threading.Thread(target=_run_server_side, args=(b, os.urandom(32), errors))
    t.start()
    # speak the protocol but with another key: the server must fail it. The client cannot get
    # past the server proof either, so craft the final step by hand.
    cnonce = os.urandom(32)
    a.send_bytes(agent.HS_MAGIC + cnonce)
    msg = a.recv_bytes(128)
    a.send_bytes(agent._proof(os.urandom(32), b"client", cnonce, msg[:32]))
    t.join()
    assert len(errors) == 1
    assert isinstance(errors[0], agent.HandshakeError)
    with pytest.raises((EOFError, OSError)):
        a.recv_bytes(16)  # no acknowledgement was ever sent


def test_handshake_proofs_are_not_interchangeable() -> None:
    key, cn, sn = os.urandom(32), os.urandom(32), os.urandom(32)
    assert agent._proof(key, b"server", cn, sn) != agent._proof(key, b"client", cn, sn)


@pytest.mark.parametrize(
    "garbage", [b"", b"hello", b"\x00" * 200, agent.HS_MAGIC, agent.HS_MAGIC + b"short"]
)
def test_server_rejects_garbage_first_message(garbage: bytes) -> None:
    a, b = Pipe()
    errors: list[Exception] = []
    t = threading.Thread(target=_run_server_side, args=(b, os.urandom(32), errors))
    t.start()
    a.send_bytes(garbage)
    t.join()
    assert len(errors) == 1
    assert isinstance(errors[0], agent.HandshakeError)


def test_handshake_timeout_when_peer_is_silent() -> None:
    a, _b = Pipe()
    with pytest.raises(agent.HandshakeError, match="in time"):
        agent.server_handshake(a, os.urandom(32), timeout=0.2)


def test_handshake_closed_connection() -> None:
    a, b = Pipe()
    b.close()
    with pytest.raises(agent.HandshakeError):
        agent.client_handshake(a, os.urandom(32), timeout=1)


# --------------------------------------------------------------- real server transport


def test_client_rejects_impostor_listener(tmp_path: Path) -> None:
    """An impostor listening where agent.json points (no authkey) is rejected by the client."""
    address, family = _address()
    listener = Listener(address, family, authkey=None)
    seen: list[bytes] = []

    def impostor() -> None:
        conn = listener.accept()
        seen.append(conn.recv_bytes(128))
        conn.send_bytes(os.urandom(64))  # fake nonce + fake proof
        time.sleep(0.5)
        conn.close()

    t = threading.Thread(target=impostor, daemon=True)
    t.start()
    info = agent.AgentInfo(
        address, family, os.urandom(32), os.getpid(), time.time(), time.time() + 60, None
    )
    with pytest.raises(agent.HandshakeError):
        agent.AgentClient.connect_info(info)
    t.join(3)
    listener.close()
    assert seen and seen[0].startswith(agent.HS_MAGIC)


def test_wrong_authkey_is_rejected_and_agent_keeps_serving(
    agent_thread: Callable[..., ThreadAgent],
) -> None:
    ta = agent_thread()
    bad = agent.AgentInfo(**{**ta.info.__dict__, "authkey": os.urandom(32)})
    with pytest.raises(agent.HandshakeError):
        agent.AgentClient.connect_info(bad)
    with ta.client() as client:
        assert client.status()["locked"] is False


def test_raw_garbage_connection_does_not_disturb_agent(
    agent_thread: Callable[..., ThreadAgent],
) -> None:
    ta = agent_thread()
    raw = Client(ta.info.address, ta.info.family, authkey=None)
    raw.send_bytes(b"\x80\x04\x95 pickle-looking garbage")
    with pytest.raises((EOFError, OSError)):
        raw.recv_bytes(64)  # the server hangs up without answering
    raw.close()
    with ta.client() as client:
        assert client.hello() == agent.PROTO


def test_oversized_message_is_refused(agent_thread: Callable[..., ThreadAgent]) -> None:
    ta = agent_thread()
    client = ta.client()
    huge = b"\x01\x03" + b"x" * agent.MAX_MESSAGE  # one byte beyond the limit
    with contextlib.suppress(OSError, ValueError):  # the server may hang up mid-send
        client._conn.send_bytes(huge)
    with pytest.raises(agent.AgentNotRunningError):
        client.status()  # that connection is gone ...
    client.close()
    with ta.client() as fresh:  # ... but the agent is fine
        assert fresh.status()["locked"] is False


@pytest.mark.parametrize(
    "request_bytes",
    [b"", b"\x01", b"\x02\x01", bytes([agent.PROTO, 99]), bytes([agent.PROTO, agent.OP_MAC])],
)
def test_bad_requests_get_errors_and_connection_survives(
    agent_thread: Callable[..., ThreadAgent], request_bytes: bytes
) -> None:
    ta = agent_thread()
    with ta.client() as client:
        client._conn.send_bytes(request_bytes)
        reply = client._conn.recv_bytes(agent.MAX_MESSAGE)
        assert reply[1] == agent.STATUS_ERR
        assert client.hello() == agent.PROTO


# ------------------------------------------------------------------------- operations


def test_operations_match_local_crypto(agent_thread: Callable[..., ThreadAgent]) -> None:
    ta = agent_thread()
    keys = crypto.KeySet(KEY)
    fid = crypto.new_file_id()
    with ta.client() as c:
        assert c.key_id() == keys.key_id
        assert c.mac(b"data") == crypto.content_mac(keys, b"data")
        blob = c.enc_blob(fid, b"hello", 512)
        assert blob == crypto.encrypt_blob(keys, fid, b"hello", 512)
        assert c.dec_blob(fid, blob) == b"hello"
        index = {"v": 1, "entries": {}, "z": "\u00e9"}
        enc = c.enc_index(index, 256)
        assert enc == crypto.encrypt_index(keys, index, 256)
        assert c.dec_index(enc) == index
        status = c.status()
        assert status["key_id"] == keys.key_id.hex()
        assert status["pid"] == os.getpid()


@pytest.mark.parametrize(
    ("call", "exc"),
    [
        (lambda c, fid: c.enc_blob("not-an-id", b"x"), crypto.InvalidArgumentError),
        (lambda c, fid: c.enc_blob(fid, b"x", 0), crypto.InvalidArgumentError),
        (lambda c, fid: c.dec_blob(fid, b"short"), crypto.BlobFormatError),
        (
            lambda c, fid: c.dec_blob(fid, crypto.MAGIC + b"\x01" + b"\x00" * 60),
            crypto.KeyIdMismatchError,
        ),
        (lambda c, fid: c.dec_index(b"short"), crypto.BlobFormatError),
    ],
)
def test_crypto_errors_become_typed_exceptions(
    agent_thread: Callable[..., ThreadAgent], call: Callable[..., object], exc: type[Exception]
) -> None:
    ta = agent_thread()
    with ta.client() as c, pytest.raises(exc):
        call(c, crypto.new_file_id())


def test_tampered_blob_and_wrong_id_fail_authentication(
    agent_thread: Callable[..., ThreadAgent],
) -> None:
    ta = agent_thread()
    fid, other = crypto.new_file_id(), crypto.new_file_id()
    with ta.client() as c:
        blob = bytearray(c.enc_blob(fid, b"payload"))
        with pytest.raises(crypto.AuthenticationError):
            c.dec_blob(other, bytes(blob))
        blob[-1] ^= 1
        with pytest.raises(crypto.AuthenticationError):
            c.dec_blob(fid, bytes(blob))


def test_index_must_be_object_and_errors_do_not_echo_data(
    agent_thread: Callable[..., ThreadAgent],
) -> None:
    ta = agent_thread()
    marker = "MARKER_PAYLOAD_1234"
    with ta.client() as c:
        c._conn.send_bytes(
            bytes([agent.PROTO, agent.OP_ENC_INDEX])
            + agent.pack_args(struct.pack(">I", 64), json.dumps([marker]).encode())
        )
        reply = c._conn.recv_bytes(agent.MAX_MESSAGE)
        assert reply[1] == agent.STATUS_ERR and marker.encode() not in reply
        with pytest.raises(crypto.InvalidArgumentError) as info:
            c.enc_blob("MARKER_PAYLOAD_1234", marker.encode())
        assert marker not in str(info.value)


def test_locked_agent_refuses_crypto_but_answers_status(
    agent_thread: Callable[..., ThreadAgent],
) -> None:
    ta = agent_thread(master=None)
    with ta.client() as c:
        assert c.status()["locked"] is True
        for call in (c.key_id, lambda: c.mac(b"x"), lambda: c.enc_blob("0" * 32, b"x")):
            with pytest.raises(agent.AgentLockedError):
                call()
        with pytest.raises(crypto.InvalidKeyError):
            c.load_key(b"too short")
        c.load_key(KEY)
        with pytest.raises(agent.AgentError):
            c.load_key(KEY)  # the key can be loaded only once
        assert c.key_id() == crypto.KeySet(KEY).key_id


def test_status_and_repr_never_expose_the_key(agent_thread: Callable[..., ThreadAgent]) -> None:
    ta = agent_thread()
    text = repr(ta.info) + str(ta.info) + repr(ta.server.info)
    assert ta.info.authkey.hex() not in text
    raw = agent.agent_json_path(ta.state_dir).read_bytes()
    for needle in (KEY, KEY.hex().encode(), crypto.encode_key(KEY).encode()):
        assert needle not in raw
    assert "authkey" not in json.loads(raw)  # nothing to authenticate with is written ...
    assert ta.info.authkey.hex().encode() not in raw and ta.info.authkey not in raw
    assert json.loads(raw)["nonce"] == ta.info.nonce.hex()  # ... only the public nonce


# ----------------------------------------------------------------------- lifecycle


def _wait(event: threading.Event, seconds: float = 6.0) -> bool:
    return event.wait(seconds)


def test_ttl_expiry_stops_and_cleans_up(agent_thread: Callable[..., ThreadAgent]) -> None:
    ta = agent_thread(ttl=0.6)
    assert agent.agent_json_path(ta.state_dir).exists()
    assert _wait(ta.exited)
    assert not agent.agent_json_path(ta.state_dir).exists()
    with pytest.raises(agent.AgentNotRunningError):
        agent.AgentClient.connect(ta.state_dir)


def test_setting_the_wall_clock_back_does_not_extend_the_ttl(
    agent_thread: Callable[..., ThreadAgent], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Codex lead (audit 2026-10-10): the TTL also runs on the monotonic clock."""
    real = time.time
    ta = agent_thread(ttl=0.6)
    monkeypatch.setattr(time, "time", lambda: real() - 3600)  # the clock jumped an hour back
    assert _wait(ta.exited)


def test_expired_agent_answers_expired_before_exit(
    agent_thread: Callable[..., ThreadAgent],
) -> None:
    ta = agent_thread(ttl=60)
    with ta.client() as c:
        ta.server._expires_at = time.time() - 1  # the watchdog has not noticed yet
        with pytest.raises(agent.AgentExpiredError):
            c.mac(b"x")


def test_idle_timeout_counts_activity_but_not_status(
    agent_thread: Callable[..., ThreadAgent],
) -> None:
    ta = agent_thread(idle=1.0)
    with ta.client() as c:
        for _ in range(4):
            time.sleep(0.4)
            c.mac(b"keep alive")  # real activity extends the idle deadline
        assert not ta.exited.is_set()
        t0 = time.monotonic()
        while not ta.exited.is_set() and time.monotonic() - t0 < 6:
            try:
                c.status()  # status/hello are not activity
            except agent.AgentError:
                break
            time.sleep(0.1)
    assert _wait(ta.exited)


def test_agent_without_key_gives_up(agent_thread: Callable[..., ThreadAgent]) -> None:
    ta = agent_thread(master=None, key_wait=0.5)
    assert _wait(ta.exited)
    assert not agent.agent_json_path(ta.state_dir).exists()


def test_lock_op_stops_agent_and_removes_state(agent_thread: Callable[..., ThreadAgent]) -> None:
    ta = agent_thread()
    with ta.client() as c:
        c.lock()
    assert _wait(ta.exited)
    assert not agent.agent_json_path(ta.state_dir).exists()


def test_connection_cap_does_not_wedge_agent(agent_thread: Callable[..., ThreadAgent]) -> None:
    ta = agent_thread()
    raws = [
        Client(ta.info.address, ta.info.family, authkey=None)
        for _ in range(agent.MAX_CONNECTIONS + 2)
    ]
    for r in raws:
        r.close()
    deadline = time.monotonic() + 8
    while True:
        try:
            with ta.client() as c:
                assert c.hello() == agent.PROTO
            break
        except agent.AgentError:
            assert time.monotonic() < deadline
            time.sleep(0.2)


# ----------------------------------------------------------------- state / orphans


def _info(state_dir: Path, pid: int, expires: float) -> agent.AgentInfo:
    return make_info(state_dir, pid, expires)


def _dead_pid() -> int:
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


def test_pid_alive() -> None:
    assert agent.pid_alive(os.getpid())
    assert not agent.pid_alive(0)
    assert not agent.pid_alive(-5)
    assert not agent.pid_alive(_dead_pid())


def test_orphan_with_dead_pid_is_cleaned(tmp_path: Path) -> None:
    agent.write_agent_info(tmp_path, _info(tmp_path, _dead_pid(), time.time() + 100))
    assert agent.cleanup_orphan(tmp_path) is True
    assert not agent.agent_json_path(tmp_path).exists()
    with pytest.raises(agent.AgentNotRunningError):
        agent.AgentClient.connect(tmp_path)


def test_connect_cleans_orphan_itself(tmp_path: Path) -> None:
    agent.write_agent_info(tmp_path, _info(tmp_path, _dead_pid(), time.time() + 100))
    with pytest.raises(agent.AgentNotRunningError):
        agent.AgentClient.connect(tmp_path)
    assert not agent.agent_json_path(tmp_path).exists()


def test_expired_and_corrupted_state_is_cleaned(tmp_path: Path) -> None:
    agent.write_agent_info(tmp_path, _info(tmp_path, os.getpid(), time.time() - 1))
    assert agent.cleanup_orphan(tmp_path) is True
    agent.agent_json_path(tmp_path).write_bytes(b"{not json")
    with pytest.raises(agent.AgentNotRunningError):
        agent.AgentClient.connect(tmp_path)
    assert not agent.agent_json_path(tmp_path).exists()
    agent.agent_json_path(tmp_path).write_bytes(b"{}")
    assert agent.cleanup_orphan(tmp_path) is True


def test_live_state_is_not_cleaned_and_missing_is_noop(tmp_path: Path) -> None:
    assert agent.cleanup_orphan(tmp_path) is False
    agent.write_agent_info(tmp_path, _info(tmp_path, os.getpid(), time.time() + 100))
    assert agent.cleanup_orphan(tmp_path) is False
    with pytest.raises(agent.AgentNotRunningError):  # live pid but nobody listening
        agent.AgentClient.connect(tmp_path)
    assert agent.agent_json_path(tmp_path).exists()


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(v=1),
        lambda d: d.update(v=3),
        lambda d: d.update(nonce="zz"),
        lambda d: d.update(nonce="00" * 5),
        lambda d: d.pop("nonce"),
        lambda d: d.pop("pid"),
        lambda d: d.update(pid="x"),
        lambda d: d.update(pid=0),
        lambda d: d.update(expires_at=float("inf")),
    ],
)
def test_agent_json_validation(tmp_path: Path, mutate: Callable[[dict], None]) -> None:
    data = json.loads(_info(tmp_path, 1, time.time() + 1).to_json())
    mutate(data)
    secret = os.urandom(32)
    with pytest.raises(agent.AgentError, match="corrupted"):
        agent.AgentInfo.from_json(json.dumps(data, allow_nan=True).encode(), secret)
    with pytest.raises(agent.AgentError):
        agent.AgentInfo.from_json(b"\xff\xfe", secret)


def test_agent_json_roundtrip_with_idle(tmp_path: Path) -> None:
    info = make_info(tmp_path, 7, 2.0, 3.0)
    agent.write_agent_info(tmp_path, info)
    again = agent.read_agent_info(tmp_path)
    assert again is not None and again.authkey == info.authkey  # derived, not stored
    assert again.idle_timeout == 3.0 and again.pid == 7
    agent.remove_agent_info(tmp_path)
    agent.remove_agent_info(tmp_path)  # idempotent
    assert agent.read_agent_info(tmp_path) is None


def test_unlock_guard_serializes(tmp_path: Path) -> None:
    with (
        agent.unlock_guard(tmp_path),
        pytest.raises(agent.AgentError, match="in progress"),
        agent.unlock_guard(tmp_path),
    ):
        pass
    with agent.unlock_guard(tmp_path):  # released afterwards
        pass


def test_unlock_guard_clears_stale_lock(tmp_path: Path) -> None:
    lock = tmp_path / agent.UNLOCK_LOCK
    lock.write_bytes(b"")
    old = time.time() - 1000
    os.utime(lock, (old, old))
    with agent.unlock_guard(tmp_path):
        pass


def test_agent_environment_is_minimal_and_inherits_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("NBP_SAFE_SOMETHING", "PYTHONPATH", "PYTHONSTARTUP", "KEEP_ME"):
        monkeypatch.setenv(name, "x")
    env = agent._agent_environment()
    assert set(env) <= {"SYSTEMROOT", "WINDIR", "PATH"}
    assert not any(k.startswith(("NBP_SAFE_", "PYTHON")) for k in env)


def test_reprs_and_errors_never_contain_key_material(
    agent_thread: Callable[..., ThreadAgent],
) -> None:
    ta = agent_thread()
    secrets_ = [KEY, KEY.hex().encode(), crypto.encode_key(KEY).encode(), repr(KEY).encode()]
    with ta.client() as c:
        texts = [repr(ta.server), repr(c), repr(ta), repr(ta.info), str(ta.info), repr(c.info)]
        errors = []
        for call in (lambda: c.dec_blob("0" * 32, b"x" * 64), lambda: c.enc_blob("bad", b"x")):
            try:
                call()
            except Exception as exc:
                errors += [repr(exc), str(exc)]
        texts += errors
    blob = "\n".join(texts).encode("utf-8", "replace")
    assert all(needle not in blob for needle in secrets_)
    assert len(errors) == 4
