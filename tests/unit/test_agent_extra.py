# SPDX-License-Identifier: MIT
"""Remaining agent edge cases: entry point, defensive branches, error masking."""

from __future__ import annotations

import os
import struct
import subprocess
import sys
import threading
import time
from multiprocessing.connection import Pipe
from pathlib import Path

import pytest

from nbp_git_safe import agent, crypto
from tests.helpers import ThreadAgent

KEY = bytes(range(64))


def test_agent_main_runs_serves_and_exits(tmp_path: Path) -> None:
    exited = threading.Event()
    state = tmp_path / "state"
    thread = threading.Thread(
        target=agent.main,
        args=(["--state-dir", str(state), "--ttl", "1.5"], lambda _code: exited.set()),
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + 5
    while agent.read_agent_info(state) is None and time.monotonic() < deadline:
        time.sleep(0.05)
    with agent.AgentClient.connect(state) as client:
        assert client.status()["locked"] is True
    assert exited.wait(8)  # the TTL ended it
    assert agent.read_agent_info(state) is None


def test_agent_main_refuses_to_start_next_to_a_live_agent(tmp_path: Path) -> None:
    other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        info = agent.AgentInfo(
            "x", "AF_PIPE", os.urandom(32), other.pid, time.time(), time.time() + 60, None
        )
        agent.write_agent_info(tmp_path, info)
        assert agent.main(["--state-dir", str(tmp_path), "--ttl", "5"]) == 3
        assert agent.read_agent_info(tmp_path) == info  # left untouched
    finally:
        other.kill()
        other.wait()


def test_agent_main_replaces_a_corrupted_state_file(tmp_path: Path) -> None:
    (tmp_path / "agent.json").write_bytes(b"corrupt")
    exited = threading.Event()
    thread = threading.Thread(
        target=agent.main,
        args=(["--state-dir", str(tmp_path), "--ttl", "1"], lambda _code: exited.set()),
        daemon=True,
    )
    thread.start()
    assert exited.wait(8)


def test_module_entry_point_prints_version() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "nbp_git_safe", "--version"], capture_output=True, text=True
    )
    assert proc.returncode == 0 and proc.stdout.startswith("nbp-git-safe ")


def test_client_handshake_rejects_wrong_sized_and_unexpected_replies() -> None:
    a, b = Pipe()
    b.send_bytes(b"short")
    with pytest.raises(agent.HandshakeError, match="failed authentication"):
        agent.client_handshake(a, os.urandom(32), timeout=2)

    c, d = Pipe()
    key = os.urandom(32)

    def server() -> None:
        msg = d.recv_bytes(128)
        cnonce, snonce = msg[len(agent.HS_MAGIC) :], os.urandom(32)
        d.send_bytes(snonce + agent._proof(key, b"server", cnonce, snonce))
        d.recv_bytes(128)
        d.send_bytes(b"NO")  # authenticated server, but it refuses us

    t = threading.Thread(target=server)
    t.start()
    with pytest.raises(agent.HandshakeError, match="rejected"):
        agent.client_handshake(c, key, timeout=2)
    t.join()


def test_internal_errors_are_masked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ta = ThreadAgent(tmp_path, KEY, 60)
    try:

        def boom(*_args: object, **_kw: object) -> bytes:
            raise RuntimeError("SECRET-DETAIL-THAT-MUST-NOT-LEAK")

        monkeypatch.setattr(crypto, "content_mac", boom)
        with ta.client() as client:
            with pytest.raises(agent.AgentError) as exc:
                client.mac(b"x")
            assert "SECRET-DETAIL" not in str(exc.value) and "refused" in str(exc.value)
            monkeypatch.undo()
            assert client.mac(b"x") == crypto.content_mac(crypto.KeySet(KEY), b"x")
    finally:
        ta.stop()


def test_malformed_arguments_are_bad_requests(tmp_path: Path) -> None:
    ta = ThreadAgent(tmp_path, KEY, 60)
    try:
        with ta.client() as client:
            bad_bucket = agent.pack_args(b"0" * 32, b"\x00\x01", b"data")  # not 4 bytes
            not_json = agent.pack_args(struct.pack(">I", 64), b"\xff\xfe")
            for op, body in (
                (agent.OP_ENC_BLOB, bad_bucket),
                (agent.OP_ENC_INDEX, not_json),
                (agent.OP_ENC_INDEX, agent.pack_args(struct.pack(">I", 64), b"[1]")),
            ):
                client._conn.send_bytes(bytes([agent.PROTO, op]) + body)
                reply = client._conn.recv_bytes(agent.MAX_MESSAGE)
                assert reply[1] == agent.STATUS_ERR and reply[2:] == b"bad_request"
            for bad in (True, -1, 1 << 32, "64"):
                with pytest.raises(crypto.InvalidArgumentError):
                    client.enc_blob("0" * 32, b"x", bad)  # type: ignore[arg-type]
            assert client.hello() == agent.PROTO
    finally:
        ta.stop()


def test_silent_authenticated_connection_is_dropped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(agent, "CONN_IDLE_TIMEOUT", 0.6)
    ta = ThreadAgent(tmp_path, KEY, 60)
    try:
        client = ta.client()
        time.sleep(2.0)
        with pytest.raises(agent.AgentNotRunningError):
            client.hello()
        client.close()
        with ta.client() as fresh:
            assert fresh.hello() == agent.PROTO
    finally:
        ta.stop()


def test_connect_to_unreachable_address_reports_not_running(tmp_path: Path) -> None:
    info = agent.AgentInfo(
        r"\\.\pipe\nbp-git-safe-does-not-exist-xyz"
        if sys.platform == "win32"
        else str(tmp_path / "nope.sock"),
        "AF_PIPE" if sys.platform == "win32" else "AF_UNIX",
        os.urandom(32),
        os.getpid(),
        time.time(),
        time.time() + 60,
        None,
    )
    with pytest.raises(agent.AgentNotRunningError, match="not reachable"):
        agent.AgentClient.connect_info(info)


def test_unlock_guard_survives_lock_file_vanishing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = tmp_path / agent.UNLOCK_LOCK
    lock.write_bytes(b"")
    real_stat = Path.stat
    calls = {"n": 0}

    def flaky(self: Path, *args: object, **kwargs: object) -> os.stat_result:
        if self == lock and calls["n"] == 0:
            calls["n"] += 1
            lock.unlink()
            raise FileNotFoundError
        return real_stat(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "stat", flaky)
    with agent.unlock_guard(tmp_path):
        pass


def test_spawn_gives_up_when_agent_never_publishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Dead:
        pid = 1

        def poll(self) -> int:
            return 1

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: Dead())
    (tmp_path / "s").mkdir()
    (tmp_path / "s" / "agent.json").write_bytes(b"corrupt")  # unreadable while waiting
    with pytest.raises(agent.AgentError, match="failed to start"):
        agent.spawn_agent(tmp_path / "s", 5, None)
