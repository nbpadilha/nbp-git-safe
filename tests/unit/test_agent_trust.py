# SPDX-License-Identifier: MIT
"""Where the agent's trust comes from (regressions for review findings C2 and A1).

* C2: ``agent.json`` is data, never an instruction. A planted file (wrong family, relative path,
  a path into a "victim" directory) must not make any code delete anything.
* A1: the state lives in a per-user directory that is verified on every use, the connection key is
  derived from a secret in that directory (never stored in ``agent.json``), and the process that
  serves the connection is checked before anything is sent.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

from nbp_git_safe import agent, unlock
from tests.helpers import ThreadAgent

WINDOWS = sys.platform == "win32"
KEY = bytes(range(64))
NONCE_HEX = "ab" * 32
SOCK = "a" * 12 + "-" + "b" * 12 + ".sock"


def make_victim(root: Path) -> Path:
    victim = root / "victim-documents"
    (victim / "sub").mkdir(parents=True)
    (victim / "sub" / "thesis.docx").write_bytes(b"important")
    (victim / "agent.sock").write_bytes(b"not a socket")
    return victim


def assert_victim_intact(victim: Path) -> None:
    assert (victim / "sub" / "thesis.docx").read_bytes() == b"important"
    assert (victim / "agent.sock").exists()


def plant(state_dir: Path, **fields: object) -> Path:
    """Write an ``agent.json`` by hand into the (verified) state directory, as an attacker able to
    write there would, together with a secret so that the parser gets as far as the endpoint."""
    rdir = agent.private_dir(state_dir, create=True)
    assert rdir is not None
    endpoint = agent.new_endpoint(state_dir)  # creates the secret; a valid address by default
    data: dict[str, object] = {
        "v": agent.STATE_VERSION,
        "address": endpoint.address,
        "family": endpoint.family,
        "nonce": NONCE_HEX,
        "pid": os.getpid(),
        "started": 0.0,
        "expires_at": 9e18,
        "idle_timeout": None,
    }
    data.update(fields)
    path = rdir / agent.AGENT_JSON
    path.write_text(json.dumps(data))
    return path


def hostile_addresses(victim: Path, cwd: Path) -> list[tuple[str, str]]:
    sock = str(victim / "agent.sock")
    relative = os.path.relpath(sock, cwd)
    return [
        (sock, "AF_UNIX"),  # the other platform's family (POSIX address on Windows)
        (sock, "AF_PIPE"),
        (relative, "AF_UNIX"),  # ../.. style, resolved against the current directory
        (str(victim / "sub" / ".." / "agent.sock"), "AF_UNIX"),
        (rf"\\.\pipe\{victim.name}", "AF_PIPE"),  # a pipe name that is not ours
        (
            str(victim) + "/" + "0" * 12 + "-" + "0" * 12 + ".sock",
            "AF_UNIX",
        ),  # right shape, wrong directory
    ]


# ------------------------------------------------------------------------------------ C2


@pytest.mark.parametrize("live", [False, True], ids=["dead-and-expired", "live-pid"])
def test_planted_agent_json_never_deletes_anything(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, live: bool
) -> None:
    victim = make_victim(tmp_path)
    monkeypatch.chdir(tmp_path)
    state = tmp_path / "repo" / ".git" / "nbp-safe"
    for address, family in hostile_addresses(victim, tmp_path):
        plant(
            state,
            address=address,
            family=family,
            pid=os.getpid() if live else 2_000_000_000 - 7,
            expires_at=9e18 if live else 1.0,
        )
        assert unlock.current_status(state) is None  # what every hook / status / doctor does
        with pytest.raises(agent.AgentNotRunningError):
            agent.AgentClient.connect(state)
        agent.cleanup_orphan(state)  # must not raise, whatever the file says
        assert_victim_intact(victim)
        agent.remove_agent_info(state)
    assert_victim_intact(victim)


def test_the_legacy_location_inside_git_is_never_read(tmp_path: Path) -> None:
    """The review's PoC: an ``agent.json`` planted where version 0.0.x kept it."""
    victim = make_victim(tmp_path)
    state = tmp_path / "repo" / ".git" / "nbp-safe"
    state.mkdir(parents=True)
    legacy = state / "agent.json"
    legacy.write_text(
        json.dumps(
            {
                "v": 1,
                "address": str(victim / "agent.sock"),
                "family": "AF_UNIX",
                "authkey": "00" * 32,
                "pid": 2_000_000_000 - 7,
                "started": 0.0,
                "expires_at": 9e18,
                "idle_timeout": None,
            }
        )
    )
    assert unlock.current_status(state) is None
    assert agent.cleanup_orphan(state) is False
    assert_victim_intact(victim)
    assert legacy.exists()  # not even touched


def test_cleanup_removes_only_agent_json_and_an_exact_socket(tmp_path: Path) -> None:
    state = tmp_path / "s"
    victim = make_victim(tmp_path)
    plant(state, address=str(victim / "agent.sock"), expires_at=1.0)
    rdir = agent.runtime_path(state)
    before = sorted(p.name for p in rdir.iterdir())
    assert agent.cleanup_orphan(state) is True
    after = sorted(p.name for p in rdir.iterdir())
    assert set(before) - set(after) == {agent.AGENT_JSON}  # nothing else went away
    assert_victim_intact(victim)


@pytest.mark.skipif(WINDOWS, reason="a filesystem socket exists on POSIX only")
def test_posix_socket_is_unlinked_only_at_its_exact_place(tmp_path: Path) -> None:
    import socket

    state = tmp_path / "s"
    sdir = agent.private_socket_dir(create=True)
    assert sdir is not None
    good = sdir / ("1" * 12 + "-" + "2" * 12 + ".sock")
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(str(good))
    srv.close()
    plant(state, address=str(good), family="AF_UNIX", expires_at=1.0)
    assert agent.cleanup_orphan(state) is True
    assert not good.exists()


@pytest.mark.parametrize(
    ("address", "family", "valid_on"),
    [
        (rf"\\.\pipe\nbp-git-safe-{'a' * 24}", "AF_PIPE", "win32"),
        (rf"\\.\pipe\nbp-git-safe-{'a' * 23}", "AF_PIPE", None),
        (rf"\\.\pipe\nbp-git-safe-{'A' * 24}", "AF_PIPE", None),
        (rf"\\.\pipe\nbp-git-safe-{'a' * 24}\..", "AF_PIPE", None),
        (rf"\\.\pipe\other-{'a' * 24}", "AF_PIPE", None),
        (rf"\\.\pipe\nbp-git-safe-{'a' * 24}", "AF_UNIX", None),
        ("", "AF_PIPE", None),
        ("relative/" + SOCK, "AF_UNIX", None),
        ("/abs/other/" + SOCK, "AF_UNIX", None),
        ("/abs/rdir/../rdir/" + SOCK, "AF_UNIX", None),
        ("/abs/rdir/" + SOCK, "AF_UNIX", "posix"),
        ("/abs/rdir/" + SOCK, "AF_INET", None),
    ],
)
def test_check_endpoint_accepts_only_what_this_program_makes(
    address: str, family: str, valid_on: str | None
) -> None:
    rdir = Path("/abs/rdir")
    ok = (valid_on == "win32" and WINDOWS) or (valid_on == "posix" and not WINDOWS)
    if ok:
        agent.check_endpoint(address, family, rdir)
    else:
        with pytest.raises(agent.AgentError, match="not valid"):
            agent.check_endpoint(address, family, rdir)


def test_a_handoff_with_a_foreign_endpoint_is_refused(tmp_path: Path) -> None:
    agent.private_dir(tmp_path / "s", create=True)
    sdir = agent.private_socket_dir(create=True)  # None on Windows (pipes have no directory)
    good = agent.new_endpoint(tmp_path / "s")
    assert agent.Endpoint.from_handoff(good.to_handoff(), sdir).address == good.address
    victim = make_victim(tmp_path)
    bad = dataclasses.replace(good, address=str(victim / "agent.sock"), family="AF_UNIX")
    with pytest.raises(agent.AgentError):
        agent.Endpoint.from_handoff(bad.to_handoff(), sdir)


# ------------------------------------------------------------------------------------ A1


def test_state_lives_outside_the_repository_and_is_per_repository(tmp_path: Path) -> None:
    one, two = tmp_path / "a" / ".git" / "nbp-safe", tmp_path / "b" / ".git" / "nbp-safe"
    assert agent.runtime_path(one) != agent.runtime_path(two)
    assert agent.runtime_path(one) == agent.runtime_path(one)
    assert agent.runtime_path(one).parent == agent.runtime_root()
    assert not agent.runtime_path(one).is_relative_to(tmp_path / "a")
    assert re.fullmatch(r"[0-9a-f]{24}", agent.runtime_path(one).name)


def test_runtime_root_follows_the_platform_conventions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent.clear_runtime_root()
    # Windows: %LOCALAPPDATA%; elsewhere only the explicit override moves the root (XDG_RUNTIME_DIR
    # does not: tests/unit/test_review2_unit.py)
    var = "LOCALAPPDATA" if WINDOWS else agent.RUNTIME_DIR_ENV
    expected = tmp_path / "base" / agent.RUNTIME_NAME if WINDOWS else tmp_path / "base"
    monkeypatch.setenv(var, str(tmp_path / "base"))
    assert agent.runtime_root() == expected
    monkeypatch.setenv(var, "relative-is-ignored")
    assert agent.runtime_root().is_absolute()
    assert Path("relative-is-ignored") not in agent.runtime_root().parents


def test_secret_and_derived_authkey(tmp_path: Path) -> None:
    rdir = agent.private_dir(tmp_path / "s", create=True)
    assert rdir is not None
    assert agent.load_secret(rdir, create=False) is None
    secret = agent.load_secret(rdir, create=True)
    assert secret is not None and len(secret) == agent.SECRET_LEN
    assert agent.load_secret(rdir, create=True) == secret  # stable
    assert agent.load_secret(rdir, create=False) == secret
    nonce = os.urandom(32)
    expected = hmac.new(secret, b"nbp-git-safe/agent/authkey/v2" + nonce, hashlib.sha256).digest()
    assert agent.derive_authkey(secret, nonce) == expected
    assert agent.derive_authkey(secret, os.urandom(32)) != expected
    assert agent.derive_authkey(os.urandom(32), nonce) != expected


def test_a_garbled_secret_is_replaced_only_when_creating(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rdir = agent.private_dir(tmp_path / "s", create=True)
    assert rdir is not None
    (rdir / agent.SECRET_FILE).write_bytes(b"short")
    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))
    clock = iter(range(0, 10_000, 3))
    monkeypatch.setattr(time, "monotonic", lambda: next(clock))
    with pytest.raises(agent.AgentError, match="corrupted"):
        agent.load_secret(rdir, create=False)
    fresh = agent.load_secret(rdir, create=True)
    assert fresh is not None and len(fresh) == agent.SECRET_LEN


def test_a_secret_that_is_not_a_regular_file_is_refused(tmp_path: Path) -> None:
    rdir = agent.private_dir(tmp_path / "s", create=True)
    assert rdir is not None
    (rdir / agent.SECRET_FILE).mkdir()
    with pytest.raises(agent.InsecureStateError):
        agent.load_secret(rdir, create=True)
    with pytest.raises(agent.InsecureStateError):
        agent.load_secret(rdir, create=False)


def make_loose(path: Path) -> None:
    """Make ``path`` writable by everybody (what a shared or hostile directory looks like)."""
    if WINDOWS:
        done = subprocess.run(
            ["icacls", str(path), "/grant", "*S-1-1-0:(OI)(CI)M"],
            capture_output=True,
            check=False,
        )
        assert done.returncode == 0, done.stderr
    else:
        path.chmod(0o777)


def test_a_state_directory_others_can_write_is_refused_and_left_alone(tmp_path: Path) -> None:
    state = tmp_path / "repo" / ".git" / "nbp-safe"
    rdir = agent.private_dir(state, create=True)
    assert rdir is not None
    plant(state)  # a perfectly valid-looking record ...
    assert agent.read_agent_info(state) is not None
    make_loose(rdir)  # ... in a directory somebody else can now write to
    with pytest.raises(agent.InsecureStateError, match="not private"):
        agent.read_agent_info(state)
    with pytest.raises(agent.AgentNotRunningError, match="not private"):
        agent.AgentClient.connect(state)
    assert unlock.current_status(state) is None
    assert agent.cleanup_orphan(state) is False
    agent.remove_agent_info(state)
    assert (rdir / agent.AGENT_JSON).exists()  # nothing was deleted from it
    with pytest.raises(agent.InsecureStateError):
        agent.write_agent_info(state, agent.AgentInfo("a", "AF_PIPE", b"k" * 32, 1, 1.0, 2.0, None))
    with pytest.raises(agent.InsecureStateError):
        agent.new_endpoint(state)
    with pytest.raises(agent.AgentError), agent.unlock_guard(state):
        pass
    with pytest.raises(agent.AgentError):
        agent.spawn_agent(state, 60, None)
    assert not any(p.suffix == ".sock" or p.name.startswith("s-") for p in rdir.iterdir())


@pytest.mark.skipif(WINDOWS, reason="a socket directory exists on POSIX only")
def test_a_squatted_or_loose_socket_directory_fails_closed(tmp_path: Path) -> None:
    """Squatting of the shared temp location: whoever pre-creates the socket directory can at
    most stop the agent from starting (denial of service); no socket is made in it and nothing
    secret is ever put there."""
    state = tmp_path / "s"
    sdir = agent.private_socket_dir(create=True)
    assert sdir is not None
    assert agent.private_socket_dir(create=True) == sdir  # an existing good one is accepted
    sdir.chmod(0o755)  # a loose mode (stands in for "created by somebody else")
    with pytest.raises(agent.InsecureStateError, match="socket directory is not private"):
        agent.private_socket_dir(create=True)
    with pytest.raises(agent.InsecureStateError):
        agent.new_endpoint(state)
    with pytest.raises(agent.AgentError):
        agent.spawn_agent(state, 60, None)
    assert list(sdir.iterdir()) == []
    sdir.chmod(0o700)
    sdir.rmdir()
    sdir.symlink_to(tmp_path)  # a link is no directory of ours
    with pytest.raises(agent.InsecureStateError):
        agent.private_socket_dir(create=True)
    assert list(tmp_path.glob("*.sock")) == []


@pytest.mark.skipif(WINDOWS, reason="AF_UNIX paths are POSIX only")
def test_socket_paths_are_short_and_a_too_long_root_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ep = agent.new_endpoint(tmp_path / "s")
    assert len(ep.address.encode()) <= agent.MAX_SOCKET_PATH
    agent.set_runtime_root(tmp_path / ("d" * 120))
    with pytest.raises(agent.AgentError, match="too long"):
        agent.new_endpoint(tmp_path / "s")


@pytest.mark.skipif(WINDOWS, reason="POSIX default location")
def test_default_socket_dir_is_short_and_fixed(monkeypatch: pytest.MonkeyPatch) -> None:
    agent.set_runtime_root(agent._default_posix_root())
    sdir = agent.socket_dir()
    assert sdir == Path(f"/tmp/nbp-{os.geteuid()}")  # noqa: S108
    assert len(str(sdir / ("a" * 12 + "-" + "b" * 12 + ".sock"))) < 60


def test_a_loose_runtime_root_is_refused_too(tmp_path: Path) -> None:
    root = agent.runtime_root()
    root.mkdir(parents=True, exist_ok=True)
    make_loose(root)
    with pytest.raises(agent.InsecureStateError):
        agent.private_dir(tmp_path / "s", create=True)
    with pytest.raises(agent.InsecureStateError):
        agent.private_dir(tmp_path / "s", create=False)  # an existing root is judged, too


def test_a_link_in_place_of_the_state_directory_is_refused(tmp_path: Path) -> None:
    state = tmp_path / "s"
    target = tmp_path / "elsewhere"
    target.mkdir()
    agent.runtime_root().mkdir(parents=True, exist_ok=True)
    link = agent.runtime_path(state)
    try:
        if WINDOWS:
            done = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link), str(target)],
                capture_output=True,
                check=False,
            )
            if done.returncode != 0:
                pytest.skip("cannot create a junction here")
        else:
            os.symlink(target, link)
    except OSError:
        pytest.skip("cannot create a link here")
    with pytest.raises(agent.InsecureStateError):
        agent.private_dir(state, create=True)
    assert list(target.iterdir()) == []


# --------------------------------------------------------------- the connection is checked


def test_the_serving_process_must_be_the_one_the_state_names(tmp_path: Path) -> None:
    ta = ThreadAgent(tmp_path / "s", KEY)
    try:
        wrong = dataclasses.replace(ta.info, pid=ta.info.pid + 1)
        with pytest.raises(agent.HandshakeError, match="not the expected"):
            agent.AgentClient.connect_info(wrong)
        with ta.client() as client:  # the right pid still works
            assert client.status()["locked"] is False
    finally:
        ta.stop()


def test_a_server_without_the_derived_key_is_rejected_before_any_request(tmp_path: Path) -> None:
    state = tmp_path / "s"
    evil_endpoint = dataclasses.replace(
        agent.new_endpoint(state), nonce=os.urandom(32), authkey=os.urandom(32)
    )
    evil = agent.AgentServer(state, 60, exit_func=lambda _c: None, endpoint=evil_endpoint)
    seen: list[int] = []
    real = evil._handle

    def spy(op: int, body: bytes):  # type: ignore[no-untyped-def]
        seen.append(op)
        return real(op, body)

    evil._handle = spy  # type: ignore[method-assign]
    evil.start()
    import threading

    threading.Thread(target=evil.serve_forever, daemon=True).start()
    try:
        with pytest.raises(agent.HandshakeError):
            agent.AgentClient.connect(state)
        assert seen == []  # not a single operation, let alone a key or plaintext, got through
    finally:
        evil.shutdown("test")


@pytest.mark.skipif(not WINDOWS, reason="Windows named pipes")
def test_windows_pipe_is_for_the_current_user_only_and_rejects_remote_clients(
    tmp_path: Path,
) -> None:
    from nbp_git_safe import winsec

    ta = ThreadAgent(tmp_path / "s", KEY)
    try:
        client = ta.client()
        try:
            sddl = winsec.pipe_dacl_sddl(client._conn._handle)  # type: ignore[attr-defined]
        finally:
            client.close()
        aces = re.findall(r"\(([^()]*)\)", sddl)
        assert aces, sddl
        assert all(ace.split(";")[0] == "A" for ace in aces)  # no other kind of entry
        me = winsec.current_user_sid()
        # the SDDL text may print the built-in Administrator as the alias ``LA`` (CI runner)
        trustees = {winsec._resolve_trustee(ace.split(";")[5], me) for ace in aces}
        assert trustees == {me.upper()}, sddl
    finally:
        ta.stop()
    assert winsec.PIPE_MODE & winsec.PIPE_REJECT_REMOTE_CLIENTS == 0x8
    assert (
        winsec.PIPE_MODE & winsec.PIPE_TYPE_MESSAGE
        and winsec.PIPE_MODE & winsec.PIPE_READMODE_MESSAGE
    )


@pytest.mark.skipif(not WINDOWS, reason="Windows named pipes")
def test_windows_pipe_name_cannot_be_squatted(tmp_path: Path) -> None:
    from nbp_git_safe import winsec

    ta = ThreadAgent(tmp_path / "s", KEY)
    try:
        with pytest.raises(OSError):  # FILE_FLAG_FIRST_PIPE_INSTANCE: the name is taken
            winsec.create_pipe_instance(ta.info.address, first=True)
    finally:
        ta.stop()


@pytest.mark.skipif(not WINDOWS, reason="Windows named pipes")
def test_windows_client_never_grants_impersonation(monkeypatch: pytest.MonkeyPatch) -> None:
    import _winapi

    from nbp_git_safe import winsec

    seen: list[int] = []

    def fake_create_file(name, access, share, sa, disposition, flags, template):  # type: ignore[no-untyped-def]
        seen.append(flags)
        raise OSError(2, "stop here")

    monkeypatch.setattr(_winapi, "CreateFile", fake_create_file)
    with pytest.raises(OSError):
        winsec.connect_pipe(r"\\.\pipe\whatever")
    assert seen and seen[0] & winsec.SECURITY_SQOS_PRESENT
    assert seen[0] & winsec.SECURITY_IDENTIFICATION


@pytest.mark.skipif(not WINDOWS, reason="Windows ACLs")
def test_windows_private_dir_check_knows_good_from_bad(tmp_path: Path) -> None:
    from nbp_git_safe import winsec

    good = tmp_path / "good"
    winsec.create_private_dir(good)
    assert winsec.private_dir_problem(good) is None
    assert winsec.private_dir_problem(good / "missing") == "cannot be inspected"
    (tmp_path / "file").write_bytes(b"x")
    assert winsec.private_dir_problem(tmp_path / "file") == "is not a directory"
    make_loose(good)
    assert "another account" in (winsec.private_dir_problem(good) or "")
    for system_dir in (r"C:\Windows", r"C:\Users"):  # owned by SYSTEM / TrustedInstaller
        assert winsec.private_dir_problem(system_dir) is not None


@pytest.mark.skipif(not WINDOWS, reason="Windows process identity")
def test_windows_process_identity_helpers() -> None:
    from nbp_git_safe import winsec

    assert winsec.is_current_user_process(os.getpid())
    assert winsec.parent_pid(os.getpid()) == os.getppid()
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"])
    try:
        assert winsec.parent_pid(child.pid) == os.getpid()
        assert winsec.process_owner_sid(child.pid) == winsec.current_user_sid()
    finally:
        child.kill()
        child.wait()
    assert winsec.process_owner_sid(2_000_000_000) is None
    assert winsec.parent_pid(2_000_000_000) is None
    assert not winsec.is_current_user_process(2_000_000_000)


def test_spawn_refuses_a_process_that_is_not_the_one_it_started(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ``READY <pid>`` line comes over a private pipe, but the pid it names must still be the
    started process (or, for a launcher stub, its direct child)."""
    import io

    killed: list[int] = []

    class Proc:
        pid = 4_000_000

        def __init__(self, line: bytes) -> None:
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO(line)

        def kill(self) -> None:
            killed.append(1)

        def wait(self, timeout: float | None = None) -> int:
            return 0

    stranger = os.getpid()  # alive, but neither the started process nor its child
    for line in (
        b"READY %d\n" % stranger,
        b"READY\n",
        b"READY 12 extra\n",
        b"HELLO 12\n",
        b"",
    ):
        monkeypatch.setattr(subprocess, "Popen", lambda *a, line=line, **k: Proc(line))
        with pytest.raises(agent.AgentError, match="failed to start"):
            agent.spawn_agent(tmp_path / "s", 5, None)
    assert len(killed) == 5  # every refused child was killed, none left running


def test_agent_info_repr_and_json_hide_the_authkey(tmp_path: Path) -> None:
    ta = ThreadAgent(tmp_path / "s", KEY)
    try:
        assert ta.info.authkey.hex() not in repr(ta.info)
        assert ta.info.authkey.hex() not in ta.info.to_json().decode()
        endpoint = agent.new_endpoint(tmp_path / "s2")
        assert endpoint.authkey.hex() not in repr(endpoint)
    finally:
        ta.stop()
