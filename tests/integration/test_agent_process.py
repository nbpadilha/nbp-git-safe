# SPDX-License-Identifier: MIT
"""The agent as a real, detached process driven through the CLI."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from nbp_git_safe import agent, crypto
from tests.helpers import NbpRepo, _kill, populate
from tests.leak.harness import LeakScanner, _b64_stable, assert_no_leaks


def wait_until(predicate, seconds: float = 10.0) -> bool:  # type: ignore[no-untyped-def]
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return predicate()


def live_info(repo: NbpRepo) -> agent.AgentInfo:
    info = agent.read_agent_info(repo.state_dir)
    assert info is not None
    return info


def key_needles(key: bytes) -> tuple[list[str], dict[str, bytes]]:
    """Everything that could be the key in a file: text forms through the harness, raw forms as
    literal needles."""
    text = [crypto.encode_key(key), key.hex(), key.hex().upper()]
    raw: dict[str, bytes] = {"key-raw": key, "key-b64-text-utf16": text[0].encode("utf-16-le")}
    for alignment in range(3):
        raw[f"key-b64-a{alignment}"] = _b64_stable(key, alignment, urlsafe=False)
        raw[f"key-b64url-a{alignment}"] = _b64_stable(key, alignment, urlsafe=True)
    return text, raw


def test_unlock_status_lock_with_a_real_detached_process(make_repo) -> None:  # type: ignore[no-untyped-def]
    repo: NbpRepo = make_repo()
    result = repo.cli("unlock")
    assert result.code == 0, result.err
    assert "unlocked (key " in result.out
    info = live_info(repo)
    assert info.pid != os.getpid() and agent.pid_alive(info.pid)
    assert info.family == ("AF_PIPE" if sys.platform == "win32" else "AF_UNIX")
    if sys.platform == "win32":
        assert info.address.startswith("\\\\.\\pipe\\nbp-git-safe-")

    again = repo.cli("unlock")
    assert again.code == 0 and "already unlocked" in again.out
    assert live_info(repo).pid == info.pid

    status = repo.cli("status")
    assert status.code == 0 and "agent: unlocked" in status.out

    assert repo.cli("lock").out.strip() == "locked"
    assert not agent.agent_json_path(repo.state_dir).exists()
    assert wait_until(lambda: not agent.pid_alive(info.pid))
    after = repo.cli("status")
    assert after.code == 3 and "locked" in after.out
    assert repo.cli("lock").out.strip() == "agent was not running"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only: checks the pythonw image")
def test_windows_agent_runs_windowless_under_pythonw(make_repo) -> None:  # type: ignore[no-untyped-def]
    repo: NbpRepo = make_repo()
    assert repo.cli("unlock").code == 0
    pid = live_info(repo).pid
    listing = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.lower()
    assert "pythonw" in listing


def test_ttl_expires_for_real(make_repo) -> None:  # type: ignore[no-untyped-def]
    repo: NbpRepo = make_repo()
    populate(repo)
    assert repo.cli("unlock", "--ttl", "3s").code == 0
    info = live_info(repo)
    assert info.expires_at - info.started == pytest.approx(3, abs=0.5)
    assert wait_until(lambda: not agent.pid_alive(info.pid), 15)
    assert not agent.agent_json_path(repo.state_dir).exists()
    sealed = repo.cli("seal")
    assert sealed.code == 3 and "unlock" in sealed.err
    assert repo.sh("for-each-ref", "refs/heads/nbp-safe").strip() == ""


def test_idle_timeout_for_real(make_repo) -> None:  # type: ignore[no-untyped-def]
    repo: NbpRepo = make_repo()
    assert repo.cli("unlock", "--idle-timeout", "2s").code == 0
    info = live_info(repo)
    assert info.idle_timeout == 2
    assert wait_until(lambda: not agent.pid_alive(info.pid), 15)


def test_key_is_absent_from_disk_agent_json_and_git_dir(make_repo, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    repo: NbpRepo = make_repo()
    populate(repo)
    assert repo.cli("unlock").code == 0
    assert repo.cli("seal").code == 0
    assert repo.cli("open").code == 0
    assert repo.cli("status").code == 0

    text, raw = key_needles(repo.master)
    scanner = LeakScanner(text, git_env=repo.git.env, raw_needles=raw)
    hits = scanner.scan_git_dir(repo.path / ".git")  # objects, refs, agent.json, statcache, ...
    hits += scanner.scan_dir(tmp_path)  # the whole temp tree of the test (work tree included)
    assert_no_leaks(hits)

    data = json.loads(agent.agent_json_path(repo.state_dir).read_text())
    assert set(data) == {
        "v",
        "address",
        "family",
        "authkey",
        "pid",
        "started",
        "expires_at",
        "idle_timeout",
    }
    assert crypto.encode_key(repo.master) not in json.dumps(data)


def test_key_scanner_is_proven_by_planting_the_key(tmp_path: Path) -> None:
    """The key-variant scanner is only trustworthy if it finds a deliberately planted key."""
    key = crypto.generate_key()
    text, raw = key_needles(key)
    scanner = LeakScanner(text, raw_needles=raw)
    for name, payload in {
        "raw": key,
        "b64": crypto.encode_key(key).encode(),
        "hex": key.hex().encode(),
        "embedded-b64": b"prefix" + base64.b64encode(b"zz" + key + b"zz"),
        "utf16": crypto.encode_key(key).encode("utf-16-le"),
    }.items():
        planted = tmp_path / f"{name}.dat"
        planted.write_bytes(b"noise " + payload + b" noise")
        assert scanner.scan_dir(tmp_path), name
        planted.unlink()
    assert scanner.scan_dir(tmp_path) == []


@pytest.mark.parametrize("mode", ["exit1", "garbage", "short", "long"])
def test_bad_key_command_fails_closed_without_an_agent(make_repo, mode: str) -> None:  # type: ignore[no-untyped-def]
    repo: NbpRepo = make_repo(mode=mode)
    result = repo.cli("unlock")
    assert result.code == 1
    assert "error" in result.err
    assert crypto.encode_key(repo.master) not in result.err + result.out
    assert not agent.agent_json_path(repo.state_dir).exists()
    assert repo.cli("status").code == 3


def test_key_command_timeout_fails_closed(make_repo) -> None:  # type: ignore[no-untyped-def]
    repo: NbpRepo = make_repo(mode="sleep")
    repo.set_config("nbp-safe.keyCommandTimeout", "1")
    started = time.monotonic()
    result = repo.cli("unlock")
    assert result.code == 1 and "timed out" in result.err
    assert time.monotonic() - started < 60
    assert not agent.agent_json_path(repo.state_dir).exists()


def test_no_key_command_configured(make_repo) -> None:  # type: ignore[no-untyped-def]
    repo: NbpRepo = make_repo()
    repo.sh("config", "--local", "--unset", "nbp-safe.keyCommand")
    result = repo.cli("unlock")
    assert result.code == 1 and "no keyCommand configured" in result.err


def test_versioned_file_cannot_provide_a_key_command(make_repo) -> None:  # type: ignore[no-untyped-def]
    repo: NbpRepo = make_repo()
    repo.sh("config", "--local", "--unset", "nbp-safe.keyCommand")
    marker = repo.path / "rce-marker"
    payload = json.dumps([sys.executable, "-c", f"open({str(marker)!r}, 'w').write('x')"])
    repo.write(".nbp-safe.config", f"[nbp-safe]\n\tkeyCommand = {payload}\n")
    assert repo.cli("unlock").code == 1
    assert not marker.exists()


def test_killed_agent_fails_closed_and_orphan_is_cleaned(make_repo) -> None:  # type: ignore[no-untyped-def]
    repo: NbpRepo = make_repo()
    populate(repo)
    assert repo.cli("unlock").code == 0
    pid = live_info(repo).pid
    _kill(pid)
    assert wait_until(lambda: not agent.pid_alive(pid))
    assert agent.agent_json_path(repo.state_dir).exists()  # orphan left behind by the kill

    for command in ("seal", "open", "ls"):
        result = repo.cli(command)
        assert result.code == 3, (command, result.err)
    assert not agent.agent_json_path(repo.state_dir).exists()  # cleaned on first contact
    assert repo.sh("for-each-ref", "refs/heads/nbp-safe").strip() == ""  # nothing was sealed


def test_unlock_cleans_an_orphan_and_starts_fresh(make_repo) -> None:  # type: ignore[no-untyped-def]
    repo: NbpRepo = make_repo()
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()
    repo.state_dir.mkdir(parents=True, exist_ok=True)
    orphan = agent.AgentInfo(
        "stale", "AF_PIPE", os.urandom(32), dead.pid, time.time(), time.time() + 1000, None
    )
    agent.write_agent_info(repo.state_dir, orphan)
    assert repo.cli("unlock").code == 0
    assert live_info(repo).pid != dead.pid
    assert repo.cli("status").code == 0


def test_agent_started_by_one_cli_serves_another_and_a_worktree(make_repo, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    repo: NbpRepo = make_repo()
    repo.write("seed.txt", "x")
    repo.sh("add", "seed.txt")
    repo.sh("commit", "-q", "-m", "seed")
    other = tmp_path / "linked"
    repo.sh("worktree", "add", "-q", str(other), "-b", "side")
    assert repo.cli("unlock").code == 0
    linked = NbpRepo(other, repo.git, repo.canaries, repo.master)
    linked_status = linked.cli("status")
    assert linked_status.code == 0 and "agent: unlocked" in linked_status.out
    assert agent.agent_json_path(repo.state_dir).exists()  # the state lives in the common dir


def test_keygen_prints_once_to_stdout_and_stores_nothing(
    make_repo, tmp_path: Path, monkeypatch
) -> None:  # type: ignore[no-untyped-def]
    repo: NbpRepo = make_repo()
    before = {p for p in tmp_path.rglob("*")}
    result = repo.cli("keygen")
    assert result.code == 0
    key = result.out.strip()
    assert len(crypto.decode_key(key)) == 64
    assert "ONCE" in result.err and key not in result.err
    assert {p for p in tmp_path.rglob("*")} == before  # nothing written anywhere

    init = repo.cli("init", "--generate-key")
    assert init.code == 0
    key2 = init.out.strip()
    assert len(crypto.decode_key(key2)) == 64 and key2 != key
    assert key2 not in init.err
    scanner = LeakScanner([key2], git_env=repo.git.env)
    assert_no_leaks(scanner.scan_git_dir(repo.path / ".git") + scanner.scan_dir(tmp_path))
