# SPDX-License-Identifier: MIT
from __future__ import annotations

import sys
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from nbp_git_safe import agent, crypto, unlock
from tests.helpers import KEYCMD, ThreadAgent


def _cmd(mode: str) -> list[str]:
    return [sys.executable, str(KEYCMD), mode]


def test_run_key_command_returns_the_key(master_key: bytes) -> None:
    assert unlock.run_key_command(_cmd("ok"), 30) == master_key


@pytest.mark.parametrize(
    ("mode", "fragment"),
    [
        ("exit1", "exit code 1"),  # even though it printed a valid key
        ("garbage", "not a valid key"),
        ("short", "not a valid key"),
        ("long", "not a valid key"),
    ],
)
def test_run_key_command_fails_closed(master_key: bytes, mode: str, fragment: str) -> None:
    with pytest.raises(unlock.KeyCommandError, match=fragment) as exc:
        unlock.run_key_command(_cmd(mode), 30)
    assert crypto.encode_key(master_key) not in str(exc.value)


def test_run_key_command_timeout_kills_the_process(master_key: bytes) -> None:
    t0 = time.monotonic()
    with pytest.raises(unlock.KeyCommandError, match="timed out"):
        unlock.run_key_command(_cmd("sleep"), 1.0)
    assert time.monotonic() - t0 < 30


def test_run_key_command_missing_executable_and_empty() -> None:
    with pytest.raises(unlock.KeyCommandError, match="not found"):
        unlock.run_key_command(["definitely-not-a-real-program-xyz"], 5)
    with pytest.raises(unlock.KeyCommandError, match="no keyCommand"):
        unlock.run_key_command([], 5)


def test_run_key_command_is_not_run_through_a_shell(master_key: bytes, tmp_path: Path) -> None:
    marker = tmp_path / "pwned"
    # a shell would interpret the ``&``; as a plain argv element it is just an argument
    argv = [sys.executable, str(KEYCMD), "ok", "&", "echo", "x", ">", str(marker)]
    assert unlock.run_key_command(argv, 30) == master_key
    assert not marker.exists()


def test_run_key_command_cannot_be_started(tmp_path: Path) -> None:
    with pytest.raises(unlock.KeyCommandError, match=r"could not be started|not found"):
        unlock.run_key_command([str(tmp_path)], 5)  # a directory is not executable


def _spawn_in_thread(created: list[ThreadAgent]) -> Callable[..., agent.AgentInfo]:
    def spawn(state_dir: Path, ttl: float, idle: float | None) -> agent.AgentInfo:
        ta = ThreadAgent(state_dir, None, ttl, idle)
        created.append(ta)
        return ta.info

    return spawn


def test_unlock_flow_with_stub_spawn(master_key: bytes, tmp_path: Path) -> None:
    created: list[ThreadAgent] = []
    spawn = _spawn_in_thread(created)
    try:
        newly, status = unlock.unlock(
            tmp_path, _cmd("ok"), ttl=60, idle_timeout=None, key_timeout=30, spawn=spawn
        )
        assert newly is True
        assert status["key_id"] == crypto.KeySet(master_key).key_id.hex()
        newly, status = unlock.unlock(
            tmp_path, _cmd("ok"), ttl=60, idle_timeout=None, key_timeout=30, spawn=spawn
        )
        assert newly is False and len(created) == 1  # already unlocked: nothing spawned
        assert unlock.current_status(tmp_path)["locked"] is False  # type: ignore[index]
        assert unlock.lock(tmp_path) is True
        assert created[0].exited.wait(5)  # the exit callback runs just after the record is gone
        assert unlock.current_status(tmp_path) is None
        assert unlock.lock(tmp_path) is False
    finally:
        for ta in created:
            ta.stop()


@pytest.mark.parametrize("mode", ["exit1", "garbage", "short", "long"])
def test_failed_key_command_starts_no_agent(master_key: bytes, tmp_path: Path, mode: str) -> None:
    created: list[ThreadAgent] = []
    with pytest.raises(unlock.KeyCommandError):
        unlock.unlock(
            tmp_path,
            _cmd(mode),
            ttl=60,
            idle_timeout=None,
            key_timeout=30,
            spawn=_spawn_in_thread(created),
        )
    assert created == []
    assert not agent.agent_json_path(tmp_path).exists()


def test_missing_key_command_starts_no_agent(tmp_path: Path) -> None:
    created: list[ThreadAgent] = []
    with pytest.raises(unlock.KeyCommandError, match="no keyCommand"):
        unlock.unlock(
            tmp_path,
            None,
            ttl=60,
            idle_timeout=None,
            key_timeout=5,
            spawn=_spawn_in_thread(created),
        )
    assert created == []


def test_unlock_replaces_an_agent_that_never_got_a_key(master_key: bytes, tmp_path: Path) -> None:
    created: list[ThreadAgent] = []
    created.append(ThreadAgent(tmp_path, None, 60))  # running but empty
    try:
        newly, status = unlock.unlock(
            tmp_path,
            _cmd("ok"),
            ttl=60,
            idle_timeout=None,
            key_timeout=30,
            spawn=_spawn_in_thread(created),
        )
        assert newly is True and status["locked"] is False
        assert created[0].exited.wait(5)
    finally:
        for ta in created:
            ta.stop()


def test_failed_delivery_locks_the_new_agent(master_key: bytes, tmp_path: Path) -> None:
    created: list[ThreadAgent] = []

    def spawn(state_dir: Path, ttl: float, idle: float | None) -> agent.AgentInfo:
        ta = ThreadAgent(state_dir, None, ttl, idle)
        created.append(ta)
        ta.server._keys = crypto.KeySet(b"\x01" * 64)  # key already present: load_key will fail
        return ta.info

    try:
        with pytest.raises(agent.AgentError):
            unlock.unlock(
                tmp_path, _cmd("ok"), ttl=60, idle_timeout=None, key_timeout=30, spawn=spawn
            )
        assert created[0].exited.wait(5)  # the half-initialised agent was told to lock
    finally:
        for ta in created:
            ta.stop()


def test_spawn_does_not_pass_the_key_in_argv_or_env(
    master_key: bytes, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real spawn path: capture what would be handed to the new process."""
    import io
    import subprocess

    seen: dict[str, object] = {}

    class Sink(io.BytesIO):
        def close(self) -> None:
            seen["handoff"] = self.getvalue()
            super().close()

    class FakeProc:
        pid = 0

        def __init__(self) -> None:
            self.stdin = Sink()
            self.stdout = io.BytesIO(b"")  # dies before announcing itself

        def kill(self) -> None:
            pass

        def wait(self, timeout: float | None = None) -> int:
            return 1

    def fake_popen(argv: list[str], **kwargs: object) -> FakeProc:
        seen["argv"], seen["kwargs"] = argv, kwargs
        return FakeProc()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    with pytest.raises(agent.AgentError, match="failed to start"):
        agent.spawn_agent(tmp_path / "s", 60, 30)
    key_text = crypto.encode_key(master_key)
    handoff = seen["handoff"]
    assert isinstance(handoff, bytes) and handoff.endswith(b"\n")  # the endpoint went over stdin
    blob = repr({k: v for k, v in seen.items() if k != "handoff"}) + repr(handoff)
    for needle in (key_text, master_key.hex(), repr(master_key)):
        assert needle not in blob
    kwargs = seen["kwargs"]
    assert isinstance(kwargs, dict)
    assert kwargs["stdin"] == subprocess.PIPE and kwargs["stdout"] == subprocess.PIPE
    assert "NBP_SAFE_TEST_KEY" not in kwargs["env"]  # type: ignore[operator]
    assert Path(kwargs["cwd"]) == agent.runtime_path(tmp_path / "s")  # type: ignore[arg-type]
    if sys.platform == "win32":
        flags = kwargs["creationflags"]
        assert flags & subprocess.DETACHED_PROCESS and flags & subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
    else:
        assert kwargs["start_new_session"] is True
    argv = seen["argv"]
    assert isinstance(argv, list) and "--idle" in argv
    assert argv[1:4] == ["-I", "-m", "nbp_git_safe.agent"]
