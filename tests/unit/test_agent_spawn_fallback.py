# SPDX-License-Identifier: MIT
"""Fallback to ``python.exe`` when Application Control blocks ``pythonw.exe`` at spawn time."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from nbp_git_safe import agent


def _interp_dir(tmp_path: Path, with_pythonw: bool) -> str:
    root = tmp_path / "interp"
    root.mkdir()
    if with_pythonw:
        (root / "pythonw.exe").write_bytes(b"")
    return str(root / "python.exe")


def test_agent_executables_prefers_pythonw_when_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = _interp_dir(tmp_path, with_pythonw=True)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "executable", exe)
    pythonw = str(Path(exe).with_name("pythonw.exe"))
    assert agent._agent_executables() == [pythonw, exe]
    assert agent._agent_executable() == pythonw


def test_agent_executables_without_pythonw_sibling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exe = _interp_dir(tmp_path, with_pythonw=False)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "executable", exe)
    assert agent._agent_executables() == [exe]


class _Started(Exception):
    """Sentinel raised by the fake ``Popen`` to mark a simulated successful start."""


def _fake_spawn_setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Let ``spawn_agent`` reach ``Popen`` without touching real agent state."""
    endpoint = agent.Endpoint(
        r"\\.\pipe\nbp-git-safe-aaaaaaaaaaaaaaaaaaaaaaaa", "AF_PIPE", bytes(range(32)), bytes(32)
    )
    monkeypatch.setattr(
        agent, "_agent_executables", lambda: ["C:/x/pythonw.exe", "C:/x/python.exe"]
    )
    monkeypatch.setattr(agent, "new_endpoint", lambda _state_dir: endpoint)
    monkeypatch.setattr(agent, "runtime_path", lambda _state_dir: tmp_path / "rdir")


def test_spawn_falls_back_to_python_exe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_spawn_setup(tmp_path, monkeypatch)
    calls: list[list[str]] = []

    def fake_popen(argv: list[str], *args: object, **kwargs: object) -> object:
        calls.append(argv)
        if argv[0].endswith("pythonw.exe"):
            raise OSError(22, "blocked", None, 4551)
        raise _Started()

    monkeypatch.setattr(agent.subprocess, "Popen", fake_popen)
    with pytest.raises(_Started):
        agent.spawn_agent(tmp_path / "s", 60.0, None)
    assert [argv[0] for argv in calls] == ["C:/x/pythonw.exe", "C:/x/python.exe"]
    assert calls[1][1:4] == ["-I", "-m", "nbp_git_safe.agent"]


def test_spawn_raises_agent_error_when_every_interpreter_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _fake_spawn_setup(tmp_path, monkeypatch)

    def fake_popen(argv: list[str], *args: object, **kwargs: object) -> object:
        raise OSError(22, "blocked", None, 4551)

    monkeypatch.setattr(agent.subprocess, "Popen", fake_popen)
    with pytest.raises(agent.AgentError) as excinfo:
        agent.spawn_agent(tmp_path / "s", 60.0, None)
    message = str(excinfo.value)
    assert "could not be started" in message
    assert "blocked" not in message and "C:/x" not in message and "pythonw.exe" not in message
