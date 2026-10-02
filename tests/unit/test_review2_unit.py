# SPDX-License-Identifier: MIT
"""Second adversarial review, the small items: agent identity under elevation, DACL aliases,
PATH entries inside the repository, the clean git environment and the Linux state root.

Everything here is a pure-logic test with simulated inputs (no Windows API, no Linux needed)."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from nbp_git_safe import agent, gitutil, hooks, winsec

# ------------------------------------------------------------- agent identity and elevation

ME = "S-1-5-21-1111111111-2222222222-3333333333-1001"


class FakeDll:
    """Stands in for a ctypes DLL: ``OpenProcess`` succeeds, ``OpenProcessToken`` is set."""

    def __init__(self, token_ok: bool, process_ok: bool = True) -> None:
        self.token_ok, self.process_ok = token_ok, process_ok
        self.closed: list[object] = []

    def OpenProcess(self, *_a: object) -> int:
        return 1 if self.process_ok else 0

    def OpenProcessToken(self, *_a: object) -> int:
        return 1 if self.token_ok else 0

    def CloseHandle(self, handle: object) -> None:
        self.closed.append(handle)


def info_for(pid: int) -> agent.AgentInfo:
    return SimpleNamespace(pid=pid)  # type: ignore[return-value]


@pytest.mark.parametrize("failing", ["OpenProcessToken", "OpenProcess"])
def test_an_agent_that_cannot_be_inspected_degrades_with_an_elevation_hint(
    monkeypatch: pytest.MonkeyPatch, failing: str
) -> None:
    """The agent runs elevated and the hook does not (or the reverse): the process token cannot be
    opened. That must not read as "an impostor" and must not break the commit."""
    dll = FakeDll(token_ok=failing != "OpenProcessToken", process_ok=failing != "OpenProcess")
    monkeypatch.setattr(winsec, "_dll", lambda _name: dll)
    monkeypatch.setattr(winsec, "current_user_sid", lambda: ME)
    monkeypatch.setattr(winsec, "pipe_server_pid", lambda _handle: 4242)
    assert winsec.process_owner_sid(4242) is None
    conn = SimpleNamespace(_handle=7)
    with pytest.raises(agent.ProcessInspectionError) as caught:
        agent._verify_windows(conn, info_for(4242))  # type: ignore[arg-type]
    assert "elevation" in str(caught.value)
    assert isinstance(caught.value, agent.HandshakeError)  # still a failed authentication


def test_another_process_or_another_user_is_still_an_impostor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(winsec, "current_user_sid", lambda: ME)
    monkeypatch.setattr(winsec, "pipe_server_pid", lambda _handle: 1)
    with pytest.raises(agent.HandshakeError) as wrong_pid:
        agent._verify_windows(SimpleNamespace(_handle=7), info_for(4242))  # type: ignore[arg-type]
    assert not isinstance(wrong_pid.value, agent.ProcessInspectionError)
    monkeypatch.setattr(winsec, "pipe_server_pid", lambda _handle: 4242)
    monkeypatch.setattr(winsec, "process_owner_sid", lambda _pid: "S-1-5-21-9-9-9-1002")
    with pytest.raises(agent.HandshakeError) as other_user:
        agent._verify_windows(SimpleNamespace(_handle=7), info_for(4242))  # type: ignore[arg-type]
    assert not isinstance(other_user.value, agent.ProcessInspectionError)
    monkeypatch.setattr(winsec, "process_owner_sid", lambda _pid: ME)
    agent._verify_windows(SimpleNamespace(_handle=7), info_for(4242))  # type: ignore[arg-type]


def test_hooks_fall_back_to_the_path_check_and_say_why(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(_state_dir: object) -> object:
        raise agent.ProcessInspectionError(agent.ELEVATION_MESSAGE)

    monkeypatch.setattr(agent.AgentClient, "connect", staticmethod(refuse))
    repo = SimpleNamespace(state_dir=Path("unused"))
    cfg = SimpleNamespace(auto_unlock=False, key_command=None)
    client, reason = hooks.acquire_backend(repo, cfg)  # type: ignore[arg-type]
    assert client is None and "elevation" in reason
    hint = hooks._locked_hint(reason)
    assert hint.startswith("agent unavailable") and "elevation" in hint
    assert "run `nbp-git-safe unlock`" not in hint  # unlocking again would not help


# ------------------------------------------------------------------------ DACL aliases

SDDL = "D:PAI{}"


@pytest.mark.parametrize(
    ("aces", "me", "expected_ok"),
    [
        ("(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + ME + ")", ME, True),
        ("(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;CO)", ME, True),
        # the current user is the built-in Administrator: SDDL prints the alias LA for its SID
        ("(A;OICI;FA;;;LA)(A;OICI;FA;;;SY)", "S-1-5-21-1111111111-2222222222-3333333333-500", True),
        ("(A;OICI;FA;;;S-1-5-21-1111111111-2222222222-3333333333-500)", ME, True),  # admin
        ("(A;;FA;;;LA)", ME, True),  # the built-in Administrator is as trusted as BA
        ("(A;;GA;;;OW)(A;;GA;;;" + ME + ")", ME, True),  # owner rights
        ("(A;OICI;FA;;;WD)", ME, False),  # Everyone
        ("(A;OICI;FA;;;AU)", ME, False),  # Authenticated Users
        ("(A;OICI;FA;;;BU)", ME, False),  # Users
        ("(A;OICI;FA;;;IU)", ME, False),  # Interactive
        ("(A;OICI;FA;;;AN)", ME, False),  # Anonymous
        ("(A;OICI;FA;;;S-1-5-21-1111111111-2222222222-3333333333-1002)", ME, False),  # another user
        ("(A;OICI;FA;;;S-1-5-21-9-9-9-500)", ME, False),  # another machine's administrator
        ("(D;OICI;FA;;;WD)(A;OICI;FA;;;SY)", ME, True),  # a deny entry grants nothing
        ("(A;OICI;FA;;)", ME, False),  # malformed
    ],
)
def test_dacl_aliases_are_resolved_before_comparing(aces: str, me: str, expected_ok: bool) -> None:
    problem = winsec._dacl_problem(SDDL.format(aces), me)
    assert (problem is None) == expected_ok, problem


# ----------------------------------------------------- PATH entries inside the repository


def make_tool(directory: Path, name: str = "faketool") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (name + (".exe" if sys.platform == "win32" else ""))
    path.write_bytes(b"#!/bin/sh\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def test_path_entries_inside_the_repository_tree_are_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "src").mkdir()
    planted = make_tool(repo / "node_modules" / ".bin")
    planted_deep = make_tool(repo / "tools" / "bin")
    genuine = make_tool(tmp_path / "elsewhere")
    path = os.pathsep.join([str(planted.parent), str(planted_deep.parent), str(genuine.parent)])
    env = {"PATH": path, "PATHEXT": ".EXE"}
    # the working directory is a SUBDIRECTORY: only the repository root tells where "inside" ends
    monkeypatch.chdir(repo / "src")
    assert gitutil.resolve_executable("faketool", env) == str(genuine)
    # nothing outside the repository: the bare name comes back (never a planted file)
    only_planted = {"PATH": str(planted.parent), "PATHEXT": ".EXE"}
    assert gitutil.resolve_executable("faketool", only_planted) == "faketool"
    # outside any repository only the current directory is skipped, as before
    outside = tmp_path / "plain"
    outside.mkdir()
    monkeypatch.chdir(outside)
    assert gitutil.resolve_executable("faketool", only_planted) == str(planted)


def test_a_declared_repository_root_is_avoided_even_from_another_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``nbp-git-safe -C <repo>`` runs from anywhere: ``discover`` declares the repository."""
    repo = tmp_path / "repo"
    planted = make_tool(repo / "bin")
    genuine = make_tool(tmp_path / "elsewhere")
    env = {"PATH": os.pathsep.join([str(planted.parent), str(genuine.parent)]), "PATHEXT": ".EXE"}
    monkeypatch.chdir(tmp_path)
    assert gitutil.resolve_executable("faketool", env) == str(planted)
    assert gitutil.resolve_executable("faketool", env, avoid=(repo,)) == str(genuine)


# --------------------------------------------------------------------------- clean env


def test_the_clean_environment_drops_config_and_program_injection() -> None:
    dirty = {
        "PATH": "/bin",
        "HOME": "/home/x",
        "GIT_AUTHOR_NAME": "Test User",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_DIR": "/repo/.git",
        "GIT_CONFIG_PARAMETERS": "'core.hooksPath=/evil'",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.fsmonitor",
        "GIT_CONFIG_VALUE_0": "/evil",
        "GIT_EXTERNAL_DIFF": "/evil",
        "GIT_PAGER": "/evil",
        "GIT_ASKPASS": "/evil",
        "SSH_ASKPASS": "/evil",
        "GIT_SSH_COMMAND": "/evil",
        "GIT_EDITOR": "/evil",
        "GIT_TRACE": "1",
        "GIT_TRACE2_EVENT": "1",
    }
    clean = gitutil.clean_env(dirty)
    assert set(clean) == {
        "PATH",
        "HOME",
        "GIT_AUTHOR_NAME",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_NOSYSTEM",
    }  # identity and the user's own (or the test's) config files stay; nothing that executes


def test_the_user_environment_of_the_main_repository_is_left_alone() -> None:
    """The decision: only auxiliary (scratch) repositories get the clean environment. The calls
    about the user's repository keep GIT_CONFIG_*/GIT_ASKPASS/GIT_SSH_COMMAND, which fetch and push
    legitimately need."""
    git = gitutil.Git(".", {"PATH": "/bin", "GIT_ASKPASS": "x", "GIT_CONFIG_COUNT": "1"})
    assert git.env["GIT_ASKPASS"] == "x" and git.env["GIT_CONFIG_COUNT"] == "1"
    assert "GIT_ASKPASS" not in git.clean("elsewhere").env


# ------------------------------------------------------------ Linux state root (simulated)


@pytest.mark.parametrize("xdg", [None, "/run/user/1000", "/run/user/1000/", "relative"])
def test_the_posix_state_root_does_not_depend_on_xdg_runtime_dir(xdg: str | None) -> None:
    env = {"HOME": "/somewhere/else"} | ({} if xdg is None else {"XDG_RUNTIME_DIR": xdg})
    root = agent.compute_runtime_root("linux", env, uid=1000, home=Path("/home/alice"))
    assert root == Path("/home/alice/.cache") / f"{agent.RUNTIME_NAME}-1000"


def test_the_posix_state_root_is_per_user_and_ignores_home_in_the_environment() -> None:
    a = agent.compute_runtime_root("linux", {"HOME": "/x"}, uid=1000, home=Path("/home/alice"))
    b = agent.compute_runtime_root("darwin", {"HOME": "/y"}, uid=1001, home=Path("/Users/bob"))
    assert a != b and a.name.endswith("-1000") and b.name.endswith("-1001")
    assert agent.compute_runtime_root("linux", {}, uid=1000, home=Path("/home/alice")) == a


def test_the_explicit_override_wins_and_must_be_absolute() -> None:
    absolute = Path(os.path.abspath("nbp-runtime-override"))
    env = {"NBP_SAFE_RUNTIME_DIR": str(absolute)}
    assert agent.compute_runtime_root("linux", env, uid=1, home=Path("/h")) == absolute
    relative = {"NBP_SAFE_RUNTIME_DIR": "rel/dir"}
    assert agent.compute_runtime_root("linux", relative, uid=1, home=Path("/h")) == (
        Path("/h/.cache") / f"{agent.RUNTIME_NAME}-1"
    )


def test_the_windows_root_still_uses_localappdata() -> None:
    base = Path(os.path.abspath("localappdata"))
    root = agent.compute_runtime_root(
        "win32", {"LOCALAPPDATA": str(base)}, uid=None, home=Path("/h")
    )
    assert root == base / agent.RUNTIME_NAME
