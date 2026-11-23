# SPDX-License-Identifier: MIT
"""A git that talks to a remote must never wait for ever (review finding M2): a hard time limit
that kills the WHOLE process tree (an ``ssh`` or a credential helper holding the pipes open would
otherwise keep the wait going), an environment in which nothing can ask a person, and a refusal of
the user's own ssh choice being overridden. The "remote" is a local socket that accepts a connection
and never answers; no real host, no real data."""

from __future__ import annotations

import socket
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from nbp_git_safe import agent, fleetops, gitutil, multi
from nbp_git_safe.config import Config
from nbp_git_safe.gitutil import Git, GitTimeoutError, Repo
from tests import helpers
from tests.integration.fleetkit import MakeRepo, repo_named


class MuteServer:
    """Accepts TCP connections and never says a word. ``closed`` is set when a client goes away
    (the proof that the process holding the connection is really dead)."""

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.accepted = threading.Event()
        self.closed = threading.Event()
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        self.sock.settimeout(0.2)
        held: list[socket.socket] = []
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                conn = None
            except OSError:
                break
            if conn is not None:
                conn.settimeout(0.2)
                held.append(conn)
                self.accepted.set()
            for client in held:
                try:
                    if client.recv(65536) == b"":  # EOF: the client was killed or gave up
                        self.closed.set()
                except TimeoutError:
                    pass
                except OSError:  # a reset is the same thing
                    self.closed.set()
        for client in held:
            client.close()

    def stop(self) -> None:
        self._stop = True
        self._thread.join(2)
        self.sock.close()


@pytest.fixture
def mute_origin() -> Iterator[MuteServer]:
    server = MuteServer()
    yield server
    server.stop()


# ------------------------------------------------------------------ the real thing: a hung origin


def test_a_push_to_an_origin_that_never_answers_is_stopped_with_its_children(
    make_repo: MakeRepo, mute_origin: MuteServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    repo = repo_named(make_repo, "hung")
    helpers.populate(repo)
    repo.set_config("nbp-safe.autoPush", "true")
    thread_agent = repo.unlock_in_thread()
    try:
        assert repo.cli("init").code == 0 and repo.cli("seal").code == 0
    finally:
        thread_agent.stop()
    repo.sh("remote", "add", "origin", f"http://127.0.0.1:{mute_origin.port}/hung.git")
    handle = fleetops.open_handle(repo.path, 1)
    started = time.monotonic()
    outcome = fleetops.push_one(handle, timeout=3)
    elapsed = time.monotonic() - started
    assert mute_origin.accepted.is_set()  # git really connected, so it was really waiting
    assert outcome.kind == fleetops.WARN and outcome.code == "push-timeout"
    assert "3 s" in outcome.message and "nbp-git-safe push" in outcome.message
    assert 3 <= elapsed < 20  # the limit, plus the time to kill the tree
    assert mute_origin.closed.wait(10)  # the process that held the connection is gone too


def test_the_vault_fetch_has_the_same_limit(
    make_repo: MakeRepo, mute_origin: MuteServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    repo = repo_named(make_repo, "fetchhung")
    repo.sh("remote", "add", "origin", f"http://127.0.0.1:{mute_origin.port}/x.git")
    handle = fleetops.open_handle(repo.path, 1)
    git = Git(handle.git.cwd, gitutil.network_env(handle.git.env))
    with pytest.raises(GitTimeoutError, match="2 s"):
        multi.fetch_vault(git, handle.cfg, timeout=2)
    assert mute_origin.closed.wait(10)


# ------------------------------------------------- the whole tree, with a stand-in for git


def fake_git(tmp_path: Path, pid_file: Path) -> str:
    """An executable that behaves like a git whose ssh child never exits: it starts a grandchild
    that inherits the pipes, records its pid, and then sleeps."""
    script = tmp_path / "fakegit.py"
    script.write_text(
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
        f"open({str(pid_file)!r}, 'w').write(str(child.pid))\n"
        "time.sleep(120)\n",
        encoding="utf-8",
    )
    if sys.platform == "win32":
        wrapper = tmp_path / "fakegit.cmd"
        wrapper.write_text(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n', encoding="ascii")
    else:
        wrapper = tmp_path / "fakegit.sh"
        wrapper.write_text(
            f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="ascii"
        )
        wrapper.chmod(0o755)
    return str(wrapper)


def test_the_timeout_kills_grandchildren_that_hold_the_pipes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid_file = tmp_path / "grandchild.pid"
    monkeypatch.setattr(gitutil, "git_executable", lambda: fake_git(tmp_path, pid_file))
    git = Git(tmp_path)
    started = time.monotonic()
    with pytest.raises(GitTimeoutError, match="did not finish within 2 s"):
        git.run_status("push", "origin", timeout=2)
    assert time.monotonic() - started < 30  # not the two minutes the grandchild sleeps
    deadline = time.monotonic() + 10
    pid = int(pid_file.read_text(encoding="ascii"))
    while agent.pid_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not agent.pid_alive(pid)  # nothing was left behind


def test_run_and_status_without_a_timeout_are_unchanged(tmp_path: Path) -> None:
    git = Git(tmp_path)
    assert git.run("--version").startswith(b"git version")
    code, out, _err = git.run_status("--version")
    assert code == 0 and out.startswith(b"git version")
    assert git.run_status("--version", timeout=30)[0] == 0  # the timed path works as well


# --------------------------------------------------------------------- the environment (M2b)


class StubGit:
    """Just enough of ``Git`` for ``ssh_is_user_defined``."""

    def __init__(self, env: dict[str, str], configured: bytes | None = None) -> None:
        self.env = env
        self.configured = configured

    def try_run(self, *_args: str) -> bytes | None:
        return self.configured


def test_network_env_never_prompts_and_never_opens_a_credential_window() -> None:
    env = gitutil.network_env({"PATH": "x", "GIT_HTTP_LOW_SPEED_TIME": "5"})
    assert env["GIT_TERMINAL_PROMPT"] == "0" and env["GCM_INTERACTIVE"] == "never"
    assert env["GIT_HTTP_LOW_SPEED_LIMIT"] == "1000" and env["GIT_HTTP_LOW_SPEED_TIME"] == "5"
    ssh = env["GIT_SSH_COMMAND"]
    for option in (
        "BatchMode=yes",
        "ConnectTimeout=",
        "ServerAliveInterval=",
        "ServerAliveCountMax=",
    ):
        assert option in ssh
    assert "GIT_SSH_COMMAND" not in gitutil.network_env({}, ssh_default=False)


def test_the_users_own_ssh_choice_is_never_overridden() -> None:
    assert gitutil.ssh_is_user_defined(StubGit({}, None)) is False  # type: ignore[arg-type]
    assert gitutil.ssh_is_user_defined(StubGit({"GIT_SSH_COMMAND": "ssh -i k"})) is True  # type: ignore[arg-type]
    assert gitutil.ssh_is_user_defined(StubGit({"GIT_SSH": "plink"})) is True  # type: ignore[arg-type]
    assert gitutil.ssh_is_user_defined(StubGit({}, b"ssh -F cfg\n")) is True  # type: ignore[arg-type]
    assert gitutil.ssh_is_user_defined(StubGit({}, b"\n")) is False  # type: ignore[arg-type]


def test_push_one_hands_git_that_environment_unless_the_user_chose_ssh(
    make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    repo = repo_named(make_repo, "envcheck")
    repo.set_config("nbp-safe.autoPush", "true")
    bare = repo.git.init(tmp_path / "origin.git", bare=True)
    repo.sh("remote", "add", "origin", str(bare))
    seen: list[dict[str, str]] = []

    def spy(git: Git, *_a: object, **_k: object) -> str:
        seen.append(dict(git.env))
        return "0" * 40

    monkeypatch.setattr(multi, "push_vault", spy)
    monkeypatch.delenv("GIT_SSH_COMMAND", raising=False)
    monkeypatch.delenv("GIT_SSH", raising=False)
    handle = fleetops.open_handle(repo.path, 1)
    fleetops.push_one(handle)
    assert "BatchMode=yes" in seen[-1]["GIT_SSH_COMMAND"] and seen[-1]["GCM_INTERACTIVE"] == "never"
    repo.set_config("core.sshCommand", "ssh -F /my/own/config")  # the user chose how to run ssh
    fleetops.push_one(handle)
    assert "GIT_SSH_COMMAND" not in seen[-1] and seen[-1]["GIT_TERMINAL_PROMPT"] == "0"
    repo.sh("config", "--local", "--unset", "core.sshCommand")
    monkeypatch.setenv("GIT_SSH_COMMAND", "ssh -i /my/key")
    fleetops.push_one(fleetops.open_handle(repo.path, 1))
    assert seen[-1]["GIT_SSH_COMMAND"] == "ssh -i /my/key"  # untouched


# ------------------------------------------------------------- what git said (informational)


class PushStub:
    """A ``Git`` whose push exits with a canned message."""

    def __init__(self, tmp_path: Path, message: str) -> None:
        self.cwd = tmp_path
        self.env: dict[str, str] = {}
        self.message = message.encode()
        self.pushes: list[tuple[str, ...]] = []

    def try_run(self, *_args: str, **_k: object) -> bytes:
        return b"a" * 40  # rev-parse finds the local vault branch

    def run_status(self, *args: str, **_k: object) -> tuple[int, bytes, bytes]:
        self.pushes.append(args)
        return 1, b"", self.message


def push_error(tmp_path: Path, message: str) -> tuple[Exception, PushStub]:
    stub = PushStub(tmp_path, message)
    repo = Repo(tmp_path, tmp_path / ".git", tmp_path / ".git")
    with pytest.raises(Exception) as caught:
        multi.push_vault(stub, repo, Config())  # type: ignore[arg-type]
    return caught.value, stub


def test_a_server_side_refusal_is_not_reported_as_run_sync(tmp_path: Path) -> None:
    behind, stub = push_error(
        tmp_path,
        " ! [rejected]        refs/heads/nbp-safe -> refs/heads/nbp-safe (non-fast-forward)\n",
    )
    assert isinstance(behind, multi.PushRejectedError) and "nbp-git-safe sync" in str(behind)
    fetch_first, _ = push_error(tmp_path, " ! [rejected] a -> a (fetch first)\n")
    assert isinstance(fetch_first, multi.PushRejectedError)
    refused, _ = push_error(
        tmp_path,
        " ! [remote rejected] refs/heads/nbp-safe -> refs/heads/nbp-safe "
        "(pre-receive hook declined)\n",
    )
    assert isinstance(refused, multi.PushRefusedError) and "sync" not in str(refused).split(";")[0]
    assert not isinstance(refused, multi.PushRejectedError)
    assert "--no-follow-tags" in stub.pushes[0]  # upstream tags never travel with the vault
    assert "--tags" not in stub.pushes[0] and not any(a.startswith("+") for a in stub.pushes[0])
