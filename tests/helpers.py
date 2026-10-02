# SPDX-License-Identifier: MIT
"""Shared test helpers: in-process agent, repository wrapper, fake data with canaries."""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from nbp_git_safe import agent, crypto, unlock
from nbp_git_safe.cli import main
from tests.conftest import IsolatedGit
from tests.leak.harness import LeakScanner, assert_no_leaks, make_canaries

KEYCMD = Path(__file__).parent / "keycmd.py"
TEST_KEY_ENV = "NBP_SAFE_TEST_KEY"
VERSIONED_PATTERNS = "reports/\ndata-private/**\n!data-private/keep-public.txt\n"


STATE_DIRS: list[Path] = []


class ThreadAgent:
    """A real ``AgentServer`` running in a thread of the test process (fast, and measurable)."""

    def __init__(
        self,
        state_dir: Path,
        master: bytes | None = None,
        ttl: float = 120.0,
        idle: float | None = None,
        key_wait: float = 30.0,
    ) -> None:
        self.state_dir = state_dir
        self.exited = threading.Event()
        self.server = agent.AgentServer(
            state_dir, ttl, idle, exit_func=lambda _code: self.exited.set(), key_wait=key_wait
        )
        self.info = self.server.start()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        if master is not None:
            with agent.AgentClient.connect_info(self.info) as client:
                client.load_key(master)

    def client(self) -> agent.AgentClient:
        return agent.AgentClient.connect_info(self.info)

    def stop(self) -> None:
        self.server.shutdown("test")
        self.exited.wait(5)


def make_info(
    state_dir: Path,
    pid: int,
    expires: float,
    idle: float | None = None,
    *,
    address: str | None = None,
) -> agent.AgentInfo:
    """An ``AgentInfo`` with a valid endpoint and a really derived authkey (nobody listens)."""
    endpoint = agent.new_endpoint(state_dir)
    return agent.AgentInfo(
        address or endpoint.address,
        endpoint.family,
        endpoint.authkey,
        pid,
        time.time(),
        expires,
        idle,
        endpoint.nonce,
    )


@dataclass
class CliResult:
    code: int
    out: str
    err: str


@dataclass
class NbpRepo:
    """A repository with the vault tool configured for tests."""

    path: Path
    git: IsolatedGit
    canaries: list[str]
    master: bytes
    state_dir: Path = field(init=False)

    def __post_init__(self) -> None:
        self.state_dir = self.path / ".git" / "nbp-safe"
        STATE_DIRS.append(self.state_dir)  # the autouse fixture reaps any agent left running

    def cli(self, *args: str) -> CliResult:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["-C", str(self.path), *args])
        return CliResult(code, out.getvalue(), err.getvalue())

    def write(self, rel: str, content: str | bytes) -> Path:
        target = self.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)
        return target

    def read(self, rel: str) -> bytes:
        return (self.path / rel).read_bytes()

    def sh(self, *args: str) -> str:
        return self.git.run(*args, cwd=self.path)

    def raw(
        self, *args: str, env: dict[str, str] | None = None, input: bytes | None = None
    ) -> subprocess.CompletedProcess[str]:
        """git without raising: ``.returncode`` / ``.stdout`` / ``.stderr``."""
        return self.git.run_raw(*args, cwd=self.path, env=env, input=input)

    def set_config(self, key: str, value: str) -> None:
        self.sh("config", "--local", key, value)

    def unlock_in_thread(self, **kwargs: object) -> ThreadAgent:
        return ThreadAgent(self.state_dir, self.master, **kwargs)  # type: ignore[arg-type]

    def leak_scanner(self) -> LeakScanner:
        return LeakScanner(self.canaries, git_env=self.git.env)

    def assert_no_leak(self, *others: Path) -> None:
        """Gate: canaries (content AND names) must not appear in the local .git nor in any
        bare remote given in ``others``."""
        scanner = self.leak_scanner()
        hits = scanner.scan_git_dir(self.path / ".git")
        for other in others:
            hits += scanner.scan_bare_repo(other)
        assert_no_leaks(hits)


def new_canaries() -> list[str]:
    return make_canaries(4)


def populate(repo: NbpRepo) -> dict[str, str]:
    """Fake data: canaries in contents and in names (with accents and spaces). Returns
    ``{path: content}`` of the protected files."""
    c = repo.canaries
    files = {
        f"reports/{c[0]}-summary.csv": f"id,score\n1,{c[0]}\n",
        f"reports/relatório final {c[1]}/nota {c[1]}.txt": f"line one\n{c[1]}\nline three\n",
        f"data-private/{c[2]}.json": json.dumps({"secret": c[2]}) + "\n",
        "data-private/plain.bin": "\x00\x01 binary-ish " + c[3],
    }
    for rel, content in files.items():
        repo.write(rel, content.encode("utf-8"))
    repo.write("data-private/keep-public.txt", "public, versioned normally\n")
    repo.write("README.md", "# project\n")
    return files


def seal_cleanly(repo: NbpRepo) -> CliResult:
    result = repo.cli("seal")
    assert result.code == 0, result.err
    return result


def lock_everything(state_dirs: Sequence[Path]) -> None:
    """Teardown helper: stop any agent left behind (never leave processes around)."""
    for state_dir in state_dirs:
        with contextlib.suppress(Exception):
            unlock.lock(state_dir)
        with contextlib.suppress(Exception):
            info = agent.read_agent_info(state_dir)
            if info is not None and agent.pid_alive(info.pid) and info.pid != os.getpid():
                _kill(info.pid)


def _kill(pid: int) -> None:
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            check=False,
        )
    else:
        os.kill(pid, 9)


__all__ = [
    "KEYCMD",
    "TEST_KEY_ENV",
    "VERSIONED_PATTERNS",
    "CliResult",
    "NbpRepo",
    "ThreadAgent",
    "crypto",
    "lock_everything",
    "new_canaries",
    "populate",
    "seal_cleanly",
]
