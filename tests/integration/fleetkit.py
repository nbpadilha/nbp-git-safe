# SPDX-License-Identifier: MIT
"""Helpers shared by the multi-repository integration tests (not a test module)."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import time
from collections.abc import Callable
from pathlib import Path

from nbp_git_safe import agent, crypto, registry
from nbp_git_safe.cli import main
from tests import helpers
from tests.helpers import NbpRepo
from tests.leak.harness import LeakScanner, assert_no_leaks

MakeRepo = Callable[..., object]


def run(*argv: str) -> helpers.CliResult:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return helpers.CliResult(code, out.getvalue(), err.getvalue())


def runs(log: Path) -> list[str]:
    return log.read_text(encoding="ascii").splitlines() if log.exists() else []


def repo_named(make_repo: MakeRepo, name: str, *extra: str, mode: str = "ok") -> NbpRepo:
    """A repository whose keyCommand is the test command with ``extra`` arguments (so repositories
    with the same ``extra`` share an identical argv)."""
    repo = make_repo(name)
    assert isinstance(repo, NbpRepo)
    repo.set_config(
        "nbp-safe.keyCommand", json.dumps([sys.executable, str(helpers.KEYCMD), mode, *extra])
    )
    registry.add(repo.path)
    return repo


def key_needles(master: bytes) -> dict[str, bytes]:
    text = crypto.encode_key(master)
    return {
        "key-base64": text.encode(),
        "key-raw": master,
        "key-hex": master.hex().encode(),
        "key-first-half-raw": master[:32],
    }


def assert_key_nowhere(master: bytes, repos: list[NbpRepo], *texts: str) -> None:
    scanner = LeakScanner([], raw_needles=key_needles(master))
    hits = scanner.scan_dir(agent.runtime_root())
    for repo in repos:
        hits += scanner.scan_git_dir(repo.path / ".git")
    for text in texts:
        hits += scanner.scan_bytes(text.encode("utf-8", "replace"), "command output")
    assert_no_leaks(hits)


def wait_gone(pid: int, seconds: float = 10.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not agent.pid_alive(pid):
            return True
        time.sleep(0.05)
    return False
