# SPDX-License-Identifier: MIT
"""Helpers shared by the guard / hooks / doctor integration tests."""

from __future__ import annotations

import subprocess

from tests.helpers import NbpRepo
from tests.integration.conftest import Env
from tests.leak.harness import assert_no_leaks


def init_repo(repo: NbpRepo, *flags: str) -> None:
    result = repo.cli("init", *flags)
    assert result.code == 0, result.err


def commit(
    repo: NbpRepo, message: str = "work", *flags: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return repo.raw("commit", "-q", "-m", message, *flags, env=env)


def staged(repo: NbpRepo) -> list[str]:
    return [line for line in repo.sh("diff", "--cached", "--name-only").splitlines() if line]


def tracked(repo: NbpRepo) -> list[str]:
    return [line for line in repo.sh("ls-files").splitlines() if line]


def remote_refs(env: Env) -> dict[str, str]:
    out = env.git.run("for-each-ref", "--format=%(refname) %(objectname)", cwd=env.bare)
    return dict(line.split(" ", 1) for line in out.splitlines() if line)


def first_protected(repo: NbpRepo, suffix: str) -> str:
    """Relative path of a protected file on disk whose name ends with ``suffix``."""
    for sub in ("reports", "data-private"):
        for path in sorted((repo.path / sub).rglob("*")):
            if path.is_file() and path.name.endswith(suffix) and path.name != "keep-public.txt":
                return path.relative_to(repo.path).as_posix()
    raise AssertionError(f"no protected file ending in {suffix}")


def prune_unreachable(repo: NbpRepo) -> None:
    """A blocked ``git add -f`` leaves its blob unreachable in .git/objects; drop it (the hook
    message tells the user to do exactly this)."""
    repo.sh("prune", "--expire", "now")


def assert_remote_clean(env: Env) -> None:
    """Leak gate for the REMOTE only. Used where a bypassed commit (``--no-verify``) put plain
    text into the LOCAL object database on purpose: the point of the scenario is that the push
    guard keeps it from ever reaching the remote."""
    assert_no_leaks(env.repo.leak_scanner().scan_bare_repo(env.bare))
