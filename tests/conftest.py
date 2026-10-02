# SPDX-License-Identifier: MIT
"""Shared pytest fixtures.

``isolated_git`` follows the approach of transcrypt's ``tests/_test_helper.bash``
(https://github.com/elasticdog/transcrypt, MIT, Copyright (c) 2019-2025 James Murty,
2014-2020 Aaron Bull Schaefer, 2011 Woody Gilk): isolate tests from the developer's
global/system git config (merge.conflictstyle, commit.gpgsign, ...) by pointing
``GIT_CONFIG_GLOBAL`` / ``GIT_CONFIG_SYSTEM`` at ``/dev/null`` (requires git 2.32+).
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest


class IsolatedGit:
    """Run real git in a hermetic environment (no user/system config, fixed identity)."""

    def __init__(self, env: dict[str, str]) -> None:
        self.env = env

    def run(self, *args: str, cwd: Path | str | None = None, input: bytes | None = None) -> str:
        proc = subprocess.run(
            ["git", *args],
            cwd=cwd,
            env=self.env,
            input=input,
            capture_output=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"git {' '.join(args)} failed ({proc.returncode}): "
                f"{proc.stderr.decode('utf-8', 'replace')}"
            )
        return proc.stdout.decode("utf-8", "replace")

    def init(self, path: Path, *, bare: bool = False) -> Path:
        path.mkdir(parents=True, exist_ok=True)
        flags = ["--bare"] if bare else []
        self.run("init", "--quiet", "-b", "main", *flags, str(path))
        return path


@pytest.fixture
def isolated_git(monkeypatch: pytest.MonkeyPatch) -> IsolatedGit:
    env = dict(os.environ)
    for name in [n for n in env if n.startswith(("GIT_", "NBP_SAFE_"))]:
        del env[name]
    config = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": "Test User",
        "GIT_AUTHOR_EMAIL": "test@example.invalid",
        "GIT_COMMITTER_NAME": "Test User",
        "GIT_COMMITTER_EMAIL": "test@example.invalid",
    }
    env.update(config)
    for key, value in config.items():
        monkeypatch.setenv(key, value)
    return IsolatedGit(env)


@pytest.fixture
def git_repo(isolated_git: IsolatedGit, tmp_path: Path) -> Callable[..., Path]:
    """Factory: ``git_repo("name", bare=False)`` creates a repo under tmp_path."""

    def make(name: str = "repo", *, bare: bool = False) -> Path:
        return isolated_git.init(tmp_path / name, bare=bare)

    return make
