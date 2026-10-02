# SPDX-License-Identifier: MIT
"""Shared pytest fixtures.

``isolated_git`` follows the approach of transcrypt's ``tests/_test_helper.bash``
(https://github.com/elasticdog/transcrypt, MIT, Copyright (c) 2019-2025 James Murty,
2014-2020 Aaron Bull Schaefer, 2011 Woody Gilk): isolate tests from the developer's
global/system git config (merge.conflictstyle, commit.gpgsign, ...) by pointing
``GIT_CONFIG_GLOBAL`` / ``GIT_CONFIG_SYSTEM`` at ``/dev/null`` (requires git 2.32+).
"""

from __future__ import annotations

import json
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

    def run_raw(
        self,
        *args: str,
        cwd: Path | str | None = None,
        input: bytes | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Run git without raising (hooks block with a non-zero exit); text output."""
        return subprocess.run(
            ["git", *args],
            cwd=cwd,
            env={**self.env, **(env or {})},
            input=input,
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

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


# ------------------------------------------------------------------ vault/agent fixtures
# (imports are local so that the leak-harness tests keep working without the package pieces)
@pytest.fixture
def master_key(monkeypatch: pytest.MonkeyPatch) -> bytes:
    """A throw-away key generated for this test only. It reaches ``keycmd.py`` through the
    environment of the test process; it is never written to disk."""
    from nbp_git_safe import crypto

    key = crypto.generate_key()
    monkeypatch.setenv("NBP_SAFE_TEST_KEY", crypto.encode_key(key))
    return key


@pytest.fixture
def make_repo(
    isolated_git: IsolatedGit, tmp_path: Path, master_key: bytes
) -> Callable[..., object]:
    """Factory ``make_repo(name="work", mode="ok", configure_key=True)`` -> ``NbpRepo``."""
    import sys

    from tests import helpers

    created: list[Path] = []

    def make(name: str = "work", *, mode: str = "ok", canaries: list[str] | None = None) -> object:
        path = isolated_git.init(tmp_path / name)
        repo = helpers.NbpRepo(path, isolated_git, canaries or helpers.new_canaries(), master_key)
        repo.sh("config", "--local", "user.name", "Test User")
        repo.sh("config", "--local", "user.email", "test@example.invalid")
        repo.set_config(
            "nbp-safe.keyCommand", json.dumps([sys.executable, str(helpers.KEYCMD), mode])
        )
        repo.set_config("nbp-safe.ttl", "5m")
        repo.write(".nbp-safe", helpers.VERSIONED_PATTERNS)
        created.append(repo.state_dir)
        return repo

    yield make  # type: ignore[misc]
    helpers.lock_everything(created)


@pytest.fixture(autouse=True)
def reap_agents() -> object:
    """Never leave a detached agent process behind, whatever the test did."""
    yield
    from tests import helpers

    helpers.lock_everything(list(helpers.STATE_DIRS))
    helpers.STATE_DIRS.clear()
