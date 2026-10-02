# SPDX-License-Identifier: MIT
from __future__ import annotations

import json
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from nbp_git_safe import agent, crypto, vault
from nbp_git_safe.config import load_config
from nbp_git_safe.gitutil import Git, discover
from tests import helpers
from tests.conftest import IsolatedGit
from tests.helpers import CliResult, NbpRepo, ThreadAgent


@dataclass
class Env:
    """A work repository wired to a local bare 'remote', with an in-process agent."""

    repo: NbpRepo
    bare: Path
    agent: ThreadAgent
    git: IsolatedGit

    def seal(self) -> CliResult:
        return self.repo.cli("seal")

    def open(self) -> CliResult:
        return self.repo.cli("open")

    def commits(self) -> int:
        out = self.repo.sh("rev-list", "--count", "refs/heads/nbp-safe").strip()
        return int(out)

    def tip(self) -> str:
        return self.repo.sh("rev-parse", "refs/heads/nbp-safe").strip()

    def has_vault(self) -> bool:
        return self.repo.sh("for-each-ref", "refs/heads/nbp-safe").strip() != ""

    def push(self) -> None:
        """Commit everything the main branch can see (``add -A``) and push both branches."""
        self.repo.sh("add", "-A")
        if self.repo.sh("diff", "--cached", "--name-only").strip():
            self.repo.sh("commit", "-q", "-m", "main work")
        refs = ["main"] + (["nbp-safe"] if self.has_vault() else [])
        self.repo.sh("push", "-q", "origin", *refs)

    def gate(self) -> None:
        """The phase gate: push, then scan the bare remote AND the whole local .git."""
        self.push()
        self.repo.assert_no_leak(self.bare)

    def backend(self) -> agent.AgentClient:
        return self.agent.client()

    def entries(self) -> dict[str, tuple[str, vault.Entry]]:
        """``{path: (file_id, entry)}`` of the current vault tip (decrypted via the agent)."""
        repo, git = discover(self.repo.path, self.git.env)
        cfg = load_config(git, repo)
        with self.backend() as backend:
            state = vault.load_vault(git, backend, cfg)
        return {e.path: (fid, e) for fid, e in state.index.entries.items()}

    def vault_files(self) -> dict[str, str]:
        out = self.repo.sh("ls-tree", "-r", "-z", "refs/heads/nbp-safe")
        files = {}
        for record in out.split("\0"):
            if record:
                meta, path = record.split("\t", 1)
                files[path] = meta.split()[2]
        return files


@pytest.fixture
def env(
    make_repo: Callable[..., object], isolated_git: IsolatedGit, tmp_path: Path
) -> Iterator[Env]:
    repo = make_repo()
    assert isinstance(repo, NbpRepo)
    bare = isolated_git.init(tmp_path / "remote.git", bare=True)
    repo.sh("remote", "add", "origin", str(bare))
    helpers.populate(repo)
    thread_agent = repo.unlock_in_thread()
    yield Env(repo, bare, thread_agent, isolated_git)
    thread_agent.stop()


def make_clone(
    isolated_git: IsolatedGit, bare: Path, dest: Path, master: bytes, canaries: list[str]
) -> NbpRepo:
    """Clone the bare remote and configure it like a second machine."""
    isolated_git.run("clone", "-q", str(bare), str(dest))
    clone = NbpRepo(dest, isolated_git, canaries, master)
    clone.set_config("nbp-safe.ttl", "5m")
    clone.sh("config", "--local", "user.name", "Test User")
    clone.sh("config", "--local", "user.email", "test@example.invalid")
    clone.set_config("nbp-safe.keyCommand", json.dumps([sys.executable, str(helpers.KEYCMD), "ok"]))
    return clone


@pytest.fixture
def clone_factory(isolated_git: IsolatedGit, tmp_path: Path) -> Callable[..., NbpRepo]:
    counter = {"n": 0}

    def factory(env: Env) -> NbpRepo:
        counter["n"] += 1
        return make_clone(
            isolated_git,
            env.bare,
            tmp_path / f"clone{counter['n']}",
            env.repo.master,
            env.repo.canaries,
        )

    return factory


def make_git(repo: NbpRepo) -> Git:
    return Git(repo.path, repo.git.env)


__all__ = ["Env", "crypto", "make_git"]
