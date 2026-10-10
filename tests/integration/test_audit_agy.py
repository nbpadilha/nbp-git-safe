# SPDX-License-Identifier: MIT
"""Findings of the independent audit of 2026-10-10 (agy): an unattended run must never end
"green" with a stale vault, nor skip a check in silence."""

from __future__ import annotations

import io

import pytest

from nbp_git_safe import hooks
from tests.integration.conftest import Env
from tests.integration.guardkit import commit, first_protected, remote_refs


@pytest.fixture
def inside(hooked: Env, monkeypatch: pytest.MonkeyPatch) -> Env:
    monkeypatch.chdir(hooked.repo.path)
    return hooked


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


# ------------------------------------------------------- 1: locked or expired, unattended


def test_non_interactive_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NBP_SAFE_NONINTERACTIVE", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setattr("sys.stderr", _Tty())
    assert hooks.non_interactive() is False  # a terminal, no automation variable
    monkeypatch.setenv("CI", "true")
    assert hooks.non_interactive() is True
    monkeypatch.setenv("CI", "false")
    assert hooks.non_interactive() is False
    monkeypatch.setenv("NBP_SAFE_NONINTERACTIVE", "1")
    assert hooks.non_interactive() is True
    monkeypatch.setenv("NBP_SAFE_NONINTERACTIVE", "0")
    monkeypatch.setenv("CI", "true")
    assert hooks.non_interactive() is False  # the explicit setting wins
    monkeypatch.delenv("NBP_SAFE_NONINTERACTIVE")
    monkeypatch.delenv("CI")
    monkeypatch.setattr("sys.stderr", io.StringIO())
    assert hooks.non_interactive() is True  # stderr is not a terminal


def test_post_commit_unattended_with_a_locked_agent_fails_loudly(
    inside: Env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = inside.repo
    tip = inside.tip()
    inside.agent.stop()  # what an agent past its TTL looks like to the hook
    repo.write(first_protected(repo, ".json"), '{"after": "expiry"}\n')
    monkeypatch.setenv("NBP_SAFE_NONINTERACTIVE", "1")
    assert hooks.run_hook("post-commit", []) == 1
    err = capsys.readouterr().err
    assert "ERROR: protected files were not sealed" in err and "nbp-git-safe unlock" in err
    assert inside.tip() == tip
    monkeypatch.setenv("NBP_SAFE_NONINTERACTIVE", "0")  # interactive: a warning, as before
    assert hooks.run_hook("post-commit", []) == 0
    assert "not sealed" in capsys.readouterr().err


def test_unattended_commit_and_push_with_a_locked_agent_never_end_green(hooked: Env) -> None:
    repo = hooked.repo
    assert repo.raw("push", "-q", "origin", "main", "nbp-safe").returncode == 0
    pushed_vault = remote_refs(hooked)["refs/heads/nbp-safe"]
    hooked.agent.stop()
    repo.write(first_protected(repo, ".json"), '{"daily": "bundle"}\n')
    done = commit(repo, "daily", "--allow-empty")
    assert done.returncode == 0  # git ignores post-commit's status ...
    assert "ERROR: protected files were not sealed" in done.stderr  # ... so it says so loudly
    refused = repo.raw("push", "origin", "main", "nbp-safe")
    assert refused.returncode != 0
    assert "push refused" in refused.stderr and "autoUnlock" in refused.stderr
    assert remote_refs(hooked)["refs/heads/nbp-safe"] == pushed_vault
    # a person at a terminal is warned and may push (they can see it and unlock)
    manual = repo.raw("push", "origin", "main", "nbp-safe", env={"NBP_SAFE_NONINTERACTIVE": "0"})
    assert manual.returncode == 0, manual.stderr
    assert "not sealed" in manual.stderr
    # unattended, even a push of the code alone is refused: its content check could not run
    repo.write("notes.txt", "more\n")
    repo.sh("add", "notes.txt")
    assert commit(repo, "notes").returncode == 0
    code_only = repo.raw("push", "origin", "main")
    assert code_only.returncode != 0 and "push refused" in code_only.stderr
    repo.assert_no_leak(hooked.bare)
