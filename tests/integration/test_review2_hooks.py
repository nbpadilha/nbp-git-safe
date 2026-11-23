# SPDX-License-Identifier: MIT
"""Second adversarial review: a hook that cannot talk to the agent (elevation mismatch) says why and
does not let a protected path through (in-process, so the error can be injected where
``OpenProcessToken`` would fail on Windows). Since the audit of 2026-10-10 (agy, finding 5) it
refuses instead of skipping the content check in silence."""

from __future__ import annotations

import pytest

from nbp_git_safe import agent, hooks
from tests.integration.conftest import Env
from tests.integration.guardkit import prune_unreachable


@pytest.fixture
def unreachable_agent(hooked: Env, monkeypatch: pytest.MonkeyPatch) -> Env:
    """The agent is running (and unlocked) but its process cannot be inspected from the hook."""
    monkeypatch.chdir(hooked.repo.path)

    def refuse(_state_dir: object) -> object:
        raise agent.ProcessInspectionError(agent.ELEVATION_MESSAGE)

    monkeypatch.setattr(agent.AgentClient, "connect", staticmethod(refuse))
    return hooked


def test_pre_commit_refuses_and_mentions_elevation(
    unreachable_agent: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = unreachable_agent.repo
    assert hooks.run_hook("pre-commit", []) == 1  # fail closed, even with nothing to refuse
    err = capsys.readouterr().err
    assert "commit refused" in err and "agent unavailable" in err and "elevation" in err
    assert "content check skipped" not in err and "--no-verify" in err
    assert "run `nbp-git-safe unlock`" not in err  # unlocking again would not help

    repo.write("reports/z.csv", "z")
    repo.sh("add", "-f", "reports/z.csv")
    assert hooks.run_hook("pre-commit", []) == 1  # the path check still stops it
    assert "commit blocked" in capsys.readouterr().err
    repo.sh("restore", "--staged", "--", "reports/z.csv")
    prune_unreachable(repo)


def test_pre_push_refuses_in_both_modes_and_says_why(
    unreachable_agent: Env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = unreachable_agent.repo
    oid = repo.sh("rev-parse", "refs/heads/main").strip()
    line = f"refs/heads/main {oid} refs/heads/main {'0' * 40}\n"
    for mode in ("0", "1"):
        monkeypatch.setenv("NBP_SAFE_NONINTERACTIVE", mode)
        assert hooks.run_hook("pre-push", ["origin"], line) == 1
        err = capsys.readouterr().err
        assert "push refused" in err and "agent unavailable" in err and "elevation" in err


def test_post_commit_does_not_seal_and_says_so(
    unreachable_agent: Env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    tip = unreachable_agent.tip()
    monkeypatch.setenv("NBP_SAFE_NONINTERACTIVE", "0")  # even at a terminal: an ERROR
    assert hooks.run_hook("post-commit", []) == 1
    assert unreachable_agent.tip() == tip  # nothing was sealed behind a connection we cannot trust
    err = capsys.readouterr().err
    assert "agent unavailable" in err and "elevation" in err
