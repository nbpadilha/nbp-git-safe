# SPDX-License-Identifier: MIT
"""Second adversarial review: a hook that cannot talk to the agent (elevation mismatch) degrades to
the path check, says why, and does not let a protected path through (in-process, so the error can
be injected where ``OpenProcessToken`` would fail on Windows)."""

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


def test_pre_commit_degrades_to_the_path_check_and_mentions_elevation(
    unreachable_agent: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = unreachable_agent.repo
    assert hooks.run_hook("pre-commit", []) == 0  # nothing staged, nothing to refuse
    err = capsys.readouterr().err
    assert "content check skipped" in err and "agent unavailable" in err and "elevation" in err
    assert "run `nbp-git-safe unlock`" not in err  # unlocking again would not help

    repo.write("reports/z.csv", "z")
    repo.sh("add", "-f", "reports/z.csv")
    assert hooks.run_hook("pre-commit", []) == 1  # the path check still stops it
    assert "commit blocked" in capsys.readouterr().err
    repo.sh("restore", "--staged", "--", "reports/z.csv")
    prune_unreachable(repo)


def test_pre_push_degrades_with_a_warning_and_still_checks_paths(
    unreachable_agent: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = unreachable_agent.repo
    oid = repo.sh("rev-parse", "refs/heads/main").strip()
    line = f"refs/heads/main {oid} refs/heads/main {'0' * 40}\n"
    assert hooks.run_hook("pre-push", ["origin"], line) == 0
    err = capsys.readouterr().err
    assert "agent unavailable" in err and "elevation" in err


def test_post_commit_does_not_seal_and_says_so(
    unreachable_agent: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    tip = unreachable_agent.tip()
    assert hooks.run_hook("post-commit", []) == 0
    assert unreachable_agent.tip() == tip  # nothing was sealed behind a connection we cannot trust
    err = capsys.readouterr().err
    assert "agent unavailable" in err and "elevation" in err
