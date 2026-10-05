# SPDX-License-Identifier: MIT
"""Review findings about how the multi-repository operations see a repository: a folder whose
``.git`` vanished must not turn into the repository above it (B5), an agent state directory that is
not private is an ERROR and not "locked" (B4), and ``onMissing=ask`` must not leave a pending file
that no tray seal can ever clear (B2)."""

from __future__ import annotations

import contextlib
import os
import shutil
import stat
from pathlib import Path

import pytest

from nbp_git_safe import agent, fleet, fleetops, registry, vault
from nbp_git_safe.config import Config
from tests import helpers
from tests.integration.fleetkit import MakeRepo, repo_named, run


def rmtree_hard(path: Path) -> None:
    """``shutil.rmtree`` that also removes read-only files (git's object files are, on Windows)."""
    for root, dirs, files in os.walk(path):
        for name in (*dirs, *files):
            with contextlib.suppress(OSError):
                os.chmod(os.path.join(root, name), stat.S_IWRITE | stat.S_IREAD)
    shutil.rmtree(path)


# ------------------------------------------------------------------------------------- B5


def test_a_folder_whose_dot_git_vanished_is_not_the_repository_that_contains_it(
    make_repo: MakeRepo,
) -> None:
    outer = repo_named(make_repo, "outer")
    inner_path = outer.path / "inner"
    outer.git.init(inner_path)
    assert fleetops.open_handle(inner_path, 1).repo.toplevel.name == "inner"  # a repository
    rmtree_hard(inner_path / ".git")  # ... until its .git is deleted
    with pytest.raises(fleetops.HandleError) as caught:
        fleetops.open_handle(inner_path, 1)
    assert caught.value.code == "not-a-repo"
    # and the operations report it for that entry instead of acting on the outer repository
    handles, failures = fleetops.open_all([registry.Entry(str(inner_path), 1)])
    assert handles == [] and [f.code for f in failures] == ["not-a-repo"]


def test_a_subfolder_of_a_repository_is_not_accepted_as_one(make_repo: MakeRepo) -> None:
    outer = repo_named(make_repo, "outer2")
    sub = outer.path / "sub"
    sub.mkdir()
    with pytest.raises(fleetops.HandleError) as caught:
        fleetops.open_handle(sub, 1)
    assert caught.value.code == "not-a-repo"
    assert fleetops.open_handle(outer.path, 1).repo.toplevel.name == "outer2"


# ------------------------------------------------------------------------------------- B4


def insecure(*_a: object, **_k: object) -> object:
    raise agent.InsecureStateError("the key agent's state directory is not private: test")


def test_an_untrusted_state_directory_is_an_error_not_locked(
    make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = repo_named(make_repo, "untrusted")
    handle = fleetops.open_handle(repo.path, 1)
    monkeypatch.setattr(agent, "read_agent_info", insecure)
    view = fleetops.read_agent(handle)
    assert view.state == "error" and view.code == "insecure-state"
    assert "owner and permissions" in view.message  # actionable
    status = fleetops.status_one(handle)
    assert status.kind == fleetops.FAILED and status.code == "insecure-state"
    sealed = fleetops.seal_one(handle)
    assert sealed.kind == fleetops.FAILED and sealed.code == "insecure-state"  # not "locked"
    out = run("status", "--all")
    assert out.code == 1 and "FAILED" in out.out and "not private" in out.out
    seal_all = run("seal", "--all")
    assert seal_all.code == 1 and "locked" not in seal_all.out.splitlines()[0]
    # the model shows it red, whatever the pending/problem counters say
    state = fleet.RepoState("k" * 24, 1, "untrusted", str(repo.path), fleet.ERROR, error=view.code)
    assert fleet.aggregate_color([state], 0.0) == fleet.Color.RED


def test_the_single_commands_also_say_error_not_locked(
    make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = repo_named(make_repo, "single")
    monkeypatch.setattr(agent, "read_agent_info", insecure)
    status = repo.cli("status")
    assert status.code == 1 and "not private" in status.err  # not exit 3 ("locked")
    with pytest.raises(agent.InsecureStateError):
        agent.AgentClient.connect(repo.state_dir)


# ------------------------------------------------------------------------------------- B2


def test_pending_count_ignores_missing_files_unless_a_seal_would_remove_them() -> None:
    analysis = vault.Analysis(
        state=None,  # type: ignore[arg-type]
        entries={},
        observed={},
        new=["n"],
        missing=["gone1", "gone2"],
    )
    assert fleetops.pending_count(analysis, Config(on_missing="keep")) == 1
    assert fleetops.pending_count(analysis, Config(on_missing="ask")) == 1  # nobody to ask
    assert fleetops.pending_count(analysis, Config(on_missing="remove")) == 3


def test_ask_policy_does_not_leave_a_pending_file_the_tray_seal_never_clears(
    make_repo: MakeRepo,
) -> None:
    repo = repo_named(make_repo, "askpolicy")
    repo.set_config("nbp-safe.onMissing", "ask")
    fields = helpers.populate(repo)
    handle = fleetops.open_handle(repo.path, 1)
    thread_agent = repo.unlock_in_thread()
    try:
        assert fleetops.seal_one(handle).kind == fleetops.OK
        gone = next(iter(fields))
        (repo.path / gone).unlink()  # a protected file deleted locally
        for _cycle in range(3):  # what the tray does: a health check, then the periodic seal
            assert fleetops.deep_check(handle).pending == 0  # nothing a seal could ever write
            outcome = fleetops.seal_one(handle)
            assert outcome.kind == fleetops.OK and outcome.code == "nothing"
        assert "pending: nothing" in fleetops.status_one(handle).message
        repo.set_config("nbp-safe.onMissing", "remove")  # a policy that DOES remove it counts
        assert fleetops.deep_check(fleetops.open_handle(repo.path, 1)).pending == 1
    finally:
        thread_agent.stop()


# ------------------------------------------------------------------------------------- B8


def test_doctor_all_prints_counts_not_the_names_of_protected_files(make_repo: MakeRepo) -> None:
    """``docs/TRAY.md`` promises that ``--all`` output never carries a protected file name; the
    single-repository ``doctor`` (run by the owner inside the repository) still names them."""
    repo = repo_named(make_repo, "tracked")
    fields = helpers.populate(repo)
    tracked = next(iter(fields))
    repo.sh("add", "-f", "--", tracked)  # a protected file that got tracked on the main branch
    single = repo.cli("doctor")
    assert single.code == 1 and tracked in single.out  # the owner is told which
    everyone = run("doctor", "--all")
    assert everyone.code == 1 and "1 protected file(s) are tracked" in everyone.out
    assert "doctor` inside the repository to see which" in everyone.out
    for canary in repo.canaries:
        assert canary not in everyone.out and canary not in everyone.err
    handle = fleetops.open_handle(repo.path, 1)
    outcome = fleetops.doctor_one(handle)
    assert outcome.kind == fleetops.FAILED and tracked not in outcome.message
