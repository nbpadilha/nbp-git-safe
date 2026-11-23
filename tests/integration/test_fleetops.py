# SPDX-License-Identifier: MIT
"""``fleetops`` one repository at a time on real git (in-process agents) and with injected faults:
the slow health check the tray uses, the output of status and doctor, and every failure path of
seal and push (each must become an outcome, never an exception)."""

from __future__ import annotations

import pytest

from nbp_git_safe import agent, fleetops, multi, unlock, vault
from tests import helpers
from tests.integration.fleetkit import MakeRepo, repo_named

EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def handle_of(repo: helpers.NbpRepo) -> fleetops.RepoHandle:
    return fleetops.open_handle(repo.path, 1)


def test_deep_check_counts_pending_files_and_problems(make_repo: MakeRepo) -> None:
    repo = repo_named(make_repo, "deep")
    helpers.populate(repo)
    handle = handle_of(repo)
    locked = fleetops.deep_check(handle)
    assert locked.pending is None and locked.problems >= 1  # not initialised: doctor objects
    assert locked.divergent is False
    thread_agent = repo.unlock_in_thread()
    try:
        before = fleetops.deep_check(handle)
        assert before.pending == 4  # the four protected files of the fake data
        assert fleetops.seal_one(handle).kind == fleetops.OK
        after = fleetops.deep_check(handle)
        assert after.pending == 0
        repo.write("reports/another.csv", "x")
        assert fleetops.deep_check(handle).pending == 1
        assert repo.cli("init").code == 0
        assert fleetops.deep_check(handle).pending == 1  # init changes nothing about files
    finally:
        thread_agent.stop()


def test_deep_check_flags_a_diverged_vault(make_repo: MakeRepo) -> None:
    repo = repo_named(make_repo, "diverged")
    helpers.populate(repo)
    thread_agent = repo.unlock_in_thread()
    try:
        handle = handle_of(repo)
        assert fleetops.seal_one(handle).kind == fleetops.OK
        stranger = repo.sh("commit-tree", EMPTY_TREE, "-m", "unrelated").strip()
        repo.sh("update-ref", "refs/remotes/origin/nbp-safe", stranger)
        assert fleetops.deep_check(handle).divergent is True
        status = fleetops.status_one(handle)
        assert "origin:" in status.message and "diverged" in status.message
    finally:
        thread_agent.stop()


def test_status_one_locked_and_unlocked_lines(make_repo: MakeRepo) -> None:
    repo = repo_named(make_repo, "status")
    handle = handle_of(repo)
    locked = fleetops.status_one(handle)
    assert locked.kind == fleetops.SKIPPED and locked.message == "agent: locked"
    thread_agent = repo.unlock_in_thread()
    try:
        helpers.populate(repo)
        unlocked = fleetops.status_one(handle)
        assert unlocked.kind == fleetops.OK
        lines = unlocked.message.splitlines()
        assert lines[0].startswith("agent: unlocked (key ") and "expires" in lines[0]
        assert "pending: 4" in lines
        for canary in repo.canaries:  # counts only, never a file name
            assert canary not in unlocked.message
    finally:
        thread_agent.stop()


def test_doctor_one_summarises(make_repo: MakeRepo) -> None:
    repo = repo_named(make_repo, "doc")
    handle = handle_of(repo)
    bad = fleetops.doctor_one(handle)
    assert bad.kind == fleetops.FAILED and bad.data["problems"] >= 1 and "[PROBLEM]" in bad.message
    assert repo.cli("init").code == 0
    good = fleetops.doctor_one(handle)
    assert good.data["problems"] == 0 and good.kind == fleetops.OK and good.code == "clean"


def test_read_agent_maps_every_state(make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = repo_named(make_repo, "agents")
    handle = handle_of(repo)
    assert fleetops.read_agent(handle) == fleetops.AgentView("locked")
    thread_agent = repo.unlock_in_thread()
    try:
        view = fleetops.read_agent(handle)
        assert view.state == "unlocked" and view.expires_at and view.key_id
    finally:
        thread_agent.stop()
    for exc, code in (
        (agent.ProcessInspectionError("elevation"), "other-elevation"),
        (agent.HandshakeError("planted"), "agent-auth"),
        (agent.ProtocolError("odd"), "agent"),
    ):
        monkeypatch.setattr(unlock, "current_status", lambda _s, e=exc: (_ for _ in ()).throw(e))
        got = fleetops.read_agent(handle)
        assert got.state == "error" and got.code == code


def test_lock_one_failure_is_an_outcome(
    make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = repo_named(make_repo, "lockfail")
    handle = handle_of(repo)
    assert fleetops.lock_one(handle).code == "not-running"

    def boom(_state: object) -> bool:
        raise agent.AgentError("key agent did not answer in time")

    monkeypatch.setattr(unlock, "lock", boom)
    result = fleetops.lock_one(handle)
    assert result.kind == fleetops.FAILED and result.code == "agent"


def test_seal_one_failure_paths(make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = repo_named(make_repo, "sealfail")
    helpers.populate(repo)
    handle = handle_of(repo)
    thread_agent = repo.unlock_in_thread()
    try:
        monkeypatch.setattr(
            vault,
            "seal",
            lambda *a, **k: (_ for _ in ()).throw(vault.VaultError("index is broken")),
        )
        failed = fleetops.seal_one(handle)
        assert (
            failed.kind == fleetops.FAILED and failed.code == "vault" and "broken" in failed.message
        )
        monkeypatch.setattr(
            vault, "seal", lambda *a, **k: (_ for _ in ()).throw(agent.AgentExpiredError("ttl"))
        )
        assert fleetops.seal_one(handle).kind == fleetops.SKIPPED  # it expired meanwhile: locked
        analysis = vault.Analysis(
            state=None, entries={}, observed={}, refused=[("big", "too large")]
        )  # type: ignore[arg-type]
        monkeypatch.setattr(vault, "seal", lambda *a, **k: (None, analysis, None))
        refused = fleetops.seal_one(handle)
        assert refused.kind == fleetops.FAILED and refused.code == "refused"
        assert "1 file(s) refused" in refused.message and "big" not in refused.message
    finally:
        thread_agent.stop()


def test_seal_one_when_the_agent_cannot_be_trusted(
    make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = repo_named(make_repo, "planted")
    handle = handle_of(repo)

    def refuse(_state: object) -> object:
        raise agent.HandshakeError("planted agent.json")

    monkeypatch.setattr(agent.AgentClient, "connect", staticmethod(refuse))
    outcome = fleetops.seal_one(handle)
    assert outcome.kind == fleetops.FAILED and outcome.code == "agent-auth"


@pytest.mark.parametrize(
    ("error", "kind", "code"),
    [
        (multi.PushRejectedError("origin has vault commits"), "failed", "push-rejected"),
        (vault.VaultError("the pre-push guard refused the vault branch"), "failed", "push-guard"),
        (vault.VaultError("there is no local vault branch to push"), "skipped", "no-vault"),
        (vault.VaultError("git push failed: could not resolve host"), "warn", "push-offline"),
        (RuntimeError("anything else"), "failed", "unexpected"),
    ],
)
def test_push_one_classification(
    make_repo: MakeRepo,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    error,
    kind,
    code,  # type: ignore[no-untyped-def]
) -> None:
    repo = repo_named(make_repo, "pushing")
    repo.set_config("nbp-safe.autoPush", "true")
    bare = repo.git.init(tmp_path / "origin.git", bare=True)
    repo.sh("remote", "add", "origin", str(bare))
    handle = handle_of(repo)

    def push(*_a: object, **_k: object) -> str:
        raise error

    monkeypatch.setattr(multi, "push_vault", push)
    outcome = fleetops.push_one(handle)
    assert (outcome.kind, outcome.code) == (kind, code)
    assert (
        "could not resolve" not in outcome.message
    )  # git's own text (it may hold a URL) is not echoed


def test_push_environment_never_prompts_and_gives_up_on_stalls() -> None:
    env = fleetops._push_env({"GIT_HTTP_LOW_SPEED_TIME": "5", "OTHER": "1"})
    assert env["GIT_TERMINAL_PROMPT"] == "0" and env["OTHER"] == "1"
    assert env["GIT_HTTP_LOW_SPEED_LIMIT"] == "1000" and env["GIT_HTTP_LOW_SPEED_TIME"] == "5"


def test_set_auto_unlock_writes_the_local_config(make_repo: MakeRepo) -> None:
    repo = repo_named(make_repo, "toggle")
    handle = handle_of(repo)
    fleetops.set_auto_unlock(handle, True)
    assert repo.sh("config", "--local", "--get", "nbp-safe.autoUnlock").strip() == "true"
    fleetops.set_auto_unlock(handle, False)
    assert repo.sh("config", "--local", "--get", "nbp-safe.autoUnlock").strip() == "false"
    assert handle_of(repo).cfg.auto_unlock is False
