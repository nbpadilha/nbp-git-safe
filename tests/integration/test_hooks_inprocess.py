# SPDX-License-Identifier: MIT
"""The hook handlers and guard functions called in-process (the end-to-end behaviour through git
is in test_guard / test_push_guard / test_hooks_matrix; those run the hooks in child processes,
which coverage does not see). Error paths that git would hide are exercised here."""

from __future__ import annotations

import pytest

from nbp_git_safe import agent, crypto, doctor, guard, hooks, multi, unlock, vault
from nbp_git_safe.config import load_config
from nbp_git_safe.gitutil import GitError, discover
from tests.helpers import ThreadAgent, make_info
from tests.integration.conftest import Env
from tests.integration.guardkit import commit, first_protected, prune_unreachable
from tests.integration.test_vault_tamper import read_vault, write_vault_commit

ZERO = "0" * 40


@pytest.fixture
def inside(hooked: Env, monkeypatch: pytest.MonkeyPatch) -> Env:
    monkeypatch.chdir(hooked.repo.path)
    return hooked


def push_line(env: Env, ref: str = "refs/heads/main", remote_oid: str = ZERO) -> str:
    oid = env.repo.sh("rev-parse", ref).strip()
    return f"{ref} {oid} {ref} {remote_oid}\n"


# ------------------------------------------------------------------------------ pre-commit


def test_pre_commit_blocks_and_allows(inside: Env, capsys: pytest.CaptureFixture[str]) -> None:
    repo = inside.repo
    assert hooks.run_hook("pre-commit", []) == 0
    repo.write("reports/z.csv", "z")
    repo.sh("add", "-f", "reports/z.csv")
    assert hooks.run_hook("pre-commit", []) == 1
    err = capsys.readouterr().err
    assert "reports/z.csv" in err and "commit blocked" in err
    repo.sh("restore", "--staged", "--", "reports/z.csv")
    prune_unreachable(repo)
    assert hooks.run_hook("pre-commit", []) == 0


def test_pre_commit_locked_skips_the_content_check(
    inside: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    inside.agent.stop()
    assert hooks.run_hook("pre-commit", []) == 0
    assert "content check skipped" in capsys.readouterr().err


def test_pre_commit_blocks_deleting_the_pattern_file(inside: Env) -> None:
    repo = inside.repo
    repo.sh("rm", "-q", "--cached", ".nbp-safe")
    (repo.path / ".nbp-safe").unlink()
    (repo.path / ".git" / "info" / "nbp-safe").unlink(missing_ok=True)
    assert hooks.run_hook("pre-commit", []) == 1  # removing the pattern file is itself blocked
    repo.sh("reset", "-q", "--", ".nbp-safe")
    repo.sh("checkout", "--", ".nbp-safe")


def test_pre_commit_fails_closed_on_errors(
    inside: Env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def explode(*_a: object, **_k: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(guard, "check_commit", explode)
    assert hooks.run_hook("pre-commit", []) == 1
    assert "failed unexpectedly" in capsys.readouterr().err

    def git_fails(*_a: object, **_k: object) -> None:
        raise GitError("git went away")

    monkeypatch.setattr(guard, "check_commit", git_fails)
    assert hooks.run_hook("pre-commit", []) == 1
    assert "could not verify the commit" in capsys.readouterr().err


def test_pre_commit_outside_a_repository_fails_closed(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    isolated_git: object,  # type: ignore[no-untyped-def]
) -> None:
    monkeypatch.chdir(tmp_path)
    assert hooks.run_hook("pre-commit", []) == 1


# -------------------------------------------------------------------------------- pre-push


def test_pre_push_ok_blocked_and_errors(
    inside: Env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = inside.repo
    assert hooks.run_hook("pre-push", ["origin", "url"], push_line(inside)) == 0
    repo.write("reports/leak.csv", "x")
    repo.sh("add", "-f", "reports/leak.csv")
    assert commit(repo, "bypass", "--no-verify").returncode == 0
    assert hooks.run_hook("pre-push", ["origin", "url"], push_line(inside)) == 1
    assert "push blocked" in capsys.readouterr().err

    def git_fails(*_a: object, **_k: object) -> None:
        raise GitError("nope")

    monkeypatch.setattr(guard, "check_push", git_fails)
    assert hooks.run_hook("pre-push", [], push_line(inside)) == 1
    assert "could not verify the push" in capsys.readouterr().err

    def explode(*_a: object, **_k: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(guard, "check_push", explode)
    assert hooks.run_hook("pre-push", [], push_line(inside)) == 1


def test_pre_push_survives_a_failing_seal(
    inside: Env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail(*_a: object, **_k: object) -> None:
        raise vault.VaultError("cannot seal now")

    monkeypatch.setattr(vault, "seal", fail)
    assert hooks.run_hook("pre-push", ["origin", "url"], push_line(inside)) == 0
    assert "could not be sealed before the push" in capsys.readouterr().err


# ----------------------------------------------------------------------------- post hooks


def test_post_commit_seals_and_survives_errors(
    inside: Env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = inside.repo
    tip = inside.tip()
    repo.write(first_protected(repo, ".json"), '{"post": "commit"}\n')
    assert hooks.run_hook("post-commit", []) == 0
    assert inside.tip() != tip and "vault sealed" in capsys.readouterr().err
    assert hooks.run_hook("post-commit", []) == 0  # nothing to seal: silent
    assert capsys.readouterr().err == ""

    def explode(*_a: object, **_k: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(vault, "seal", explode)
    monkeypatch.setenv("NBP_SAFE_NONINTERACTIVE", "0")  # a person at a terminal: a warning
    assert hooks.run_hook("post-commit", []) == 0
    assert "warning: could not seal after the commit" in capsys.readouterr().err
    monkeypatch.setenv("NBP_SAFE_NONINTERACTIVE", "1")  # unattended: an error and a non-zero exit
    assert hooks.run_hook("post-commit", []) == 1
    assert "ERROR: could not seal after the commit" in capsys.readouterr().err


def test_post_commit_locked_hints_only_when_protected_files_exist(
    inside: Env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    inside.agent.stop()
    monkeypatch.setenv("NBP_SAFE_NONINTERACTIVE", "0")
    assert hooks.run_hook("post-commit", []) == 0
    assert "not sealed" in capsys.readouterr().err
    repo = inside.repo
    for sub in ("reports", "data-private"):
        for path in sorted((repo.path / sub).rglob("*")):
            if path.is_file() and path.name != "keep-public.txt":
                path.unlink()
    assert hooks.run_hook("post-commit", []) == 0
    assert capsys.readouterr().err == ""
    monkeypatch.setenv("NBP_SAFE_NONINTERACTIVE", "1")  # nothing protected: nothing to fail on
    assert hooks.run_hook("post-commit", []) == 0
    assert capsys.readouterr().err == ""


def test_post_commit_without_patterns_is_silent(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    isolated_git,
    capsys: pytest.CaptureFixture[str],  # type: ignore[no-untyped-def]
) -> None:
    root = isolated_git.init(tmp_path / "plain")
    monkeypatch.chdir(root)
    assert hooks.run_hook("post-commit", []) == 0
    assert hooks.run_hook("post-merge", ["0"]) == 0
    assert capsys.readouterr().err == ""


def test_post_refresh_variants(
    inside: Env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = inside.repo
    victim = first_protected(repo, ".csv")
    expected = repo.read(victim)
    assert hooks.run_hook("post-checkout", ["a", "b", "0"]) == 0  # a file checkout: ignored
    (repo.path / victim).unlink()
    assert hooks.run_hook("post-checkout", ["a", "b", "0"]) == 0
    assert not (repo.path / victim).exists()
    assert hooks.run_hook("post-checkout", ["a", "b", "1"]) == 0
    assert repo.read(victim) == expected and "vault opened" in capsys.readouterr().err

    def explode(*_a: object, **_k: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(vault, "open_vault", explode)
    assert hooks.run_hook("post-merge", ["0"]) == 0
    assert "could not open the vault" in capsys.readouterr().err
    monkeypatch.undo()


def test_post_merge_reports_a_vault_that_cannot_be_synced(
    inside: Env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(*_a: object, **_k: object) -> None:
        raise multi.SyncError("not today")

    monkeypatch.setattr(multi, "sync", refuse)
    assert hooks.run_hook("post-merge", ["0"]) == 0
    assert "not synced with origin" in capsys.readouterr().err


def test_post_merge_locked_hint(inside: Env, capsys: pytest.CaptureFixture[str]) -> None:
    inside.agent.stop()
    assert hooks.run_hook("post-merge", ["0"]) == 0
    assert "vault not opened" in capsys.readouterr().err


def test_unknown_event_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert hooks.run_hook("pre-rebase", []) == 2
    assert "unknown hook event" in capsys.readouterr().err


# ------------------------------------------------------------------------- acquire_backend


def test_acquire_backend_reasons_and_auto_unlock_failures(
    inside: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_obj, git = discover(inside.repo.path, inside.git.env)
    cfg = load_config(git, repo_obj)
    client, reason = hooks.acquire_backend(repo_obj, cfg)
    assert client is not None and reason == ""
    client.close()
    inside.agent.stop()
    none, reason = hooks.acquire_backend(repo_obj, cfg)
    assert none is None and "unlock" in reason

    def fail(*_a: object, **_k: object) -> None:
        raise unlock.KeyCommandError("keyCommand failed (exit code 1)")

    monkeypatch.setattr(unlock, "unlock", fail)
    auto = load_config(git, repo_obj, env={"NBP_SAFE_AUTOUNLOCK": "true"})
    assert auto.auto_unlock
    none, reason = hooks.acquire_backend(repo_obj, auto)
    assert none is None and reason.startswith("autoUnlock failed")


def test_a_running_agent_without_a_key_counts_as_locked(inside: Env) -> None:
    inside.agent.stop()
    repo_obj, git = discover(inside.repo.path, inside.git.env)
    cfg = load_config(git, repo_obj)
    empty = ThreadAgent(inside.repo.state_dir, None)
    try:
        none, reason = hooks.acquire_backend(repo_obj, cfg)
        assert none is None and "holds no key" in reason
    finally:
        empty.stop()


# -------------------------------------------------------------------------- guard internals


def test_vault_validation_edge_cases(inside: Env) -> None:
    _repo, git = discover(inside.repo.path, inside.git.env)
    cache: dict[str, bytes | None] = {}
    problem, _ = guard.validate_vault_commit(git, ZERO + "", cache)
    assert problem == "commit has no tree"
    good, key_id = guard.validate_vault_commit(git, inside.tip(), cache)
    assert good is None and key_id == crypto.KeySet(inside.repo.master).key_id
    files = read_vault(inside.repo)
    del files[sorted(p for p in files if p.startswith("store/"))[0]]
    write_vault_commit(inside.repo, {**files, "nbp-safe/extra-index": b"x"}, inside.tip())
    problem, _ = guard.validate_vault_commit(git, inside.tip(), {})
    assert problem is not None and "unexpected path" in problem
    assert guard.read_blobs(git, [ZERO]) is not None
    assert list(guard.read_blobs(git, [ZERO])) == []
    assert guard.blob_sizes(git, [ZERO]) == {}


def test_check_push_refuses_objects_it_cannot_examine(inside: Env) -> None:
    """Review M3: an object that cannot be examined is not an object that is allowed (this used
    to be a warning, which let a tag of a tree or blob through)."""
    repo_obj, git = discover(inside.repo.path, inside.git.env)
    cfg = load_config(git, repo_obj)
    bogus = guard.RefUpdate("refs/tags/odd", "f" * 40, "refs/tags/odd", ZERO)
    report = guard.check_push(git, repo_obj, cfg, None, [bogus], "origin")
    assert not report.ok and any("could not be verified" in v.detail for v in report.violations)
    delete = guard.RefUpdate("(delete)", ZERO, "refs/heads/x", "a" * 40)
    assert guard.check_push(git, repo_obj, cfg, None, [delete], "origin").ok


# ------------------------------------------------------------------------- doctor / multi


def test_doctor_reports_a_corrupted_and_a_stale_agent_file(inside: Env) -> None:
    repo_obj, git = discover(inside.repo.path, inside.git.env)
    cfg = load_config(git, repo_obj)
    path = agent.agent_json_path(repo_obj.state_dir)
    saved = path.read_bytes()
    path.write_bytes(b"{broken")
    messages = [f.message for f in doctor.run_doctor(git, repo_obj, cfg)]
    assert any("agent.json is corrupted" in m for m in messages)
    inside.agent.stop()
    stale = make_info(repo_obj.state_dir, 2**22, 2.0)
    agent.write_agent_info(repo_obj.state_dir, stale)
    messages = [f.message for f in doctor.run_doctor(git, repo_obj, cfg)]
    assert any("agent.json is stale" in m for m in messages)
    assert saved  # (the original file is gone with the agent; nothing to restore)


def test_shim_pointing_at_another_python_is_reported(
    inside: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo_obj, git = discover(inside.repo.path, inside.git.env)
    hooks.uninstall_hooks(git)
    monkeypatch.setattr(hooks, "MIN_GIT", (99, 0))
    assert set(hooks.install_hooks(git, repo_obj).mechanisms.values()) == {"shim"}
    monkeypatch.setattr(hooks, "hook_python", lambda: "/somewhere/else/python")
    status = hooks.inspect_event(git, repo_obj, "pre-commit")
    assert not status.ok and "another Python" in status.detail


def test_multi_state_files_are_robust_to_garbage(inside: Env) -> None:
    repo_obj, git = discover(inside.repo.path, inside.git.env)
    cfg = load_config(git, repo_obj)
    repo_obj.state_dir.mkdir(parents=True, exist_ok=True)
    for name in (multi.SEEN_FILE, multi.PURGED_FILE, multi.AUTOPUSH_FILE):
        (repo_obj.state_dir / name).write_bytes(b"[not json")
    assert multi.read_seen(repo_obj) == {} and multi.read_purge_marker(repo_obj) == {}
    (repo_obj.state_dir / multi.SEEN_FILE).write_bytes(b'{"refs": {"a": "not-a-sha"}}')
    assert multi.read_seen(repo_obj) == {}
    assert multi.disable_auto_push(git, repo_obj) == []
    assert multi.remote_status(git, repo_obj, cfg).kind == "no-remote"
    assert multi.purge_pending(git, repo_obj, cfg) is False


def test_remote_status_without_a_local_vault_and_with_unrelated_histories(
    hooked: Env,
) -> None:
    repo = hooked.repo
    assert repo.raw("push", "-q", "origin", "main", "nbp-safe").returncode == 0
    repo_obj, git = discover(repo.path, hooked.git.env)
    cfg = load_config(git, repo_obj)
    assert multi.remote_status(git, repo_obj, cfg).kind == "in-sync"
    tip = hooked.tip()
    repo.sh("update-ref", "-d", "refs/heads/nbp-safe")
    assert multi.remote_status(git, repo_obj, cfg).kind == "no-local"
    write_vault_commit(repo, read_vault(repo, tip), None)  # an orphan: unrelated history
    status = multi.remote_status(git, repo_obj, cfg)
    assert status.kind == "diverged" and (status.ahead, status.behind) == (1, 1)


def test_push_and_fetch_failures_are_reported(hooked: Env) -> None:
    repo = hooked.repo
    repo_obj, git = discover(repo.path, hooked.git.env)
    cfg = load_config(git, repo_obj)
    with pytest.raises(vault.VaultError, match="could not fetch"):
        multi.fetch_vault(git, cfg, remote="no-such-remote")
    assert multi.fetch_vault(git, cfg) is False  # the remote has no vault branch yet
    with pytest.raises(vault.VaultError, match="git push failed"):
        multi.push_vault(git, repo_obj, cfg, remote="no-such-remote")
    repo.sh("update-ref", "-d", "refs/heads/nbp-safe")
    with pytest.raises(vault.VaultError, match="no local vault branch"):
        multi.push_vault(git, repo_obj, cfg)
    with pytest.raises(multi.ConfirmationError):
        multi.check_confirmation("purge nbp-safe", None)
    assert multi.confirmation_text("purge", "refs/heads/nbp-safe-2027") == "purge nbp-safe-2027"
