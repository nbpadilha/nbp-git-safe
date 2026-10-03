# SPDX-License-Identifier: MIT
"""Third adversarial review, end to end through git and the hooks.

M-N1: a collaborator replaces ``reports/`` by ``reports/<CR><CR>`` in ``.nbp-safe``. For git that is
a different (useless) pattern; the tool used to call it "the same version", prune the old one and
hand git the raw file, so ``reports/`` stopped being protected without a word.
B-N1: a vault branch that went back (a rollback on origin, then a re-sync with the local branch
deleted) must not be adopted, sealed upon, or pushed.
Info: the exemption of ``.nbp-safe`` / ``.nbp-safe.config`` is by PATH only, never from the content
check. B-N3/B-N5 at hook level: a link or an unreadable memory makes the hooks fail closed.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

import pytest

from nbp_git_safe import guard, hooks, protect, vault
from nbp_git_safe.config import Config, load_config
from nbp_git_safe.gitutil import discover
from tests.helpers import VERSIONED_PATTERNS, NbpRepo
from tests.integration.conftest import Env
from tests.integration.guardkit import (
    assert_remote_clean,
    commit,
    first_protected,
    prune_unreachable,
    remote_refs,
    staged,
)

# ------------------------------------------------------------------------------------- M-N1


def cr_attack(env: Env, clone_factory) -> str:  # type: ignore[no-untyped-def]
    """Push, let a collaborator without the tool pad ``reports/`` with two CRs, pull it. Returns
    the path of a brand new protected file (not sealed yet) under ``reports/``."""
    repo = env.repo
    assert repo.raw("push", "-q", "origin", "main", "nbp-safe").returncode == 0
    attacker: NbpRepo = clone_factory(env)
    padded = VERSIONED_PATTERNS.replace("reports/\n", "reports/\r\r\n")
    assert padded != VERSIONED_PATTERNS
    (attacker.path / ".nbp-safe").write_bytes(padded.encode())
    attacker.sh("add", ".nbp-safe")
    assert attacker.raw("commit", "-q", "-m", "tidy").returncode == 0
    assert attacker.raw("push", "-q", "origin", "main").returncode == 0
    pulled = repo.raw("pull", "-q", "--no-rebase", "origin", "main")
    assert pulled.returncode == 0, pulled.stderr  # it used to fail: "outside the protected set"
    assert b"reports/\r\r\n" in (repo.path / ".nbp-safe").read_bytes()  # it really arrived
    rel = f"reports/{repo.canaries[0]}-NEW.csv"
    repo.write(rel, f"brand new secret {repo.canaries[0]} {os.urandom(12).hex()}\n")
    return rel


def test_mn1_cr_padded_pattern_does_not_unprotect(hooked: Env, clone_factory) -> None:  # type: ignore[no-untyped-def]
    repo = hooked.repo
    rel = cr_attack(hooked, clone_factory)
    repo_obj, git = discover(repo.path, hooked.git.env)
    assert rel in protect.list_protected(git, repo_obj)
    assert rel in protect.match_paths(git, repo_obj, [rel])
    assert "reports/" in protect.lost_protection(git, repo_obj)  # the owner is warned
    # a new file is sealed like any other, and the vault opens again
    sealed = repo.cli("seal")
    assert sealed.code == 0, sealed.err
    assert "NEW" in repo.cli("ls").out
    assert repo.cli("open").code == 0
    # `git add -A` does not stage it
    repo.sh("add", "-A")
    assert not [p for p in staged(repo) if p.startswith("reports/")]
    # a renamed copy of it is caught by content, at commit time and (with --no-verify) at push
    repo.write("export-copy.txt", repo.read(rel))
    repo.sh("add", "export-copy.txt")
    blocked = commit(repo, "copy")
    assert blocked.returncode != 0 and "export-copy.txt" in blocked.stderr
    assert commit(repo, "copy", "--no-verify").returncode == 0
    pushed = repo.raw("push", "origin", "main")
    assert pushed.returncode != 0 and "push blocked" in pushed.stderr
    assert "refs/heads/main" in remote_refs(hooked)  # from the first push, before the copy
    assert_remote_clean(hooked)  # zero hits for the canaries in the bare remote
    assert repo.leak_scanner().scan_bare_repo(hooked.bare) == []


def test_mn1_control_without_the_padding_nothing_changes(hooked: Env) -> None:
    repo = hooked.repo
    rel = f"reports/{repo.canaries[0]}-NEW.csv"
    repo.write(rel, f"brand new secret {repo.canaries[0]}\n")
    repo.write("export-copy.txt", repo.read(rel))
    repo.sh("add", "export-copy.txt")
    assert commit(repo, "copy").returncode != 0


# ------------------------------------------------------------------------------------- B-N1


def rollback_setup(env: Env, *, cli_push_first: bool) -> tuple[NbpRepo, str, str, str]:
    repo = env.repo
    rel = first_protected(repo, ".csv")
    v1_tip = env.tip()
    assert repo.raw("push", "-q", "origin", "main").returncode == 0
    if cli_push_first:
        assert repo.cli("push").code == 0  # records "seen" = v1
    else:
        assert repo.raw("push", "-q", "origin", "nbp-safe").returncode == 0
    repo.write(rel, repo.read(rel) + b"\nNEWEST VERSION\n")
    assert commit(repo, "edit", "--allow-empty").returncode == 0
    v2_tip = env.tip()
    assert v2_tip != v1_tip
    # a plain `git push` of the vault (what --auto-push does) does not update "seen"
    assert repo.raw("push", "-q", "origin", "nbp-safe").returncode == 0
    return repo, rel, v1_tip, v2_tip


def local_vault_tip(repo: NbpRepo) -> str | None:
    proc = repo.raw("rev-parse", "--verify", "-q", "refs/heads/nbp-safe")
    return proc.stdout.strip() if proc.returncode == 0 else None


@pytest.mark.parametrize("cli_push_first", [False, True], ids=["P1a-no-seen", "P1b-old-seen"])
def test_bn1_resync_without_a_local_branch_does_not_adopt_an_older_tip(
    hooked: Env, cli_push_first: bool
) -> None:
    repo, _rel, v1_tip, v2_tip = rollback_setup(hooked, cli_push_first=cli_push_first)
    hooked.git.run("update-ref", "refs/heads/nbp-safe", v1_tip, cwd=hooked.bare)  # rollback
    repo.sh("branch", "-D", "nbp-safe")  # the owner drops the local branch to "re-sync"
    refused = repo.cli("sync", "--no-open")
    assert refused.code != 0
    assert "accept-remote-rewrite" in refused.err
    assert local_vault_tip(repo) is None  # nothing was adopted
    # the explicit flag is the way to take it anyway
    allowed = repo.cli("sync", "--no-open", "--accept-remote-rewrite")
    assert allowed.code == 0, allowed.err
    assert local_vault_tip(repo) == v1_tip
    assert v2_tip != v1_tip


def test_bn1_resync_still_works_when_origin_is_ahead_or_equal(hooked: Env) -> None:
    repo, _rel, _v1, v2_tip = rollback_setup(hooked, cli_push_first=False)
    repo.sh("branch", "-D", "nbp-safe")
    ok = repo.cli("sync", "--no-open")
    assert ok.code == 0, ok.err
    assert local_vault_tip(repo) == v2_tip


def test_bn1_seal_refuses_to_build_on_a_branch_that_went_back(hooked: Env) -> None:
    repo, _rel, v1_tip, _v2 = rollback_setup(hooked, cli_push_first=False)
    repo.sh("update-ref", "refs/heads/nbp-safe", v1_tip)  # the branch went back some other way
    other = first_protected(repo, ".json")
    repo.write(other, repo.read(other) + b"\n{}\n")
    sealed = repo.cli("seal")
    assert sealed.code != 0 and "behind" in sealed.err
    assert local_vault_tip(repo) == v1_tip  # no commit was laundered on top of it
    repo_obj, _git = discover(repo.path, hooked.git.env)
    assert vault.read_verified(repo_obj)["refs/heads/nbp-safe"][0] != v1_tip


def test_bn1_pre_push_refuses_a_vault_branch_that_went_back(hooked: Env) -> None:
    repo, _rel, v1_tip, v2_tip = rollback_setup(hooked, cli_push_first=False)
    repo.sh("update-ref", "refs/heads/nbp-safe", v1_tip)
    forced = repo.raw("push", "--force", "origin", "nbp-safe")
    assert forced.returncode != 0 and "push blocked" in forced.stderr
    assert remote_refs(hooked)["refs/heads/nbp-safe"] == v2_tip  # origin was not rolled back
    # the guard on its own: refused while the record says v2, accepted once the owner reset it
    repo_obj, git = discover(repo.path, hooked.git.env)
    cfg = load_config(git, repo_obj)
    update = guard.RefUpdate("refs/heads/nbp-safe", v1_tip, "refs/heads/nbp-safe", v2_tip)
    with hooked.backend() as backend:
        report = guard.check_push(git, repo_obj, cfg, backend, [update], "origin")
        assert [v.kind for v in report.violations] == ["vault"]
        vault.mark_verified(repo_obj, "refs/heads/nbp-safe", v1_tip, 1, reset=True)
        assert guard.check_push(git, repo_obj, cfg, backend, [update], "origin").ok


def test_bn1_ensure_not_behind_without_a_record_has_nothing_to_compare(hooked: Env) -> None:
    repo_obj, git = discover(hooked.repo.path, hooked.git.env)
    vault.ensure_not_behind(git, repo_obj, "refs/heads/nbp-safe-other", hooked.tip())


# ------------------------------------------------------------------------------------- Info


def test_info_the_content_check_still_runs_for_our_own_file_names(hooked: Env) -> None:
    repo = hooked.repo
    secret = secrets.token_hex(8)
    config = f"[pad]\n\tbucket = 4096\n# {secret}\n"
    repo.write(f"data-private/cfg-{secret}.ini", config)  # protected, valid git-config text
    repo.write(".nbp-safe.config", config)  # ... copied under a name that is exempt by PATH
    repo.sh("add", ".nbp-safe.config")
    blocked = commit(repo, "cfg")
    assert blocked.returncode != 0
    assert ".nbp-safe.config" in blocked.stderr and "same content" in blocked.stderr
    repo.sh("restore", "--staged", "--", ".nbp-safe.config")
    # the same for a copy of protected content in .nbp-safe itself (patterns that only add)
    repo.write(f"data-private/pat-{secret}.txt", VERSIONED_PATTERNS + f"# {secret}\n")
    repo.write(".nbp-safe", VERSIONED_PATTERNS + f"# {secret}\n")
    repo.sh("add", ".nbp-safe")
    blocked = commit(repo, "patterns")
    assert blocked.returncode != 0 and "same content" in blocked.stderr
    repo.sh("restore", "--staged", "--", ".nbp-safe")
    prune_unreachable(repo)


def test_info_a_legitimate_config_file_is_still_committable(hooked: Env) -> None:
    repo = hooked.repo
    repo.write(".nbp-safe.config", "[pad]\n\tbucket = 4096\n")
    repo.sh("add", ".nbp-safe.config")
    assert commit(repo, "cfg").returncode == 0


def test_info_the_exemption_folds_case_only_where_the_file_system_does(
    isolated_git,
    tmp_path: Path,  # type: ignore[no-untyped-def]
) -> None:
    root = isolated_git.init(tmp_path / "case")
    repo, git = discover(root, isolated_git.env)
    (root / ".nbp-safe").write_text("*\n", newline="\n")  # a broad pattern: covers everything
    blob = isolated_git.run("hash-object", "-w", "--stdin", cwd=root, input=b"fake\n").strip()
    for name in (".nbp-safe.config", ".NBP-SAFE.CONFIG", "other.txt"):
        isolated_git.run("update-index", "--add", "--cacheinfo", f"100644,{blob},{name}", cwd=root)

    def violating(ignorecase: str) -> set[str]:
        isolated_git.run("config", "core.ignorecase", ignorecase, cwd=root)
        report = guard.check_commit(git, repo, Config(), None, {})
        return {v.subject for v in report.violations if v.kind == "path"}

    # a case-sensitive file system: `.NBP-SAFE.CONFIG` is an ordinary file next to ours
    assert violating("false") == {".NBP-SAFE.CONFIG", "other.txt"}
    # a case-insensitive one: it IS ours
    assert violating("true") == {"other.txt"}
    assert protect.is_exempt(".nbp-safe", False) and not protect.is_exempt(".Nbp-Safe", False)
    assert protect.is_exempt(".Nbp-Safe", True)


# -------------------------------------------------------------------------- B-N3 / B-N5 hooks


@pytest.fixture
def inside(hooked: Env, monkeypatch: pytest.MonkeyPatch) -> Env:
    monkeypatch.chdir(hooked.repo.path)
    return hooked


def test_bn5_pre_commit_fails_closed_when_a_remembered_version_cannot_be_read(
    inside: Env, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo_obj, _git = discover(inside.repo.path, inside.git.env)
    assert hooks.run_hook("pre-commit", []) == 0
    broken = next(iter(protect.stored_versions(repo_obj)))
    real = Path.read_bytes

    def flaky(self: Path) -> bytes:
        if self.name == broken:
            raise PermissionError(13, "Permission denied")
        return real(self)

    capsys.readouterr()
    with monkeypatch.context() as patched:
        patched.setattr(Path, "read_bytes", flaky)
        assert hooks.run_hook("pre-commit", []) == 1
        assert hooks.run_hook("pre-push", []) == 1
    assert "cannot be read" in capsys.readouterr().err
    assert hooks.run_hook("pre-commit", []) == 0


def test_bn3_pre_commit_fails_closed_on_a_nbp_safe_that_is_a_link(
    inside: Env, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = inside.repo
    secret = "OUTSIDE-" + secrets.token_hex(8)
    outside = tmp_path / "outside.txt"
    outside.write_text(secret + "/\n", newline="\n")
    (repo.path / ".nbp-safe").unlink()
    try:
        os.symlink(outside, repo.path / ".nbp-safe")
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create a symbolic link here ({exc})")
    capsys.readouterr()
    assert hooks.run_hook("pre-commit", []) == 1
    assert "symbolic link" in capsys.readouterr().err
    for path in (repo.path / ".git").rglob("*"):
        if path.is_file() and path.stat().st_size < 1 << 20 and "objects" not in path.parts:
            assert secret.encode() not in path.read_bytes(), path
