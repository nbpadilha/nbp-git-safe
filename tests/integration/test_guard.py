# SPDX-License-Identifier: MIT
"""Guard on the main branch, commit side: ``pre-commit`` by path and by content, pattern-file
protection, automatic sealing by ``post-commit``, and what ``--no-verify`` does and does not stop.
Every scenario ends with the leak gate (bare remote + whole local .git)."""

from __future__ import annotations

from nbp_git_safe import guard
from tests.integration.conftest import Env
from tests.integration.guardkit import (
    commit,
    first_protected,
    prune_unreachable,
    remote_refs,
    staged,
    tracked,
)

# --------------------------------------------------------------------------- happy path


def test_edit_commit_push_needs_no_extra_command(hooked: Env) -> None:
    repo = hooked.repo
    assert hooked.commits() == 1
    target = first_protected(repo, ".json")
    repo.write(target, '{"secret": "edited", "marker": "' + repo.canaries[2] + '"}\n')
    result = commit(repo, "second", "--allow-empty")
    assert result.returncode == 0 and "vault sealed" in result.stderr, result.stderr
    assert hooked.commits() == 2  # sealed by the hook, no `seal` command
    pushed = repo.raw("push", "-q", "origin", "main", "nbp-safe")
    assert pushed.returncode == 0, pushed.stderr
    refs = remote_refs(hooked)
    assert {"refs/heads/main", "refs/heads/nbp-safe"} <= refs.keys()
    assert refs["refs/heads/nbp-safe"] == hooked.tip()
    repo.assert_no_leak(hooked.bare)


# ------------------------------------------------------------------------- by path


def test_add_all_never_stages_protected_files_and_add_force_is_blocked(hooked: Env) -> None:
    repo = hooked.repo
    repo.write("reports/new-report.csv", "x,y\n1,2\n")
    repo.write("docs/public.md", "# public\n")
    repo.sh("add", "-A")
    assert staged(repo) == ["docs/public.md"]  # exclude block: protected files are invisible
    assert commit(repo, "public only").returncode == 0

    repo.sh("add", "-f", "reports/new-report.csv")
    head = repo.sh("rev-parse", "HEAD")
    blocked = commit(repo, "should not happen")
    assert blocked.returncode != 0
    assert "reports/new-report.csv" in blocked.stderr and "protected set" in blocked.stderr
    assert repo.sh("rev-parse", "HEAD") == head  # nothing was committed
    assert "--no-verify" not in blocked.stderr  # the tool never suggests bypassing itself
    repo.sh("restore", "--staged", "--", "reports/new-report.csv")
    prune_unreachable(repo)
    assert commit(repo, "clean again", "--allow-empty").returncode == 0
    repo.assert_no_leak(hooked.bare)


def test_local_pattern_file_is_enforced_too(hooked: Env) -> None:
    repo = hooked.repo
    (repo.path / ".git" / "info" / "nbp-safe").write_text("scratch-private/\n")
    repo.write("scratch-private/n.txt", "local-only protected")
    repo.sh("add", "-f", "scratch-private/n.txt")
    blocked = commit(repo, "x")
    assert blocked.returncode != 0 and "scratch-private/n.txt" in blocked.stderr


def test_protected_file_in_a_nested_pattern_and_unicode_names(hooked: Env) -> None:
    repo = hooked.repo
    repo.write("reports/relatório ñ/ação.txt", "nested, accented")
    repo.sh("add", "-f", "reports/relatório ñ/ação.txt")
    blocked = commit(repo, "x")
    assert blocked.returncode != 0 and "ação.txt" in blocked.stderr.replace("\\", "")


def test_negated_path_is_not_protected(hooked: Env) -> None:
    repo = hooked.repo
    repo.write("data-private/keep-public.txt", "changed, public by negation\n")
    repo.sh("add", "data-private/keep-public.txt")
    assert commit(repo, "public edit").returncode == 0


# ----------------------------------------------------------------------- by content


def test_renamed_copy_of_a_sealed_file_is_caught_by_content(hooked: Env) -> None:
    repo = hooked.repo
    source = first_protected(repo, ".csv")
    repo.write("public/innocent-name.txt", repo.read(source))
    repo.sh("add", "public/innocent-name.txt")
    assert "public/innocent-name.txt" in staged(repo)
    blocked = commit(repo, "copy")
    assert blocked.returncode != 0
    assert "public/innocent-name.txt" in blocked.stderr and "same content" in blocked.stderr
    repo.sh("restore", "--staged", "--", "public/innocent-name.txt")
    prune_unreachable(repo)
    (repo.path / "public" / "innocent-name.txt").unlink()
    repo.assert_no_leak(hooked.bare)


def test_copy_of_a_file_not_sealed_yet_is_caught_too(hooked: Env) -> None:
    """Content of protected files on disk counts even before the vault has them."""
    repo = hooked.repo
    repo.write("reports/fresh.txt", "brand new secret " + repo.canaries[0] + "\n")
    repo.write("public/fresh-copy.txt", "brand new secret " + repo.canaries[0] + "\n")
    repo.sh("add", "public/fresh-copy.txt")
    blocked = commit(repo, "copy")
    assert blocked.returncode != 0 and "same content" in blocked.stderr
    repo.sh("restore", "--staged", "--", "public/fresh-copy.txt")
    prune_unreachable(repo)
    (repo.path / "public" / "fresh-copy.txt").unlink()
    assert commit(repo, "ok", "--allow-empty").returncode == 0
    repo.assert_no_leak(hooked.bare)


def test_empty_and_unrelated_files_are_not_false_positives(hooked: Env) -> None:
    repo = hooked.repo
    repo.write("reports/empty.txt", "")  # protected but empty: fingerprints ignore empties
    repo.write("docs/.gitkeep", "")
    repo.write("docs/other.txt", "unrelated\n")
    repo.sh("add", "-A")
    assert commit(repo, "fine").returncode == 0
    assert "docs/.gitkeep" in repo.sh("ls-files")


def test_locked_agent_only_checks_by_path_and_says_so(hooked: Env) -> None:
    repo = hooked.repo
    source = first_protected(repo, ".csv")
    hooked.agent.stop()  # lock
    repo.write("public/copy-locked.txt", repo.read(source))
    repo.sh("add", "public/copy-locked.txt")
    result = commit(repo, "copy while locked")
    assert result.returncode == 0  # documented limit: no key, no content check
    assert "content check skipped" in result.stderr and "nbp-git-safe unlock" in result.stderr
    repo.write("reports/locked-new.csv", "x")
    repo.sh("add", "-f", "reports/locked-new.csv")
    blocked = commit(repo, "path check still works")
    assert blocked.returncode != 0 and "reports/locked-new.csv" in blocked.stderr


def test_post_commit_while_locked_warns_and_never_seals(hooked: Env) -> None:
    repo = hooked.repo
    tip = hooked.tip()
    hooked.agent.stop()
    repo.write("reports/after-lock.csv", "n,m\n")
    result = commit(repo, "more", "--allow-empty")
    assert result.returncode == 0
    assert "not sealed" in result.stderr and "nbp-git-safe unlock" in result.stderr
    assert hooked.tip() == tip
    repo.assert_no_leak(hooked.bare)


# --------------------------------------------------------- the pattern file itself


def test_removing_a_pattern_while_committing_is_blocked(hooked: Env) -> None:
    repo = hooked.repo
    repo.write(".nbp-safe", "data-private/**\n!data-private/keep-public.txt\n")  # drops reports/
    repo.sh("add", ".nbp-safe")
    blocked = commit(repo, "unprotect")
    assert blocked.returncode != 0
    assert "1 pattern(s) removed" in blocked.stderr and "NBP_SAFE_ALLOW_UNPROTECT" in blocked.stderr
    assert ".nbp-safe" in staged(repo)


def test_removing_a_pattern_and_adding_the_file_in_one_commit_is_blocked_twice(
    hooked: Env,
) -> None:
    repo = hooked.repo
    repo.write(".nbp-safe", "data-private/**\n!data-private/keep-public.txt\n")
    repo.write("reports/sneaky.csv", "a,b\n")
    repo.sh("add", ".nbp-safe")
    repo.sh("add", "-f", "reports/sneaky.csv")
    blocked = commit(repo, "sneak")
    assert blocked.returncode != 0
    # the union keeps the pattern from HEAD alive, so the path check fires as well
    assert "reports/sneaky.csv" in blocked.stderr and "pattern(s) removed" in blocked.stderr
    prune_unreachable(repo)


def test_unprotect_override_is_explicit_and_only_for_that_commit(hooked: Env) -> None:
    repo = hooked.repo
    repo.write(".nbp-safe", "data-private/**\n!data-private/keep-public.txt\n")
    repo.sh("add", ".nbp-safe")
    allowed = commit(repo, "deliberate", env={guard.ALLOW_UNPROTECT_ENV: "1"})
    assert allowed.returncode == 0 and "allowed by NBP_SAFE_ALLOW_UNPROTECT=1" in allowed.stderr
    assert (
        commit(repo, "plain", "--allow-empty", env={guard.ALLOW_UNPROTECT_ENV: "0"}).returncode == 0
    )


def test_adding_a_negation_to_an_existing_pattern_file_is_blocked(hooked: Env) -> None:
    repo = hooked.repo
    repo.write(".nbp-safe", repo.read(".nbp-safe").decode() + "!reports/exposed.csv\n")
    repo.sh("add", ".nbp-safe")
    blocked = commit(repo, "negate")
    assert blocked.returncode != 0 and "1 negation(s) added" in blocked.stderr


def test_adding_patterns_is_fine_and_name_like_patterns_only_warn(hooked: Env) -> None:
    repo = hooked.repo
    repo.write(".nbp-safe", repo.read(".nbp-safe").decode() + "extra-private/\nMaria Silva/\n")
    repo.sh("add", ".nbp-safe")
    result = commit(repo, "more patterns")
    assert result.returncode == 0
    assert "looks like a person's name" in result.stderr and "Maria" not in result.stderr


def test_deleting_the_pattern_file_is_blocked(hooked: Env) -> None:
    repo = hooked.repo
    repo.sh("rm", "-q", ".nbp-safe")
    blocked = commit(repo, "drop all protection")
    assert blocked.returncode != 0 and "pattern(s) removed" in blocked.stderr


# -------------------------------------------------------------------------- --no-verify


def test_no_verify_still_leaves_the_exclude_block_protecting_add_all(hooked: Env) -> None:
    repo = hooked.repo
    repo.write("reports/late.csv", "late,data\n")
    repo.write("docs/pub.md", "public\n")
    repo.sh("add", "-A")
    result = commit(repo, "skipping hooks", "--no-verify")
    assert result.returncode == 0
    assert tracked(repo).count("docs/pub.md") == 1
    assert not [p for p in tracked(repo) if p.startswith(("reports/", "data-private/**"))]
    assert hooked.tip()  # post-commit still ran (--no-verify skips pre-commit and commit-msg only)
    repo.assert_no_leak(hooked.bare)


def test_add_force_plus_no_verify_leaks_by_design_and_doctor_reports_it(hooked: Env) -> None:
    """The documented limit: with both ``add -f`` and ``--no-verify`` nothing stops the commit.
    Afterwards ``doctor`` flags the tracked protected file (and the push is blocked, see
    test_push_guard)."""
    repo = hooked.repo
    repo.write("reports/leaked.csv", "oops\n")
    repo.sh("add", "-f", "reports/leaked.csv")
    assert commit(repo, "bypass", "--no-verify").returncode == 0
    assert "reports/leaked.csv" in tracked(repo)
    report = repo.cli("doctor")
    assert report.code == 1 and "tracked on the main branch" in report.out
