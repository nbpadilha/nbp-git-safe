# SPDX-License-Identifier: MIT
"""``pre-push`` and refs that do not point at commits (regression for review M3).

A tag can point at a tree or a blob. ``rev-list`` of such a ref used to fail, the failure was
turned into a warning, and the push went through with protected files inside the tree. Now an
object that cannot be examined blocks the push; trees are walked with ``rev-list --objects`` and
annotated tags are followed to their final target.
"""

from __future__ import annotations

import subprocess

import pytest

from nbp_git_safe import guard
from nbp_git_safe.config import load_config
from nbp_git_safe.gitutil import discover
from tests.helpers import NbpRepo
from tests.integration.conftest import Env
from tests.integration.guardkit import assert_remote_clean, first_protected, remote_refs


def tree_with_protected_file(repo: NbpRepo) -> str:
    """A tree object holding a protected file (staged with `add -f`, then unstaged again)."""
    rel = first_protected(repo, ".csv")
    repo.sh("add", "-f", rel)
    tree = repo.sh("write-tree").strip()
    repo.sh("reset", "-q")
    return tree


def clean_tree(repo: NbpRepo) -> str:
    repo.write("plain/readme.txt", "nothing secret here\n")
    repo.sh("add", "plain/readme.txt")
    tree = repo.sh("write-tree").strip()
    repo.sh("reset", "-q")
    return tree


def push_tag(env: Env, name: str) -> subprocess.CompletedProcess[str]:
    return env.repo.raw("push", "origin", f"refs/tags/{name}")


def test_a_tag_of_a_tree_with_a_protected_file_is_blocked(hooked: Env) -> None:
    repo = hooked.repo
    repo.sh("tag", "snap", tree_with_protected_file(repo))
    pushed = push_tag(hooked, "snap")
    assert pushed.returncode != 0 and "push blocked" in pushed.stderr
    assert "matches the protected set" in pushed.stderr
    assert "refs/tags/snap" not in remote_refs(hooked)
    assert_remote_clean(hooked)


def test_an_annotated_tag_of_a_tag_of_a_tree_is_followed_to_the_end(hooked: Env) -> None:
    repo = hooked.repo
    tree = tree_with_protected_file(repo)
    repo.sh("tag", "-a", "-m", "inner", "inner", tree)
    repo.sh("tag", "-a", "-m", "outer", "outer", "inner")
    pushed = push_tag(hooked, "outer")
    assert pushed.returncode != 0 and "push blocked" in pushed.stderr
    assert "refs/tags/outer" not in remote_refs(hooked)
    assert_remote_clean(hooked)


def test_a_tag_of_a_tree_with_a_renamed_copy_is_caught_by_content(hooked: Env) -> None:
    repo = hooked.repo
    rel = first_protected(repo, ".csv")
    repo.write("innocent-name.txt", repo.read(rel))
    repo.sh("add", "innocent-name.txt")
    tree = repo.sh("write-tree").strip()
    repo.sh("reset", "-q")
    repo.sh("tag", "copy", tree)
    pushed = push_tag(hooked, "copy")
    assert pushed.returncode != 0 and "same content as a protected file" in pushed.stderr
    assert_remote_clean(hooked)


def test_a_tag_of_an_innocent_tree_and_of_a_commit_still_goes_through(hooked: Env) -> None:
    repo = hooked.repo
    repo.sh("tag", "docs", clean_tree(repo))
    repo.sh("tag", "-a", "-m", "release", "v1")
    for name in ("docs", "v1"):
        pushed = push_tag(hooked, name)
        assert pushed.returncode == 0, pushed.stderr
    assert {"refs/tags/docs", "refs/tags/v1"} <= set(remote_refs(hooked))
    repo.assert_no_leak(hooked.bare)


def test_a_tag_of_a_bare_file_needs_the_agent_and_is_compared_by_content(hooked: Env) -> None:
    repo = hooked.repo
    rel = first_protected(repo, ".csv")
    secret_blob = repo.sh("hash-object", "-w", rel).strip()
    repo.sh("tag", "blobtag", secret_blob)
    blocked = push_tag(hooked, "blobtag")
    assert blocked.returncode != 0 and "same content as a protected file" in blocked.stderr
    assert "refs/tags/blobtag" not in remote_refs(hooked)
    assert_remote_clean(hooked)

    repo.write("notes/innocent.txt", "no relation to anything sealed " + "x" * 40 + "\n")
    harmless = repo.sh("hash-object", "-w", "notes/innocent.txt").strip()
    repo.sh("tag", "harmless", harmless)
    assert push_tag(hooked, "harmless").returncode == 0

    hooked.agent.stop()  # locked: a blob has no path, so nothing can be verified
    repo.sh("tag", "again", harmless)
    locked = push_tag(hooked, "again")
    assert locked.returncode != 0 and "no path to check" in locked.stderr
    assert "refs/tags/again" not in remote_refs(hooked)


@pytest.mark.parametrize("update_ref", ["refs/tags/odd", "refs/heads/nbp-safe"])
def test_an_object_that_cannot_be_examined_blocks_the_push(hooked: Env, update_ref: str) -> None:
    repo_obj, git = discover(hooked.repo.path, hooked.git.env)
    cfg = load_config(git, repo_obj)
    bogus = guard.RefUpdate(update_ref, "f" * 40, update_ref, "0" * 40)
    report = guard.check_push(git, repo_obj, cfg, None, [bogus], "origin")
    assert not report.ok
    assert any("could not be verified" in v.detail for v in report.violations)
    assert not report.warnings or all("not checked" not in w for w in report.warnings)


def test_check_push_never_downgrades_a_git_failure_to_a_warning(
    hooked: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    from nbp_git_safe.gitutil import GitError

    def boom(*_a: object, **_k: object) -> object:
        raise GitError("simulated")

    monkeypatch.setattr(guard, "peel", boom)
    repo_obj, git = discover(hooked.repo.path, hooked.git.env)
    cfg = load_config(git, repo_obj)
    tip = hooked.repo.sh("rev-parse", "HEAD").strip()
    update = guard.RefUpdate("refs/heads/main", tip, "refs/heads/main", "0" * 40)
    report = guard.check_push(git, repo_obj, cfg, None, [update], "origin")
    assert not report.ok and not report.warnings
