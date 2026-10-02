# SPDX-License-Identifier: MIT
"""A pattern that disappears from ``.nbp-safe`` stays protected here (regression for review A3).

Anyone with push access to the main branch can remove ``reports/`` from ``.nbp-safe`` (on GitHub's
web UI no hook runs at all). After ``git pull`` the exclude block used to be rewritten without it
and the owner's next ``git add -A``, commit and push published the regenerated files. Defence in
depth: (1) a sticky local memory of every pattern ever seen, which only the explicit, confirmed
``unprotect`` command shrinks; (2) paths of the vault index are blocked even when no pattern covers
them; (3) the post-merge/post-checkout hooks keep the exclude block and warn loudly; ``doctor``
lists what is only remembered.
"""

from __future__ import annotations

import os
import unicodedata
from pathlib import Path

import pytest

from nbp_git_safe import doctor, guard, protect
from nbp_git_safe.config import load_config
from nbp_git_safe.gitutil import discover
from tests.helpers import NbpRepo
from tests.integration.conftest import Env
from tests.integration.guardkit import (
    assert_remote_clean,
    commit,
    first_protected,
    prune_unreachable,
    remote_refs,
    staged,
)

ATTACKER_PATTERNS = "data-private/**\n!data-private/keep-public.txt\n"  # `reports/` is gone


def push_everything(env: Env) -> None:
    assert env.repo.raw("push", "-q", "origin", "main", "nbp-safe").returncode == 0


def remove_pattern_upstream(env: Env, clone_factory) -> None:  # type: ignore[no-untyped-def]
    """A collaborator without the tool (so: no hooks) removes ``reports/`` and pushes."""
    attacker: NbpRepo = clone_factory(env)
    attacker.write(".nbp-safe", ATTACKER_PATTERNS)
    attacker.sh("add", ".nbp-safe")
    assert attacker.raw("commit", "-q", "-m", "tidy patterns").returncode == 0
    assert attacker.raw("push", "-q", "origin", "main").returncode == 0


def regenerate_reports(repo: NbpRepo) -> list[str]:
    """What the owner's scripts do every day: rewrite the report files with new content."""
    touched = []
    for path in sorted((repo.path / "reports").rglob("*")):
        if path.is_file():
            path.write_bytes(
                path.read_bytes() + b"regenerated today " + os.urandom(6).hex().encode()
            )
            touched.append(path.relative_to(repo.path).as_posix())
    assert touched
    return touched


def test_a_pattern_removed_upstream_does_not_unprotect_after_pull(
    hooked: Env, clone_factory
) -> None:  # type: ignore[no-untyped-def]
    repo = hooked.repo
    push_everything(hooked)
    remove_pattern_upstream(hooked, clone_factory)

    pulled = repo.raw("pull", "-q", "--no-rebase", "origin", "main")
    assert pulled.returncode == 0, pulled.stderr
    assert "reports/" not in repo.read(".nbp-safe").decode()  # the removal really arrived
    assert "STILL protects" in pulled.stderr  # loud, in the post-merge hook
    assert "reports" not in pulled.stderr  # ... without echoing patterns or names

    regenerate_reports(repo)
    repo.sh("add", "-A")
    assert not any(p.startswith("reports/") for p in staged(repo)), "layer 1 relaxed"
    repo.write("notes.txt", "ordinary work\n")
    repo.sh("add", "notes.txt")
    assert commit(repo, "daily work").returncode == 0
    pushed = repo.raw("push", "-q", "origin", "main")
    assert pushed.returncode == 0, pushed.stderr
    assert_remote_clean(hooked)
    repo.assert_no_leak(hooked.bare)


def test_the_exclude_block_survives_even_if_the_hook_did_not_run(
    hooked: Env, clone_factory
) -> None:  # type: ignore[no-untyped-def]
    repo = hooked.repo
    push_everything(hooked)
    remove_pattern_upstream(hooked, clone_factory)
    off = ["-c", "hook.nbp-git-safe-post-merge.enabled=false"]  # a client that skips the hook
    assert repo.raw(*off, "pull", "-q", "--no-rebase", "origin", "main").returncode == 0
    regenerate_reports(repo)
    repo.sh("add", "-A")
    assert not any(p.startswith("reports/") for p in staged(repo))


def test_a_stale_exclude_block_is_not_even_needed_for_the_commit_guard(
    hooked: Env, clone_factory
) -> None:  # type: ignore[no-untyped-def]
    """Layer 2 alone: someone stages the files with `add -f` after the pull."""
    repo = hooked.repo
    push_everything(hooked)
    remove_pattern_upstream(hooked, clone_factory)
    assert repo.raw("pull", "-q", "--no-rebase", "origin", "main").returncode == 0
    touched = regenerate_reports(repo)
    repo.sh("add", "-f", *touched)
    blocked = commit(repo, "force it")
    assert blocked.returncode != 0 and "matches the protected set" in blocked.stderr
    prune_unreachable(repo)


def test_doctor_lists_patterns_that_only_the_memory_keeps(hooked: Env, clone_factory) -> None:  # type: ignore[no-untyped-def]
    repo = hooked.repo
    push_everything(hooked)
    remove_pattern_upstream(hooked, clone_factory)
    assert repo.raw("pull", "-q", "--no-rebase", "origin", "main").returncode == 0
    repo_obj, git = discover(repo.path, hooked.git.env)
    findings = doctor.run_doctor(git, repo_obj, load_config(git, repo_obj))
    sticky = [f for f in findings if "still protected here" in f.message]
    assert len(sticky) == 1 and sticky[0].level == doctor.WARN and "reports/" in sticky[0].message
    assert protect.sticky_only(repo_obj) == ["reports/"]


def test_unprotect_is_explicit_confirmed_and_the_only_way_out(hooked: Env, clone_factory) -> None:  # type: ignore[no-untyped-def]
    repo = hooked.repo
    push_everything(hooked)
    remove_pattern_upstream(hooked, clone_factory)
    assert repo.raw("pull", "-q", "--no-rebase", "origin", "main").returncode == 0

    refused = repo.cli("unprotect", "reports/")
    assert refused.code != 0 and "confirmation" in refused.err  # no terminal, no --confirm
    wrong = repo.cli("unprotect", "reports/", "--confirm", "yes please")
    assert wrong.code != 0
    assert protect.sticky_only(discover(repo.path, hooked.git.env)[0]) == ["reports/"]

    unknown = repo.cli("unprotect", "nothing/", "--confirm", "unprotect nothing/")
    assert unknown.code != 0 and "no such remembered pattern" in unknown.err
    versioned = repo.cli("unprotect", "data-private/**", "--confirm", "unprotect data-private/**")
    assert versioned.code != 0 and "still in .nbp-safe" in versioned.err

    done = repo.cli("unprotect", "reports/", "--confirm", "unprotect reports/")
    assert done.code == 0, done.err
    exclude = (repo.path / ".git" / "info" / "exclude").read_text()
    assert "reports/" not in exclude
    assert protect.sticky_only(discover(repo.path, hooked.git.env)[0]) == []
    regenerate_reports(repo)
    repo.sh("add", "-A")
    assert any(p.startswith("reports/") for p in staged(repo))  # now the user's own decision
    repo.sh("reset", "-q")


# --------------------------------------------------------- index membership (layer 2b)


def drop_every_pattern(repo: NbpRepo) -> None:
    """Leave the clone with no source that mentions ``reports/``: the removal is committed (a
    deliberate act), and the sticky memory and the exclude block are rebuilt from scratch."""
    repo.write(".nbp-safe", ATTACKER_PATTERNS)
    repo.sh("add", ".nbp-safe")
    assert commit(repo, "tidy", env={guard.ALLOW_UNPROTECT_ENV: "1"}).returncode == 0
    (repo.path / ".git" / "nbp-safe" / protect.STICKY_FILE).unlink(missing_ok=True)
    repo_obj, _ = discover(repo.path, repo.git.env)
    protect.remove_exclude_block(repo_obj)
    protect.install_exclude_block(repo_obj)
    assert protect.sticky_only(repo_obj) == []


def test_a_sealed_path_is_blocked_even_when_no_pattern_covers_it(hooked: Env) -> None:
    repo = hooked.repo
    rel = first_protected(repo, ".csv")
    drop_every_pattern(repo)
    (repo.path / rel).write_bytes((repo.path / rel).read_bytes() + b"edited, so the MAC differs")
    repo.sh("add", "-f", rel)
    blocked = commit(repo, "sneak")
    assert blocked.returncode != 0
    assert "is a path of the vault" in blocked.stderr
    prune_unreachable(repo)


def test_a_sealed_path_in_another_unicode_form_is_blocked_too(hooked: Env) -> None:
    repo = hooked.repo
    nfc = "reports/relatório final " + repo.canaries[1] + "/nota " + repo.canaries[1] + ".txt"
    assert (repo.path / nfc).is_file()
    drop_every_pattern(repo)
    nfd = unicodedata.normalize("NFD", nfc)
    assert nfd != nfc
    repo.write(nfd, "unrelated bytes, same name once normalised\n" + repo.canaries[0])
    repo.sh("add", "-f", "--", nfd)
    blocked = commit(repo, "sneak")
    assert blocked.returncode != 0 and "is a path of the vault" in blocked.stderr
    prune_unreachable(repo)


def test_pushing_a_sealed_path_is_blocked_by_the_index_too(hooked: Env) -> None:
    repo = hooked.repo
    rel = first_protected(repo, ".csv")
    drop_every_pattern(repo)
    (repo.path / rel).write_bytes((repo.path / rel).read_bytes() + b"edited")
    repo.sh("add", "-f", rel)
    assert commit(repo, "bypass", "--no-verify").returncode == 0
    blocked = repo.raw("push", "origin", "main")
    assert blocked.returncode != 0 and "push blocked" in blocked.stderr
    assert "refs/heads/main" not in remote_refs(hooked)
    assert_remote_clean(hooked)


# ------------------------------------------------------------------------- unit level


def sticky_repo(isolated_git, tmp_path: Path):  # type: ignore[no-untyped-def]
    root = isolated_git.init(tmp_path / "unit")
    repo, git = discover(root, isolated_git.env)
    return root, repo, git


def test_sticky_memory_semantics(isolated_git, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    root, repo, _git = sticky_repo(isolated_git, tmp_path)
    (root / ".nbp-safe").write_text("a/\n!a/keep.txt\nb/\n")
    assert protect.refresh_sticky(repo) is True
    assert protect.refresh_sticky(repo) is False  # idempotent
    assert protect.read_patterns(protect.sticky_path(repo)) == ["a/", "!a/keep.txt", "b/"]
    assert protect.sticky_only(repo) == []

    (root / ".nbp-safe").write_text("c/\n!c/x\n")  # a, b and the negation vanish
    assert protect.sticky_only(repo) == ["a/", "b/"]  # a negation is never kept alive
    assert protect.refresh_sticky(repo) is True
    assert protect.read_patterns(protect.sticky_path(repo)) == ["c/", "!c/x", "a/", "b/"]
    assert protect.block_lines(repo)[:4] == ["c/", "!c/x", "a/", "b/"]

    (root / ".nbp-safe").unlink()  # the whole file deleted upstream
    assert protect.sticky_only(repo) == ["c/", "a/", "b/"]
    assert protect.refresh_sticky(repo) is True
    assert protect.pattern_files(repo) == [protect.sticky_path(repo)]

    assert protect.unprotect(repo, "a/") == "removed"
    assert protect.unprotect(repo, "a/") == "unknown"
    (root / ".nbp-safe").write_text("c/\n")
    assert protect.unprotect(repo, "c/") == "still-versioned"
    assert "a/" not in protect.read_patterns(protect.sticky_path(repo))


def test_sticky_extra_versions_are_remembered(isolated_git, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    root, repo, _git = sticky_repo(isolated_git, tmp_path)
    (root / ".nbp-safe").write_text("now/\n")
    protect.refresh_sticky(repo, [b"staged-only/\n!neg\n# comment\n"])
    assert protect.read_patterns(protect.sticky_path(repo)) == ["now/", "staged-only/"]


def test_nothing_is_written_when_there_is_nothing_to_remember(isolated_git, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    _root, repo, _git = sticky_repo(isolated_git, tmp_path)
    assert protect.refresh_sticky(repo) is False
    assert not protect.sticky_path(repo).exists()


@pytest.mark.parametrize("what", ["exclude", "sticky"])
def test_state_files_do_not_hold_names_beyond_the_patterns(hooked: Env, what: str) -> None:
    repo = hooked.repo
    text = (
        (repo.path / ".git" / "info" / "exclude").read_text()
        if what == "exclude"
        else (repo.path / ".git" / "nbp-safe" / protect.STICKY_FILE).read_text()
    )
    assert not any(c in text for c in repo.canaries)
