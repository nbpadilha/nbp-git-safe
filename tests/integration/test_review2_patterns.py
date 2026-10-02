# SPDX-License-Identifier: MIT
"""Second adversarial review, pattern memory (H1, B-N2 and the silent ``unprotect``).

H1: the memory of removed patterns used to store LINES, negations included. A collaborator without
the tool pushed ``.nbp-safe`` with ``reports/`` followed by ``!reports/`` and ``!reports/**``;
after ``git pull`` every source carried the negation, the exclude block re-included the files and
``git add -A`` + commit + push published them. The memory now keeps VERSIONS of the file, and each
version is one more source of the union: a negation of a newer version never cancels what an older
version protects, while a negation inside the version it is written in keeps working.
"""

from __future__ import annotations

import os

from nbp_git_safe import doctor, guard, protect
from nbp_git_safe.config import load_config
from nbp_git_safe.gitutil import discover
from tests.helpers import VERSIONED_PATTERNS, NbpRepo
from tests.integration.conftest import Env
from tests.integration.guardkit import (
    assert_remote_clean,
    commit,
    prune_unreachable,
    remote_refs,
    staged,
)

NEGATION = VERSIONED_PATTERNS + "!reports/\n!reports/**\n"


def push_everything(env: Env) -> None:
    assert env.repo.raw("push", "-q", "origin", "main", "nbp-safe").returncode == 0


def upstream(env: Env, clone_factory, text: str) -> None:  # type: ignore[no-untyped-def]
    """A collaborator without the tool (no hooks) rewrites ``.nbp-safe`` and pushes."""
    attacker: NbpRepo = clone_factory(env)
    attacker.write(".nbp-safe", text)
    attacker.sh("add", ".nbp-safe")
    assert attacker.raw("commit", "-q", "-m", "tidy patterns").returncode == 0
    assert attacker.raw("push", "-q", "origin", "main").returncode == 0


def pull(repo: NbpRepo) -> None:
    pulled = repo.raw("pull", "-q", "--no-rebase", "origin", "main")
    assert pulled.returncode == 0, pulled.stderr
    assert "!reports/**" in repo.read(".nbp-safe").decode()  # the negations really arrived


def fresh_report(repo: NbpRepo) -> str:
    canary = repo.canaries[0]
    rel = f"reports/{canary}-NEW.csv"
    repo.write(rel, f"brand new {canary} {os.urandom(8).hex()}\n")
    return rel


def test_h1_negation_upstream_unlocked_new_file_is_not_published(
    hooked: Env, clone_factory
) -> None:  # type: ignore[no-untyped-def]
    repo = hooked.repo
    push_everything(hooked)
    upstream(hooked, clone_factory, NEGATION)
    pull(repo)
    rel = fresh_report(repo)
    repo.sh("add", "-A")
    assert rel not in staged(repo), "layer 1 (the exclude block) was defeated by the negation"
    repo.write("notes.txt", "ordinary work\n")
    repo.sh("add", "-A", "notes.txt")
    assert commit(repo, "daily work").returncode == 0
    repo.sh("add", "-f", "--", rel)
    blocked = commit(repo, "force it")
    assert blocked.returncode != 0 and "matches the protected set" in blocked.stderr
    repo.sh("reset", "-q")
    prune_unreachable(repo)  # the blocked `add -f` left its blob behind
    assert repo.raw("push", "-q", "origin", "main").returncode == 0
    assert_remote_clean(hooked)
    repo.assert_no_leak(hooked.bare)


def test_h1_negation_upstream_locked_agent_existing_files_are_not_published(  # type: ignore[no-untyped-def]
    hooked: Env, clone_factory
) -> None:
    repo = hooked.repo
    push_everything(hooked)
    upstream(hooked, clone_factory, NEGATION)
    hooked.agent.stop()  # locked: only the path checks can help
    pull(repo)
    touched = []
    for path in sorted((repo.path / "reports").rglob("*")):
        if path.is_file():
            path.write_bytes(path.read_bytes() + b"regenerated " + os.urandom(6).hex().encode())
            touched.append(path.relative_to(repo.path).as_posix())
    assert touched
    repo.sh("add", "-A")
    assert not any(p.startswith("reports/") for p in staged(repo))
    repo.sh("add", "-f", *touched)
    assert commit(repo, "daily work").returncode != 0
    repo.sh("reset", "-q")
    repo.write("notes.txt", "x\n")
    repo.sh("add", "notes.txt")
    assert commit(repo, "work").returncode == 0
    assert repo.raw("push", "-q", "origin", "main").returncode == 0
    assert_remote_clean(hooked)
    assert "refs/heads/main" in remote_refs(hooked)


def test_h1_the_push_guard_alone_blocks_the_negated_files(hooked: Env, clone_factory) -> None:  # type: ignore[no-untyped-def]
    """Even a local commit that got past pre-commit (``--no-verify``) cannot be pushed."""
    repo = hooked.repo
    push_everything(hooked)
    upstream(hooked, clone_factory, NEGATION)
    pull(repo)
    rel = fresh_report(repo)
    repo.sh("add", "-f", "--", rel)
    assert commit(repo, "bypass", "--no-verify").returncode == 0
    blocked = repo.raw("push", "origin", "main")
    assert blocked.returncode != 0 and "push blocked" in blocked.stderr
    assert_remote_clean(hooked)


def test_h1_the_negation_is_reported_loudly_and_by_doctor(hooked: Env, clone_factory) -> None:  # type: ignore[no-untyped-def]
    repo = hooked.repo
    push_everything(hooked)
    upstream(hooked, clone_factory, NEGATION)
    pulled = repo.raw("pull", "-q", "--no-rebase", "origin", "main")
    assert pulled.returncode == 0
    assert "STILL protects" in pulled.stderr and "negation" in pulled.stderr
    assert "reports" not in pulled.stderr  # a count, never the patterns
    repo_obj, git = discover(repo.path, hooked.git.env)
    assert protect.lost_protection(git, repo_obj) == ["reports/"]
    findings = doctor.run_doctor(git, repo_obj, load_config(git, repo_obj))
    weak = [f for f in findings if "defeated there by a negation" in f.message]
    assert len(weak) == 1 and weak[0].level == doctor.WARN and "reports/" in weak[0].message


def test_a_legitimate_negation_inside_one_version_keeps_working(hooked: Env) -> None:
    """``!data-private/keep-public.txt`` is part of the version it was written in."""
    repo = hooked.repo
    repo.write("data-private/keep-public.txt", "public, edited " + os.urandom(4).hex() + "\n")
    fresh_report(repo)
    repo.sh("add", "-A")
    names = staged(repo)
    assert names == ["data-private/keep-public.txt"]
    repo_obj, git = discover(repo.path, hooked.git.env)
    assert protect.lost_protection(git, repo_obj) == []


def test_a_new_negation_in_a_new_version_is_refused_by_the_commit_guard(hooked: Env) -> None:
    """Adding a negation yourself, in a commit, needs the deliberate override as before; and even
    then the older version keeps protecting until ``unprotect --accept-current``."""
    repo = hooked.repo
    repo.write(".nbp-safe", NEGATION)
    repo.sh("add", ".nbp-safe")
    refused = commit(repo, "negate")
    assert refused.returncode != 0 and "negation" in refused.stderr
    assert commit(repo, "negate", env={guard.ALLOW_UNPROTECT_ENV: "1"}).returncode == 0
    rel = fresh_report(repo)
    repo.sh("add", "-A")
    assert rel not in staged(repo)  # still protected by the older version
    done = repo.cli("unprotect", "--accept-current", "--confirm", "unprotect --accept-current")
    assert done.code == 0, done.err
    repo.sh("add", "-A")
    assert rel in staged(repo)  # now the owner's own decision
    repo.sh("reset", "-q")


def test_accept_current_needs_the_typed_confirmation(hooked: Env, clone_factory) -> None:  # type: ignore[no-untyped-def]
    repo = hooked.repo
    push_everything(hooked)
    upstream(hooked, clone_factory, NEGATION)
    pull(repo)
    assert repo.cli("unprotect", "--accept-current").code != 0
    wrong = repo.cli("unprotect", "--accept-current", "--confirm", "yes")
    assert wrong.code != 0
    both = repo.cli("unprotect", "reports/", "--accept-current")
    assert both.code != 0
    rel = fresh_report(repo)
    repo.sh("add", "-A")
    assert rel not in staged(repo)  # nothing changed
    done = repo.cli("unprotect", "--accept-current", "--confirm", "unprotect --accept-current")
    assert done.code == 0, done.err
    repo.sh("add", "-A")
    assert rel in staged(repo)
    repo.sh("reset", "-q")
    # durable: later hooks (a commit, a seal) do not bring the old version back
    repo.write("notes.txt", "x\n")
    repo.sh("add", "notes.txt")
    assert commit(repo, "work").returncode == 0
    repo_obj, git = discover(repo.path, hooked.git.env)
    assert protect.lost_protection(git, repo_obj) == []
    repo.sh("add", "-A")
    assert rel in staged(repo)
    repo.sh("reset", "-q")


# ------------------------------------------------- unprotect is durable and says what remains


def test_unprotect_is_not_undone_by_a_later_hook_and_reports_head(hooked: Env) -> None:
    repo = hooked.repo
    repo.write(".nbp-safe", "data-private/**\n!data-private/keep-public.txt\n")  # reports/ is gone
    repo_obj, _git = discover(repo.path, hooked.git.env)
    assert protect.sticky_only(repo_obj) == ["reports/"]  # ... but HEAD and the memory have it
    done = repo.cli("unprotect", "reports/", "--confirm", "unprotect reports/")
    assert done.code == 0, done.err
    assert "HEAD" in done.err and "still protected" in done.err  # what remains, and through what
    # a later hook re-reads HEAD (which still has the pattern) and the staged file
    repo.write("notes.txt", "x\n")
    repo.sh("add", "notes.txt", ".nbp-safe")
    refused = commit(repo, "tidy")  # the commit that removes it is the owner's deliberate act
    assert refused.returncode != 0 and "pattern(s) removed" in refused.stderr
    assert commit(repo, "tidy", env={guard.ALLOW_UNPROTECT_ENV: "1"}).returncode == 0
    assert protect.sticky_only(repo_obj) == []  # not brought back from the old HEAD
    assert not any(
        "reports/" in lines
        for _v, t in protect.stored_versions(repo_obj).items()
        for lines in [protect.lines_of(t)]
    )
    rel = fresh_report(repo)
    repo.sh("add", "-A")
    assert rel in staged(repo)
    repo.sh("reset", "-q")


# ----------------------------------------------------- B-N2: a broad pattern from the remote


def test_bn2_star_from_the_remote_cannot_lock_the_pattern_file(hooked: Env, clone_factory) -> None:  # type: ignore[no-untyped-def]
    repo = hooked.repo
    push_everything(hooked)
    upstream(hooked, clone_factory, VERSIONED_PATTERNS + "*\n")
    assert repo.raw("pull", "-q", "--no-rebase", "origin", "main").returncode == 0
    repo.write(".nbp-safe", VERSIONED_PATTERNS)
    repo.sh("add", ".nbp-safe")
    # the removal of `*` is still the deliberate act the guard asks for ...
    assert commit(repo, "fix", env={guard.ALLOW_UNPROTECT_ENV: "1"}).returncode == 0
    # ... and it goes through: .nbp-safe is not a protected path, whatever the patterns say
    repo_obj, git = discover(repo.path, hooked.git.env)
    assert ".nbp-safe" not in protect.tracked_matches(git, repo_obj)
    assert ".nbp-safe" not in protect.list_protected(git, repo_obj)
    done = repo.cli("unprotect", "*", "--confirm", "unprotect *")
    assert done.code == 0, done.err
    repo.write("code.py", "print(1)\n")
    repo.sh("add", "-A")
    assert "code.py" in staged(repo)
    assert commit(repo, "code").returncode == 0


def test_bn2_the_exempt_files_are_skipped_by_the_path_check(hooked: Env) -> None:
    repo = hooked.repo
    repo_obj, git = discover(repo.path, hooked.git.env)
    sources = [b"*\n"]
    changes = [
        guard.Change(".nbp-safe", "100644", "a" * 40, "M"),
        guard.Change(".nbp-safe.config", "100644", "b" * 40, "A"),
        guard.Change("code.py", "100644", "c" * 40, "A"),
    ]
    report = guard.Report()
    flagged = guard._check_changes(git, None, sources, None, changes, report, lambda c: "no")
    assert {path for path, _commit in flagged} == {"code.py"}
    assert repo_obj  # the repository fixture is only needed for the git environment
