# SPDX-License-Identifier: MIT
"""Linked worktrees (regression for the review finding C1).

In a linked worktree git exports ``GIT_DIR=<repo>/.git/worktrees/<name>`` to the hooks. The scratch
repository the matcher creates must not inherit it: that used to re-initialise the REAL repository
(``core.bare=true``) and the failed ``check-ignore`` then read as "nothing protected", so
``git add -f`` + ``git commit`` of a protected file passed the guard."""

from __future__ import annotations

from pathlib import Path

import pytest

from nbp_git_safe import gitutil, protect
from nbp_git_safe.gitutil import Git, GitError
from tests.integration.conftest import Env
from tests.integration.guardkit import assert_remote_clean, remote_refs


def add_worktree(env: Env, tmp_path: Path) -> Path:
    wt = tmp_path / "wt"
    env.repo.sh("worktree", "add", "-q", "-b", "feature", str(wt))
    return wt


def assert_main_repo_intact(env: Env) -> None:
    repo = env.repo
    bare = repo.raw("config", "--get", "core.bare")
    assert bare.stdout.strip() in ("", "false"), "the main repository was re-initialised as bare"
    assert repo.raw("status", "--porcelain").returncode == 0
    assert (repo.path / ".git" / "HEAD").is_file()
    assert "refs/heads/nbp-safe" in repo.sh("for-each-ref", "--format=%(refname)")


def write_secret(env: Env, wt: Path, suffix: str) -> str:
    c = env.repo.canaries[1]
    rel = f"reports/{c}-{suffix}.csv"
    target = wt / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(f"fresh secret {c} {suffix}\n")
    return rel


def test_add_force_and_commit_in_a_linked_worktree_is_blocked(hooked: Env, tmp_path: Path) -> None:
    wt = add_worktree(hooked, tmp_path)
    rel = write_secret(hooked, wt, "force")
    git = hooked.git
    assert git.run_raw("add", "-f", rel, cwd=wt).returncode == 0
    blocked = git.run_raw("commit", "-q", "-m", "wt work", cwd=wt)
    assert blocked.returncode != 0, "the guard failed open in a linked worktree"
    assert "commit blocked" in blocked.stderr and "matches the protected set" in blocked.stderr
    assert_main_repo_intact(hooked)
    assert "reports" not in git.run("ls-tree", "-r", "--name-only", "feature", cwd=wt)


def test_add_all_in_a_linked_worktree_does_not_stage_protected_files(
    hooked: Env, tmp_path: Path
) -> None:
    wt = add_worktree(hooked, tmp_path)
    write_secret(hooked, wt, "all")
    (wt / "code.txt").write_text("ordinary\n")
    git = hooked.git
    assert git.run_raw("add", "-A", cwd=wt).returncode == 0
    staged = git.run("diff", "--cached", "--name-only", cwd=wt).split()
    assert staged == ["code.txt"]
    assert git.run_raw("commit", "-q", "-m", "ordinary", cwd=wt).returncode == 0
    assert_main_repo_intact(hooked)


def test_pre_push_from_a_linked_worktree_blocks_a_bypassed_leak(
    hooked: Env, tmp_path: Path
) -> None:
    wt = add_worktree(hooked, tmp_path)
    rel = write_secret(hooked, wt, "push")
    git = hooked.git
    assert git.run_raw("add", "-f", rel, cwd=wt).returncode == 0
    assert git.run_raw("commit", "-q", "--no-verify", "-m", "bypass", cwd=wt).returncode == 0
    blocked = git.run_raw("push", "origin", "feature", cwd=wt)
    assert blocked.returncode != 0 and "push blocked" in blocked.stderr
    assert "refs/heads/feature" not in remote_refs(hooked)
    assert_remote_clean(hooked)
    assert_main_repo_intact(hooked)


def test_pre_push_from_a_linked_worktree_passes_for_ordinary_work(
    hooked: Env, tmp_path: Path
) -> None:
    wt = add_worktree(hooked, tmp_path)
    (wt / "code.txt").write_text("ordinary\n")
    git = hooked.git
    git.run("add", "code.txt", cwd=wt)
    assert git.run_raw("commit", "-q", "-m", "ordinary", cwd=wt).returncode == 0
    pushed = git.run_raw("push", "origin", "feature", cwd=wt)
    assert pushed.returncode == 0, pushed.stderr
    assert_main_repo_intact(hooked)


# ------------------------------------------------------------------------ unit level


LOCAL_VARS = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_PREFIX",
    "GIT_CEILING_DIRECTORIES",
)


def test_clean_env_drops_every_repository_local_variable() -> None:
    env = {name: "x" for name in LOCAL_VARS}
    env.update({"GIT_PUSH_OPTION_COUNT": "1", "GIT_PUSH_OPTION_0": "a"})
    env.update({"GIT_CONFIG_GLOBAL": "/dev/null", "PATH": "p", "GIT_AUTHOR_NAME": "n"})
    cleaned = gitutil.clean_env(env)
    assert cleaned == {"GIT_CONFIG_GLOBAL": "/dev/null", "PATH": "p", "GIT_AUTHOR_NAME": "n"}
    assert "GIT_DIR" in env  # the input is not modified


def test_the_matcher_ignores_a_hostile_git_dir(hooked: Env) -> None:
    repo = hooked.repo
    victim = repo.path / ".git"
    head_before = (victim / "HEAD").read_bytes()
    env = {**hooked.git.env, "GIT_DIR": str(victim), "GIT_WORK_TREE": str(repo.path)}
    git = Git(repo.path, env)
    found = protect.match_paths_texts(git, [b"reports/\n"], ["reports/x.csv", "other.txt"])
    assert found == {"reports/x.csv"}
    assert (victim / "HEAD").read_bytes() == head_before
    assert hooked.repo.raw("config", "--get", "core.bare").stdout.strip() in ("", "false")


@pytest.mark.parametrize("code", [128, 2, 255])
def test_a_failing_matcher_fails_closed(monkeypatch: pytest.MonkeyPatch, code: int, hooked) -> None:  # type: ignore[no-untyped-def]
    real = Git.run_status

    def fake(self: Git, *args: str, **kwargs: object):  # type: ignore[no-untyped-def]
        if "check-ignore" in args:
            return code, b"", b"fatal: simulated"
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Git, "run_status", fake)
    git = Git(hooked.repo.path, hooked.git.env)
    with pytest.raises(GitError):
        protect.match_paths_texts(git, [b"reports/\n"], ["reports/x.csv"])


def test_pattern_lookup_distinguishes_absent_from_broken(
    monkeypatch: pytest.MonkeyPatch, hooked: Env
) -> None:
    git = Git(hooked.repo.path, hooked.git.env)
    assert gitutil.optional_blob(git, ".nbp-safe", "HEAD") is not None
    assert gitutil.optional_blob(git, "no-such-file", "HEAD") is None
    assert gitutil.optional_blob(git, "no-such-file") is None
    real = Git.run_status

    def broken(self: Git, *args: str, **kwargs: object):  # type: ignore[no-untyped-def]
        if args and args[0] in ("ls-tree", "ls-files"):
            return 128, b"", b"fatal"
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Git, "run_status", broken)
    with pytest.raises(GitError):
        gitutil.optional_blob(git, ".nbp-safe", "HEAD")
    with pytest.raises(GitError):
        gitutil.optional_blob(git, ".nbp-safe")


def test_a_failing_git_config_is_not_an_empty_configuration(
    monkeypatch: pytest.MonkeyPatch, hooked: Env
) -> None:
    from nbp_git_safe import config as config_mod

    real = Git.run_status

    def broken(self: Git, *args: str, **kwargs: object):  # type: ignore[no-untyped-def]
        if args[:2] == ("config", "--local"):
            return 128, b"", b"fatal"
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Git, "run_status", broken)
    git = Git(hooked.repo.path, hooked.git.env)
    with pytest.raises(GitError):
        config_mod._local_layer(git)
