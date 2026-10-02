# SPDX-License-Identifier: MIT
from __future__ import annotations

import contextlib
import io
from pathlib import Path

import pytest

from nbp_git_safe import __version__, protect
from nbp_git_safe.cli import main
from nbp_git_safe.gitutil import GitError, discover, split_z
from nbp_git_safe.statcache import StatCache, path_key_input
from tests.conftest import IsolatedGit
from tests.helpers import NbpRepo


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def test_version_flag_and_no_arguments() -> None:
    assert run("--version")[0] == 0
    code, out, _ = run()
    assert code == 0 and out == f"nbp-git-safe {__version__}\n"


def test_usage_errors_return_2() -> None:
    assert run("no-such-command")[0] == 2
    assert run("log")[0] == 2  # missing path
    assert run("seal", "--on-missing", "explode")[0] == 2


def test_outside_a_repository(tmp_path: Path, isolated_git: IsolatedGit) -> None:
    code, _, err = run("-C", str(tmp_path), "status")
    assert code == 1 and "not inside a git work tree" in err


def test_init_installs_exclude_block_idempotently(make_repo) -> None:  # type: ignore[no-untyped-def]
    repo: NbpRepo = make_repo()
    first = repo.cli("init")
    assert first.code == 0 and "installed" in first.err
    assert "already up to date" in repo.cli("init").err
    assert "reports/" in protect.exclude_path(discover(repo.path, repo.git.env)[0]).read_text()
    (repo.path / ".nbp-safe").unlink()
    assert "no .nbp-safe file yet" in repo.cli("init").err


def test_unknown_error_paths_use_exit_code_1(make_repo) -> None:  # type: ignore[no-untyped-def]
    repo: NbpRepo = make_repo()
    repo.set_config("nbp-safe.ttl", "forever")
    result = repo.cli("unlock")
    assert result.code == 1 and "ttl" in result.err


def test_paths_outside_the_repository_are_refused(make_repo) -> None:  # type: ignore[no-untyped-def]
    repo: NbpRepo = make_repo()
    agent = repo.unlock_in_thread()
    try:
        result = repo.cli("log", "../../elsewhere")
        assert result.code == 1 and "outside the repository" in result.err
    finally:
        agent.stop()


def test_relative_paths_are_resolved_from_the_working_directory(make_repo) -> None:  # type: ignore[no-untyped-def]
    repo: NbpRepo = make_repo()
    repo.write("reports/a.txt", "one")
    agent = repo.unlock_in_thread()
    try:
        assert repo.cli("seal").code == 0
        assert repo.cli("log", "reports/a.txt").code == 0
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["-C", str(repo.path / "reports"), "log", "a.txt"])
        assert code == 0 and out.getvalue().count("\n") == 1
    finally:
        agent.stop()


def test_gitutil_helpers(isolated_git: IsolatedGit, tmp_path: Path) -> None:
    root = isolated_git.init(tmp_path / "g")
    repo, git = discover(root, isolated_git.env)
    assert repo.state_dir == repo.common_dir / "nbp-safe"
    assert split_z(b"a\0b\0") == ["a", "b"]
    with pytest.raises(GitError):
        git.run("not-a-git-command")
    assert git.try_run("not-a-git-command") is None
    assert git.text("rev-parse", "--git-dir").strip() == ".git"


def test_statcache_rules(tmp_path: Path) -> None:
    path = tmp_path / "sc"
    now = 1_000_000_000_000_000_000
    old = now - 10_000_000_000
    cache = StatCache(path, "aa")
    cache.put("k1", 5, old, "mac1", now)
    cache.put("k2", 5, now - 1, "mac2", now)  # racily clean: not cached
    cache.save()
    reloaded = StatCache(path, "aa")
    assert reloaded.get("k1", 5, old) == "mac1"
    assert reloaded.get("k1", 6, old) is None  # size differs
    assert reloaded.get("k1", 5, old + 1) is None  # mtime differs
    assert reloaded.get("k2", 5, now - 1) is None
    assert StatCache(path, "bb").get("k1", 5, old) is None  # different key: discarded
    path.write_bytes(b"garbage")
    assert StatCache(path, "aa").get("k1", 5, old) is None
    path.write_bytes(b'{"v": 1, "key_id": "aa", "entries": {"k": [1, 2]}}')
    assert StatCache(path, "aa").get("k", 1, 2) is None  # malformed entry
    assert path_key_input("a/b").startswith(b"nbp-git-safe/path\x00")
    # a stale entry is dropped on save (only what was used this run survives)
    cache2 = StatCache(tmp_path / "sc2", "aa")
    cache2.put("keep", 1, old, "m", now)
    cache2.save()
    again = StatCache(tmp_path / "sc2", "aa")
    again.save()
    assert StatCache(tmp_path / "sc2", "aa").get("keep", 1, old) is None
