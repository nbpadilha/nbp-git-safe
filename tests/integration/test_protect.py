# SPDX-License-Identifier: MIT
"""Protected-set resolution with real git: ``**``, negation, directories, spaces, accents, the
local pattern file, and agreement between the two matching methods."""

from __future__ import annotations

from pathlib import Path

import pytest

from nbp_git_safe import protect
from nbp_git_safe.gitutil import Git, Repo, discover
from tests.conftest import IsolatedGit

PATTERNS = """\
# generic patterns only
reports/
**/secret-*.txt
build/**
!build/keep.txt
/rootonly.txt
*.xlsx
docs/*.pdf
data/**/z.dat
relatório acentuado/
espaço dir/**

"""

PROTECTED = {
    "reports/a.csv",
    "reports/deep/er/b.csv",
    "x/y/secret-1.txt",
    "secret-top.txt",
    "build/out.bin",
    "build/sub/x.bin",
    "rootonly.txt",
    "a.xlsx",
    "d/e.xlsx",
    "docs/a.pdf",
    "data/z.dat",
    "data/a/b/z.dat",
    "relatório acentuado/f.txt",
    "espaço dir/a b.txt",
    "espaço dir/sub/ç.txt",
    "extra-local/x.txt",
}
UNPROTECTED = {
    "secretary.txt",
    "build/keep.txt",
    "sub/rootonly.txt",
    "a.xlsx.bak",
    "docs/sub/a.pdf",
    "data/zz.dat",
    "other.txt",
    "other-ignored.log",
    "keep/me.txt",
}


@pytest.fixture
def tree(isolated_git: IsolatedGit, tmp_path: Path) -> tuple[Repo, Git]:
    root = isolated_git.init(tmp_path / "r")
    (root / ".nbp-safe").write_text(PATTERNS, encoding="utf-8")
    (root / ".gitignore").write_text("*.log\n*.bak\n", encoding="utf-8")
    for rel in sorted(PROTECTED | UNPROTECTED):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x", encoding="utf-8")
    (root / "reports" / "x.nbp-tmp").write_text("temp")
    (root / "reports" / "a.csv.nbp-theirs").write_text("theirs")
    info = root / ".git" / "info"
    info.mkdir(exist_ok=True)
    (info / "nbp-safe").write_text("extra-local/\n!reports/\n", encoding="utf-8")
    repo, git = discover(root, isolated_git.env)
    return repo, git


def test_list_protected_covers_the_tricky_patterns(tree: tuple[Repo, Git]) -> None:
    repo, git = tree
    found = set(protect.list_protected(git, repo))
    assert found == PROTECTED  # also: nbp-tmp / nbp-theirs files are never in the set


def test_local_negation_cannot_unprotect_a_versioned_pattern(tree: tuple[Repo, Git]) -> None:
    repo, git = tree
    assert "reports/a.csv" in protect.list_protected(git, repo)  # despite `!reports/` locally


def test_untracked_only_and_tracked_violations_are_reported(
    tree: tuple[Repo, Git], isolated_git: IsolatedGit
) -> None:
    repo, git = tree
    isolated_git.run("add", "-f", "reports/a.csv", cwd=repo.toplevel)
    assert "reports/a.csv" not in protect.list_protected(git, repo)
    assert protect.tracked_matches(git, repo) == ["reports/a.csv"]
    assert protect.tracked_files(git) == ["reports/a.csv"]


def test_both_matching_methods_agree(tree: tuple[Repo, Git]) -> None:
    repo, git = tree
    candidates = sorted(PROTECTED | UNPROTECTED)
    assert protect.match_paths(git, repo, candidates) == PROTECTED
    # paths that do not exist at all (what an index from the vault looks like)
    hypothetical = {
        "reports/never-seen.csv": True,
        "q/secret-9.txt": True,
        "build/ghost.bin": True,
        "build/keep.txt": False,
        "ghost.xlsx": True,
        "docs/ghost/x.pdf": False,
        "totally/other.txt": False,
        "extra-local/ghost": True,
        "other-ignored.log": False,
    }
    got = protect.match_paths(git, repo, list(hypothetical))
    assert got == {p for p, expected in hypothetical.items() if expected}


def test_users_gitignore_and_global_excludes_do_not_leak_into_matching(
    tree: tuple[Repo, Git], tmp_path: Path, isolated_git: IsolatedGit
) -> None:
    repo, git = tree
    global_ignore = tmp_path / "global-ignore"
    global_ignore.write_text("global-only.txt\n")
    isolated_git.run(
        "config", "--local", "core.excludesFile", global_ignore.as_posix(), cwd=repo.toplevel
    )
    assert protect.match_paths(git, repo, ["x.log", "global-only.txt", "foo.bak"]) == set()


def test_no_pattern_files_means_empty_set(isolated_git: IsolatedGit, tmp_path: Path) -> None:
    root = isolated_git.init(tmp_path / "bare-tree")
    (root / "f.txt").write_text("x")
    repo, git = discover(root, isolated_git.env)
    assert protect.pattern_texts(repo) == []
    assert protect.list_protected(git, repo) == []
    assert protect.match_paths(git, repo, ["f.txt"]) == set()
    assert protect.match_paths(git, repo, []) == set()


def test_read_patterns_drops_blanks_comments_and_our_markers(tmp_path: Path) -> None:
    file = tmp_path / "p"
    lines = ["# c", "", "keep-me", protect.BLOCK_BEGIN, "  ", "!neg", protect.BLOCK_END, ""]
    file.write_bytes("\r\n".join(lines).encode())
    assert protect.read_patterns(file) == ["keep-me", "!neg"]


def test_a_pattern_file_cannot_smuggle_the_block_markers(
    isolated_git: IsolatedGit, tmp_path: Path
) -> None:
    root = isolated_git.init(tmp_path / "m")
    (root / ".nbp-safe").write_text(f"a/\n{protect.BLOCK_END}\nb/\n{protect.BLOCK_BEGIN}\n")
    repo, _ = discover(root, isolated_git.env)
    protect.install_exclude_block(repo)
    text = protect.exclude_path(repo).read_text()
    assert text.count(protect.BLOCK_BEGIN) == 1 and text.count(protect.BLOCK_END) == 1
    assert "a/" in text and "b/" in text


def test_nested_repositories_are_ignored(isolated_git: IsolatedGit, tmp_path: Path) -> None:
    root = isolated_git.init(tmp_path / "outer")
    (root / ".nbp-safe").write_text("inner/\n")
    isolated_git.init(root / "inner")
    (root / "inner" / "f.txt").write_text("x")
    repo, git = discover(root, isolated_git.env)
    assert protect.list_protected(git, repo) == []
