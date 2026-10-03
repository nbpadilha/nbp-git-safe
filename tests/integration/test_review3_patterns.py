# SPDX-License-Identifier: MIT
"""Third adversarial review, pattern files: M-N1 (the tool's reading of ``.nbp-safe`` differs from
git's), B-N2 (marker injection in the exclude block), B-N3 (``.nbp-safe`` as a link), B-N4 (a
positive its own version negates and re-adds), B-N5 (fail open on an unreadable memory) and B-N6
(no limit on the memory of versions). Fake data only; random canaries for anything that must not
leak."""

from __future__ import annotations

import os
import random
import secrets
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from nbp_git_safe import guard, plainfile, protect
from nbp_git_safe.config import ConfigError, load_config
from nbp_git_safe.gitutil import Git, GitError, Repo, discover
from tests.conftest import IsolatedGit

BOM = b"\xef\xbb\xbf"


def new_repo(isolated_git: IsolatedGit, tmp_path: Path) -> tuple[Path, Repo, Git]:
    root = isolated_git.init(tmp_path / "unit")
    repo, git = discover(root, isolated_git.env)
    return root, repo, git


# ---------------------------------------------------------------------------- M-N1: the reading


def test_one_cr_is_removed_not_all_of_them() -> None:
    assert protect.lines_of(b"reports/\r\n") == ["reports/"]
    assert protect.lines_of(b"reports/\r\r\n") == ["reports/\r"]  # git: a different pattern
    assert protect.lines_of(b"reports/\r\r\r\n") == ["reports/\r\r"]
    assert protect.lines_of(b"reports/\r") == ["reports/"]  # last line without a newline


def test_bom_trailing_spaces_tabs_blanks_and_comments_are_read_like_git() -> None:
    assert protect.lines_of(BOM + b"reports/\n") == ["reports/"]
    assert protect.lines_of(BOM + b"# comment\nreports/\n") == ["reports/"]
    assert protect.lines_of(b"a/  \nb/\\ \nc/\\\\ \n") == ["a/", "b/\\ ", "c/\\\\"]  # escaped kept
    assert protect.lines_of(b"a/\t\n") == ["a/\t"]  # a tab is an ordinary character
    assert protect.lines_of(b"\t\n") == ["\t"]  # ... so a line of one tab is a pattern
    assert protect.lines_of(b"   \n\n \r\n# x\n  # y\n") == ["  # y"]  # leading blank: a pattern
    assert protect.lines_of(b"a/\\") == ["a/\\"]  # a lone backslash at the end stays
    assert protect.lines_of(b"a/\x00junk\n") == ["a/"]  # a C string stops at NUL
    assert protect.lines_of(BOM + BOM + b"#x\n") == [chr(0xFEFF) + "#x"]  # only one BOM goes


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"reports/\r\r\n!reports/keep\r\n",
        BOM + b"a/\n",
        b"a/ \r \n",
        b"x\r\r\n\r\r\n\n\r\n",
        BOM + BOM + b"#x\n",
        b"a/\r\r",
        b"\t\n \t\n",
    ],
)
def test_normalization_is_idempotent_and_keeps_the_lines(raw: bytes) -> None:
    once = protect.normalize_pattern_text(raw)
    assert protect.normalize_pattern_text(once) == once
    assert protect.lines_of(once) == protect.lines_of(raw)
    assert guard.pattern_lines(raw) == protect.lines_of(raw)  # one implementation for everyone
    assert protect.normalize(raw) == once


def test_cr_padding_does_not_prune_the_version_that_protects(
    isolated_git: IsolatedGit, tmp_path: Path
) -> None:
    """M-N1: ``reports/\\n`` replaced by ``reports/\\r\\r\\n`` used to read as the same version, so
    the old one was pruned and git (which sees the pattern ``reports/<CR>``) matched nothing."""
    root, repo, git = new_repo(isolated_git, tmp_path)
    (root / ".nbp-safe").write_bytes(b"reports/\n")
    protect.install_exclude_block(repo)
    (root / ".nbp-safe").write_bytes(b"reports/\r\r\n")
    (root / "reports").mkdir()
    (root / "reports" / "a.csv").write_text("fake")
    assert len(protect.pattern_texts(repo)) == 2  # the old version stays: it is not the same
    assert protect.list_protected(git, repo) == ["reports/a.csv"]
    assert protect.match_paths(git, repo, ["reports/a.csv", "other.txt"]) == {"reports/a.csv"}
    assert "reports/" in protect.lost_protection(git, repo)  # ... and the owner is told
    assert "reports/" in protect.block_lines(repo)
    isolated_git.run("add", "-A", cwd=root)
    isolated_git.run("add", "-f", "reports/a.csv", cwd=root)  # now tracked despite the pattern
    assert protect.tracked_matches(git, repo) == ["reports/a.csv"]


@pytest.mark.parametrize("mode", ["list_protected", "match_paths", "tracked_matches"])
def test_a_text_that_only_git_reads_differently_is_still_evaluated_as_git_does(
    isolated_git: IsolatedGit, tmp_path: Path, mode: str
) -> None:
    root, repo, git = new_repo(isolated_git, tmp_path)
    (root / ".nbp-safe").write_bytes(BOM + b"# c\r\n  \r\nkeys/ \r\n")  # BOM, blank, trailing space
    (root / "keys").mkdir()
    (root / "keys" / "id").write_text("fake")
    if mode == "list_protected":
        assert protect.list_protected(git, repo) == ["keys/id"]
    elif mode == "match_paths":
        assert protect.match_paths(git, repo, ["keys/id"]) == {"keys/id"}
    else:
        isolated_git.run("add", "-f", "keys/id", cwd=root)
        assert protect.tracked_matches(git, repo) == ["keys/id"]


FRAGMENTS = [
    "reports/",
    "reports/**",
    "!reports/keep.csv",
    "a/*",
    "a/**/c.txt",
    "*.txt",
    "!b",
    "b",
    "c/",
    "/c",
    "**/d",
    "keys/",
    "x",
    "x\\ ",
    "\\#h",
    "\\!n",
    "tab",
    "#comment",
    "# reports/",
    "reports/\r",
    "[ab]/e",
]
ENDINGS = ["\n", "\n", "\n", "\r\n", "\r\r\n", " \n", "  \r\n", "\t\n", " \r\r\n", "\r\n\n", "\n\n"]
PATHS = [
    "reports/a.csv",
    "reports/keep.csv",
    "reports",
    "reports/",
    "reports\r/a.csv",
    "reports\r",
    "a/x",
    "a/b/c.txt",
    "b",
    "b/y",
    "c/z",
    "c",
    "d/q",
    "x",
    "x ",
    "x\t",
    "tab",
    "tab\t",
    "tab ",
    "#h",
    "#comment",
    "!n",
    "keys/id",
    "a/e",
    "e",
    "f.txt",
    "g/f.txt",
]


def random_pattern_text(rng: random.Random) -> bytes:
    parts = []
    for _ in range(rng.randint(1, 6)):
        atom = rng.choice(FRAGMENTS)
        if rng.random() < 0.04:
            atom += "\0junk"
        parts.append(atom + rng.choice(ENDINGS))
    text = "".join(parts)
    if rng.random() < 0.15:
        text = text.rstrip("\r\n \t")  # the last line has no line end
    data = text.encode()
    return BOM + data if rng.random() < 0.2 else data


def raw_git_matches(
    isolated_git: IsolatedGit, scratch: Path, texts: list[bytes], paths: list[str]
) -> list[set[str]]:
    """What git itself says about the RAW texts: one ``.gitignore`` per directory ``v<n>/``."""
    payload = b""
    for number, text in enumerate(texts):
        directory = scratch / f"v{number}"
        directory.mkdir(exist_ok=True)
        (directory / ".gitignore").write_bytes(text)
        payload += b"".join(f"v{number}/{p}".encode() + b"\0" for p in paths)
    empty = scratch / "empty"
    empty.write_bytes(b"")
    proc = subprocess.run(
        [
            "git",
            "-c",
            f"core.excludesFile={empty.as_posix()}",
            "check-ignore",
            "--no-index",
            "-z",
            "--stdin",
        ],
        input=payload,
        cwd=scratch,
        env=isolated_git.env,
        capture_output=True,
        check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    out: list[set[str]] = [set() for _ in texts]
    for item in proc.stdout.decode().split("\0"):
        if item:
            number, _, rest = item.partition("/")
            out[int(number[1:])].add(rest)
    return out


def test_normalized_text_is_evaluated_by_git_like_the_raw_text(
    isolated_git: IsolatedGit, tmp_path: Path
) -> None:
    """Property test (fixed seed, 500 cases): evaluating the NORMALIZED text gives exactly what
    git gives for the raw file, for texts with CR padding, BOM, trailing spaces, tabs, NUL, blank
    and comment lines. A few cases are also checked against git's own ``core.excludesFile``."""
    root, _repo, git = new_repo(isolated_git, tmp_path)
    rng = random.Random(20261003)  # noqa: S311 - a fixed seed, not a secret
    texts = [random_pattern_text(rng) for _ in range(500)]
    for start in range(0, len(texts), 50):
        batch = texts[start : start + 50]
        scratch = tmp_path / f"fuzz{start}"
        scratch.mkdir()
        isolated_git.run("init", "-q", str(scratch))
        want = raw_git_matches(isolated_git, scratch, batch, PATHS)
        got = protect.match_paths_each(git, batch, PATHS, base=tmp_path / "scratch-base")
        for text, w, g in zip(batch, want, got, strict=True):
            assert w == g, (text, w ^ g)
            normalized = protect.normalize_pattern_text(text)
            assert protect.normalize_pattern_text(normalized) == normalized
            assert protect.lines_of(normalized) == protect.lines_of(text)
    # the per-directory trick itself against git's own reading of a pattern file
    for number, text in enumerate(texts[:40]):
        pf = tmp_path / f"native-{number}"
        pf.write_bytes(text)
        proc = subprocess.run(
            [
                "git",
                "-c",
                f"core.excludesFile={pf.as_posix()}",
                "check-ignore",
                "--no-index",
                "-z",
                "--stdin",
            ],
            input=b"".join(p.encode() + b"\0" for p in PATHS),
            cwd=root,
            env=isolated_git.env,
            capture_output=True,
            check=False,
        )
        native = {x for x in proc.stdout.decode().split("\0") if x}
        assert native == protect.match_paths_each(git, [text], PATHS)[0], text


def test_odd_paths_are_refused_not_evaluated_below_the_wrong_directory(
    isolated_git: IsolatedGit, tmp_path: Path
) -> None:
    _root, _repo, git = new_repo(isolated_git, tmp_path)
    for bad in ("../x", "a/../b", "./a", "/abs", "a//b", "a\\..\\b", ""):
        with pytest.raises(GitError, match="clean relative path"):
            protect.match_paths_texts(git, [b"x\n"], [bad])
    assert protect.match_paths_texts(git, [b"d/\n"], ["d/", "d/f"]) == {"d/", "d/f"}


# ------------------------------------------------------------------------ B-N2: marker injection


def exclude_lines(repo: Repo) -> list[str]:
    return protect.exclude_path(repo).read_text().splitlines()


@pytest.mark.parametrize("marker", [protect.BLOCK_END, protect.BLOCK_BEGIN])
def test_a_pattern_that_contains_a_marker_does_not_grow_the_block(
    isolated_git: IsolatedGit, tmp_path: Path, marker: str
) -> None:
    root, repo, _git = new_repo(isolated_git, tmp_path)
    (root / ".nbp-safe").write_text(f"reports/\nx{marker}\nsecret/\n", newline="\n")
    protect.exclude_path(repo).write_text("# my own line\n", newline="\n")
    snapshots = []
    for _ in range(5):
        protect.install_exclude_block(repo)
        snapshots.append(protect.exclude_path(repo).read_text())
        assert protect.exclude_block_current(repo)
    assert len(set(snapshots)) == 1  # N installations = one block, nothing grows
    lines = exclude_lines(repo)
    assert lines.count(protect.BLOCK_BEGIN) == 1 and lines.count(protect.BLOCK_END) == 1
    assert lines[0] == "# my own line"
    assert "secret/" in lines  # the pattern after the odd one is still protected
    assert not any(line != marker and marker in line for line in lines)  # escaped, not raw
    ignored = isolated_git.run_raw("check-ignore", "secret/a", cwd=root)
    assert ignored.returncode == 0
    assert protect.remove_exclude_block(repo)
    assert exclude_lines(repo) == ["# my own line"]  # no residue
    assert any("marker" in w for w in guard.lint_patterns((root / ".nbp-safe").read_bytes()))


def test_the_escaped_marker_pattern_still_means_the_same(
    isolated_git: IsolatedGit, tmp_path: Path
) -> None:
    root, repo, _git = new_repo(isolated_git, tmp_path)
    odd = "weird" + protect.BLOCK_END  # a file name with that text in it
    (root / ".nbp-safe").write_text(odd + "\n", newline="\n")
    protect.install_exclude_block(repo)
    assert isolated_git.run_raw("check-ignore", "--", odd, cwd=root).returncode == 0


def test_markers_with_crlf_line_ends_are_still_found(
    isolated_git: IsolatedGit, tmp_path: Path
) -> None:
    root, repo, _git = new_repo(isolated_git, tmp_path)
    (root / ".nbp-safe").write_text("reports/\n", newline="\n")
    protect.install_exclude_block(repo)
    path = protect.exclude_path(repo)
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))  # an editor converted the file
    protect.install_exclude_block(repo)
    assert path.read_bytes().count(protect.BLOCK_BEGIN.encode()) == 1


# ---------------------------------------------------------------- B-N4: positive, negated, again


def test_a_positive_that_its_version_negates_and_adds_again_stays_in_the_block(
    isolated_git: IsolatedGit, tmp_path: Path
) -> None:
    root, repo, git = new_repo(isolated_git, tmp_path)
    (root / ".nbp-safe").write_text("keys/\n!keys/\nkeys/\n", newline="\n")
    protect.install_exclude_block(repo)
    (root / ".nbp-safe").write_text("other/\n", newline="\n")  # a pull removed the three lines
    protect.install_exclude_block(repo)
    assert "keys/" in protect.block_lines(repo)
    (root / "keys").mkdir()
    (root / "keys" / "id_x").write_text("PRIVATE fake")
    isolated_git.run("add", "-A", cwd=root)
    assert "keys/id_x" not in isolated_git.run("ls-files", cwd=root)  # `git add -A` skipped it
    assert protect.list_protected(git, repo) == ["keys/id_x"]


def test_a_positive_whose_last_occurrence_is_negated_is_left_out(
    isolated_git: IsolatedGit, tmp_path: Path
) -> None:
    root, repo, _git = new_repo(isolated_git, tmp_path)
    (root / ".nbp-safe").write_text("keys/\n!keys/\nother/\n", newline="\n")
    protect.install_exclude_block(repo)
    (root / ".nbp-safe").write_text("else/\n", newline="\n")
    assert "keys/" not in protect.block_lines(repo)  # that version itself did not protect it
    assert "other/" in protect.block_lines(repo)


# --------------------------------------------------------------------------- B-N3: link as file


def try_symlink(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:  # Windows needs a privilege or developer mode
        pytest.skip(f"cannot create a symbolic link here ({exc})")


def test_nbp_safe_as_a_symlink_is_refused_and_nothing_is_copied(
    isolated_git: IsolatedGit, tmp_path: Path
) -> None:
    root, repo, git = new_repo(isolated_git, tmp_path)
    secret = "OUTSIDE-" + secrets.token_hex(8)
    outside = tmp_path / "outside-secret.txt"
    outside.write_text(secret + "/\n", newline="\n")
    exclude_before = (
        protect.exclude_path(repo).read_text() if protect.exclude_path(repo).exists() else ""
    )
    try_symlink(root / ".nbp-safe", outside)
    for call in (
        lambda: protect.record_versions(repo),
        lambda: protect.install_exclude_block(repo),
        lambda: protect.pattern_texts(repo),
        lambda: protect.list_protected(git, repo),
        lambda: guard.pattern_sources(git, repo),
    ):
        with pytest.raises(plainfile.UnsafeFileError, match="symbolic link"):
            call()
    assert not protect.versions_dir(repo).exists() or not list(protect.versions_dir(repo).iterdir())
    exclude_after = (
        protect.exclude_path(repo).read_text() if protect.exclude_path(repo).exists() else ""
    )
    assert exclude_after == exclude_before and secret not in exclude_after


def test_nbp_safe_config_as_a_symlink_is_refused(isolated_git: IsolatedGit, tmp_path: Path) -> None:
    root, repo, git = new_repo(isolated_git, tmp_path)
    outside = tmp_path / "outside.cfg"
    outside.write_text("[pad]\n\tbucket = 4096\n", newline="\n")
    try_symlink(root / ".nbp-safe.config", outside)
    with pytest.raises(ConfigError, match="symbolic link"):
        load_config(git, repo)


@pytest.mark.skipif(sys.platform != "win32", reason="junctions exist on Windows only")
def test_a_junction_in_place_of_nbp_safe_is_refused(
    isolated_git: IsolatedGit, tmp_path: Path
) -> None:
    root, repo, _git = new_repo(isolated_git, tmp_path)
    target = tmp_path / "somedir"
    target.mkdir()
    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(root / ".nbp-safe"), str(target)],
        capture_output=True,
        check=False,
    )
    if made.returncode != 0:
        pytest.skip("cannot create a junction here")
    with pytest.raises(plainfile.UnsafeFileError, match=r"reparse point|not a regular"):
        protect.record_versions(repo)


def test_a_directory_or_an_oversized_file_is_refused_without_reading(
    isolated_git: IsolatedGit, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, repo, _git = new_repo(isolated_git, tmp_path)
    (root / ".nbp-safe").mkdir()
    with pytest.raises(plainfile.UnsafeFileError, match="not a regular file"):
        protect.record_versions(repo)
    (root / ".nbp-safe").rmdir()
    (root / ".nbp-safe").write_bytes(b"x" * (plainfile.MAX_CONFIG_FILE_BYTES + 1))

    def no_open(*_a: object, **_k: object) -> None:
        raise AssertionError("an oversized file must be refused before it is opened")

    monkeypatch.setattr(os, "open", no_open)
    with pytest.raises(plainfile.UnsafeFileError, match="larger than"):
        protect.pattern_texts(repo)


def test_reparse_points_and_fifos_are_recognised_by_their_stat() -> None:
    reparse = SimpleNamespace(st_mode=0o100644, st_size=3, st_file_attributes=0x400)
    assert "reparse" in str(plainfile._problem(reparse, 100))  # type: ignore[arg-type]
    link = SimpleNamespace(st_mode=0o120777, st_size=3)
    assert "symbolic link" in str(plainfile._problem(link, 100))  # type: ignore[arg-type]
    fifo = SimpleNamespace(st_mode=0o010644, st_size=0)
    assert "not a regular" in str(plainfile._problem(fifo, 100))  # type: ignore[arg-type]
    plain = SimpleNamespace(st_mode=0o100644, st_size=3)
    assert plainfile._problem(plain, 100) is None  # type: ignore[arg-type]


@pytest.mark.skipif(sys.platform == "win32", reason="named pipes via mkfifo are POSIX only")
def test_a_fifo_does_not_hang_the_hooks(isolated_git: IsolatedGit, tmp_path: Path) -> None:
    root, repo, _git = new_repo(isolated_git, tmp_path)
    os.mkfifo(root / ".nbp-safe")
    with pytest.raises(plainfile.UnsafeFileError, match="not a regular"):
        protect.pattern_texts(repo)


def test_plain_files_are_read_and_missing_ones_are_none(tmp_path: Path) -> None:
    assert plainfile.read_plain_file(tmp_path / "absent") is None
    (tmp_path / "ok").write_bytes(b"data")
    assert plainfile.read_plain_file(tmp_path / "ok") == b"data"
    (tmp_path / "big").write_bytes(b"123456")
    with pytest.raises(plainfile.UnsafeFileError):
        plainfile.read_plain_file(tmp_path / "big", max_size=5)


# ------------------------------------------------------------------ B-N5: unreadable memory


def test_an_unreadable_version_makes_everything_fail_closed(
    isolated_git: IsolatedGit, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, repo, git = new_repo(isolated_git, tmp_path)
    (root / ".nbp-safe").write_text("a/\n", newline="\n")
    protect.record_versions(repo)
    (root / ".nbp-safe").write_text("b/\n", newline="\n")
    protect.record_versions(repo)
    assert len(protect.stored_versions(repo)) == 2
    exclude_before = (
        protect.exclude_path(repo).read_text() if protect.exclude_path(repo).exists() else ""
    )
    real = Path.read_bytes
    broken = next(iter(protect.stored_versions(repo)))

    def flaky(self: Path) -> bytes:
        if self.name == broken:
            raise PermissionError(13, "Permission denied")
        return real(self)

    with monkeypatch.context() as patched:
        patched.setattr(Path, "read_bytes", flaky)
        for call in (
            lambda: protect.stored_versions(repo),
            lambda: protect.pattern_texts(repo),
            lambda: protect.block_lines(repo),
            lambda: protect.install_exclude_block(repo),
            lambda: protect.list_protected(git, repo),
            lambda: protect.match_paths(git, repo, ["a/x"]),
            lambda: guard.pattern_sources(git, repo),
        ):
            with pytest.raises(protect.PatternMemoryError, match="cannot be read"):
                call()
    exclude_after = (
        protect.exclude_path(repo).read_text() if protect.exclude_path(repo).exists() else ""
    )
    assert exclude_after == exclude_before  # the block was not rewritten without that version


def test_an_unlistable_memory_directory_fails_closed(
    isolated_git: IsolatedGit, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, repo, _git = new_repo(isolated_git, tmp_path)
    (root / ".nbp-safe").write_text("a/\n", newline="\n")
    protect.record_versions(repo)

    def denied(_path: object) -> list[str]:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(os, "listdir", denied)
    with pytest.raises(protect.PatternMemoryError, match="cannot be listed"):
        protect.stored_versions(repo)


# ----------------------------------------------------------------- B-N6: limit and compaction


def test_versions_that_another_covers_are_removed_from_the_disk(
    isolated_git: IsolatedGit, tmp_path: Path
) -> None:
    root, repo, _git = new_repo(isolated_git, tmp_path)
    lines: list[str] = []
    for number in range(300):  # every version only adds a pattern to the one before
        lines.append(f"dir{number}/")
        (root / ".nbp-safe").write_text("\n".join(lines) + "\n", newline="\n")
        protect.record_versions(repo)
    assert len(protect.stored_versions(repo)) == 1
    assert len(list(protect.versions_dir(repo).iterdir())) == 1  # ... and from the disk
    # a version that is covered by what is stored is not written at all
    protect.record_versions(repo, [b"dir1/\ndir2/\n"])
    assert len(list(protect.versions_dir(repo).iterdir())) == 1


def fill(repo: Repo, count: int) -> None:
    texts = [f"p{number}/\n!n{number}/\n".encode() for number in range(count)]
    protect.record_versions(repo, texts)


def test_the_memory_has_a_limit_and_never_drops_a_protection_to_keep_it(
    isolated_git: IsolatedGit, tmp_path: Path
) -> None:
    root, repo, git = new_repo(isolated_git, tmp_path)
    fill(repo, protect.MAX_VERSIONS)
    before = sorted(protect.stored_versions(repo))
    assert len(before) == protect.MAX_VERSIONS
    with pytest.raises(protect.PatternMemoryFullError, match="--accept-current"):
        protect.record_versions(repo, [b"one-more/\n"])
    assert sorted(protect.stored_versions(repo)) == before  # nothing dropped, nothing added
    # the owner takes the current file as the base: the memory is small again
    (root / ".nbp-safe").write_text("current/\n", newline="\n")
    result = protect.accept_current(git, repo)
    assert result.forgotten_versions == protect.MAX_VERSIONS
    assert len(protect.stored_versions(repo)) == 1
    assert protect.record_versions(repo, [b"one-more/\n"])  # and it works again


def test_sixty_four_versions_are_cheap(isolated_git: IsolatedGit, tmp_path: Path) -> None:
    """Measured on the development machine: the memory work (read, prune, block) about 15 ms and
    the whole ``list_protected`` / ``match_paths`` about 120 ms with 64 versions (it used to be one
    git run per version, over two seconds). The limits below leave a generous margin."""
    root, repo, git = new_repo(isolated_git, tmp_path)
    fill(repo, protect.MAX_VERSIONS - 1)
    (root / ".nbp-safe").write_text("now/\n", newline="\n")
    (root / "p7").mkdir()
    (root / "p7" / "f.txt").write_text("fake")
    started = time.perf_counter()
    for _ in range(3):
        texts = protect.pattern_texts(repo)
        protect.block_lines(repo)
        protect.record_versions(repo)
    memory = (time.perf_counter() - started) / 3
    assert len(texts) == protect.MAX_VERSIONS
    assert memory < 1.0, memory
    started = time.perf_counter()
    assert protect.list_protected(git, repo) == ["p7/f.txt"]
    assert protect.match_paths(git, repo, ["p62/x", "n3/x"]) == {"p62/x"}
    both = time.perf_counter() - started
    assert both < 4.0, both


def test_the_same_cap_stops_the_hooks_with_the_instruction(
    isolated_git: IsolatedGit, tmp_path: Path
) -> None:
    root, repo, git = new_repo(isolated_git, tmp_path)
    fill(repo, protect.MAX_VERSIONS)
    (root / ".nbp-safe").write_text("brand-new-version/\n", newline="\n")
    with pytest.raises(protect.PatternMemoryFullError, match="unprotect --accept-current"):
        guard.pattern_sources(git, repo)
    assert isinstance(protect.PatternMemoryFullError("x"), GitError)  # the hooks fail closed
