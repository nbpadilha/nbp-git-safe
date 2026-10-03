# SPDX-License-Identifier: MIT
"""Deterministic fuzzing of the ``.nbp-safe`` reading (``protect.lines_of`` / normalization) and of
the matcher against a real ``git check-ignore``, with more variants than the 500-case property
test of the third review: CRLF, BOM, backslash escapes, escaped ``#`` / ``!``, ``**``, escaped
trailing spaces, NUL, lone backslashes and invalid UTF-8. Fixed seeds."""

from __future__ import annotations

import random
from pathlib import Path

from nbp_git_safe import protect
from tests.conftest import IsolatedGit
from tests.integration.test_review3_patterns import new_repo, raw_git_matches

BOM = b"\xef\xbb\xbf"
SEED = 20261005

FRAGMENTS = [
    "reports/",
    "reports/**",
    "**/reports",
    "**/reports/**",
    "a/**/c.txt",
    "a/**",
    "a/*",
    "a?/x",
    "[ab]/e",
    "[!a]/e",
    "*.csv",
    "*.txt",
    "!reports/keep.csv",
    "!*.txt",
    "!b",
    "b",
    "/c",
    "c/",
    "x\\ ",  # escaped trailing space: kept
    "x\\  ",  # escaped space then a plain one: the plain one goes
    "x \\ ",
    "x\\\\ ",  # escaped backslash then a trailing space: the space goes
    "x\\\\",
    "x\\",  # lone backslash
    "\\#h",
    "\\!n",
    "\\ lead",
    "\\\\",
    "#comment",
    "# reports/",
    " #notcomment",
    "  ",  # only blanks: a pattern of two spaces
    "\t",
    "tab\t",
    "reports/\r",  # CR before the line end: one CR is the line end, a second is part of it
    "kéy/",
    "dir with space/",
    "é/",
]
ENDINGS = [
    "\n",
    "\n",
    "\r\n",
    "\r\r\n",
    " \n",
    "  \r\n",
    "\t\n",
    "\r",
    "\n\n",
    "\r\n\r\n",
    "\\\n",
    " \\\n",
]
PATHS = [
    "reports/a.csv",
    "reports/keep.csv",
    "reports/sub/deep/x.bin",
    "reports",
    "a/x",
    "a/b/c.txt",
    "a/b/c/c.txt",
    "ax/x",
    "a/e",
    "b/e",
    "c/z",
    "c",
    "b",
    "b/y",
    "x",
    "x ",
    "x  ",
    "x\\ ",
    " lead",
    "#h",
    "#comment",
    "!n",
    " #notcomment",
    "tab",
    "tab\t",
    "\t",
    "  ",
    "kéy/id",
    "dir with space/f",
    "é/f",
    "plain.txt",
    "deep/er/plain.csv",
]


def random_text(rng: random.Random) -> bytes:
    parts = []
    for _ in range(rng.randint(1, 7)):
        atom = rng.choice(FRAGMENTS)
        if rng.random() < 0.03:
            atom += "\0junk"
        parts.append(atom + rng.choice(ENDINGS))
    text = "".join(parts)
    if rng.random() < 0.15:
        text = text.rstrip("\r\n \t")
    data = text.encode()
    if rng.random() < 0.05:
        data += b"\xff\xfe"  # invalid UTF-8 stays byte-for-byte
    return BOM + data if rng.random() < 0.25 else data


def test_fuzz_normalization_is_idempotent_and_keeps_the_meaning() -> None:
    """No git needed: lines_of/normalize are stable under re-reading, for any bytes."""
    rng = random.Random(SEED)  # noqa: S311 - a fixed seed, not a secret
    for _ in range(3000):
        kind = rng.random()
        data = rng.randbytes(rng.randint(0, 120)) if kind < 0.2 else random_text(rng)
        lines = protect.lines_of(data)
        normalized = protect.normalize_pattern_text(data)
        assert protect.lines_of(normalized) == lines
        assert protect.normalize_pattern_text(normalized) == normalized
        assert protect.normalize(data) == normalized
        assert protect.version_id(normalized) == protect.version_id(
            protect.normalize_pattern_text(normalized)
        )
        for line in lines:
            assert line and not line.startswith("#") and "\0" not in line


def test_fuzz_matcher_equals_git_for_raw_and_normalized_texts(
    isolated_git: IsolatedGit, tmp_path: Path
) -> None:
    """400 random texts, evaluated by git itself (raw file) and by the tool (normalized text)."""
    _root, _repo, git = new_repo(isolated_git, tmp_path)
    rng = random.Random(SEED + 1)  # noqa: S311
    texts = [random_text(rng) for _ in range(400)]
    base = tmp_path / "scratch-base"
    for start in range(0, len(texts), 100):
        batch = texts[start : start + 100]
        scratch = tmp_path / f"fuzz{start}"
        scratch.mkdir()
        isolated_git.run("init", "-q", str(scratch))
        want = raw_git_matches(isolated_git, scratch, batch, PATHS)
        got = protect.match_paths_each(git, batch, PATHS, base=base)
        for text, w, g in zip(batch, want, got, strict=True):
            assert w == g, (text, w ^ g)
