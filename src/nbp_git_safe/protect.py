# SPDX-License-Identifier: MIT
"""The protected set and the managed ``.git/info/exclude`` block.

Patterns use ``.gitignore`` syntax and live in two files:

* ``.nbp-safe`` (versioned, repository root), and
* ``.git/info/nbp-safe`` (local, unversioned).

Each file is evaluated on its own and the results are unioned, so a local negation (``!``) can
never unprotect something a versioned pattern protects. Files are resolved with git itself
(``git ls-files -o -i -X <file>``); paths that do not exist on disk (used to validate an index
coming from the vault) are matched with ``git check-ignore --no-index`` inside a scratch
repository so that neither the user's ``.gitignore`` files nor global excludes interfere.
"""

from __future__ import annotations

import contextlib
import tempfile
from collections.abc import Sequence
from pathlib import Path

from nbp_git_safe.gitutil import Git, Repo, split_z

VERSIONED_PATTERNS = ".nbp-safe"
LOCAL_PATTERNS = ("info", "nbp-safe")
BLOCK_BEGIN = "# >>> nbp-git-safe managed >>>"
BLOCK_END = "# <<< nbp-git-safe managed <<<"
MANAGED_SUFFIX_PATTERNS = ("*.nbp-theirs", "*.nbp-tmp")
SKIP_SUFFIXES = (".nbp-theirs", ".nbp-tmp")


def pattern_files(repo: Repo) -> list[Path]:
    """Existing pattern files: versioned first, then local."""
    candidates = [repo.toplevel / VERSIONED_PATTERNS, repo.common_dir.joinpath(*LOCAL_PATTERNS)]
    return [p for p in candidates if p.is_file()]


def read_patterns(path: Path) -> list[str]:
    """Meaningful pattern lines (no blanks/comments; never our own markers)."""
    text = path.read_bytes().decode("utf-8", "surrogateescape")
    lines = []
    for raw in text.split("\n"):
        line = raw.rstrip("\r")
        if not line.strip() or line.startswith("#") or line in (BLOCK_BEGIN, BLOCK_END):
            continue
        lines.append(line)
    return lines


def list_protected(git: Git, repo: Repo) -> list[str]:
    """Untracked files that match any pattern file (sorted, ``/``-separated, repo-relative)."""
    found: set[str] = set()
    for pf in pattern_files(repo):
        out = git.run("ls-files", "-z", "-o", "-i", "-X", str(pf))
        for path in split_z(out):
            if path.endswith("/") or path.endswith(SKIP_SUFFIXES):
                continue  # nested repositories and our own temp/conflict files
            found.add(path)
    return sorted(found)


def tracked_matches(git: Git, repo: Repo) -> list[str]:
    """Files already tracked on the main branch that match a pattern (a guard violation)."""
    found: set[str] = set()
    for pf in pattern_files(repo):
        found.update(split_z(git.run("ls-files", "-z", "-c", "-i", "-X", str(pf))))
    return sorted(found)


def tracked_files(git: Git) -> list[str]:
    return split_z(git.run("ls-files", "-z", "-c"))


def match_paths(git: Git, repo: Repo, paths: Sequence[str]) -> set[str]:
    """Which of ``paths`` (which need not exist) match the protected set."""
    files = pattern_files(repo)
    if not paths or not files:
        return set()
    payload = b"".join(p.encode("utf-8", "surrogateescape") + b"\0" for p in paths)
    matched: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="nbp-match-") as scratch:
        scratch_git = Git(scratch, git.env)
        scratch_git.run("init", "--quiet", "--template=", scratch)
        git_dir = Path(scratch, ".git")
        for pf in files:
            out = scratch_git.run(
                f"--git-dir={git_dir}",
                f"--work-tree={scratch}",
                "-c",
                f"core.excludesFile={pf.as_posix()}",
                "check-ignore",
                "--no-index",
                "-z",
                "--stdin",
                input=payload,
                check=False,
            )
            matched.update(split_z(out))
    return matched


# ------------------------------------------------------------------ exclude block


def exclude_path(repo: Repo) -> Path:
    return repo.common_dir / "info" / "exclude"


def block_lines(repo: Repo) -> list[str]:
    """Patterns written into the managed block: versioned patterns, local patterns without
    negations (a local ``!`` must not re-expose a versioned pattern), then the temp/conflict
    suffix patterns."""
    lines: list[str] = []
    versioned = repo.toplevel / VERSIONED_PATTERNS
    if versioned.is_file():
        lines.extend(read_patterns(versioned))
    local = repo.common_dir.joinpath(*LOCAL_PATTERNS)
    if local.is_file():
        lines.extend(line for line in read_patterns(local) if not line.startswith("!"))
    lines.extend(MANAGED_SUFFIX_PATTERNS)
    return lines


def render_block(lines: Sequence[str]) -> str:
    return "\n".join([BLOCK_BEGIN, *lines, BLOCK_END]) + "\n"


def _split_block(text: str) -> tuple[str, str] | None:
    """Return (text before block, text after block) or None when there is no block."""
    begin = text.find(BLOCK_BEGIN)
    if begin == -1:
        return None
    end = text.find(BLOCK_END, begin)
    if end == -1:
        return text[:begin], ""  # unterminated block: everything after BEGIN is ours
    after = end + len(BLOCK_END)
    if text[after : after + 2] == "\r\n":
        after += 2
    elif text[after : after + 1] == "\n":
        after += 1
    return text[:begin], text[after:]


def _read_exclude(repo: Repo) -> str:
    path = exclude_path(repo)
    try:
        return path.read_bytes().decode("utf-8", "surrogateescape")
    except FileNotFoundError:
        return ""


def _write_exclude(repo: Repo, text: str) -> None:
    path = exclude_path(repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8", "surrogateescape"))


def install_exclude_block(repo: Repo) -> bool:
    """Create or update the managed block (idempotent). Returns True if the file changed."""
    block = render_block(block_lines(repo))
    current = _read_exclude(repo)
    parts = _split_block(current)
    if parts is None:
        prefix = current if not current or current.endswith("\n") else current + "\n"
        new = prefix + block
    else:
        new = parts[0] + block + parts[1]
    if new == current:
        return False
    _write_exclude(repo, new)
    return True


def remove_exclude_block(repo: Repo) -> bool:
    """Remove the managed block, leaving every other line untouched."""
    current = _read_exclude(repo)
    parts = _split_block(current)
    if parts is None:
        return False
    _write_exclude(repo, parts[0] + parts[1])
    return True


def has_exclude_block(repo: Repo) -> bool:
    return _split_block(_read_exclude(repo)) is not None


def cleanup_tmp(path: Path) -> None:
    with contextlib.suppress(OSError):
        path.unlink()
