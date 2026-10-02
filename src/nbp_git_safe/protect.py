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
import os
import shutil
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path

from nbp_git_safe.gitutil import Git, GitError, Repo, split_z

VERSIONED_PATTERNS = ".nbp-safe"
LOCAL_PATTERNS = ("info", "nbp-safe")
BLOCK_BEGIN = "# >>> nbp-git-safe managed >>>"
BLOCK_END = "# <<< nbp-git-safe managed <<<"
MANAGED_SUFFIX_PATTERNS = ("*.nbp-theirs", "*.nbp-tmp")
SKIP_SUFFIXES = (".nbp-theirs", ".nbp-tmp")
SCRATCH_PREFIX = "match-"
STICKY_FILE = "sticky-patterns"


def managed_suffix_text() -> bytes:
    """The temp and conflict suffix patterns as a pattern-file content (for the guard)."""
    return ("\n".join(MANAGED_SUFFIX_PATTERNS) + "\n").encode("ascii")


def sticky_path(repo: Repo) -> Path:
    return repo.state_dir / STICKY_FILE


def pattern_files(repo: Repo) -> list[Path]:
    """Existing pattern files: versioned first, then local, then the sticky memory."""
    candidates = [
        repo.toplevel / VERSIONED_PATTERNS,
        repo.common_dir.joinpath(*LOCAL_PATTERNS),
        sticky_path(repo),
    ]
    return [p for p in candidates if p.is_file()]


def read_patterns(path: Path) -> list[str]:
    """Meaningful pattern lines (no blanks/comments; never our own markers)."""
    return lines_of(path.read_bytes())


def lines_of(data: bytes) -> list[str]:
    """Meaningful pattern lines of a pattern file's content."""
    text = data.decode("utf-8", "surrogateescape")
    lines = []
    for raw in text.split("\n"):
        line = raw.rstrip("\r")
        if not line.strip() or line.startswith("#") or line in (BLOCK_BEGIN, BLOCK_END):
            continue
        lines.append(line)
    return lines


# ----------------------------------------------------------------------- sticky memory


def _current_lines(repo: Repo) -> list[str]:
    versioned = repo.toplevel / VERSIONED_PATTERNS
    return read_patterns(versioned) if versioned.is_file() else []


def _sticky_lines(repo: Repo) -> list[str]:
    path = sticky_path(repo)
    return read_patterns(path) if path.is_file() else []


def merged_lines(repo: Repo, extra_texts: Sequence[bytes] = ()) -> list[str]:
    """The versioned patterns as they are now, followed by every positive pattern this clone has
    ever seen in them (or in ``extra_texts``) and that is gone from the file: the sticky ones.
    Removing a pattern upstream (a push from the web, a merge) never shrinks the protected set;
    only ``unprotect`` does."""
    current = _current_lines(repo)
    present = set(current)
    seen = _sticky_lines(repo)
    for text in extra_texts:
        seen.extend(lines_of(text))
    extra = [
        line for line in dict.fromkeys(seen) if line not in present and not line.startswith("!")
    ]
    return [*current, *extra]


def sticky_only(repo: Repo) -> list[str]:
    """Patterns protected only by this clone's memory: in ``.nbp-safe`` once, not any more."""
    present = set(_current_lines(repo))
    return [
        line for line in _sticky_lines(repo) if line not in present and not line.startswith("!")
    ]


def _write_sticky(repo: Repo, lines: Sequence[str]) -> None:
    path = sticky_path(repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8", "surrogateescape")
    tmp = path.with_name(f"{STICKY_FILE}.{os.getpid()}.tmp")
    with open(tmp, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def refresh_sticky(repo: Repo, extra_texts: Sequence[bytes] = ()) -> bool:
    """Bring the sticky file up to date with the versioned patterns (and with any other version of
    them in ``extra_texts``, for example the staged one). True if it changed. It never drops a
    pattern that is gone upstream."""
    wanted = merged_lines(repo, extra_texts)
    path = sticky_path(repo)
    if not wanted and not path.exists():
        return False
    if path.is_file() and _sticky_lines(repo) == wanted:
        return False
    _write_sticky(repo, wanted)
    return True


def unprotect(repo: Repo, pattern: str) -> str:
    """Forget a sticky pattern (the explicit, confirmed local act). Returns ``"removed"``,
    ``"still-versioned"`` (it is in ``.nbp-safe`` too: remove it there first) or ``"unknown"``."""
    if pattern in set(_current_lines(repo)):
        return "still-versioned"
    old = _sticky_lines(repo)
    if pattern not in old:
        return "unknown"
    _write_sticky(repo, [line for line in old if line != pattern])
    return "removed"


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
    return match_paths_texts(git, [pf.read_bytes() for pf in pattern_files(repo)], paths)


def match_paths_texts(git: Git, texts: Sequence[bytes], paths: Sequence[str]) -> set[str]:
    """Like ``match_paths`` but the pattern sets are given as contents (for example the
    ``.nbp-safe`` of HEAD or of the index). Each text is evaluated on its own and the results
    are unioned, so a negation in one can never unprotect what another protects.

    Fails closed: ``check-ignore`` answers 0 (something matched) or 1 (nothing did); any other
    status, or a scratch repository that cannot be created, raises ``GitError``, and the callers
    block. It never reads as "nothing is protected". The scratch repository lives inside the
    repository's own ``.git/nbp-safe`` (the pattern texts may hold names, and the system temp
    directory is not a place for them) and runs with a clean git environment, so a hook's
    ``GIT_DIR`` cannot point it at the real repository."""
    if not paths or not texts:
        return set()
    payload = b"".join(p.encode("utf-8", "surrogateescape") + b"\0" for p in paths)
    matched: set[str] = set()
    base = _scratch_base(git)
    base.mkdir(parents=True, exist_ok=True)
    _sweep_stale_scratch(base)
    scratch = Path(tempfile.mkdtemp(prefix=SCRATCH_PREFIX, dir=base))
    try:
        scratch_git = git.clean(scratch)
        scratch_git.run("init", "--quiet", "--template=", str(scratch))
        git_dir = scratch / ".git"
        for number, text in enumerate(texts):
            pf = scratch / f"patterns-{number}"
            pf.write_bytes(text)
            code, out, _err = scratch_git.run_status(
                f"--git-dir={git_dir}",
                f"--work-tree={scratch}",
                "-c",
                f"core.excludesFile={pf.as_posix()}",
                "check-ignore",
                "--no-index",
                "-z",
                "--stdin",
                input=payload,
            )
            if code not in (0, 1):
                raise GitError(f"git check-ignore failed ({code}); refusing to guess")
            matched.update(split_z(out))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return matched


def _scratch_base(git: Git) -> Path:
    out = git.text("rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    if not out:
        raise GitError("could not locate the git directory")
    return Path(out) / "nbp-safe" / "scratch"


def _sweep_stale_scratch(base: Path) -> None:
    """Remove scratch repositories an interrupted run left behind (older than an hour)."""
    cutoff = time.time() - 3600
    for child in base.glob(SCRATCH_PREFIX + "*"):
        with contextlib.suppress(OSError):
            if child.stat().st_mtime < cutoff:
                shutil.rmtree(child, ignore_errors=True)


# ------------------------------------------------------------------ exclude block


def exclude_path(repo: Repo) -> Path:
    return repo.common_dir / "info" / "exclude"


def block_lines(repo: Repo) -> list[str]:
    """Patterns written into the managed block: the versioned patterns plus the ones only the
    sticky memory still has, local patterns without negations (a local ``!`` must not re-expose a
    versioned pattern), then the temp/conflict suffix patterns."""
    lines: list[str] = merged_lines(repo)
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


def _read_text(path: Path) -> str:
    try:
        return path.read_bytes().decode("utf-8", "surrogateescape")
    except FileNotFoundError:
        return ""


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode("utf-8", "surrogateescape"))


def _install_block(path: Path, lines: Sequence[str]) -> bool:
    """Create or update the managed block of ``path`` (idempotent). True if the file changed."""
    block = render_block(lines)
    current = _read_text(path)
    parts = _split_block(current)
    if parts is None:
        prefix = current if not current or current.endswith("\n") else current + "\n"
        new = prefix + block
    else:
        new = parts[0] + block + parts[1]
    if new == current:
        return False
    _write_text(path, new)
    return True


def _remove_block(path: Path) -> bool:
    """Remove the managed block, leaving every other line untouched."""
    current = _read_text(path)
    parts = _split_block(current)
    if parts is None:
        return False
    _write_text(path, parts[0] + parts[1])
    return True


def install_exclude_block(repo: Repo) -> bool:
    """Create or update the managed block (idempotent). Returns True if the file changed. The
    sticky memory is refreshed first, so the block never loses a pattern that disappeared from
    ``.nbp-safe``."""
    refresh_sticky(repo)
    return _install_block(exclude_path(repo), block_lines(repo))


def remove_exclude_block(repo: Repo) -> bool:
    return _remove_block(exclude_path(repo))


def has_exclude_block(repo: Repo) -> bool:
    return _split_block(_read_text(exclude_path(repo))) is not None


def exclude_block_current(repo: Repo) -> bool:
    """Is the installed block exactly what ``install_exclude_block`` would write now?"""
    return render_block(block_lines(repo)) in _read_text(exclude_path(repo))


# --------------------------------------------------- optional block in the versioned .gitignore


def gitignore_path(repo: Repo) -> Path:
    return repo.toplevel / ".gitignore"


def gitignore_lines(repo: Repo) -> list[str]:
    """Versioned patterns only (local patterns never go into a versioned file)."""
    lines: list[str] = []
    versioned = repo.toplevel / VERSIONED_PATTERNS
    if versioned.is_file():
        lines.extend(read_patterns(versioned))
    lines.extend(MANAGED_SUFFIX_PATTERNS)
    return lines


def install_gitignore_block(repo: Repo) -> bool:
    return _install_block(gitignore_path(repo), gitignore_lines(repo))


def remove_gitignore_block(repo: Repo) -> bool:
    return _remove_block(gitignore_path(repo))


def has_gitignore_block(repo: Repo) -> bool:
    return _split_block(_read_text(gitignore_path(repo))) is not None


def cleanup_tmp(path: Path) -> None:
    with contextlib.suppress(OSError):
        path.unlink()
