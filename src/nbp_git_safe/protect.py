# SPDX-License-Identifier: MIT
"""The protected set and the managed ``.git/info/exclude`` block.

Patterns use ``.gitignore`` syntax and live in two files:

* ``.nbp-safe`` (versioned, repository root), and
* ``.git/info/nbp-safe`` (local, unversioned),

plus the memory of every earlier version of the versioned file this clone has seen (one more
pattern file per version, see below).

Each file is evaluated on its own and the results are unioned, so a local negation (``!``), or a
negation that only a newer version of ``.nbp-safe`` has, can never unprotect something that
another file protects. Files are resolved with git itself
(``git ls-files -o -i -X <file>``); paths that do not exist on disk (used to validate an index
coming from the vault) are matched with ``git check-ignore --no-index`` inside a scratch
repository so that neither the user's ``.gitignore`` files nor global excludes interfere.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets
import shutil
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from nbp_git_safe.gitutil import Git, GitError, Repo, optional_blob, split_z

VERSIONED_PATTERNS = ".nbp-safe"
LOCAL_PATTERNS = ("info", "nbp-safe")
BLOCK_BEGIN = "# >>> nbp-git-safe managed >>>"
BLOCK_END = "# <<< nbp-git-safe managed <<<"
MANAGED_SUFFIX_PATTERNS = ("*.nbp-theirs", "*.nbp-tmp")
SKIP_SUFFIXES = (".nbp-theirs", ".nbp-tmp")
SCRATCH_PREFIX = "match-"
VERSIONS_DIR = "pattern-versions"
FORGOTTEN_FILE = "pattern-forgotten.json"
_ID_RE = re.compile(r"^[0-9a-f]{32}$")
# Our own configuration files are never part of the protected set, whatever the patterns say: a
# broad pattern pushed from the remote (``*``) must not make ``.nbp-safe`` itself a protected path
# (the commit that fixes it would be refused and the file could never be committed again). The
# vault index already refuses them as entries (``index.py``).
EXEMPT_PATHS = (".nbp-safe", ".nbp-safe.config")


def managed_suffix_text() -> bytes:
    """The temp and conflict suffix patterns as a pattern-file content (for the guard)."""
    return ("\n".join(MANAGED_SUFFIX_PATTERNS) + "\n").encode("ascii")


def pattern_files(repo: Repo) -> list[Path]:
    """Existing pattern files: versioned first, then local, then one per remembered version (the
    versions that another file already covers, see ``dominates``, are left out: they add nothing
    to the union)."""
    candidates = [
        repo.toplevel / VERSIONED_PATTERNS,
        repo.common_dir.joinpath(*LOCAL_PATTERNS),
        *(versions_dir(repo) / vid for vid in stored_versions(repo)),
    ]
    files = [p for p in candidates if p.is_file()]
    contents = []
    for path in files:
        with contextlib.suppress(OSError):
            contents.append((path, lines_of(path.read_bytes())))
    keep = prune_dominated([lines for _p, lines in contents])
    return [contents[i][0] for i in keep]


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


# ------------------------------------------------------------ memory of pattern-file versions
#
# The memory keeps every distinct version of ``.nbp-safe`` this clone has seen, each as a SEPARATE
# pattern file (``<state>/pattern-versions/<id>``: the meaningful lines only, so nothing but the
# patterns themselves). Every version is one more source of the union (see ``pattern_files``), so
# a path is protected if ANY version protects it and no negation of that SAME version cancels it.
# A negation that only a newer version has can never take protection away from an older one (the
# memory used to store lines, and a pushed ``!reports/`` was carried into the memory and defeated
# it). Only ``unprotect`` forgets, and what it forgets stays forgotten (``FORGOTTEN_FILE``).


def normalize(data: bytes) -> bytes:
    """The meaningful lines of a pattern file as a canonical text (empty when there are none)."""
    lines = lines_of(data)
    return _join(lines)


def _join(lines: Sequence[str]) -> bytes:
    return ("\n".join(lines) + "\n").encode("utf-8", "surrogateescape") if lines else b""


def version_id(normalized: bytes) -> str:
    return hashlib.sha256(normalized).hexdigest()[:32]


def versions_dir(repo: Repo) -> Path:
    return repo.state_dir / VERSIONS_DIR


def is_positive(line: str) -> bool:
    return not line.startswith("!")


def _current_bytes(repo: Repo) -> bytes:
    versioned = repo.toplevel / VERSIONED_PATTERNS
    return versioned.read_bytes() if versioned.is_file() else b""


def _current_lines(repo: Repo) -> list[str]:
    return lines_of(_current_bytes(repo))


def stored_versions(repo: Repo) -> dict[str, bytes]:
    """``{id: normalized text}`` of every remembered version (unreadable files are skipped)."""
    out: dict[str, bytes] = {}
    directory = versions_dir(repo)
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return out
    for name in names:
        if _ID_RE.match(name):
            with contextlib.suppress(OSError):
                out[name] = (directory / name).read_bytes()
    return out


def _forgotten_path(repo: Repo) -> Path:
    return repo.state_dir / FORGOTTEN_FILE


def read_forgotten(repo: Repo) -> tuple[list[str], list[str]]:
    """``(patterns, version ids)`` the owner told ``unprotect`` to forget."""
    try:
        data = json.loads(_forgotten_path(repo).read_bytes().decode("utf-8"))
    except (OSError, ValueError):
        return [], []
    if not isinstance(data, dict):
        return [], []
    lines = [x for x in data.get("lines", []) if isinstance(x, str)]
    ids = [x for x in data.get("versions", []) if isinstance(x, str) and _ID_RE.match(x)]
    return lines, ids


def _write_forgotten(repo: Repo, lines: Sequence[str], ids: Sequence[str]) -> None:
    path = _forgotten_path(repo)
    if not lines and not ids:
        path.unlink(missing_ok=True)
        return
    payload = {"lines": sorted(set(lines)), "versions": sorted(set(ids))}
    _atomic_write(path, json.dumps(payload, sort_keys=True).encode("utf-8"))


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    with open(tmp, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def dominates(newer: Sequence[str], older: Sequence[str]) -> bool:
    """Does ``newer`` protect at least what ``older`` protects? True when every line of ``older``
    appears in ``newer`` in the same order and everything else ``newer`` has is a positive
    pattern: adding a positive line can only add protection, never take it away. Conservative (a
    ``False`` only means "cannot tell")."""
    position = 0
    extras: list[str] = []
    for line in newer:
        if position < len(older) and line == older[position]:
            position += 1
        else:
            extras.append(line)
    return position == len(older) and all(is_positive(line) for line in extras)


def prune_dominated(versions: Sequence[Sequence[str]]) -> list[int]:
    """Indexes of the versions that are not dominated by another one (of equal versions the first
    stays). A dominated version adds nothing to a union."""
    keep = []
    for i, mine in enumerate(versions):
        redundant = any(
            j != i and dominates(other, mine) and (not dominates(mine, other) or j < i)
            for j, other in enumerate(versions)
        )
        if not redundant:
            keep.append(i)
    return keep


def record_versions(repo: Repo, extra_texts: Sequence[bytes] = ()) -> bool:
    """Remember the current ``.nbp-safe`` (and any other version in ``extra_texts``, for example
    the staged or committed one). True if the memory changed. A version with no positive pattern
    protects nothing and is not kept; patterns and versions the owner forgot with ``unprotect``
    are not brought back, unless the working-tree file itself has them again."""
    changed = False
    forgotten, forgotten_ids = read_forgotten(repo)
    texts: list[bytes] = []
    working = _current_bytes(repo)
    if working:
        texts.append(working)
        now = set(lines_of(working))
        back = {line for line in forgotten if line in now}
        working_id = version_id(normalize(working))
        if back or working_id in forgotten_ids:  # the owner wrote it again: it counts again
            forgotten = [line for line in forgotten if line not in back]
            forgotten_ids = [i for i in forgotten_ids if i != working_id]
            _write_forgotten(repo, forgotten, forgotten_ids)
    texts.extend(extra_texts)
    existing = set(stored_versions(repo))
    drop = set(forgotten)
    for text in texts:
        lines = [line for line in lines_of(text) if line not in drop]
        if not any(is_positive(line) for line in lines):
            continue
        norm = _join(lines)
        vid = version_id(norm)
        if vid in existing or vid in forgotten_ids or version_id(normalize(text)) in forgotten_ids:
            continue
        _atomic_write(versions_dir(repo) / vid, norm)
        existing.add(vid)
        changed = True
    return changed


def refresh_sticky(repo: Repo, extra_texts: Sequence[bytes] = ()) -> bool:
    """Bring the memory up to date (the name callers of the old line memory know)."""
    return record_versions(repo, extra_texts)


def sticky_only(repo: Repo) -> list[str]:
    """Patterns only the memory still has: positive lines of a remembered version that the current
    ``.nbp-safe`` no longer contains (a textual check; ``lost_protection`` also finds patterns a
    negation defeats)."""
    present = set(_current_lines(repo))
    seen: dict[str, None] = {}
    for _vid, text in sorted(stored_versions(repo).items()):
        for line in lines_of(text):
            if is_positive(line) and line not in present:
                seen[line] = None
    return list(seen)


_GLOB_CLASS = re.compile(r"\[(\^|!)?\]?[^\]]*\]")


def probe_paths(pattern: str) -> list[str]:
    """A few concrete paths a gitignore ``pattern`` is meant to match (``*`` becomes ``zz``). Used
    only to explain a weakened protection to the owner (``lost_protection``): git, not this
    function, decides what is protected."""
    body = pattern.strip().lstrip("/")
    directory = body.endswith("/")
    body = body.rstrip("/").replace("\\", "")
    body = _GLOB_CLASS.sub("z", body)
    body = body.replace("**", "zz").replace("*", "zz").replace("?", "z")
    if not body:
        return []
    probes = [body + "/zz.txt", body + "/zz/zz.txt"]
    if not directory:
        probes.append(body)
    return probes


def lost_protection(git: Git, repo: Repo) -> list[str]:
    """Patterns of earlier versions of ``.nbp-safe`` that the current one no longer enforces:
    removed from it, or defeated by one of its negations. This clone still protects them (the
    memory is a union); the list feeds the warning. Raises ``GitError`` if git cannot answer."""
    current_text = normalize(_current_bytes(repo))
    current = lines_of(current_text)
    present = set(current)
    found: dict[str, None] = dict.fromkeys(sticky_only(repo))
    for _vid, text in sorted(stored_versions(repo).items()):
        older = lines_of(text)
        if dominates(current, older):
            continue
        probes: dict[str, str] = {}
        for line in older:
            if is_positive(line) and line in present:
                for probe in probe_paths(line):
                    probes.setdefault(probe, line)
        if not probes:
            continue
        paths = sorted(probes)
        then = match_paths_texts(git, [text], paths)
        now = match_paths_texts(git, [current_text], paths) if current_text else set()
        for probe in then - now:
            found.setdefault(probes[probe], None)
    return list(found)


@dataclass(frozen=True)
class UnprotectResult:
    status: str  # "removed" | "unknown" | "still-versioned"
    live: tuple[str, ...] = ()  # sources that still carry the pattern: "HEAD", "the index"


def _live_sources(git: Git, pattern: str) -> tuple[str, ...]:
    live = []
    for label, rev in (("HEAD", "HEAD"), ("the index", None)):
        data = optional_blob(git, VERSIONED_PATTERNS, rev)
        if data is not None and pattern in lines_of(data):
            live.append(label)
    return tuple(live)


def unprotect(git: Git, repo: Repo, pattern: str) -> UnprotectResult:
    """Forget one pattern in every remembered version (the explicit, confirmed local act), for
    good: the forgotten patterns are kept, so a later hook that reads an older ``HEAD`` or index
    cannot bring it back. ``"still-versioned"``: the working-tree ``.nbp-safe`` has it (remove it
    there first). ``live`` lists what else still carries it (``HEAD``, the index): it stays
    protected through those until the commit that removes it from ``.nbp-safe`` is made."""
    if pattern in set(_current_lines(repo)):
        return UnprotectResult("still-versioned")
    hit = {vid: text for vid, text in stored_versions(repo).items() if pattern in lines_of(text)}
    if not hit:
        return UnprotectResult("unknown", _live_sources(git, pattern))
    forgotten, forgotten_ids = read_forgotten(repo)
    for vid, text in hit.items():
        (versions_dir(repo) / vid).unlink(missing_ok=True)
        lines = [line for line in lines_of(text) if line != pattern]
        if any(is_positive(line) for line in lines):
            new = _join(lines)
            _atomic_write(versions_dir(repo) / version_id(new), new)
    _write_forgotten(repo, [*forgotten, pattern], forgotten_ids)
    return UnprotectResult("removed", _live_sources(git, pattern))


@dataclass(frozen=True)
class AcceptResult:
    forgotten_versions: int
    forgotten_patterns: int
    differs_from_head: bool


def accept_current(git: Git, repo: Repo) -> AcceptResult:
    """Take the working-tree ``.nbp-safe`` as the only base: forget every earlier version (and so
    every protection only they gave). Durable like ``unprotect``."""
    stored = stored_versions(repo)
    current_bytes = _current_bytes(repo)
    current = set(lines_of(current_bytes))
    current_id = version_id(normalize(current_bytes))
    forgotten, forgotten_ids = read_forgotten(repo)
    gone_ids = [vid for vid in stored if vid != current_id]
    gone_lines = {
        line
        for vid in gone_ids
        for line in lines_of(stored[vid])
        if is_positive(line) and line not in current
    }
    for vid in gone_ids:
        (versions_dir(repo) / vid).unlink(missing_ok=True)
    _write_forgotten(repo, [*forgotten, *gone_lines], [*forgotten_ids, *gone_ids])
    record_versions(repo)  # the current version is the base now
    head = optional_blob(git, VERSIONED_PATTERNS, "HEAD")
    differs = normalize(head or b"") != normalize(current_bytes)
    return AcceptResult(len(gone_ids), len(gone_lines), differs)


def _exempt(path: str) -> bool:
    return path.casefold() in EXEMPT_PATHS


def list_protected(git: Git, repo: Repo) -> list[str]:
    """Untracked files that match any pattern file (sorted, ``/``-separated, repo-relative)."""
    found: set[str] = set()
    for pf in pattern_files(repo):
        out = git.run("ls-files", "-z", "-o", "-i", "-X", str(pf))
        for path in split_z(out):
            if path.endswith("/") or path.endswith(SKIP_SUFFIXES) or _exempt(path):
                continue  # nested repositories, our own temp/conflict files, our own config
            found.add(path)
    return sorted(found)


def tracked_matches(git: Git, repo: Repo) -> list[str]:
    """Files already tracked on the main branch that match a pattern (a guard violation)."""
    found: set[str] = set()
    for pf in pattern_files(repo):
        found.update(split_z(git.run("ls-files", "-z", "-c", "-i", "-X", str(pf))))
    return sorted(path for path in found if not _exempt(path))


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
    """Patterns written into the managed block (one file cannot hold a union of versions, so this
    errs on the side of protecting): the current ``.nbp-safe`` as it is (its own negations work),
    then the positive patterns of every remembered version that the current one does not cover
    (a negation of the current version must not re-expose what an older version protects), local
    patterns without negations (a local ``!`` must not re-expose a versioned pattern), the
    temp/conflict suffix patterns, and last the exemption of our own configuration files."""
    current = _current_lines(repo)
    lines: list[str] = list(current)
    extras: dict[str, None] = {}
    for _vid, text in sorted(stored_versions(repo).items()):
        older = lines_of(text)
        if dominates(current, older):
            continue
        negated = {line[1:] for line in older if not is_positive(line)}
        for line in older:
            if is_positive(line) and line not in negated:
                extras[line] = None
    lines.extend(extras)
    local = repo.common_dir.joinpath(*LOCAL_PATTERNS)
    if local.is_file():
        lines.extend(line for line in read_patterns(local) if not line.startswith("!"))
    lines.extend(MANAGED_SUFFIX_PATTERNS)
    lines.extend(f"!/{name}" for name in EXEMPT_PATHS)
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
    memory of versions is refreshed first, so the block never loses a pattern that disappeared
    from ``.nbp-safe`` or that a newer version defeats with a negation."""
    record_versions(repo)
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
