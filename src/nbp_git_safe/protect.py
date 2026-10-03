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
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from nbp_git_safe import plainfile
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
# The memory keeps at most this many versions that no other version covers (see ``dominates``).
# Past that, remembering one more would cost every hook a git run per version; the owner is told
# to take the current file as the base (``unprotect --accept-current``) instead of the tool
# dropping a protection on its own.
MAX_VERSIONS = 64


class PatternMemoryError(GitError):
    """The memory of pattern versions cannot be read: the hooks fail closed instead of leaving a
    version (and what only it protects) out."""


class PatternMemoryFullError(PatternMemoryError):
    """More than ``MAX_VERSIONS`` independent versions: nothing was dropped, nothing was added."""


def managed_suffix_text() -> bytes:
    """The temp and conflict suffix patterns as a pattern-file content (for the guard)."""
    return ("\n".join(MANAGED_SUFFIX_PATTERNS) + "\n").encode("ascii")


def pattern_texts(repo: Repo) -> list[bytes]:
    """The pattern sets that count, each as NORMALIZED text (``normalize_pattern_text``): the
    versioned file, the local file, then one per remembered version. The versions that another set
    already covers (see ``dominates``) are left out: they add nothing to the union.

    Git must be given exactly these texts, never the raw files: this module's idea of "the same
    version" is decided on the normalized lines, so what git evaluates has to be the normalized
    text too (a CR-padded line that normalizes to an older one but means something else to git
    would otherwise let the older, protecting version be pruned). Unreadable or non-regular files
    raise (``plainfile.UnsafeFileError``, ``PatternMemoryError``): nothing is skipped silently."""
    raw = [
        _current_bytes(repo),
        plainfile.read_plain_file(_local_path(repo)) or b"",
        *stored_versions(repo).values(),
    ]
    unique = [t for t in dict.fromkeys(normalize_pattern_text(b) for b in raw) if t]
    keep = prune_dominated([lines_of(t) for t in unique])
    return [unique[i] for i in keep]


def _local_path(repo: Repo) -> Path:
    return repo.common_dir.joinpath(*LOCAL_PATTERNS)


def read_patterns(path: Path) -> list[str]:
    """Meaningful pattern lines (no blanks/comments; never our own markers)."""
    return lines_of(plainfile.read_plain_file(path) or b"")


# What git does with a pattern file (``dir.c``: ``add_patterns_from_buffer``, ``trim_trailing_
# spaces``), reproduced here and ONLY here: a leading UTF-8 BOM is skipped; a line is dropped when
# it is empty or starts with ``#``; ONE trailing CR is removed (not all of them); the line stops
# at a NUL; trailing spaces are removed unless escaped with a backslash. Tabs are ordinary
# characters. Anything else is part of the pattern.


def _trim_trailing_spaces(line: str) -> str:
    last_space: int | None = None
    i = 0
    while i < len(line):
        char = line[i]
        if char == " ":
            if last_space is None:
                last_space = i
        elif char == "\\":
            i += 1
            if i >= len(line):
                return line  # a lone trailing backslash: git leaves the line as it is
            last_space = None
        else:
            last_space = None
        i += 1
    return line if last_space is None else line[:last_space]


def clean_pattern_line(raw: str) -> str | None:
    """The pattern git makes of one physical line (without its newline), or ``None`` when git
    ignores the line."""
    if not raw or raw[0] == "#":
        return None
    if raw[-1] == "\r":
        raw = raw[:-1]
    line = _trim_trailing_spaces(raw.split("\0", 1)[0])
    return line or None


def lines_of(data: bytes) -> list[str]:
    """Meaningful pattern lines of a pattern file's content, as git reads them."""
    text = data.decode("utf-8", "surrogateescape")
    if text.startswith("\ufeff"):
        text = text[1:]
    lines = []
    for raw in text.split("\n"):
        line = clean_pattern_line(raw)
        if line is not None:
            lines.append(line)
    return lines


def emit_lines(lines: Sequence[str]) -> str:
    """Pattern lines as a text that reads back as exactly these lines (``lines_of`` of it is
    ``lines``). A line that ends in CR gets ``CR LF``, since git removes one CR before the newline;
    a first line that starts with a BOM gets a BOM of its own in front."""
    body = terminated(lines)
    return "\ufeff" + body if lines and lines[0].startswith("\ufeff") else body


def terminated(lines: Sequence[str]) -> str:
    """Pattern lines, each followed by the line end that keeps it as it is (see ``emit_lines``)."""
    return "".join(line + ("\r\n" if line.endswith("\r") else "\n") for line in lines)


def normalize_pattern_text(data: bytes) -> bytes:
    """THE normalization of a pattern file: its meaningful lines as a canonical text (empty when
    there are none). Idempotent. Everything that compares, remembers or hands patterns to git goes
    through this one function."""
    return _join(lines_of(data))


# ------------------------------------------------------------ memory of pattern-file versions
#
# The memory keeps every distinct version of ``.nbp-safe`` this clone has seen, each as a SEPARATE
# pattern file (``<state>/pattern-versions/<id>``: the meaningful lines only, so nothing but the
# patterns themselves). Every version is one more source of the union (see ``pattern_texts``), so
# a path is protected if ANY version protects it and no negation of that SAME version cancels it.
# A negation that only a newer version has can never take protection away from an older one (the
# memory used to store lines, and a pushed ``!reports/`` was carried into the memory and defeated
# it). Only ``unprotect`` forgets, and what it forgets stays forgotten (``FORGOTTEN_FILE``).


def normalize(data: bytes) -> bytes:
    """Another name for ``normalize_pattern_text``."""
    return normalize_pattern_text(data)


def _join(lines: Sequence[str]) -> bytes:
    return emit_lines(lines).encode("utf-8", "surrogateescape")


def version_id(normalized: bytes) -> str:
    return hashlib.sha256(normalized).hexdigest()[:32]


def versions_dir(repo: Repo) -> Path:
    return repo.state_dir / VERSIONS_DIR


def is_positive(line: str) -> bool:
    return not line.startswith("!")


def _current_bytes(repo: Repo) -> bytes:
    """The working-tree ``.nbp-safe`` (empty when absent). A symbolic link, a junction, a special
    file or a huge one is refused (``plainfile.UnsafeFileError``) without being read: it is a file
    a collaborator can commit, and a link would pull in a file from outside the repository."""
    return plainfile.read_plain_file(repo.toplevel / VERSIONED_PATTERNS) or b""


def working_patterns(repo: Repo) -> bytes | None:
    """The working-tree ``.nbp-safe`` as it is, ``None`` when there is none (same refusals as
    ``_current_bytes``)."""
    return plainfile.read_plain_file(repo.toplevel / VERSIONED_PATTERNS)


def _current_lines(repo: Repo) -> list[str]:
    return lines_of(_current_bytes(repo))


def stored_versions(repo: Repo) -> dict[str, bytes]:
    """``{id: normalized text}`` of every remembered version. A memory that cannot be read raises
    ``PatternMemoryError``: a version that silently vanished would take its protection with it
    (the exclude block and the guard would both lose it), so the hooks fail closed instead."""
    out: dict[str, bytes] = {}
    directory = versions_dir(repo)
    try:
        names = sorted(os.listdir(directory))
    except (FileNotFoundError, NotADirectoryError):
        return out
    except OSError as exc:
        raise PatternMemoryError(
            f"the memory of .nbp-safe versions cannot be listed ({exc.strerror or 'I/O error'}); "
            "nothing is guessed: fix the permissions of .git/nbp-safe and try again"
        ) from exc
    for name in names:
        if not _ID_RE.match(name):
            continue
        try:
            data = (directory / name).read_bytes()
        except FileNotFoundError:
            continue  # removed meanwhile (unprotect): it is gone for real
        except OSError as exc:
            raise PatternMemoryError(
                f"a remembered version of .nbp-safe ({name[:8]}) cannot be read "
                f"({exc.strerror or 'I/O error'}); nothing is guessed: fix "
                f".git/nbp-safe/{VERSIONS_DIR} and try again"
            ) from exc
        out[name] = data
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
    stays). A dominated version adds nothing to a union. A version can only be dominated by one
    that has all its lines, so the set test comes first and the ordered test only runs for the few
    that pass it."""
    sets = [frozenset(version) for version in versions]
    keep = []
    for i, mine in enumerate(versions):
        redundant = any(
            j != i
            and sets[i] <= sets[j]
            and dominates(other, mine)
            and (not dominates(mine, other) or j < i)
            for j, other in enumerate(versions)
        )
        if not redundant:
            keep.append(i)
    return keep


def record_versions(repo: Repo, extra_texts: Sequence[bytes] = ()) -> bool:
    """Remember the current ``.nbp-safe`` (and any other version in ``extra_texts``, for example
    the staged or committed one). True if the memory changed. A version with no positive pattern
    protects nothing and is not kept; patterns and versions the owner forgot with ``unprotect``
    are not brought back, unless the working-tree file itself has them again.

    The memory stays small: a version that another one covers (``dominates``) is neither written
    nor kept (the ones already on disk are removed), and at most ``MAX_VERSIONS`` independent
    versions are kept. Past that nothing is written and nothing is dropped:
    ``PatternMemoryFullError`` tells the owner to take the current file as the base."""
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
    existing = stored_versions(repo)
    drop = set(forgotten)
    fresh: dict[str, bytes] = {}
    for text in texts:
        lines = [line for line in lines_of(text) if line not in drop]
        if not any(is_positive(line) for line in lines):
            continue
        norm = _join(lines)
        vid = version_id(norm)
        if vid in existing or vid in fresh or vid in forgotten_ids:
            continue
        if version_id(normalize(text)) in forgotten_ids:
            continue
        fresh[vid] = norm
    pool = {**existing, **fresh}
    ids = list(pool)
    keep = {ids[i] for i in prune_dominated([lines_of(pool[vid]) for vid in ids])}
    if len(keep) > MAX_VERSIONS:
        raise PatternMemoryFullError(
            f"the memory of .nbp-safe versions would hold {len(keep)} independent versions "
            f"(the limit is {MAX_VERSIONS}); nothing was dropped and nothing was added. Review "
            "`git log -p -- .nbp-safe`, then run `nbp-git-safe unprotect --accept-current` to take "
            "the current file as the only base"
        )
    for vid in ids:
        if vid in keep and vid in fresh:
            _atomic_write(versions_dir(repo) / vid, fresh[vid])
            changed = True
        elif vid not in keep and vid in existing:  # covered by another one: the disk forgets it
            (versions_dir(repo) / vid).unlink(missing_ok=True)
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
    olders: list[bytes] = []
    wanted: list[dict[str, str]] = []  # per older version: probe path -> the pattern it probes
    for _vid, text in sorted(stored_versions(repo).items()):
        older = lines_of(text)
        if dominates(current, older):
            continue
        probes: dict[str, str] = {}
        for line in older:
            if is_positive(line) and line in present:
                for probe in probe_paths(line):
                    probes.setdefault(probe, line)
        if probes:
            olders.append(text)
            wanted.append(probes)
    if not olders:
        return list(found)
    every = sorted({probe for probes in wanted for probe in probes})
    # one git run answers for every version at once (the current one, if any, is the last text)
    answers = match_paths_each(git, [*olders, current_text] if current_text else olders, every)
    now = answers[len(olders)] if current_text else set()
    for probes, then in zip(wanted, answers, strict=False):
        for probe in sorted(set(probes) & then):
            if probe not in now:
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


def ignore_case(git: Git) -> bool:
    """Does this repository treat file names case-insensitively (``core.ignorecase``, which
    ``git init`` sets on Windows and macOS)?"""
    code, out, _err = git.run_status("config", "--type=bool", "--get", "core.ignorecase")
    return code == 0 and out.strip() == b"true"


def is_exempt(path: str, fold: bool) -> bool:
    """Is ``path`` one of our own configuration files (see ``EXEMPT_PATHS``)? The names are
    compared as written, and only where the file system itself does not tell ``.NBP-SAFE`` from
    ``.nbp-safe`` (``fold``, from ``ignore_case``) with ``casefold``. The choice errs on the side
    of protecting: on a case-sensitive file system ``.NBP-SAFE`` is an ordinary file next to
    ours, which a broad pattern may protect like any other, so it must not borrow our exemption."""
    return (path.casefold() if fold else path) in EXEMPT_PATHS


def list_protected(git: Git, repo: Repo) -> list[str]:
    """Untracked files that match any pattern set (sorted, ``/``-separated, repo-relative)."""
    texts = pattern_texts(repo)
    if not texts:
        return []
    base = repo.state_dir / "scratch"
    candidates = _candidates(git, texts, "-o", base)
    fold = ignore_case(git)
    wanted = [
        path
        for path in candidates
        if not (path.endswith("/") or path.endswith(SKIP_SUFFIXES) or is_exempt(path, fold))
    ]  # nested repositories, our own temp/conflict files, our own configuration
    return sorted(_union(match_paths_each(git, texts, wanted, base=base)))


def tracked_matches(git: Git, repo: Repo) -> list[str]:
    """Files already tracked on the main branch that match a pattern (a guard violation)."""
    texts = pattern_texts(repo)
    if not texts:
        return []
    base = repo.state_dir / "scratch"
    fold = ignore_case(git)
    candidates = [p for p in _candidates(git, texts, "-c", base) if not is_exempt(p, fold)]
    return sorted(_union(match_paths_each(git, texts, candidates, base=base)))


def tracked_files(git: Git) -> list[str]:
    return split_z(git.run("ls-files", "-z", "-c"))


def match_paths(git: Git, repo: Repo, paths: Sequence[str]) -> set[str]:
    """Which of ``paths`` (which need not exist) match the protected set."""
    return match_paths_texts(git, pattern_texts(repo), paths, base=repo.state_dir / "scratch")


def match_paths_texts(
    git: Git, texts: Sequence[bytes], paths: Sequence[str], *, base: Path | None = None
) -> set[str]:
    """Like ``match_paths`` but the pattern sets are given as contents (for example the
    ``.nbp-safe`` of HEAD or of the index). Each text is evaluated on its own and the results
    are unioned, so a negation in one can never unprotect what another protects."""
    return _union(match_paths_each(git, texts, paths, base=base))


def _union(sets: Sequence[set[str]]) -> set[str]:
    out: set[str] = set()
    for item in sets:
        out |= item
    return out


_PREFIXED = re.compile(r"\Av(\d+)/(.*)\Z", re.DOTALL)


def _check_path(path: str) -> None:
    """A path to evaluate must be a clean, repository-relative one: it is evaluated below a
    directory of a scratch repository, and ``..`` or ``.`` (or, on Windows, a backslash version of
    them) would climb out of it and read as "not protected"."""
    for form in (path, path.replace("\\", "/")):
        body = form[:-1] if form.endswith("/") else form  # ``dir/`` is a directory
        if (
            not body
            or body.startswith("/")
            or any(part in ("", ".", "..") for part in body.split("/"))
        ):
            raise GitError("refusing to evaluate a path that is not a clean relative path")
    if "\0" in path:
        raise GitError("refusing to evaluate a path with a NUL byte")


def match_paths_each(
    git: Git, texts: Sequence[bytes], paths: Sequence[str], *, base: Path | None = None
) -> list[set[str]]:
    """For each pattern set (given as text; it is normalized here, see ``normalize_pattern_text``)
    which of ``paths`` it matches, evaluated by git itself with ONE ``check-ignore`` run for all
    the sets: set ``n`` is written as the ``.gitignore`` of its own directory ``v<n>/`` of a
    scratch repository and every path is asked below ``v<n>/``, so the sets stay independent
    (a negation of one never touches another) and the cost does not grow with their number.

    Fails closed: ``check-ignore`` answers 0 (something matched) or 1 (nothing did); any other
    status, an unexpected answer, a path that is not a clean relative one, or a scratch repository
    that cannot be created raises ``GitError``, and the callers block. It never reads as "nothing
    is protected". The scratch repository lives inside the repository's own ``.git/nbp-safe`` (the
    pattern texts may hold names, and the system temp directory is not a place for them) and runs
    with a clean git environment, so a hook's ``GIT_DIR`` cannot point it at the real
    repository."""
    results: list[set[str]] = [set() for _ in texts]
    if not paths or not texts:
        return results
    for path in paths:
        _check_path(path)
    unique = list(dict.fromkeys(paths))
    with _scratch_dir(git, base) as scratch:
        scratch_git = git.clean(scratch)
        scratch_git.run("init", "--quiet", "--template=", str(scratch))
        git_dir = scratch / ".git"
        empty = scratch / "no-excludes"
        empty.write_bytes(b"")  # keeps the user's global excludes (core.excludesFile) out of it
        for number, text in enumerate(texts):
            directory = scratch / f"v{number}"
            directory.mkdir()
            (directory / ".gitignore").write_bytes(normalize_pattern_text(text))
        payload = b"".join(
            f"v{number}/".encode() + path.encode("utf-8", "surrogateescape") + b"\0"
            for number in range(len(texts))
            for path in unique
        )
        code, out, _err = scratch_git.run_status(
            f"--git-dir={git_dir}",
            f"--work-tree={scratch}",
            "-c",
            f"core.excludesFile={empty.as_posix()}",
            "check-ignore",
            "--no-index",
            "-z",
            "--stdin",
            input=payload,
        )
    if code not in (0, 1):
        raise GitError(f"git check-ignore failed ({code}); refusing to guess")
    for item in split_z(out):
        found = _PREFIXED.match(item)
        if found is None or int(found.group(1)) >= len(results):
            raise GitError("git check-ignore gave an answer that was not asked for; refusing")
        results[int(found.group(1))].add(found.group(2))
    return results


def _candidates(git: Git, texts: Sequence[bytes], mode: str, base: Path) -> list[str]:
    """A superset of the files (``-o`` untracked, ``-c`` tracked) that any of the pattern sets
    matches, found with ONE ``ls-files`` run over the positive lines of all of them (dropping the
    negations can only match more); ``match_paths_each`` then decides exactly."""
    positives: dict[str, None] = {}
    for text in texts:
        for line in lines_of(text):
            if is_positive(line):
                positives[line] = None
    if not positives:
        return []
    with _scratch_dir(git, base) as scratch:
        wide = scratch / "positives"
        wide.write_bytes(_join(list(positives)))
        out = git.run("ls-files", "-z", mode, "-i", "-X", str(wide))
    return split_z(out)


@contextlib.contextmanager
def _scratch_dir(git: Git, base: Path | None = None) -> Iterator[Path]:
    root = base if base is not None else _scratch_base(git)
    root.mkdir(parents=True, exist_ok=True)
    _sweep_stale_scratch(root)
    scratch = Path(tempfile.mkdtemp(prefix=SCRATCH_PREFIX, dir=root))
    try:
        yield scratch
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


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
        negated = _negated_at_the_end(older)
        for line in older:
            if is_positive(line) and line not in negated:
                extras[line] = None
    lines.extend(extras)
    lines.extend(line for line in read_patterns(_local_path(repo)) if not line.startswith("!"))
    lines.extend(MANAGED_SUFFIX_PATTERNS)
    lines.extend(f"!/{name}" for name in EXEMPT_PATHS)
    return [_escape_markers(line) for line in lines]


def _negated_at_the_end(lines: Sequence[str]) -> set[str]:
    """Positive lines that a negation of the SAME text follows their last occurrence: the version
    itself ends up not protecting them (``keys/``, ``!keys/``). ``keys/``, ``!keys/``, ``keys/``
    protects, so ``keys/`` is not in the set."""
    negated: set[str] = set()
    for line in lines:
        if is_positive(line):
            negated.discard(line)
        else:
            negated.add(line[1:])
    return negated


def _escape_markers(line: str) -> str:
    r"""A pattern line that contains one of the block markers would be read as a marker by anything
    that looks for them; the first ``<``/``>`` of the marker is backslash-escaped (git reads ``\<``
    as ``<``, so the pattern means the same) to keep the markers unique to the lines we write."""
    for marker in (BLOCK_BEGIN, BLOCK_END):
        if marker in line:
            line = line.replace(marker, marker[:2] + "\\" + marker[2:])
    return line


def render_block(lines: Sequence[str]) -> str:
    return f"{BLOCK_BEGIN}\n{terminated(lines)}{BLOCK_END}\n"


def _marker_line(text: str, marker: str, start: int) -> tuple[int, int] | None:
    """Span ``(begin, end)`` of the first line at or after ``start`` that IS ``marker`` (the whole
    line, ignoring a CR before its newline; ``end`` is after the newline). A marker that is only
    part of a line (a pattern such as ``x# <<< ...``) is not a marker."""
    position = start
    while position <= len(text):
        newline = text.find("\n", position)
        stop = len(text) if newline == -1 else newline
        if text[position:stop].rstrip("\r") == marker:
            return position, stop + 1 if newline != -1 else stop
        if newline == -1:
            return None
        position = newline + 1
    return None


def _split_block(text: str) -> tuple[str, str] | None:
    """Return (text before block, text after block) or None when there is no block. The markers
    are whole lines."""
    begin = _marker_line(text, BLOCK_BEGIN, 0)
    if begin is None:
        return None
    end = _marker_line(text, BLOCK_END, begin[1])
    if end is None:
        return text[: begin[0]], ""  # unterminated block: everything after BEGIN is ours
    return text[: begin[0]], text[end[1] :]


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
    lines.extend(_current_lines(repo))
    lines.extend(MANAGED_SUFFIX_PATTERNS)
    return [_escape_markers(line) for line in lines]


def install_gitignore_block(repo: Repo) -> bool:
    return _install_block(gitignore_path(repo), gitignore_lines(repo))


def remove_gitignore_block(repo: Repo) -> bool:
    return _remove_block(gitignore_path(repo))


def has_gitignore_block(repo: Repo) -> bool:
    return _split_block(_read_text(gitignore_path(repo))) is not None


def cleanup_tmp(path: Path) -> None:
    with contextlib.suppress(OSError):
        path.unlink()
