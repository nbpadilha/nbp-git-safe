# SPDX-License-Identifier: MIT
"""Per-user registry of repositories (discovery only).

A small JSON file in the private per-user state directory (``repos.json`` next to the agent state:
``%LOCALAPPDATA%\\nbp-git-safe`` on Windows) lists the repositories ``init`` was run in, so that
``status --all``, ``unlock --all`` and the tray know where to look. It holds **absolute canonical
paths and dates and nothing else**: no key, no configuration, no file name of a protected file.

The registry is not a source of authority. Every operation still reads the configuration of the
repository itself (the local ``.git/config``, where ``keyCommand`` lives); nothing in this file is
ever executed or interpreted as a command. Reading is strict and fails safe: a malformed file, a
wrong type, a relative path, a ``..`` component, a UNC or device path gives an ignored entry and a
warning, never an error that stops the commands and never a guess. A damaged file is moved to a
``.bak`` file before the next write, so it is never silently overwritten.
"""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from nbp_git_safe import agent, plainfile, statefile

REGISTRY_NAME = "repos.json"
LOCK_NAME = "repos.json.lock"
VERSION = 1
MAX_ENTRIES = 1000
MAX_FILE_BYTES = 1 << 20
MAX_PATH_CHARS = 4096
MAX_DATE = 4_102_444_800  # 2100-01-01: anything later is not a date this tool wrote
_WINDOWS_BAD_CHARS = re.compile(r'[<>"|?*:\x00-\x1f]')


class RegistryError(Exception):
    """The registry cannot be read or changed (messages carry no file content)."""


@dataclass(frozen=True)
class Entry:
    path: str  # absolute, canonical
    added: int  # seconds since the epoch


@dataclass
class Loaded:
    entries: list[Entry] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    damaged: bool = False  # something was dropped or the whole file was unusable
    unsupported: bool = False  # written by a newer version: read-only for this one


def registry_path(root: Path) -> Path:
    return root / REGISTRY_NAME


def key_of(path: str | os.PathLike[str]) -> str:
    """Comparison key of a path: case-folded on Windows, separators normalised."""
    return os.path.normcase(os.path.normpath(os.fspath(path)))


def canonical(path: str | os.PathLike[str]) -> str:
    """Absolute path with links and junctions resolved (what the registry stores)."""
    return os.path.normpath(os.path.realpath(os.path.abspath(os.fspath(path))))


def path_problem(text: object) -> str | None:
    """Why ``text`` is not an acceptable registry path, or ``None``. Pure (touches no disk)."""
    if not isinstance(text, str) or not text:
        return "not a text path"
    if len(text) > MAX_PATH_CHARS:
        return "path too long"
    if "\x00" in text or any(ord(c) < 32 for c in text):
        return "control character in the path"
    if os.name == "nt":
        drive, rest = os.path.splitdrive(text)
        if text.startswith(("\\\\", "//")) or len(drive) != 2 or drive[1] != ":":
            return "not a local drive path (UNC, device and relative paths are not supported)"
        if not rest.startswith("\\"):
            return "not an absolute path"
        if _WINDOWS_BAD_CHARS.search(rest):
            return "character not allowed in a path"
        parts = rest.replace("/", "\\").split("\\")
    else:
        if not os.path.isabs(text) or text.startswith("//"):
            return "not an absolute path"
        parts = text.split("/")
    if ".." in parts or "." in parts:
        return "relative component in the path"
    if os.path.normpath(text) != text:
        return "path is not in canonical form"
    return None


def _entry_from(raw: object) -> Entry | str:
    """An ``Entry`` or the reason the raw item is refused."""
    if not isinstance(raw, dict):
        return "an entry is not an object"
    problem = path_problem(raw.get("path"))
    if problem:
        return f"an entry was ignored: {problem}"
    added = raw.get("added")
    if isinstance(added, bool) or not isinstance(added, int) or not 0 <= added <= MAX_DATE:
        return "an entry was ignored: bad date"
    return Entry(str(raw["path"]), added)


def parse(raw: bytes) -> Loaded:
    """Strict parser. Never raises, never executes anything."""
    result = Loaded()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        result.warnings.append("the registry is not valid JSON; ignored")
        result.damaged = True
        return result
    if not isinstance(data, dict) or not isinstance(data.get("repos"), list):
        result.warnings.append("the registry has an unexpected shape; ignored")
        result.damaged = True
        return result
    version = data.get("version")
    if isinstance(version, bool) or not isinstance(version, int):
        result.warnings.append("the registry has no valid version; ignored")
        result.damaged = True
        return result
    if version != VERSION:
        result.warnings.append(f"the registry has version {version}, this tool knows {VERSION}")
        result.unsupported = True
        return result
    seen: set[str] = set()
    items = data["repos"]
    if len(items) > MAX_ENTRIES:
        result.warnings.append(f"the registry has more than {MAX_ENTRIES} entries; extras ignored")
        result.damaged = True
        items = items[:MAX_ENTRIES]
    for item in items:
        entry = _entry_from(item)
        if isinstance(entry, str):
            result.warnings.append(entry)
            result.damaged = True
            continue
        key = key_of(entry.path)
        if key not in seen:
            seen.add(key)
            result.entries.append(entry)
    return result


def serialize(entries: list[Entry]) -> bytes:
    body = {"version": VERSION, "repos": [{"path": e.path, "added": e.added} for e in entries]}
    return (json.dumps(body, indent=1, ensure_ascii=True) + "\n").encode("ascii")


def _base(*, create: bool) -> Path | None:
    try:
        return agent.private_root(create=create)
    except agent.InsecureStateError as exc:
        raise RegistryError(f"{exc}; the registry is not used") from None
    except OSError as exc:
        raise RegistryError(f"the state directory is not usable ({exc.strerror})") from None


def _read(path: Path) -> tuple[bytes | None, Loaded]:
    """The raw bytes (when readable) and what they parse to."""
    try:
        raw = statefile.read_small(path, MAX_FILE_BYTES)
    except (plainfile.UnsafeFileError, statefile.StateFileError):
        loaded = Loaded(damaged=True)
        loaded.warnings.append("the registry file is not a plain readable file; ignored")
        return None, loaded
    if raw is None:
        return None, Loaded()
    return raw, parse(raw)


def load() -> Loaded:
    """The registered repositories (read-only; creates nothing). Problems come back as warnings;
    a state directory that is not private gives an empty registry and a warning."""
    try:
        base = _base(create=False)
    except RegistryError as exc:
        return Loaded(warnings=[str(exc)], damaged=True)
    if base is None:
        return Loaded()
    return _read(registry_path(base))[1]


def _free_backup(path: Path) -> Path:
    for n in range(1, 1000):
        candidate = path.with_name(path.name + (".bak" if n == 1 else f".{n}.bak"))
        if not os.path.lexists(candidate):
            return candidate
    raise RegistryError("too many backups of the registry; remove the old .bak files")


def _write(base: Path, loaded: Loaded, entries: list[Entry]) -> None:
    path = registry_path(base)
    if loaded.unsupported:
        raise RegistryError("the registry was written by a newer version; not modified")
    if loaded.damaged and os.path.lexists(path):
        backup = _free_backup(path)
        try:
            os.replace(path, backup)  # keep the damaged file: it is never overwritten silently
        except OSError as exc:
            raise RegistryError(f"cannot back up the damaged registry ({exc.strerror})") from None
    if len(entries) > MAX_ENTRIES:
        raise RegistryError(f"the registry is full ({MAX_ENTRIES} repositories)")
    try:
        statefile.atomic_write(path, serialize(entries))
    except OSError as exc:
        raise RegistryError(f"cannot write the registry ({exc.strerror})") from None


def _modify(change: Callable[[list[Entry]], bool]) -> bool:
    """Read, apply ``change`` (True when it changed something) and write, under the lock. A damaged
    file is rewritten only after it was moved to a ``.bak`` file."""
    base = _base(create=True)
    assert base is not None
    try:
        with statefile.file_lock(base / LOCK_NAME):
            _raw, loaded = _read(registry_path(base))
            entries = list(loaded.entries)
            changed = change(entries)
            if changed or loaded.damaged:
                _write(base, loaded, entries)
            return changed
    except statefile.StateFileError as exc:
        raise RegistryError(str(exc)) from None


def add(path: str | os.PathLike[str], *, now: float | None = None) -> bool:
    """Register a repository by its canonical path. True when it was not registered yet."""
    text = canonical(path)
    problem = path_problem(text)
    if problem:
        raise RegistryError(f"cannot register this path: {problem}")
    stamp = int(time.time() if now is None else now)

    def change(entries: list[Entry]) -> bool:
        if any(key_of(e.path) == key_of(text) for e in entries):
            return False
        entries.append(Entry(text, stamp))
        return True

    return _modify(change)


def remove(path: str | os.PathLike[str]) -> bool:
    """Forget a repository (the folder may no longer exist). True when it was registered."""
    wanted = {key_of(os.path.abspath(path)), key_of(canonical(path))}

    def change(entries: list[Entry]) -> bool:
        kept = [e for e in entries if key_of(e.path) not in wanted]
        if len(kept) == len(entries):
            return False
        entries[:] = kept
        return True

    return _modify(change)


def prune(is_repository: Callable[[str], bool]) -> list[str]:
    """Drop every entry for which ``is_repository`` is false. Returns the dropped paths. The check
    runs outside the lock (it may start git); the removal then applies to what is still listed."""
    gone = [e.path for e in load().entries if not is_repository(e.path)]
    keys = {key_of(p) for p in gone}

    def change(entries: list[Entry]) -> bool:
        kept = [e for e in entries if key_of(e.path) not in keys]
        if len(kept) == len(entries):
            return False
        entries[:] = kept
        return True

    _modify(change)
    return gone
