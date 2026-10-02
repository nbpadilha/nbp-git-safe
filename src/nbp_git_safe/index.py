# SPDX-License-Identifier: MIT
"""Index model and validation (the structural half of ``docs/FORMAT.md`` section 6).

The index maps random file ids to real (POSIX, NFC) paths plus metadata. It is decrypted only by
the key agent; this module validates what comes out of it BEFORE anything touches the working
tree: a malicious or corrupted index must never be able to write outside the protected set.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from nbp_git_safe import crypto

INDEX_VERSION = 2  # 2: seq and prev (rollback chain), see docs/FORMAT.md section 6
MAX_SEQ = 1 << 53
MAX_PATH_LEN = 1024
MAX_COMPONENT_LEN = 255
MODES = ("100644", "100755")

_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_MAC_RE = re.compile(r"^[0-9a-f]{64}$")
_DIGEST_RE = _MAC_RE
_FORBIDDEN_CHARS = set('<>:"|?*\\')
_WIN_RESERVED = {"con", "prn", "aux", "nul", "conin$", "conout$"}
_WIN_RESERVED |= {f"com{i}" for i in "123456789¹²³"}
_WIN_RESERVED |= {f"lpt{i}" for i in "123456789¹²³"}
# Names git or this tool treats specially at any depth; a vault entry may never create them.
_FORBIDDEN_NAMES = {".gitattributes", ".gitignore", ".gitmodules", ".nbp-safe", ".nbp-safe.config"}
_FORBIDDEN_SUFFIXES = (".nbp-tmp", ".nbp-theirs")
_GIT_SHORT_RE = re.compile(r"^git~\d+$")


class IndexValidationError(Exception):
    """The index (or a path in it) is not acceptable. Messages never contain the path itself."""


@dataclass(frozen=True)
class Entry:
    path: str
    mode: str
    size: int
    mac: str  # hex HMAC-SHA256 of the content
    created: int
    updated: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "mode": self.mode,
            "size": self.size,
            "mac": self.mac,
            "created": self.created,
            "updated": self.updated,
        }


def normalize_path(path: str) -> str:
    return unicodedata.normalize("NFC", path)


def is_valid_file_id(file_id: object) -> bool:
    return isinstance(file_id, str) and _ID_RE.match(file_id) is not None


def validate_path(path: object) -> str:
    """Return ``path`` if it is a safe, relative, NFC POSIX path; raise otherwise."""
    if not isinstance(path, str) or not path or len(path) > MAX_PATH_LEN:
        raise IndexValidationError("invalid path in index")
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        raise IndexValidationError("invalid path in index") from None
    if not unicodedata.is_normalized("NFC", path):
        raise IndexValidationError("path is not NFC-normalized")
    if path.startswith("/"):
        raise IndexValidationError("absolute path in index")
    for ch in path:
        if ord(ch) < 0x20 or ord(ch) == 0x7F or ch in _FORBIDDEN_CHARS:
            raise IndexValidationError("forbidden character in path")
    for part in path.split("/"):
        _validate_component(part)
    return path


def _validate_component(part: str) -> None:
    if not part or part in (".", "..") or len(part) > MAX_COMPONENT_LEN:
        raise IndexValidationError("invalid path component in index")
    if part.endswith((".", " ")):
        raise IndexValidationError("path component ends with a dot or space")
    folded = part.casefold()
    if folded == ".git" or _GIT_SHORT_RE.match(folded):
        raise IndexValidationError("path touches .git")
    if folded.split(".", 1)[0].rstrip(" ") in _WIN_RESERVED:
        raise IndexValidationError("reserved Windows device name in path")
    if folded in _FORBIDDEN_NAMES or folded.endswith(_FORBIDDEN_SUFFIXES):
        raise IndexValidationError("reserved file name in path")


def collision_key(path: str) -> str:
    return unicodedata.normalize("NFC", path.casefold())


def check_collisions(paths: Iterable[str]) -> None:
    """Reject case-insensitive duplicates and file/directory conflicts (``a`` vs ``a/b``)."""
    seen: dict[str, str] = {}
    dirs: set[str] = set()
    for path in paths:
        key = collision_key(path)
        if key in seen:
            raise IndexValidationError("paths collide on case-insensitive filesystems")
        seen[key] = path
        parts = key.split("/")
        for i in range(1, len(parts)):
            dirs.add("/".join(parts[:i]))
    if dirs & seen.keys():
        raise IndexValidationError("a path is both a file and a directory")


@dataclass
class Index:
    """Parsed and structurally validated index."""

    key_id: str
    entries: dict[str, Entry]
    seq: int = 0  # strictly increasing along the commit chain (0: not written yet)
    prev: str = ""  # digest of the first parent's index ("" for a root commit)

    @classmethod
    def empty(cls, key_id: bytes) -> Index:
        return cls(key_id.hex(), {})

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": INDEX_VERSION,
            "key_id": self.key_id,
            "entries": {fid: e.to_dict() for fid, e in sorted(self.entries.items())},
            "seq": self.seq,
            "prev": self.prev,
        }

    def digest(self) -> str:
        """SHA-256 of the canonical JSON of this index: what the next commit's ``prev`` holds."""
        return hashlib.sha256(crypto.canonical_json(self.to_dict())).hexdigest()

    def successor(self, entries: dict[str, Entry], *, other_parents: Iterable[int] = ()) -> Index:
        """The index of a child commit: same key, new entries, ``seq`` above this one and above
        every other parent's, ``prev`` pointing at this one."""
        seq = max(self.seq, *other_parents) + 1 if other_parents else self.seq + 1
        return Index(self.key_id, entries, seq, self.digest() if self.seq else "")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], expected_key_id: bytes) -> Index:
        if set(data) != {"v", "key_id", "entries", "seq", "prev"} or data["v"] != INDEX_VERSION:
            raise IndexValidationError("unsupported index structure")
        seq, prev = data["seq"], data["prev"]
        if isinstance(seq, bool) or not isinstance(seq, int) or not 1 <= seq < MAX_SEQ:
            raise IndexValidationError("invalid sequence number in index")
        if not isinstance(prev, str) or (prev and _DIGEST_RE.match(prev) is None):
            raise IndexValidationError("invalid chain link in index")
        if data["key_id"] != expected_key_id.hex():
            raise IndexValidationError("index key_id does not match the key")
        raw_entries = data["entries"]
        if not isinstance(raw_entries, dict):
            raise IndexValidationError("unsupported index structure")
        entries: dict[str, Entry] = {}
        for fid, raw in raw_entries.items():
            if not is_valid_file_id(fid) or not isinstance(raw, dict):
                raise IndexValidationError("invalid entry in index")
            entries[fid] = _entry_from_dict(raw)
        check_collisions(e.path for e in entries.values())
        return cls(data["key_id"], entries, seq, prev)

    def by_path(self) -> dict[str, str]:
        return {e.path: fid for fid, e in self.entries.items()}


def _int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise IndexValidationError("invalid entry in index")
    return value


def _entry_from_dict(raw: Mapping[str, Any]) -> Entry:
    if set(raw) != {"path", "mode", "size", "mac", "created", "updated"}:
        raise IndexValidationError("invalid entry in index")
    mode, mac = raw["mode"], raw["mac"]
    if mode not in MODES or not isinstance(mac, str) or not _MAC_RE.match(mac):
        raise IndexValidationError("invalid entry in index")
    return Entry(
        path=validate_path(raw["path"]),
        mode=mode,
        size=_int(raw["size"]),
        mac=mac,
        created=_int(raw["created"]),
        updated=_int(raw["updated"]),
    )


def validate_against_protected(
    index: Index, matcher: Callable[[list[str]], set[str]], tracked: Iterable[str] = ()
) -> None:
    """Every path must be in the protected set and must not be a file tracked on the main branch."""
    paths = [e.path for e in index.entries.values()]
    allowed = matcher(paths)
    if any(p not in allowed for p in paths):
        raise IndexValidationError("index contains a path outside the protected set")
    tracked_keys = {collision_key(t) for t in tracked}
    if any(collision_key(p) in tracked_keys for p in paths):
        raise IndexValidationError("index contains a path that is tracked on the main branch")
