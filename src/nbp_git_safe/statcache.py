# SPDX-License-Identifier: MIT
"""Stat cache: skip re-hashing files that did not change.

Stored in ``.git/nbp-safe/statcache``. The ``.git`` directory must not contain names or contents,
so entries are keyed by an HMAC of the path (computed by the key agent) and hold only
``[size, mtime_ns, content-mac]``. The cache is bound to a ``key_id``: a different key discards it.
Entries whose mtime is within ``RACY_NS`` of the moment they are recorded are not cached (same
"racily clean" reasoning git's own index uses).
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
from pathlib import Path

RACY_NS = 2_000_000_000
VERSION = 1


def path_key_input(path: str) -> bytes:
    """Bytes the agent MACs to obtain the cache key of ``path``."""
    return b"nbp-git-safe/path\x00" + path.encode("utf-8", "surrogateescape")


class StatCache:
    def __init__(self, path: Path, key_id_hex: str) -> None:
        self.path = path
        self.key_id = key_id_hex
        self._old: dict[str, list[object]] = {}
        self._new: dict[str, list[object]] = {}
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_bytes().decode("utf-8"))
        except (OSError, ValueError):
            return
        if (
            isinstance(data, dict)
            and data.get("v") == VERSION
            and data.get("key_id") == self.key_id
            and isinstance(data.get("entries"), dict)
        ):
            self._old = data["entries"]

    def get(self, key: str, size: int, mtime_ns: int) -> str | None:
        entry = self._old.get(key)
        if (
            isinstance(entry, list)
            and len(entry) == 3
            and entry[0] == size
            and entry[1] == mtime_ns
            and isinstance(entry[2], str)
        ):
            self._new[key] = entry
            return entry[2]
        return None

    def put(self, key: str, size: int, mtime_ns: int, mac_hex: str, now_ns: int) -> None:
        if abs(now_ns - mtime_ns) < RACY_NS:
            self._new.pop(key, None)
            return
        self._new[key] = [size, mtime_ns, mac_hex]

    def save(self) -> None:
        """Persist only the entries used or recorded in this run (drops stale ones).

        Best effort: the cache is an optimisation, so a lost race with another process (Windows
        refuses to replace a file another process has open) is silently ignored."""
        payload = json.dumps(
            {"v": VERSION, "key_id": self.key_id, "entries": self._new}, sort_keys=True
        ).encode("ascii")
        tmp = self.path.with_name(f"{self.path.name}.{secrets.token_hex(4)}.tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_bytes(payload)
            os.replace(tmp, self.path)
        except OSError:
            with contextlib.suppress(OSError):
                tmp.unlink()
