# SPDX-License-Identifier: MIT
"""Minimal rotating log of the tray: ``tray.log`` in the private per-user state directory.

One line per event: time, event name, the position of the repository in the registry, whole numbers
and short codes. It never receives a path, a file name, a message of an exception or anything of a
key: ``event`` and the field values are checked against a tiny alphabet, and anything else is
written as ``?``. Writing the log can never raise (a log that cannot be written is silent).
"""

from __future__ import annotations

import contextlib
import os
import re
import threading
import time
from pathlib import Path

LOG_NAME = "tray.log"
MAX_BYTES = 64 * 1024  # then the file becomes tray.log.1 (replacing the previous one)
_WORD = re.compile(r"[a-z0-9][a-z0-9_.-]{0,39}")


def _clean(value: object) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and _WORD.fullmatch(value):
        return value
    return "?"


class TrayLog:
    def __init__(self, path: Path | None, *, max_bytes: int = MAX_BYTES) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self._lock = threading.Lock()

    def write(self, event: str, repo: int | None = None, **fields: object) -> str:
        """Append one line; returns it (for tests). ``repo`` is the 1-based registry position."""
        parts = [time.strftime("%Y-%m-%dT%H:%M:%S"), _clean(event)]
        if repo is not None:
            parts.append(f"repo={_clean(repo)}")
        parts += [f"{_clean(k)}={_clean(v)}" for k, v in sorted(fields.items())]
        line = " ".join(parts)
        if self.path is not None:
            with self._lock, contextlib.suppress(OSError):
                self._append(line)
        return line

    def _append(self, line: str) -> None:
        assert self.path is not None
        with contextlib.suppress(OSError):
            if self.path.stat().st_size > self.max_bytes:
                os.replace(self.path, self.path.with_name(self.path.name + ".1"))
        with open(self.path, "ab") as handle:
            handle.write(line.encode("ascii") + b"\n")
