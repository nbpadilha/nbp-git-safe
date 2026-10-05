# SPDX-License-Identifier: MIT
"""Small per-user state files (the registry of repositories, the tray configuration): crash-safe
replacement, a cross-process lock and a read that follows no link.

These files live in the verified private base directory of the agent state (``agent.private_root``).
They never hold keys, plaintext or the name of a protected file.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import sys
import time
from collections.abc import Iterator
from pathlib import Path

from nbp_git_safe import agent, plainfile

LOCK_WAIT = 15.0  # seconds a writer waits for another writer
LOCK_STALE = 120.0  # a lock file older than this belongs to a dead process
LOCK_STEP = 0.01
_BINARY = getattr(os, "O_BINARY", 0)


class StateFileError(Exception):
    """A state file could not be read, locked or written. Messages carry no file content."""


def read_small(path: Path, max_size: int) -> bytes | None:
    """The content of a plain regular file (``None`` when absent). A link, a special file or an
    oversized file raises ``plainfile.UnsafeFileError`` before a byte is read."""
    if not plainfile.check_plain_file(path, max_size=max_size):
        return None
    try:
        data = agent.retry_sharing(path.read_bytes)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise StateFileError(f"cannot read {path.name} ({exc.strerror or 'I/O error'})") from exc
    if len(data) > max_size:
        raise plainfile.UnsafeFileError(f"{path.name} is larger than {max_size} bytes")
    return data


def atomic_write(path: Path, data: bytes) -> None:
    """Write ``data`` to a temporary file next to ``path`` (flushed and ``fsync``ed) and replace
    ``path`` with it, so a reader sees the old or the new content and never half of one."""
    tmp = path.with_name(f"{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        agent.retry_sharing(lambda: os.replace(tmp, path))
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    if sys.platform != "win32":  # make the rename itself durable (best effort)
        with contextlib.suppress(OSError):
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)


@contextlib.contextmanager
def file_lock(path: Path, *, wait: float = LOCK_WAIT, stale: float = LOCK_STALE) -> Iterator[None]:
    """Exclusive lock by an exclusively created file. Contenders retry for ``wait`` seconds; a lock
    older than ``stale`` seconds is taken over (its owner died)."""
    deadline = time.monotonic() + wait
    while True:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY, 0o600)
        except (FileExistsError, PermissionError):
            # PermissionError: Windows reports a lock file that is being deleted this way
            with contextlib.suppress(OSError):
                if time.time() - path.stat().st_mtime > stale:
                    path.unlink()
                    continue
            if time.monotonic() >= deadline:
                raise StateFileError("another process is writing this file; try again") from None
            time.sleep(LOCK_STEP)
            continue
        os.close(fd)
        break
    try:
        yield
    finally:
        with contextlib.suppress(OSError):
            path.unlink()
