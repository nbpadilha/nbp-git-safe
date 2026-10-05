# SPDX-License-Identifier: MIT
"""Small per-user state files (the registry of repositories, the tray configuration): crash-safe
replacement, a cross-process lock and a read that follows no link.

These files live in the verified private base directory of the agent state (``agent.private_root``).
They never hold keys, plaintext or the name of a protected file.

The writer lock is an operating-system lock on an (empty) lock file, not the existence of the file:
the system releases it when its holder dies, so there is no "stale lock" to guess about (a guess two
contenders could make at the same moment, both taking the lock) and nothing to delete.
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


def _try_lock(fd: int) -> bool:
    """Take the exclusive lock on the lock file without waiting (``False``: someone holds it)."""
    try:
        if sys.platform == "win32":
            import msvcrt

            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # type: ignore[attr-defined]
    except OSError:
        return False
    return True


def _unlock(fd: int) -> None:
    if sys.platform == "win32":
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]
    # POSIX: ``flock`` is released by closing the descriptor


@contextlib.contextmanager
def file_lock(path: Path, *, wait: float = LOCK_WAIT) -> Iterator[None]:
    """Exclusive lock: an operating-system lock on ``path`` (created empty, private, and left in
    place: deleting it would race with the next holder). Contenders retry for ``wait`` seconds. The
    system drops the lock if its holder dies, so a crashed writer never blocks the next one."""
    deadline = time.monotonic() + wait
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | _BINARY, 0o600)
    except OSError as exc:
        raise StateFileError(f"cannot open the lock file ({exc.strerror or 'I/O error'})") from exc
    try:
        while not _try_lock(fd):
            if time.monotonic() >= deadline:
                raise StateFileError("another process is writing this file; try again")
            time.sleep(LOCK_STEP)
        try:
            yield
        finally:
            with contextlib.suppress(OSError):
                _unlock(fd)
    finally:
        os.close(fd)
