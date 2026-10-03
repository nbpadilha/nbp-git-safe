# SPDX-License-Identifier: MIT
"""Reading the small configuration files of the working tree without following anything.

``.nbp-safe`` and ``.nbp-safe.config`` are files a collaborator can commit. A symbolic link (or a
junction, or any other reparse point) in their place would make this tool read a file OUTSIDE the
repository and copy its content into the pattern memory and ``.git/info/exclude``; on POSIX a link
to ``/dev/zero`` or a FIFO would hang every hook. So the file is inspected with ``lstat`` first and
is read only when it is a regular, plain, reasonably small file; anything else fails closed with a
message, and nothing is read.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from nbp_git_safe.gitutil import GitError

MAX_CONFIG_FILE_BYTES = 1 << 20  # 1 MiB: a pattern or config file is a few lines
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class UnsafeFileError(GitError):
    """A configuration file is not a plain regular file (or is too large): it is not read."""


def _problem(st: os.stat_result, max_size: int) -> str | None:
    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & (
        _FILE_ATTRIBUTE_REPARSE_POINT
    ):
        return "is a symbolic link or a reparse point"
    if not stat.S_ISREG(st.st_mode):
        return "is not a regular file"
    if st.st_size > max_size:
        return f"is larger than {max_size} bytes"
    return None


def check_plain_file(path: Path, *, max_size: int = MAX_CONFIG_FILE_BYTES) -> bool:
    """``False`` when ``path`` does not exist; ``True`` when it is a plain regular file within the
    size limit; ``UnsafeFileError`` for anything else. Reads nothing."""
    try:
        st = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError as exc:
        raise UnsafeFileError(
            f"cannot inspect {path.name} ({exc.strerror or 'I/O error'})"
        ) from exc
    why = _problem(st, max_size)
    if why is not None:
        raise UnsafeFileError(f"{path.name} {why}; refusing to read it")
    return True


def read_plain_file(path: Path, *, max_size: int = MAX_CONFIG_FILE_BYTES) -> bytes | None:
    """The content of a plain regular file, or ``None`` when it does not exist. Anything that is
    not a plain regular file within ``max_size`` raises ``UnsafeFileError`` before a byte is read;
    the open itself refuses to follow a link and never blocks on a FIFO."""
    if not check_plain_file(path, max_size=max_size):
        return None
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise UnsafeFileError(f"cannot read {path.name} ({exc.strerror or 'I/O error'})") from exc
    try:
        why = _problem(os.fstat(fd), max_size)
        if why is not None:  # replaced between the lstat and the open
            raise UnsafeFileError(f"{path.name} {why}; refusing to read it")
        data = b""
        while len(data) <= max_size:
            chunk = os.read(fd, max_size + 1 - len(data))
            if not chunk:
                break
            data += chunk
        if len(data) > max_size:
            raise UnsafeFileError(f"{path.name} is larger than {max_size} bytes; refusing it")
        return data
    except OSError as exc:
        raise UnsafeFileError(f"cannot read {path.name} ({exc.strerror or 'I/O error'})") from exc
    finally:
        os.close(fd)
