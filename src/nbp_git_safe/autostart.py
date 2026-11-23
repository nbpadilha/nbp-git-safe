# SPDX-License-Identifier: MIT
"""Start the tray at login (Windows): one value in ``HKCU\\Software\\Microsoft\\Windows\\
CurrentVersion\\Run``.

Per user, no administrator rights, reversible (``remove`` deletes exactly the value this module
wrote), idempotent. The command is built from absolute paths with no shell involved:
``"<pythonw.exe>" -I -m nbp_git_safe tray`` (``-I``: isolated mode, nothing from the current
directory or the environment is imported into the process). ``winreg`` is imported only when
needed, so this module loads everywhere; the functions raise ``AutostartError`` elsewhere.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "nbp-git-safe-tray"
TRAY_ARGS = ("-I", "-m", "nbp_git_safe", "tray")


class AutostartError(Exception):
    """Autostart cannot be read or changed (messages carry no secret)."""


@dataclass(frozen=True)
class InstallResult:
    action: str  # "installed", "updated" or "unchanged"
    command: str


@dataclass(frozen=True)
class Status:
    installed: bool
    command: str | None = None
    current: bool = False  # the stored command is exactly what ``install`` would write now


def supported() -> bool:
    return sys.platform == "win32"


def _winreg() -> Any:
    if not supported():
        raise AutostartError("autostart is supported on Windows only")
    import winreg

    return winreg


def tray_executable(executable: str | None = None) -> str:
    """Absolute path of the interpreter without a console window (``pythonw.exe`` next to the
    running ``python.exe``, which is the one of the ``uv tool`` / virtual environment)."""
    raw = executable if executable is not None else sys.executable
    if not raw:
        raise AutostartError("cannot find the running Python interpreter")
    exe = Path(raw).absolute()
    if exe.name.lower() == "python.exe":
        windowless = exe.with_name("pythonw.exe")
        if windowless.is_file():
            exe = windowless
    if not exe.is_file():
        raise AutostartError("the Python interpreter was not found on disk")
    text = str(exe)
    if '"' in text or "%" in text:
        raise AutostartError("the interpreter path has a quote or a percent sign; not supported")
    return text


def exposure_problem(program: str) -> str | None:
    """Why the program started at login (or the folder it sits in, where a replaced library or
    program would be run instead) can be changed by another account; ``None`` when only the user,
    SYSTEM and Administrators can. Windows only (the answer comes from the ACLs)."""
    from nbp_git_safe import winsec

    path = Path(program)
    for target, what in ((path, "the program"), (path.parent, "its folder")):
        problem = winsec.write_exposure(target)
        if problem is not None:
            return f"{what} {problem}"
    return None


def program_of(command: str) -> str | None:
    """The executable named by a Run-key command line (quoted or not)."""
    text = command.strip()
    if text.startswith('"'):
        end = text.find('"', 1)
        return text[1:end] if end > 1 else None
    return text.split(" ", 1)[0] or None


def stored_program_missing(status: Status) -> bool:
    """The stored command names a program that is no longer on disk (a moved or deleted
    environment): the value is dead and every login would fail silently."""
    program = program_of(status.command) if status.installed and status.command else None
    return program is not None and not os.path.isfile(program)


def command_line(executable: str | None = None) -> str:
    """The Run-key value, quoted for paths with spaces (``list2cmdline`` rules)."""
    return subprocess.list2cmdline([tray_executable(executable), *TRAY_ARGS])


def status(key_path: str = RUN_KEY, *, command: str | None = None) -> Status:
    reg = _winreg()
    try:
        with reg.OpenKey(reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_QUERY_VALUE) as key:
            value, kind = reg.QueryValueEx(key, VALUE_NAME)
    except FileNotFoundError:
        return Status(False)
    except OSError as exc:
        raise AutostartError(f"cannot read the Run key ({exc.strerror})") from None
    if kind != reg.REG_SZ or not isinstance(value, str):
        return Status(True, None, False)
    try:
        wanted = command if command is not None else command_line()
    except AutostartError:
        wanted = None
    return Status(True, value, value == wanted)


def install(
    key_path: str = RUN_KEY, *, command: str | None = None, allow_writable: bool = False
) -> InstallResult:
    """Write the Run value. Without an explicit ``command`` the interpreter that is running is
    registered, and is REFUSED (``AutostartError``) when it or its folder can be changed by
    another account (``allow_writable`` overrides, knowingly): anything started at every login
    with the user's rights is only as safe as who can replace it."""
    reg = _winreg()
    wanted = command if command is not None else command_line()
    if command is None and not allow_writable:
        program = program_of(wanted)
        problem = exposure_problem(program) if program else None
        if problem is not None:
            raise AutostartError(
                f"not installed: {problem} (another account could replace what runs at every "
                "login); use an interpreter in a folder only you control, or pass "
                "--allow-writable to install it anyway"
            )
    try:
        with reg.CreateKeyEx(
            reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_SET_VALUE | reg.KEY_QUERY_VALUE
        ) as key:
            try:
                existing, kind = reg.QueryValueEx(key, VALUE_NAME)
            except FileNotFoundError:
                existing, kind = None, None
            if existing == wanted and kind == reg.REG_SZ:
                return InstallResult("unchanged", wanted)
            reg.SetValueEx(key, VALUE_NAME, 0, reg.REG_SZ, wanted)
    except OSError as exc:
        raise AutostartError(f"cannot write the Run key ({exc.strerror})") from None
    return InstallResult("installed" if existing is None else "updated", wanted)


def remove(key_path: str = RUN_KEY) -> bool:
    """Delete the value. True when it existed."""
    reg = _winreg()
    try:
        with reg.OpenKey(reg.HKEY_CURRENT_USER, key_path, 0, reg.KEY_SET_VALUE) as key:
            reg.DeleteValue(key, VALUE_NAME)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise AutostartError(f"cannot change the Run key ({exc.strerror})") from None
    return True
