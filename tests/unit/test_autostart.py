# SPDX-License-Identifier: MIT
"""Autostart: the command line is computed everywhere; the registry part runs on Windows only and
only inside a throw-away key of the current user (never the real Run key)."""

from __future__ import annotations

import contextlib
import subprocess
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from nbp_git_safe import autostart
from nbp_git_safe.autostart import AutostartError

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="the Run key is Windows only")


def test_command_line_quotes_paths_with_spaces(tmp_path: Path) -> None:
    exe = tmp_path / "my tools" / "python.exe"
    exe.parent.mkdir()
    exe.write_bytes(b"")
    plain = autostart.command_line(str(exe))
    assert plain == f'"{exe}" -I -m nbp_git_safe tray'
    assert subprocess.list2cmdline([str(exe)]).startswith('"')


def test_pythonw_is_preferred_when_it_sits_next_to_python(tmp_path: Path) -> None:
    (tmp_path / "python.exe").write_bytes(b"")
    (tmp_path / "pythonw.exe").write_bytes(b"")
    assert autostart.tray_executable(str(tmp_path / "python.exe")).endswith("pythonw.exe")
    assert autostart.tray_executable(str(tmp_path / "pythonw.exe")).endswith("pythonw.exe")


def test_without_pythonw_the_interpreter_itself_is_used(tmp_path: Path) -> None:
    (tmp_path / "python.exe").write_bytes(b"")
    assert autostart.tray_executable(str(tmp_path / "python.exe")).endswith("python.exe")


@pytest.mark.parametrize("name", ['bad"quote', "100%percent"])
def test_unsafe_characters_in_the_path_are_refused(tmp_path: Path, name: str) -> None:
    if sys.platform == "win32" and name.startswith("bad"):
        pytest.skip("a double quote cannot be a file name on Windows")
    exe = tmp_path / name
    exe.write_bytes(b"")
    with pytest.raises(AutostartError, match="quote or a percent"):
        autostart.tray_executable(str(exe))


def test_missing_interpreter_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(AutostartError, match="not found"):
        autostart.tray_executable(str(tmp_path / "nothing.exe"))
    with pytest.raises(AutostartError, match="cannot find"):
        autostart.tray_executable("")


def test_the_real_interpreter_gives_a_runnable_command() -> None:
    command = autostart.command_line()
    assert command.endswith("-I -m nbp_git_safe tray")
    assert "%" not in command


@pytest.mark.skipif(sys.platform == "win32", reason="non-Windows behaviour")
def test_elsewhere_everything_says_unsupported() -> None:
    assert autostart.supported() is False
    for call in (autostart.install, autostart.remove, autostart.status):
        with pytest.raises(AutostartError, match="Windows only"):
            call()


# --------------------------------------------------------------- Windows registry branch


@pytest.fixture
def temp_key() -> Iterator[str]:
    """A private branch of HKCU, removed afterwards: the real Run key is never touched."""
    import winreg

    path = rf"Software\nbp-git-safe-tests\{uuid.uuid4().hex}\Run"
    yield path
    parent = path.rsplit("\\", 1)[0]
    for sub in (path, parent, r"Software\nbp-git-safe-tests"):
        with contextlib.suppress(OSError):
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)


@windows_only
def test_install_status_remove_cycle_is_idempotent(temp_key: str) -> None:
    command = '"C:\\Program Files\\Py\\pythonw.exe" -I -m nbp_git_safe tray'
    assert autostart.status(temp_key, command=command) == autostart.Status(False)
    assert autostart.remove(temp_key) is False  # nothing there, no error
    first = autostart.install(temp_key, command=command)
    assert first == autostart.InstallResult("installed", command)
    assert autostart.install(temp_key, command=command).action == "unchanged"
    status = autostart.status(temp_key, command=command)
    assert status == autostart.Status(True, command, True)
    other = '"D:\\New place\\pythonw.exe" -I -m nbp_git_safe tray'
    assert autostart.install(temp_key, command=other).action == "updated"
    stale = autostart.status(temp_key, command=command)
    assert stale.installed and stale.command == other and not stale.current
    assert autostart.remove(temp_key) is True
    assert autostart.remove(temp_key) is False
    assert autostart.status(temp_key, command=command).installed is False


@windows_only
def test_only_our_value_is_touched(temp_key: str) -> None:
    import winreg

    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, temp_key, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "someone-else", 0, winreg.REG_SZ, "other.exe")
    autostart.install(temp_key, command="x -m y")
    autostart.remove(temp_key)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, temp_key) as key:
        assert winreg.QueryValueEx(key, "someone-else")[0] == "other.exe"


@windows_only
def test_a_value_of_the_wrong_type_is_reported_and_replaced(temp_key: str) -> None:
    import winreg

    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, temp_key, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, autostart.VALUE_NAME, 0, winreg.REG_DWORD, 7)
    assert autostart.status(temp_key, command="c") == autostart.Status(True, None, False)
    assert autostart.install(temp_key, command="c").action == "updated"
    assert autostart.status(temp_key, command="c").current


@windows_only
def test_the_real_run_key_is_not_the_default_of_these_tests() -> None:
    assert autostart.RUN_KEY == r"Software\Microsoft\Windows\CurrentVersion\Run"
    assert autostart.VALUE_NAME == "nbp-git-safe-tray"


# ------------------------------------------------------ review findings (B7): ACL and dead values


def test_program_of_reads_quoted_and_plain_commands() -> None:
    assert autostart.program_of(r'"C:\Program Files\Py\pythonw.exe" -I -m x') == (
        r"C:\Program Files\Py\pythonw.exe"
    )
    assert autostart.program_of(r"C:\Py\pythonw.exe -I -m x") == r"C:\Py\pythonw.exe"
    assert autostart.program_of('"unterminated') is None and autostart.program_of("  ") is None


def test_a_stored_value_that_names_a_missing_program_is_reported(tmp_path: Path) -> None:
    exe = tmp_path / "pythonw.exe"
    exe.write_bytes(b"")
    live = autostart.Status(True, f'"{exe}" -I -m nbp_git_safe tray', True)
    assert autostart.stored_program_missing(live) is False
    exe.unlink()  # the environment was removed or moved
    assert autostart.stored_program_missing(live) is True
    assert autostart.stored_program_missing(autostart.Status(False)) is False
    assert autostart.stored_program_missing(autostart.Status(True, None, False)) is False


@windows_only
def test_install_refuses_an_interpreter_other_accounts_can_replace(
    temp_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from nbp_git_safe import winsec

    seen: list[str] = []

    def exposed(target: object) -> str | None:
        seen.append(Path(str(target)).name)
        return "can be changed by Users" if Path(str(target)).is_dir() else None

    monkeypatch.setattr(winsec, "write_exposure", exposed)
    with pytest.raises(AutostartError, match=r"not installed.*its folder can be changed by Users"):
        autostart.install(temp_key)
    assert autostart.status(temp_key).installed is False  # nothing was written
    assert Path(autostart.tray_executable()).name in seen  # the program AND its folder are asked
    done = autostart.install(temp_key, allow_writable=True)  # knowingly
    assert done.action == "installed"
    # an explicit command (what the tests of this module use) is not an interpreter to vet
    monkeypatch.setattr(winsec, "write_exposure", lambda _t: "can be changed by Users")
    assert autostart.install(temp_key, command="x -m y").action == "updated"


@windows_only
def test_a_safe_interpreter_installs_without_the_override(
    temp_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from nbp_git_safe import winsec

    monkeypatch.setattr(winsec, "write_exposure", lambda _t: None)
    assert autostart.install(temp_key).action == "installed"
    assert autostart.exposure_problem(autostart.tray_executable()) is None
