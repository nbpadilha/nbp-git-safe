# SPDX-License-Identifier: MIT
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from nbp_git_safe import doctor, hooks


class _FakeGit:
    def __init__(self, values: list[str]) -> None:
        self._values = values

    def try_run(self, *args: str) -> bytes | None:
        if args == ("config", "--get-all", f"hook.{hooks.hook_name('pre-commit')}.command"):
            return "\n".join(self._values).encode()
        return None


def test_configured_python_round_trips_a_quoted_path(tmp_path: Path) -> None:
    python = str(tmp_path / "my tools" / "py'thon.exe")
    git = _FakeGit([hooks.hook_command("pre-commit", python=python)])
    assert hooks.configured_python(git, "pre-commit") == python


def test_configured_python_returns_none_for_a_foreign_command() -> None:
    foreign = _FakeGit(["/usr/bin/python3 -m other hook pre-commit"])
    assert hooks.configured_python(foreign, "pre-commit") is None
    assert hooks.configured_python(_FakeGit([]), "pre-commit") is None


def test_pythonw_blocked_run_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "pythonw.exe").write_bytes(b"")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "executable", str(tmp_path / "python.exe"))

    def refuse(argv: list[str]) -> None:
        raise OSError(f"{argv} refused")

    assert doctor.pythonw_blocked(refuse) is True


def test_pythonw_blocked_run_ok(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "pythonw.exe").write_bytes(b"")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "executable", str(tmp_path / "python.exe"))
    assert doctor.pythonw_blocked(lambda argv: 0) is False


def test_pythonw_blocked_run_invalid_image_hash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "pythonw.exe").write_bytes(b"")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "executable", str(tmp_path / "python.exe"))
    assert doctor.pythonw_blocked(lambda argv: 0xC0000428) is True


def test_pythonw_blocked_run_nonzero_exit_code(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "pythonw.exe").write_bytes(b"")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "executable", str(tmp_path / "python.exe"))
    assert doctor.pythonw_blocked(lambda argv: 1) is True


def test_pythonw_blocked_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    assert doctor.pythonw_blocked(lambda argv: 0) is None


def test_python_location_problem_levels(tmp_path: Path) -> None:
    alias = tmp_path / "WindowsApps" / "python.exe"
    alias.parent.mkdir()
    alias.write_bytes(b"")
    found = hooks.python_location_problem(str(alias))
    assert found is not None and found[0] == "warn" and "WindowsApps" in found[1]

    lain = tmp_path / "Packages" / "X" / "LocalCache" / "python.exe"
    lain.parent.mkdir(parents=True)
    lain.write_bytes(b"")
    found = hooks.python_location_problem(str(lain))
    assert found is not None and found[0] == "warn" and "virtualised" in found[1]

    found = hooks.python_location_problem("python-does-not-exist.exe")
    assert found is not None and found[0] == "problem"

    plain = tmp_path / "venv" / "python.exe"
    plain.parent.mkdir()
    plain.write_bytes(b"")
    assert hooks.python_location_problem(str(plain)) is None
