# SPDX-License-Identifier: MIT
"""The printing side of the multi-repository commands: registry, autostart and tray options. The
real Windows Run key is never touched (the autostart module is replaced by a fake)."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from nbp_git_safe import agent, autostart, fleetcli, registry, trayconfig
from nbp_git_safe.cli import main
from nbp_git_safe.fleetops import FAILED, OK, SKIPPED, WARN, Outcome


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def test_outcome_printing_single_and_multi_line(capsys: pytest.CaptureFixture[str]) -> None:
    fleetcli._print_outcome(Outcome(1, "alpha", OK, "unlocked (key 1234)"))
    fleetcli._print_outcome(Outcome(2, "beta", FAILED, "keyCommand failed (exit code 1)"))
    fleetcli._print_outcome(Outcome(3, "gamma", WARN, "folder gone"))
    fleetcli._print_outcome(Outcome(4, "delta", SKIPPED, "locked"))
    fleetcli._print_outcome(Outcome(5, "eps", FAILED, "line one\nline two"))
    fleetcli._print_outcome(Outcome(6, "zeta", OK, "a\nb"))
    out = capsys.readouterr().out.splitlines()
    assert out == [
        "[1] alpha: unlocked (key 1234)",
        "[2] beta: FAILED: keyCommand failed (exit code 1)",
        "[3] gamma: warning: folder gone",
        "[4] delta: locked",
        "[5] eps: FAILED",
        "  line one",
        "  line two",
        "[6] zeta",
        "  a",
        "  b",
    ]


def test_summary_wording() -> None:
    assert fleetcli._summary([Outcome(1, "a", OK)]) == "1 repository: 1 ok"
    mixed = [
        Outcome(1, "a", OK),
        Outcome(2, "b", FAILED),
        Outcome(3, "c", FAILED),
        Outcome(4, "d", SKIPPED),
    ]
    assert fleetcli._summary(mixed) == "4 repositories: 1 ok, 1 skipped, 2 failed"
    assert fleetcli._summary([]) == "0 repositories: nothing to do"


def test_registry_list_add_remove_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = agent.private_root(create=True)
    assert root is not None
    (root / registry.REGISTRY_NAME).write_bytes(b"{ not json")
    code, out, err = run("registry", "list")
    assert code == 0 and "no repositories registered" in out and "not valid JSON" in err
    # a registry that cannot be written is an error message, not a traceback
    code, _out, err = run("-C", str(tmp_path), "registry", "remove")
    assert code == 0  # a damaged registry is replaced (after a backup), nothing to remove
    (root / registry.REGISTRY_NAME).write_bytes(json.dumps({"version": 9, "repos": []}).encode())
    code, _out, err = run("-C", str(tmp_path), "registry", "remove")
    assert code == 0  # reading a newer version is fine; only a change is refused
    monkeypatch.setattr(
        registry, "add", lambda *_a, **_k: (_ for _ in ()).throw(registry.RegistryError("full"))
    )
    plain = tmp_path / "repo"
    plain.mkdir()
    import subprocess

    subprocess.run(["git", "init", "-q", str(plain)], check=True)
    code, _out, err = run("-C", str(plain), "registry", "add")
    assert code == 1 and "full" in err


def test_prune_with_an_unwritable_registry_reports_the_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(_check: object) -> list[str]:
        raise registry.RegistryError("the registry was written by a newer version; not modified")

    monkeypatch.setattr(registry, "prune", boom)
    code, _out, err = run("registry", "prune")
    assert code == 1 and "newer version" in err


# ---------------------------------------------------------------------------- autostart


@dataclass
class FakeAutostart:
    supported_value: bool = True
    installed: bool = False
    current: bool = True
    raises: bool = False
    missing: bool = False  # the stored program is no longer on disk
    exposure: str | None = None  # why another account could replace it
    refuse_writable: bool = False  # install refuses an interpreter others can change
    installs: list[bool] = field(default_factory=list)  # allow_writable of each install call

    AutostartError = autostart.AutostartError
    program_of = staticmethod(autostart.program_of)

    def stored_program_missing(self, _status: autostart.Status) -> bool:
        return self.missing

    def exposure_problem(self, _program: str) -> str | None:
        return self.exposure

    def supported(self) -> bool:
        return self.supported_value

    def _maybe(self) -> None:
        if self.raises:
            raise autostart.AutostartError("cannot write the Run key (Access is denied)")

    def install(self, *, allow_writable: bool = False) -> autostart.InstallResult:
        self._maybe()
        self.installs.append(allow_writable)
        if self.refuse_writable and not allow_writable:
            raise autostart.AutostartError("not installed: its folder can be changed by Users")
        self.installed = True
        return autostart.InstallResult("installed", '"x" -I -m nbp_git_safe tray')

    def remove(self) -> bool:
        self._maybe()
        was, self.installed = self.installed, False
        return was

    def status(self) -> autostart.Status:
        self._maybe()
        return autostart.Status(
            self.installed, '"x" tray' if self.installed else None, self.current
        )


def test_autostart_commands_print_and_report(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeAutostart()
    monkeypatch.setattr(fleetcli, "autostart", fake)
    assert run("autostart", "status")[1].strip() == "autostart: not installed"
    code, out, _ = run("autostart", "install")
    assert code == 0 and out.startswith("autostart installed: ")
    assert "installed" in run("autostart")[1]  # the default action is status
    fake.current = False
    assert "points to another program" in run("autostart", "status")[1]
    assert run("autostart", "remove")[1].strip() == "autostart removed"
    assert run("autostart", "remove")[1].strip() == "autostart was not installed"
    fake.raises = True
    code, _out, err = run("autostart", "install")
    assert code == 1 and "Access is denied" in err


def test_autostart_status_warns_about_a_dead_or_replaceable_program(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeAutostart(installed=True)
    monkeypatch.setattr(fleetcli, "autostart", fake)
    assert "warning" not in run("autostart", "status")[1]
    fake.missing = True  # the environment was moved or deleted: the value is dead
    dead = run("autostart", "status")[1]
    assert "no longer exists" in dead and "autostart remove" in dead
    fake.missing, fake.exposure = False, "its folder can be changed by Users"
    exposed = run("autostart", "status")[1]
    assert (
        "warning: its folder can be changed by Users" in exposed and "autostart remove" in exposed
    )


def test_autostart_install_refuses_a_replaceable_interpreter_unless_told_otherwise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeAutostart(refuse_writable=True)
    monkeypatch.setattr(fleetcli, "autostart", fake)
    code, _out, err = run("autostart", "install")
    assert code == 1 and "not installed" in err
    assert fake.installs == [False] and fake.installed is False
    code, _out, _err = run("autostart", "install", "--allow-writable")
    assert code == 0 and fake.installs == [False, True] and fake.installed is True


def test_autostart_says_unsupported_with_exit_code_two(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fleetcli, "autostart", FakeAutostart(supported_value=False))
    for action in ("install", "remove", "status"):
        code, _out, err = run("autostart", action)
        assert code == 2 and "not supported on this platform" in err and "docs/TRAY.md" in err


# -------------------------------------------------------------------------------- tray


def test_tray_config_show_set_and_refuse() -> None:
    code, out, _ = run("tray", "--config")
    assert code == 0 and "sealIntervalMinutes = 15" in out and "unlockAtLogin = false" in out
    code, out, err = run("tray", "--config", "sealIntervalMinutes=5", "unlockAtLogin=true")
    assert code == 0 and "sealIntervalMinutes = 5" in out and "unlockAtLogin = true" in out
    assert "saved" in err
    assert trayconfig.load()[0].sealIntervalMinutes == 5
    code, _out, err = run("tray", "--config", "sealIntervalMinutes=0")
    assert code == 1 and "between 1 and 1440" in err
    code, _out, err = run("tray", "--config", "bogus=1")
    assert code == 1 and "expected name=value" in err
    assert trayconfig.load()[0].sealIntervalMinutes == 5  # nothing half-written


def test_tray_config_with_a_broken_file_warns_and_keeps_it() -> None:
    root = agent.private_root(create=True)
    assert root is not None
    (root / trayconfig.CONFIG_NAME).write_bytes(b"{nope")
    code, _out, err = run("tray", "--config")
    assert code == 0 and "defaults are in use" in err
    code, _out, err = run("tray", "--config", "sealPush=true")
    assert code == 1 and (root / trayconfig.CONFIG_NAME).read_bytes() == b"{nope"


def test_tray_settings_without_config_flag_is_a_usage_error() -> None:
    code, _out, err = run("tray", "sealPush=true")
    assert code == 2 and "go with --config" in err


def test_tray_elsewhere_says_unsupported(monkeypatch: pytest.MonkeyPatch) -> None:
    args = argparse.Namespace(config=False, settings=[])
    monkeypatch.setattr(sys, "platform", "linux")
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        code = fleetcli.cmd_tray(args)
    assert code == 2 and "not supported on this platform" in err.getvalue()
    assert "docs/TRAY.md" in err.getvalue()
