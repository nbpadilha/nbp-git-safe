# SPDX-License-Identifier: MIT
"""Tray configuration (strict validation, atomic save) and the tray log (no names, rotation)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from nbp_git_safe import agent, trayconfig
from nbp_git_safe.traylog import TrayLog


def config_file() -> Path:
    return agent.runtime_root() / trayconfig.CONFIG_NAME


def put(raw: bytes) -> None:
    base = agent.private_root(create=True)
    assert base is not None
    (base / trayconfig.CONFIG_NAME).write_bytes(raw)


def test_defaults_without_a_file_and_nothing_is_created() -> None:
    config, error = trayconfig.load()
    assert error is None and config == trayconfig.TrayConfig()
    assert config.sealIntervalMinutes == 15 and config.unlockAtLogin is False
    assert not agent.runtime_root().exists()


def test_save_load_round_trip_and_update() -> None:
    path = trayconfig.save(trayconfig.TrayConfig(sealIntervalMinutes=5, sealPush=True))
    assert path == config_file()
    config, error = trayconfig.load()
    assert error is None and config.sealIntervalMinutes == 5 and config.sealPush is True
    updated = trayconfig.update(unlockAtLogin=True)
    assert updated.unlockAtLogin is True and updated.sealIntervalMinutes == 5
    assert trayconfig.load()[0] == updated
    names = sorted(p.name for p in agent.runtime_root().iterdir())
    assert names == [trayconfig.CONFIG_NAME, trayconfig.CONFIG_NAME + ".lock"]  # no temp file


PARTIAL = [
    ({}, trayconfig.TrayConfig()),
    ({"sealIntervalMinutes": 60}, trayconfig.TrayConfig(sealIntervalMinutes=60)),
    (
        {"warnExpiryMinutes": 0, "warnPendingMinutes": 0},
        trayconfig.TrayConfig(warnExpiryMinutes=0, warnPendingMinutes=0),
    ),
]


@pytest.mark.parametrize(("values", "expected"), PARTIAL)
def test_missing_options_take_their_defaults(values: dict[str, object], expected: object) -> None:
    assert trayconfig.parse(json.dumps(values).encode()) == expected


BAD = [
    ({"sealIntervalMinutes": 0}, "between 1 and 1440"),
    ({"sealIntervalMinutes": 1441}, "between 1 and 1440"),
    ({"sealIntervalMinutes": -3}, "between"),
    ({"sealIntervalMinutes": "15"}, "whole number"),
    ({"sealIntervalMinutes": 15.5}, "whole number"),
    ({"sealIntervalMinutes": True}, "whole number"),
    ({"sealIntervalMinutes": None}, "whole number"),
    ({"warnExpiryMinutes": 1441}, "between 0 and 1440"),
    ({"sealPush": 1}, "true or false"),
    ({"sealPush": "true"}, "true or false"),
    ({"unlockAtLogin": None}, "true or false"),
    ({"notifications": "loud"}, "expected one of full, minimal"),
    ({"notifications": 1}, "expected one of full, minimal"),
    ({"notifications": None}, "expected one of full, minimal"),
    ({"sealpush": True}, "unknown option"),
    ({"keyCommand": ["x"]}, "unknown option"),
    ({"": 1}, "unknown option"),
]


@pytest.mark.parametrize(("values", "message"), BAD)
def test_invalid_values_are_refused(values: dict[str, object], message: str) -> None:
    with pytest.raises(trayconfig.TrayConfigError, match=message):
        trayconfig.parse(json.dumps(values).encode())


@pytest.mark.parametrize(
    "raw",
    [b"", b"nope", b"[]", b"3", b"null", b"\xff\xfe", b"[" * 50000],
    ids=["empty", "text", "list", "number", "null", "bytes", "deep"],
)
def test_malformed_documents_are_refused(raw: bytes) -> None:
    with pytest.raises(trayconfig.TrayConfigError):
        trayconfig.parse(raw)


def test_an_invalid_file_gives_defaults_a_reason_and_is_not_rewritten() -> None:
    put(b'{"sealIntervalMinutes": 0}')
    config, error = trayconfig.load()
    assert config == trayconfig.TrayConfig() and error and "sealIntervalMinutes" in error
    with pytest.raises(trayconfig.TrayConfigError):
        trayconfig.update(sealPush=True)  # never replaces a file it cannot read
    assert config_file().read_bytes() == b'{"sealIntervalMinutes": 0}'


def test_an_oversized_file_is_refused_unread() -> None:
    put(b" " * (trayconfig.MAX_FILE_BYTES + 1))
    config, error = trayconfig.load()
    assert config == trayconfig.TrayConfig() and error


def test_command_line_assignments() -> None:
    assert trayconfig.parse_assignment("sealIntervalMinutes=30") == ("sealIntervalMinutes", 30)
    assert trayconfig.parse_assignment("sealPush=TRUE") == ("sealPush", True)
    assert trayconfig.parse_assignment("unlockAtLogin=false") == ("unlockAtLogin", False)
    assert trayconfig.parse_assignment("notifications=Minimal") == ("notifications", "minimal")
    assert trayconfig.parse(b'{"notifications": "minimal"}').notifications == "minimal"
    assert trayconfig.TrayConfig().notifications == "full"
    for bad in (
        "nope=1",
        "sealPush",
        "sealPush=1",
        "sealIntervalMinutes=abc",
        "sealIntervalMinutes=-1",
        "sealIntervalMinutes=\u0661",
    ):
        with pytest.raises(trayconfig.TrayConfigError):
            trayconfig.parse_assignment(bad)


def test_update_validates_the_merged_result() -> None:
    with pytest.raises(trayconfig.TrayConfigError):
        trayconfig.update(sealIntervalMinutes=99999)
    assert not config_file().exists()


# ----------------------------------------------------------------------------- log


def test_log_lines_carry_only_codes_and_numbers(tmp_path: Path) -> None:
    path = tmp_path / "tray.log"
    log = TrayLog(path)
    line = log.write("seal", 3, sealed=2, code="push-offline", ok=True)
    assert re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d seal repo=3 code=push-offline ok=1 sealed=2", line
    )
    assert path.read_text(encoding="ascii").strip() == line


@pytest.mark.parametrize(
    "hostile",
    [
        "C:\\Users\\someone\\secret report.csv",
        "reports/2026 payroll.csv",
        "AbCdEf=",  # base64-looking text
        "has space",
        "UPPER",
        "a" * 41,
        "",
        "ünïcode",
        "line\nbreak",
        None,
        3.5,
        b"bytes",
    ],
)
def test_log_replaces_anything_that_is_not_a_short_code(tmp_path: Path, hostile: object) -> None:
    line = TrayLog(tmp_path / "t.log").write("event", 1, detail=hostile)
    assert line.endswith("detail=?") and "\n" not in line
    if isinstance(hostile, str) and hostile:
        assert hostile not in line


def test_log_event_name_is_checked_too(tmp_path: Path) -> None:
    assert " ? " in TrayLog(tmp_path / "t.log").write("C:\\secret\\file.txt", 1) + " "


def test_log_rotates_and_never_raises(tmp_path: Path) -> None:
    path = tmp_path / "tray.log"
    log = TrayLog(path, max_bytes=200)
    for n in range(40):
        log.write("tick", n % 5, n=n)
    assert path.stat().st_size <= 200 + 100
    assert (tmp_path / "tray.log.1").exists()
    TrayLog(tmp_path / "missing" / "dir" / "x.log").write("tick")  # unwritable: silent
    TrayLog(None).write("tick")  # no file at all


def test_two_updates_at_the_same_moment_both_survive() -> None:
    """Review (informational): ``update`` used to read the file outside the lock, so a menu click
    and ``tray --config`` at the same moment could lose one change. Here the competing update is
    started right after the read of the first one: it must wait for the lock and apply on top."""
    import threading

    trayconfig.save(trayconfig.TrayConfig())
    competing = threading.Thread(target=lambda: trayconfig.update(sealPush=True))
    real_load = trayconfig.load
    started: list[bool] = []

    def load_then_compete() -> tuple[trayconfig.TrayConfig, str | None]:
        result = real_load()
        if not started:
            started.append(True)
            competing.start()
            competing.join(0.5)  # a lock held across the read makes this wait; none, not
        return result

    trayconfig.load = load_then_compete  # type: ignore[assignment]
    try:
        trayconfig.update(sealIntervalMinutes=30)
    finally:
        trayconfig.load = real_load  # type: ignore[assignment]
    competing.join(30)
    final, error = trayconfig.load()
    assert error is None
    assert final.sealIntervalMinutes == 30 and final.sealPush is True  # neither change was lost
