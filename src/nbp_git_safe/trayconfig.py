# SPDX-License-Identifier: MIT
"""Configuration of the tray: ``tray.json`` in the private per-user state directory.

Strictly validated: unknown names, wrong types and out-of-range numbers are refused (the tray then
runs on the defaults and says so; the file is never rewritten behind your back). Booleans are
JSON booleans, numbers are integers, ``notifications`` is one of a fixed list of words. Nothing in
it is a command, a path or a secret.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from nbp_git_safe import agent, plainfile, statefile

CONFIG_NAME = "tray.json"
MAX_FILE_BYTES = 16 * 1024
SEAL_CHOICES = (5, 15, 30, 60)  # what the tray menu offers; any 1..1440 is valid in the file
NOTIFICATION_CHOICES = ("full", "minimal")  # minimal: balloons never carry a folder name


class TrayConfigError(Exception):
    """The configuration is invalid (the message names the option, never a file content)."""


@dataclass(frozen=True)
class TrayConfig:
    sealIntervalMinutes: int = 15  # the field names are the JSON keys
    sealPush: bool = False
    unlockAtLogin: bool = False
    warnExpiryMinutes: int = 30  # 0 turns the warning off
    warnPendingMinutes: int = 30  # 0 turns the warning off
    notifications: str = "full"  # "minimal": no repository name in a balloon (see docs/TRAY.md)


# name -> (kind, minimum, maximum)
_SPEC: dict[str, tuple[type, int, int]] = {
    "sealIntervalMinutes": (int, 1, 1440),
    "sealPush": (bool, 0, 1),
    "unlockAtLogin": (bool, 0, 1),
    "warnExpiryMinutes": (int, 0, 1440),
    "warnPendingMinutes": (int, 0, 1440),
    "notifications": (str, 0, 0),
}


def validate(values: dict[str, object]) -> TrayConfig:
    """A ``TrayConfig`` from a mapping, or ``TrayConfigError`` for the first problem."""
    unknown = sorted(set(values) - set(_SPEC))
    if unknown:
        raise TrayConfigError(f"unknown option: {unknown[0][:40]!r}")
    clean: dict[str, object] = {}
    for name, value in values.items():
        kind, low, high = _SPEC[name]
        if kind is str:
            if value not in NOTIFICATION_CHOICES:
                raise TrayConfigError(f"{name}: expected one of {', '.join(NOTIFICATION_CHOICES)}")
        elif kind is bool:
            if not isinstance(value, bool):
                raise TrayConfigError(f"{name}: expected true or false")
        elif isinstance(value, bool) or not isinstance(value, int):
            raise TrayConfigError(f"{name}: expected a whole number")
        elif not low <= value <= high:
            raise TrayConfigError(f"{name}: must be between {low} and {high}")
        clean[name] = value
    return TrayConfig(**clean)  # type: ignore[arg-type]


def parse(raw: bytes) -> TrayConfig:
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        raise TrayConfigError("tray.json is not valid JSON") from None
    if not isinstance(data, dict):
        raise TrayConfigError("tray.json must be a JSON object")
    return validate(data)


def config_path() -> Path:
    base = agent.private_root(create=False) or agent.runtime_root()
    return base / CONFIG_NAME


def load() -> tuple[TrayConfig, str | None]:
    """The configuration and an error message (``None`` when fine). On any problem the defaults
    are returned together with the reason."""
    try:
        base = agent.private_root(create=False)
        if base is None:
            return TrayConfig(), None
        raw = statefile.read_small(base / CONFIG_NAME, MAX_FILE_BYTES)
        return (TrayConfig(), None) if raw is None else (parse(raw), None)
    except TrayConfigError as exc:
        return TrayConfig(), str(exc)
    except (agent.InsecureStateError, plainfile.UnsafeFileError, statefile.StateFileError) as exc:
        return TrayConfig(), f"tray.json cannot be used: {exc}"
    except OSError as exc:
        return TrayConfig(), f"tray.json cannot be read ({exc.strerror})"


def _write(base: Path, config: TrayConfig) -> Path:
    path = base / CONFIG_NAME
    statefile.atomic_write(
        path, (json.dumps(asdict(config), indent=1, sort_keys=True) + "\n").encode("ascii")
    )
    return path


def save(config: TrayConfig) -> Path:
    """Write the whole configuration atomically and return the file."""
    try:
        base = agent.private_root(create=True)
        assert base is not None
        with statefile.file_lock(base / (CONFIG_NAME + ".lock")):
            return _write(base, config)
    except (agent.InsecureStateError, statefile.StateFileError) as exc:
        raise TrayConfigError(f"tray.json was not written: {exc}") from None
    except OSError as exc:
        raise TrayConfigError(f"tray.json was not written ({exc.strerror})") from None


def update(**changes: object) -> TrayConfig:
    """Change some options: read the current file (an invalid one is an error, never replaced
    silently), validate the result and write it. The read and the write happen under ONE lock, so
    two changes at the same moment (a menu click and ``tray --config``) both survive."""
    try:
        base = agent.private_root(create=True)
        assert base is not None
        with statefile.file_lock(base / (CONFIG_NAME + ".lock")):
            current, error = load()
            if error is not None:
                raise TrayConfigError(error)
            merged = {f.name: getattr(current, f.name) for f in fields(current)} | changes
            config = validate(merged)
            _write(base, config)
            return config
    except (agent.InsecureStateError, statefile.StateFileError) as exc:
        raise TrayConfigError(f"tray.json was not written: {exc}") from None
    except OSError as exc:
        raise TrayConfigError(f"tray.json was not written ({exc.strerror})") from None


def parse_assignment(text: str) -> tuple[str, object]:
    """``name=value`` from the command line: ``true``/``false`` or a whole number."""
    name, sep, value = text.partition("=")
    if not sep or name not in _SPEC:
        raise TrayConfigError(f"expected name=value with one of: {', '.join(sorted(_SPEC))}")
    low = value.strip().lower()
    if _SPEC[name][0] is str:
        return name, low
    if _SPEC[name][0] is bool:
        if low not in ("true", "false"):
            raise TrayConfigError(f"{name}: expected true or false")
        return name, low == "true"
    if not low.isascii() or not low.isdigit():
        raise TrayConfigError(f"{name}: expected a whole number")
    return name, int(low)
