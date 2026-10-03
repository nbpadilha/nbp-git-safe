# SPDX-License-Identifier: MIT
"""Configuration with the precedence ``flag > env NBP_SAFE_* > .git/config > .nbp-safe.config
> default``.

Security rule: nothing that executes a command may come from a versioned file. ``keyCommand`` is
read ONLY from the local ``.git/config`` (section ``[nbp-safe]``); flags and environment variables
cannot set it either, and ``.nbp-safe.config`` may only carry the harmless options listed in
``VERSIONED_KEYS`` (anything else in that file is ignored, ``vault.ref`` included).
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nbp_git_safe import plainfile
from nbp_git_safe.crypto import MAX_BUCKET
from nbp_git_safe.gitutil import Git, GitError, Repo, split_z

DEFAULT_TTL = 8 * 3600
MAX_TTL = 30 * 24 * 3600
DEFAULT_REF = "refs/heads/nbp-safe"
DEFAULT_KEY_COMMAND_TIMEOUT = 120.0
VERSIONED_CONFIG_NAME = ".nbp-safe.config"
ON_MISSING_CHOICES = ("keep", "remove", "ask")

_REF_RE = re.compile(r"^refs/heads/nbp-safe(-[A-Za-z0-9][A-Za-z0-9._-]*)?$")
_DURATION_RE = re.compile(r"^(\d+)\s*([smhd]?)$")
_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}
_GRANULARITY_NAMES = {"minute": 60, "hour": 3600, "day": 86400}


class ConfigError(Exception):
    """Invalid configuration value (message never includes the value of keyCommand)."""


def parse_duration(text: str, *, what: str, allow_zero: bool = False) -> int:
    match = _DURATION_RE.match(text.strip().lower())
    if not match:
        raise ConfigError(f"{what}: expected a duration like 90s, 30m, 8h, 2d")
    seconds = int(match.group(1)) * _UNITS[match.group(2)]
    if seconds == 0 and not allow_zero:
        raise ConfigError(f"{what}: must be greater than zero")
    if seconds > MAX_TTL:
        raise ConfigError(f"{what}: must not exceed 30 days")
    return seconds


def _parse_bool(text: str, what: str) -> bool:
    value = text.strip().lower()
    if value in ("true", "yes", "on", "1"):
        return True
    if value in ("false", "no", "off", "0", ""):
        return False
    raise ConfigError(f"{what}: expected true or false")


def _parse_ttl(text: str) -> int:
    return parse_duration(text, what="ttl")


def _parse_idle(text: str) -> int | None:
    if text.strip().lower() in ("", "off", "none", "0"):
        return None
    return parse_duration(text, what="idleTimeout")


def _parse_on_missing(text: str) -> str:
    value = text.strip().lower()
    if value not in ON_MISSING_CHOICES:
        raise ConfigError("onMissing: expected keep, remove or ask")
    return value


def _parse_bucket(text: str) -> int:
    try:
        value = int(text.strip())
    except ValueError:
        raise ConfigError("pad.bucket: expected an integer") from None
    if not 1 <= value <= MAX_BUCKET:
        raise ConfigError(f"pad.bucket: must be between 1 and {MAX_BUCKET}")
    return value


def _parse_ref(text: str) -> str:
    value = text.strip()
    if not _REF_RE.match(value) or ".." in value or value.endswith((".lock", ".")):
        raise ConfigError("vault.ref: must look like refs/heads/nbp-safe[-suffix]")
    return value


def is_vault_ref(name: str) -> bool:
    """Does ``name`` look like a vault branch (``refs/heads/nbp-safe[-suffix]``)?"""
    return (
        _REF_RE.match(name) is not None and ".." not in name and not name.endswith((".lock", "."))
    )


def _parse_granularity(text: str) -> int:
    value = text.strip().lower()
    if value in _GRANULARITY_NAMES:
        return _GRANULARITY_NAMES[value]
    return parse_duration(value, what="commit.timeGranularity")


def parse_key_command(text: str) -> tuple[str, ...]:
    """``keyCommand`` is a JSON array of strings (argv, executed without a shell)."""
    try:
        value = json.loads(text)
    except ValueError:
        raise ConfigError("keyCommand: must be a JSON array of strings") from None
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise ConfigError("keyCommand: must be a non-empty JSON array of strings")
    return tuple(value)


def _parse_timeout(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise ConfigError("keyCommandTimeout: expected seconds") from None
    if not 0 < value <= 3600:
        raise ConfigError("keyCommandTimeout: must be between 0 and 3600 seconds")
    return value


# option name (lowercase) -> parser. ``idletimeout`` parses to ``None`` for "no idle timeout".
_PARSERS: dict[str, Callable[[str], Any]] = {
    "ttl": _parse_ttl,
    "idletimeout": _parse_idle,
    "onmissing": _parse_on_missing,
    "padbucket": _parse_bucket,
    "vaultref": _parse_ref,
    "timegranularity": _parse_granularity,
    "autounlock": lambda t: _parse_bool(t, "autoUnlock"),
    "autopush": lambda t: _parse_bool(t, "autoPush"),
    "keycommandtimeout": _parse_timeout,
    "keycommand": parse_key_command,
}

# ``.nbp-safe.config`` (versioned): harmless options only, as git-config keys.
# ``vault.ref`` is NOT one of them: which vault branch (and so which rollback record) this clone
# trusts must not be changeable by a commit of a collaborator or of whoever has push access.
VERSIONED_KEYS = {
    "pad.bucket": "padbucket",
    "commit.timegranularity": "timegranularity",
}
# A versioned file can ask for more privacy, never for less: its values are raised to these floors
# (a collaborator's commit must not weaken padding or timestamp rounding). ``onMissing`` decides
# whether a file deleted locally is deleted from the vault, so only the local config may set it.
MIN_VERSIONED_BUCKET = 1024
MIN_VERSIONED_GRANULARITY = 60
_VERSIONED_FLOORS = {
    "padbucket": MIN_VERSIONED_BUCKET,
    "timegranularity": MIN_VERSIONED_GRANULARITY,
}
_ENV_PREFIX = "NBP_SAFE_"
_LOCAL_ONLY = {"keycommand"}


@dataclass(frozen=True)
class Config:
    key_command: tuple[str, ...] | None = field(default=None, repr=False)
    ttl: int = DEFAULT_TTL
    idle_timeout: int | None = None
    on_missing: str = "keep"
    pad_bucket: int = 4096
    vault_ref: str = DEFAULT_REF
    time_granularity: int = 3600
    auto_unlock: bool = False
    auto_push: bool = False
    key_command_timeout: float = DEFAULT_KEY_COMMAND_TIMEOUT
    ignored_versioned_keys: tuple[str, ...] = ()
    raised_versioned_keys: tuple[str, ...] = ()

    @property
    def remote_vault_ref(self) -> str:
        return "refs/remotes/origin/" + self.vault_ref.removeprefix("refs/heads/")


def _local_layer(git: Git) -> dict[str, str]:
    code, out, _err = git.run_status("config", "--local", "-z", "--get-regexp", r"^nbp-safe\.")
    if code not in (0, 1):  # 1 = no such key; anything else must not read as "no settings"
        raise GitError(f"git config failed ({code})")
    layer: dict[str, str] = {}
    for item in split_z(out):
        key, _, value = item.partition("\n")
        layer[key.removeprefix("nbp-safe.")] = value  # last value wins
    return layer


def _versioned_layer(git: Git, repo: Repo) -> tuple[dict[str, str], list[str]]:
    path = repo.toplevel / VERSIONED_CONFIG_NAME
    try:  # a link (or junction, or special file) would make git read a file outside the repo
        if not plainfile.check_plain_file(path):
            return {}, []
    except plainfile.UnsafeFileError as exc:
        raise ConfigError(f"{exc}") from None
    try:
        out = git.run("config", "--file", str(path), "-z", "--list")
    except GitError:
        raise ConfigError(f"{VERSIONED_CONFIG_NAME} is not valid git-config syntax") from None
    layer: dict[str, str] = {}
    ignored: list[str] = []
    for item in split_z(out):
        key, _, value = item.partition("\n")
        if key in VERSIONED_KEYS:
            layer[VERSIONED_KEYS[key]] = value
        else:
            ignored.append(key)
    return layer, ignored


def _env_layer(env: Mapping[str, str]) -> dict[str, str]:
    layer: dict[str, str] = {}
    for name in _PARSERS:
        if name in _LOCAL_ONLY:
            continue
        value = env.get(_ENV_PREFIX + name.upper())
        if value is not None:
            layer[name] = value
    return layer


def load_config(
    git: Git,
    repo: Repo,
    flags: Mapping[str, str | None] | None = None,
    env: Mapping[str, str] | None = None,
) -> Config:
    """Resolve the configuration. ``flags`` keys are option names in lowercase
    (``ttl``, ``idletimeout``, ``onmissing``, ``padbucket``, ``vaultref``, ...); ``None`` values
    mean "flag not given". ``keyCommand`` cannot come from flags or env."""
    env = os.environ if env is None else env
    flag_layer = {k: v for k, v in (flags or {}).items() if v is not None and k not in _LOCAL_ONLY}
    env_layer = _env_layer(env)
    local = _local_layer(git)
    versioned, ignored = _versioned_layer(git, repo)
    values: dict[str, Any] = {}
    raised: list[str] = []
    for name, parser in _PARSERS.items():
        layers = [local] if name in _LOCAL_ONLY else [flag_layer, env_layer, local, versioned]
        for layer in layers:
            if name in layer:
                values[name] = parser(layer[name])
                floor = _VERSIONED_FLOORS.get(name)
                if layer is versioned and floor is not None and values[name] < floor:
                    values[name] = floor
                    raised.append(name)
                break
    return Config(
        key_command=values.get("keycommand"),
        ttl=values.get("ttl", DEFAULT_TTL),
        idle_timeout=values.get("idletimeout"),
        on_missing=values.get("onmissing", "keep"),
        pad_bucket=values.get("padbucket", 4096),
        vault_ref=values.get("vaultref", DEFAULT_REF),
        time_granularity=values.get("timegranularity", 3600),
        auto_unlock=values.get("autounlock", False),
        auto_push=values.get("autopush", False),
        key_command_timeout=values.get("keycommandtimeout", DEFAULT_KEY_COMMAND_TIMEOUT),
        ignored_versioned_keys=tuple(ignored),
        raised_versioned_keys=tuple(raised),
    )


def versioned_config_path(repo: Repo) -> Path:
    return repo.toplevel / VERSIONED_CONFIG_NAME
