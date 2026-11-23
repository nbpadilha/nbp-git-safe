# SPDX-License-Identifier: MIT
"""Command line side of the multi-repository features: ``<command> --all``, ``registry``,
``autostart`` and ``tray``. The work is in ``fleetops`` (neutral); this module only prints."""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Callable
from pathlib import Path

from nbp_git_safe import autostart, fleetops, registry, trayconfig
from nbp_git_safe.fleetops import FAILED, OK, SKIPPED, WARN, Outcome
from nbp_git_safe.gitutil import GitError, discover

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_LOCKED = 3
UNSUPPORTED = "not supported on this platform (contributions welcome, see docs/TRAY.md)"

ALL_COMMANDS = ("status", "unlock", "lock", "seal", "doctor")


def _out(text: str = "") -> None:
    sys.stdout.write(text + "\n")


def _err(text: str) -> None:
    sys.stderr.write(text + "\n")


def _registered() -> list[registry.Entry]:
    loaded = registry.load()
    for warning in loaded.warnings:
        _err(f"nbp-git-safe: warning: {warning}")
    return loaded.entries


def _print_outcome(outcome: Outcome) -> None:
    lines = outcome.message.splitlines() or [""]
    head = f"[{outcome.index}] {outcome.name}"
    mark = {FAILED: "FAILED", WARN: "warning", SKIPPED: ""}.get(outcome.kind, "")
    if len(lines) == 1:
        _out(f"{head}: " + (f"{mark}: " if mark else "") + lines[0])
        return
    _out(head + (f": {mark}" if mark else ""))
    for line in lines:
        _out(f"  {line}")


def _summary(outcomes: list[Outcome]) -> str:
    counts = {k: sum(1 for o in outcomes if o.kind == k) for k in (OK, SKIPPED, WARN, FAILED)}
    parts = [f"{n} {name}" for name, n in counts.items() if n]
    noun = "repository" if len(outcomes) == 1 else "repositories"
    return f"{len(outcomes)} {noun}: " + (", ".join(parts) if parts else "nothing to do")


def _flags(args: argparse.Namespace) -> dict[str, str | None]:
    return {
        "ttl": getattr(args, "ttl", None),
        "idletimeout": getattr(args, "idle_timeout", None),
    }


def run_all(command: str, args: argparse.Namespace) -> int:
    """``status|unlock|lock|seal|doctor --all``: every registered repository, one after the other.
    Continues after a failure; the exit code is 1 when anything failed (status: 3 when something
    is only locked)."""
    if args.directory:
        _err("nbp-git-safe: error: --all cannot be combined with -C")
        return EXIT_USAGE
    entries = _registered()
    if not entries:
        _out("no repositories registered (run `nbp-git-safe init` inside a repository)")
        return EXIT_OK
    handles, failures = fleetops.open_all(entries, _flags(args))
    outcomes: list[Outcome] = list(failures)
    operation: Callable[[fleetops.RepoHandle], Outcome]
    if command == "unlock":
        outcomes += fleetops.unlock_all(handles)
    else:
        if command == "status":
            operation = fleetops.status_one
        elif command == "lock":
            operation = fleetops.lock_one
        elif command == "doctor":
            operation = fleetops.doctor_one
        else:
            push = bool(getattr(args, "push", False))

            def operation(handle: fleetops.RepoHandle) -> Outcome:
                return fleetops.seal_one(handle, push=push)

        outcomes += [operation(h) for h in handles]
    outcomes.sort(key=lambda o: o.index)
    for outcome in outcomes:
        _print_outcome(outcome)
    _out(_summary(outcomes))
    if any(o.kind == FAILED for o in outcomes):
        return EXIT_ERROR
    if command == "status" and any(o.kind == SKIPPED for o in outcomes):
        return EXIT_LOCKED
    return EXIT_OK


# ------------------------------------------------------------------------------ registry


def cmd_registry(args: argparse.Namespace) -> int:
    action = args.registry_command
    if action is None:
        _err("nbp-git-safe: error: registry needs list, add, remove or prune")
        return EXIT_USAGE
    try:
        if action == "list":
            return _registry_list()
        if action == "prune":
            return _registry_prune()
        base = Path(getattr(args, "path", None) or args.directory or Path.cwd())
        if action == "add":
            try:
                repo, _git = discover(base)
            except (GitError, OSError):
                _err("nbp-git-safe: error: not inside a git work tree")
                return EXIT_ERROR
            added = registry.add(repo.toplevel)
            _out(("registered: " if added else "already registered: ") + str(repo.toplevel))
            return EXIT_OK
        removed = registry.remove(base)
        _out("removed" if removed else "was not registered")
        return EXIT_OK
    except registry.RegistryError as exc:
        _err(f"nbp-git-safe: error: {exc}")
        return EXIT_ERROR


def _registry_list() -> int:
    loaded = registry.load()
    for warning in loaded.warnings:
        _err(f"nbp-git-safe: warning: {warning}")
    if not loaded.entries:
        _out("no repositories registered")
    for position, entry in enumerate(loaded.entries, start=1):
        day = time.strftime("%Y-%m-%d", time.localtime(entry.added))
        _out(f"[{position}] {entry.path}  (since {day})")
    return EXIT_OK


def is_git_repository(path: str) -> bool:
    """Is ``path`` the top level of a git work tree? (Used by ``registry prune``.)"""
    if not Path(path).is_dir():
        return False
    try:
        repo, _git = discover(path)
    except (GitError, OSError):
        return False
    return registry.key_of(repo.toplevel) == registry.key_of(path)


def _registry_prune() -> int:
    gone = registry.prune(is_git_repository)
    for path in gone:
        _out(f"removed: {path}")
    _out(f"{len(gone)} entr{'y' if len(gone) == 1 else 'ies'} removed")
    return EXIT_OK


# ------------------------------------------------------------------------------ autostart


def cmd_autostart(args: argparse.Namespace) -> int:
    action = args.autostart_command
    if not autostart.supported():
        _err(f"nbp-git-safe: {UNSUPPORTED}")
        return EXIT_USAGE
    try:
        if action == "install":
            result = autostart.install(allow_writable=bool(getattr(args, "allow_writable", False)))
            _out(f"autostart {result.action}: {result.command}")
        elif action == "remove":
            _out("autostart removed" if autostart.remove() else "autostart was not installed")
        else:
            status = autostart.status()
            if not status.installed:
                _out("autostart: not installed")
            else:
                _out(
                    "autostart: installed"
                    + ("" if status.current else " (points to another program; run install)")
                    + f"\n  {status.command}"
                )
                _autostart_warnings(status)
    except autostart.AutostartError as exc:
        _err(f"nbp-git-safe: error: {exc}")
        return EXIT_ERROR
    return EXIT_OK


def _autostart_warnings(status: autostart.Status) -> None:
    if autostart.stored_program_missing(status):
        _out(
            "  warning: that program no longer exists, so nothing starts at login; run "
            "`nbp-git-safe autostart remove`, then `autostart install` from the environment "
            "you use now"
        )
        return
    program = autostart.program_of(status.command or "")
    problem = autostart.exposure_problem(program) if program else None
    if problem:
        _out(
            f"  warning: {problem}: another account could replace what runs at every login "
            "(`autostart remove` undoes it)"
        )


# ---------------------------------------------------------------------------------- tray


def cmd_tray(args: argparse.Namespace) -> int:
    if args.config:
        return _tray_config(args.settings)
    if args.settings:
        _err("nbp-git-safe: error: name=value settings go with --config")
        return EXIT_USAGE
    if sys.platform != "win32":
        _err(f"nbp-git-safe: {UNSUPPORTED}")
        return EXIT_USAGE
    from nbp_git_safe import tray_win  # Windows only: never imported elsewhere

    return tray_win.run()


def _tray_config(settings: list[str]) -> int:
    """``tray --config``: show the file and its values; ``tray --config name=value ...``: change
    them (validated, written atomically). Available on every platform."""
    try:
        if settings:
            changes = dict(trayconfig.parse_assignment(item) for item in settings)
            config = trayconfig.update(**changes)
            _err("nbp-git-safe: tray configuration saved (a running tray reads it within a minute)")
        else:
            config, error = trayconfig.load()
            if error:
                _err(f"nbp-git-safe: warning: {error}; the defaults are in use")
    except trayconfig.TrayConfigError as exc:
        _err(f"nbp-git-safe: error: {exc}")
        return EXIT_ERROR
    _out(f"file: {trayconfig.config_path()}")
    for name, value in vars(config).items():
        _out(f"{name} = {str(value).lower() if isinstance(value, bool) else value}")
    return EXIT_OK
