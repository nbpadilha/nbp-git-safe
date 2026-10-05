# SPDX-License-Identifier: MIT
"""``unlock`` for the tray in a short-lived CHILD process, so that the long-lived tray never holds a
key (neutral: no window, no platform call).

``fleetops.unlock_all`` passes the key through the process that runs it, as ``nbp-git-safe unlock``
does. The command line exits right after; the tray does not. Python cannot wipe the immutable copies
the interpreter makes (``THREAT_MODEL.md``), so in a process that lives for weeks they would outlive
the agent's TTL. Here the tray starts ``python -I -m nbp_git_safe unlock-batch`` instead, hands it
the folders to unlock (paths only, on stdin) and reads one JSON line per repository back (a result
code and a message, never a key). The child opens each repository itself, so it reads that
repository's own configuration at that moment, runs each distinct ``keyCommand`` once, delivers the
key to the agents it starts and exits: the key never enters the tray's address space.

The tray trusts what the child says no further than a status: codes and messages are parsed
strictly and reduced to short fixed shapes before they reach the state, the menu or the log.
"""

from __future__ import annotations

import contextlib
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import IO, Any, TextIO

from nbp_git_safe import agent, fleetops, gitutil, registry
from nbp_git_safe.fleetops import FAILED, RepoHandle

SUBCOMMAND = "unlock-batch"
MAX_LINE = 8192
MAX_PATHS = 1000
MAX_MESSAGE = 1000
_CODE_RE = re.compile(r"^[a-z0-9-]{1,32}$")
_KINDS = {"ok", "skipped", "failed", "warn"}
GRACE_SECONDS = 60.0  # on top of the key commands' own time limits


# --------------------------------------------------------------------------------- child side


def child_main(stdin: TextIO, stdout: TextIO) -> int:
    """What ``nbp-git-safe unlock-batch`` runs: ``{"paths": [...]}`` in, one JSON line per
    repository out (``index`` is the 1-based position in ``paths``)."""
    try:
        data = json.loads(stdin.read(MAX_LINE * 8))
        paths = data["paths"]
        if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
            raise ValueError("paths")
        if len(paths) > MAX_PATHS:
            raise ValueError("too many")
    except (ValueError, KeyError, TypeError, RecursionError):
        return 2

    def emit(outcome: fleetops.Outcome) -> None:
        record: dict[str, Any] = {
            "index": outcome.index,
            "kind": outcome.kind,
            "code": outcome.code,
            "message": outcome.message,
        }
        expires = outcome.data.get("expires_at")
        if isinstance(expires, int | float):
            record["expires_at"] = float(expires)
        stdout.write(json.dumps(record) + "\n")
        stdout.flush()

    entries = [registry.Entry(p, 0) for p in paths]
    handles, failures = fleetops.open_all(entries)
    for failure in failures:
        emit(failure)
    fleetops.unlock_all(handles, on_outcome=emit)
    return 0


# -------------------------------------------------------------------------------- parent side


def child_python(executable: str | None = None) -> str:
    """The interpreter for the child: ``python.exe`` next to a ``pythonw.exe`` (the tray runs
    without a console; the child has pipes of its own and no window of its own either way)."""
    exe = Path(executable if executable is not None else sys.executable)
    if exe.name.lower() == "pythonw.exe":
        console = exe.with_name("python.exe")
        if console.is_file():
            return str(console)
    return str(exe)


def child_command() -> list[str]:
    return [child_python(), "-I", "-m", "nbp_git_safe", SUBCOMMAND]


def parse_line(raw: bytes, count: int) -> fleetops.Outcome | None:
    """One line of the child's report, or ``None`` when it is not one. ``index`` is checked
    against the number of repositories asked for; codes and kinds are reduced to known shapes."""
    if len(raw) > MAX_LINE:
        return None
    try:
        record = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        return None
    if not isinstance(record, dict):
        return None
    index, kind, code, message = (record.get(k) for k in ("index", "kind", "code", "message"))
    if isinstance(index, bool) or not isinstance(index, int) or not 1 <= index <= count:
        return None
    if kind not in _KINDS or not isinstance(code, str) or not isinstance(message, str):
        return None
    if not _CODE_RE.match(code):
        code = "unexpected" if kind == FAILED else ""
    data: dict[str, Any] = {}
    expires = record.get("expires_at")
    if isinstance(expires, int | float) and not isinstance(expires, bool):
        data["expires_at"] = float(expires)
    return fleetops.Outcome(index, "", kind, message[:MAX_MESSAGE], code, data)


def run_in_child(
    handles: Sequence[RepoHandle],
    on_outcome: Callable[[fleetops.Outcome], None] | None = None,
    *,
    command: Sequence[str] | None = None,
    timeout: float | None = None,
) -> list[fleetops.Outcome]:
    """Unlock ``handles`` in a child process (see the module text). Returns one outcome per handle,
    in the order given and carrying the handle's own ``index`` and name; each is also passed to
    ``on_outcome`` as soon as the child reports it. A child that dies, stalls or says something
    unintelligible leaves the repositories it did not report as failed (``unlock-child``): nothing
    here ever raises for a child's misbehaviour."""
    if not handles:
        return []
    total = timeout
    if total is None:
        total = sum(h.cfg.key_command_timeout for h in handles) + GRACE_SECONDS
    done: dict[int, fleetops.Outcome] = {}
    reported: list[fleetops.Outcome] = []

    def accept(outcome: fleetops.Outcome) -> None:
        handle = handles[outcome.index - 1]
        final = fleetops.Outcome(
            handle.index, handle.name, outcome.kind, outcome.message, outcome.code, outcome.data
        )
        if outcome.index not in done:
            done[outcome.index] = final
            reported.append(final)
            if on_outcome is not None:
                on_outcome(final)

    kwargs: dict[str, Any] = gitutil.window_flags()
    if sys.platform != "win32":
        kwargs["start_new_session"] = True
    payload = json.dumps({"paths": [str(h.path) for h in handles]}).encode("utf-8")
    try:
        proc = subprocess.Popen(  # noqa: S603 - our own interpreter and module, no shell
            list(command) if command is not None else child_command(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=_neutral_directory(),
            env=gitutil.child_env(os.environ),
            **kwargs,
        )
    except OSError:
        proc = None
    if proc is not None and proc.stdin is not None and proc.stdout is not None:
        _talk(proc, proc.stdin, proc.stdout, payload, len(handles), total, accept)
    for position, handle in enumerate(handles, start=1):
        if position not in done:
            accept(
                fleetops.Outcome(
                    position,
                    handle.name,
                    FAILED,
                    "the unlock process ended without a result for this repository",
                    "unlock-child",
                )
            )
    return [done[position] for position in range(1, len(handles) + 1)]


def _neutral_directory() -> str:
    """Where the child starts: not a repository (it sets each key command's own folder itself)."""
    with contextlib.suppress(agent.AgentError, OSError):
        base = agent.private_root(create=False)
        if base is not None:
            return str(base)
    return str(Path.home())


def _talk(
    proc: subprocess.Popen[bytes],
    stdin: IO[bytes],
    stdout: IO[bytes],
    payload: bytes,
    count: int,
    total: float,
    accept: Callable[[fleetops.Outcome], None],
) -> None:
    with contextlib.suppress(OSError):
        stdin.write(payload)
        stdin.close()
    lines: queue.Queue[bytes | None] = queue.Queue()

    def pump() -> None:
        with contextlib.suppress(OSError, ValueError):
            for line in iter(lambda: stdout.readline(MAX_LINE + 1), b""):
                lines.put(line)
        lines.put(None)

    threading.Thread(target=pump, name="nbp-unlock-reader", daemon=True).start()
    deadline = time.monotonic() + total
    stalled = False
    while True:
        try:
            line = lines.get(timeout=max(0.05, deadline - time.monotonic()))
        except queue.Empty:
            if time.monotonic() >= deadline:
                stalled = True
                break
            continue
        if line is None:
            break
        outcome = parse_line(line.strip(), count)
        if outcome is not None:
            accept(outcome)
    if stalled:
        gitutil.kill_tree(proc)
    try:
        proc.wait(10)
    except subprocess.TimeoutExpired:
        gitutil.kill_tree(proc)
    for stream in (stdin, stdout):
        with contextlib.suppress(OSError):
            stream.close()
