# SPDX-License-Identifier: MIT
"""``keyCommand`` execution and the unlock/lock/status flow.

The command is an argv list read only from the local ``.git/config`` (see ``config.py``). It runs
in the foreground CLI process WITHOUT a shell (so interactive prompts such as a password
manager's biometric dialog can appear), with a timeout, and its stdout must be the base64 of the
64-byte master key. The key is delivered to the agent over the authenticated channel; it is never
placed in argv, the environment, a file, a log or an error message.
"""

from __future__ import annotations

import contextlib
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from nbp_git_safe import agent, crypto, gitutil, keyid

MAX_KEY_OUTPUT = 4096


class KeyCommandError(Exception):
    """keyCommand could not produce a valid key. Messages never include its output."""


_kill_tree = gitutil.kill_tree


_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


def depends_on_cwd(argv: Sequence[str], root: str | os.PathLike[str]) -> bool:
    """Could ``argv`` mean something else when run from another working directory? True for a
    program or an argument that is a relative path (``tools/key.py``, ``./k``, ``../k``, also after
    ``--option=``), and for a bare name that exists in ``root`` (``python key.py``). URIs
    (``op://vault/item``) and absolute paths do not depend on it. Conservative on purpose: a
    ``pass show team/key`` is also reported, which only costs one prompt per repository."""
    for position, arg in enumerate(argv):
        candidate = arg
        if arg.startswith("-"):
            if position == 0 or "=" not in arg:
                continue
            candidate = arg.partition("=")[2]
        if not candidate or _URI.match(candidate) or os.path.isabs(candidate):
            continue
        if candidate.startswith(("/", "\\")):
            continue  # rooted: not relative to a directory (a drive-relative path on Windows)
        if "/" in candidate or "\\" in candidate:
            return True
        if position > 0 and os.path.lexists(os.path.join(os.fspath(root), candidate)):
            return True
    return False


def run_key_command(
    argv: Sequence[str],
    timeout: float,
    *,
    avoid: Sequence[str | os.PathLike[str]] = (),
    cwd: str | os.PathLike[str] | None = None,
) -> bytes:
    """Run ``argv`` (no shell) and return the validated 64-byte master key. ``avoid`` lists
    repository trees that must not provide the program (``unlock --all`` is not run from inside
    the repository it unlocks, so the caller names them). ``cwd`` is the working directory of the
    command: always the root of the repository the key is for, so that a relative path in the argv
    means the same thing whichever way ``unlock`` was started (the command line, a hook, ``--all``
    or the tray); a relative program path is resolved against it here, not left to the platform."""
    if not argv:
        raise KeyCommandError("no keyCommand configured (git config nbp-safe.keyCommand)")
    kwargs: dict[str, Any] = gitutil.window_flags()
    if sys.platform != "win32":
        kwargs["start_new_session"] = True
    try:
        program = gitutil.resolve_executable(argv[0], avoid=avoid)  # never from the cwd
        if cwd is not None and os.path.dirname(program) and not os.path.isabs(program):
            program = os.path.join(os.fspath(cwd), program)
        command = [program, *argv[1:]]
        proc = subprocess.Popen(  # noqa: S603 - argv list from the local .git/config, no shell
            command,
            cwd=cwd,
            env=gitutil.child_env(os.environ),
            shell=False,
            stdout=subprocess.PIPE,
            **kwargs,
        )
    except FileNotFoundError:
        raise KeyCommandError("keyCommand executable not found") from None
    except OSError:
        raise KeyCommandError("keyCommand could not be started") from None
    timed_out = False
    out = b""
    try:
        out, _ = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        with contextlib.suppress(Exception):
            proc.communicate(timeout=5)
    # every refusal below drops what the command printed BEFORE it raises: the traceback of an
    # exception keeps this frame alive, and a (valid) key printed by a command that then exited
    # non-zero must not stay reachable through it
    if timed_out:
        out = b""
        raise KeyCommandError(f"keyCommand timed out after {timeout:g} s")
    if proc.returncode != 0:
        out = b""
        raise KeyCommandError(f"keyCommand failed (exit code {proc.returncode})")
    if len(out) > MAX_KEY_OUTPUT:
        out = b""
        raise KeyCommandError("keyCommand output is not a valid key")
    try:
        return crypto.decode_key(out)
    except crypto.NbpCryptoError:
        out = b""
        raise KeyCommandError(
            "keyCommand output is not a valid key (expected base64 of 64 bytes)"
        ) from None


def current_status(state_dir: Path) -> dict[str, Any] | None:
    """Status of the live agent, or ``None`` when none is running (orphans are cleaned). An agent
    that answers but fails the authentication raises ``agent.HandshakeError``."""
    try:
        with agent.AgentClient.connect(state_dir) as client:
            return client.status()
    except agent.AgentNotRunningError:
        return None


def unlock(
    state_dir: Path,
    argv: Sequence[str] | None,
    *,
    ttl: float,
    idle_timeout: float | None,
    key_timeout: float,
    spawn: Callable[[Path, float, float | None], agent.AgentInfo] = agent.spawn_agent,
    key_source: Callable[[], bytes] | None = None,
    cwd: str | os.PathLike[str] | None = None,
    expected_key_id: str | None = None,
    on_delivered: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[bool, dict[str, Any]]:
    """Unlock the repository. Returns ``(newly_unlocked, agent_status)``.

    Order matters for failing closed: the key command runs (and is validated) BEFORE any agent
    process exists, so a failing command leaves nothing running.

    ``key_source`` lets a caller that already holds the validated 64-byte key (``unlock --all`` runs
    one key command for several repositories that share it) supply it instead of running ``argv``
    again. It is called only when this repository really needs a key, and what it returns goes the
    same way as always: over the authenticated channel to an agent started here, never anywhere
    else.

    ``cwd`` is where ``argv`` runs (the repository root). ``expected_key_id`` is the key id
    registered for the repository (``keyid``): a key that differs is refused BEFORE any agent is
    started (``KeyIdMismatchError``), and a running agent holding another key is replaced, never
    kept. ``on_delivered`` runs once the key is in the agent (registering the key id, checking the
    vault); when it raises, the agent is locked again."""
    with agent.unlock_guard(state_dir):
        try:
            existing = current_status(state_dir)
        except agent.HandshakeError:
            # something answers where the state points but cannot prove it is our agent (a planted
            # agent.json, or an agent of another secret): it is never given the key, and the new
            # agent below replaces its record
            existing = None
        if (
            existing is not None
            and not existing["locked"]
            and (expected_key_id is None or existing.get("key_id") == expected_key_id)
        ):
            return False, existing
        # (an unlocked agent holding some other key than the one this repository is registered
        # for, unlocked by an older version or by hand, is not kept: it is replaced below)
        if existing is not None:  # no key, or the wrong one: replace it
            with contextlib.suppress(agent.AgentError), agent.AgentClient.connect(state_dir) as c:
                c.lock()
        master = (
            key_source()
            if key_source is not None
            else run_key_command(argv or (), key_timeout, cwd=cwd)
        )
        keyid.check(expected_key_id, keyid.of_key(master))  # before any agent exists
        # always a NEW agent, started and authenticated by this process (never one found by file)
        status = agent.deliver_key(state_dir, master, ttl, idle_timeout, spawn)
        if on_delivered is not None:
            try:
                on_delivered(status)
            except BaseException:
                with contextlib.suppress(Exception), agent.AgentClient.connect(state_dir) as c:
                    c.lock()
                raise
        return True, status


def lock(state_dir: Path) -> bool:
    """Lock (stop) the agent. Returns False if there was none."""
    try:
        client = agent.AgentClient.connect(state_dir)
    except agent.AgentNotRunningError:
        agent.cleanup_orphan(state_dir)
        return False
    with client:
        client.lock()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and agent.agent_json_path(state_dir).exists():
        time.sleep(0.02)
    return True
