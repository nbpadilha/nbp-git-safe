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
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from nbp_git_safe import agent, crypto, gitutil

MAX_KEY_OUTPUT = 4096


class KeyCommandError(Exception):
    """keyCommand could not produce a valid key. Messages never include its output."""


def _taskkill() -> str:
    root = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or r"C:\Windows"
    return str(Path(root) / "System32" / "taskkill.exe")


def _kill_tree(proc: subprocess.Popen[bytes]) -> None:
    if sys.platform == "win32":
        with contextlib.suppress(OSError):
            subprocess.run(  # noqa: S603
                [_taskkill(), "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=15,
                **gitutil.window_flags(),
            )
    else:
        with contextlib.suppress(OSError, ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)  # type: ignore[attr-defined]
    with contextlib.suppress(OSError):
        proc.kill()


def run_key_command(
    argv: Sequence[str], timeout: float, *, avoid: Sequence[str | os.PathLike[str]] = ()
) -> bytes:
    """Run ``argv`` (no shell) and return the validated 64-byte master key. ``avoid`` lists
    repository trees that must not provide the program (``unlock --all`` is not run from inside
    the repository it unlocks, so the caller names them)."""
    if not argv:
        raise KeyCommandError("no keyCommand configured (git config nbp-safe.keyCommand)")
    kwargs: dict[str, Any] = gitutil.window_flags()
    if sys.platform != "win32":
        kwargs["start_new_session"] = True
    try:
        command = [gitutil.resolve_executable(argv[0], avoid=avoid), *argv[1:]]  # not from the cwd
        proc = subprocess.Popen(  # noqa: S603 - argv list from the local .git/config, no shell
            command,
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
    if timed_out:
        raise KeyCommandError(f"keyCommand timed out after {timeout:g} s")
    if proc.returncode != 0:
        raise KeyCommandError(f"keyCommand failed (exit code {proc.returncode})")
    if len(out) > MAX_KEY_OUTPUT:
        raise KeyCommandError("keyCommand output is not a valid key")
    try:
        return crypto.decode_key(out)
    except crypto.NbpCryptoError:
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
) -> tuple[bool, dict[str, Any]]:
    """Unlock the repository. Returns ``(newly_unlocked, agent_status)``.

    Order matters for failing closed: the key command runs (and is validated) BEFORE any agent
    process exists, so a failing command leaves nothing running.

    ``key_source`` lets a caller that already holds the validated 64-byte key (``unlock --all`` runs
    one key command for several repositories that share it) supply it instead of running ``argv``
    again. It is called only when this repository really needs a key, and what it returns goes the
    same way as always: over the authenticated channel to an agent started here, never anywhere
    else."""
    with agent.unlock_guard(state_dir):
        try:
            existing = current_status(state_dir)
        except agent.HandshakeError:
            # something answers where the state points but cannot prove it is our agent (a planted
            # agent.json, or an agent of another secret): it is never given the key, and the new
            # agent below replaces its record
            existing = None
        if existing is not None and not existing["locked"]:
            return False, existing
        if existing is not None:  # a running agent that never received a key: replace it
            with contextlib.suppress(agent.AgentError), agent.AgentClient.connect(state_dir) as c:
                c.lock()
        master = (
            key_source() if key_source is not None else run_key_command(argv or (), key_timeout)
        )
        # always a NEW agent, started and authenticated by this process (never one found by file)
        status = agent.deliver_key(state_dir, master, ttl, idle_timeout, spawn)
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
