# SPDX-License-Identifier: MIT
"""``keyCommand`` execution and the unlock/lock/status flow.

The command is an argv list read only from the local ``.git/config`` (see ``config.py``). It runs
in the foreground CLI process WITHOUT a shell (so interactive prompts such as a password
manager's biometric dialog can appear), with a timeout, and its stdout must be the base64 of the
64-byte master key. The key is delivered to the agent over the authenticated channel; it is never
placed in argv, the environment, a file, a log or an error message.

The command gets an allow-listed environment (``gitutil.key_command_env``): ``OP_*`` variables only
when it is ``op`` itself (or when named in ``NBP_SAFE_PASS_ENV``). Its stderr goes to the terminal
when a person is there (a password manager may prompt on it); in an unattended run it is captured,
and only a short REDACTED tail of it is quoted in the error when the command fails.
"""

from __future__ import annotations

import contextlib
import os
import re
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from nbp_git_safe import agent, crypto, gitutil

MAX_KEY_OUTPUT = 4096
MAX_ERROR_QUOTE = 300
# Anything that looks like a token, a key or a long id: 20+ characters of a base64/base64url/hex
# alphabet. Over-redacting an error message is harmless; quoting a credential is not.
_SECRETISH = re.compile(r"[A-Za-z0-9+/_-]{20,}=*")
_TRUE = ("1", "true", "yes", "on")
_FALSE = ("0", "false", "no", "off")


def non_interactive() -> bool:
    """Is this process running unattended? ``NBP_SAFE_NONINTERACTIVE`` decides when set; otherwise
    a set ``CI`` or a stderr that is not a terminal means nobody is there to read a message."""
    flag = os.environ.get("NBP_SAFE_NONINTERACTIVE", "").strip().lower()
    if flag in _TRUE:
        return True
    if flag in _FALSE:
        return False
    if os.environ.get("CI", "").strip().lower() not in ("", *_FALSE):
        return True
    try:
        return not sys.stderr.isatty()
    except (AttributeError, ValueError, OSError):
        return True


def redact(text: str) -> str:
    """A short, redacted tail of a child's stderr, safe to put in an error message or a log."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    tail = " | ".join(lines[-3:])
    tail = _SECRETISH.sub("[redacted]", tail)
    return tail[-MAX_ERROR_QUOTE:]


class KeyCommandError(Exception):
    """keyCommand could not produce a valid key. Messages never include its stdout; a failure of
    an unattended run quotes a short, redacted tail of its stderr."""


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
            )
    else:
        with contextlib.suppress(OSError, ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)  # type: ignore[attr-defined]
    with contextlib.suppress(OSError):
        proc.kill()


def run_key_command(argv: Sequence[str], timeout: float) -> bytes:
    """Run ``argv`` (no shell) and return the validated 64-byte master key."""
    if not argv:
        raise KeyCommandError("no keyCommand configured (git config nbp-safe.keyCommand)")
    kwargs: dict[str, Any] = {}
    if sys.platform != "win32":
        kwargs["start_new_session"] = True
    capture = non_interactive()
    if capture:  # unattended: whatever it prints goes nowhere but a redacted error message
        kwargs["stderr"] = subprocess.PIPE
    try:
        command = [gitutil.resolve_executable(argv[0]), *argv[1:]]  # never from the cwd
        proc = subprocess.Popen(  # noqa: S603 - argv list from the local .git/config, no shell
            command,
            env=gitutil.key_command_env(argv[0], os.environ),
            shell=False,
            stdout=subprocess.PIPE,
            **kwargs,
        )
    except FileNotFoundError:
        raise KeyCommandError("keyCommand executable not found") from None
    except OSError:
        raise KeyCommandError("keyCommand could not be started") from None
    timed_out = False
    out = err = b""
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        with contextlib.suppress(Exception):
            proc.communicate(timeout=5)
    if timed_out:
        raise KeyCommandError(f"keyCommand timed out after {timeout:g} s")
    if proc.returncode != 0:
        said = redact((err or b"").decode("utf-8", "replace")) if capture else ""
        detail = f": {said}" if said else ""
        raise KeyCommandError(f"keyCommand failed (exit code {proc.returncode}){detail}")
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
) -> tuple[bool, dict[str, Any]]:
    """Unlock the repository. Returns ``(newly_unlocked, agent_status)``.

    Order matters for failing closed: the key command runs (and is validated) BEFORE any agent
    process exists, so a failing command leaves nothing running."""
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
        master = run_key_command(argv or (), key_timeout)
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
