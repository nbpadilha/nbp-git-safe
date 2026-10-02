# SPDX-License-Identifier: MIT
"""Regression for the flaky ``Permission denied: .../agent.json`` seen in long test runs.

On Windows an ``open``/``replace``/``unlink`` that collides with another process's open or rename
of the same name fails with ``PermissionError`` (EACCES). ``agent.json`` is replaced atomically by
the agent while the CLI polls it (``unlock`` -> ``spawn_agent``), so the CLI used to crash with
that error (or the agent failed to start). The fix waits such violations out for a bounded time.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from nbp_git_safe import agent

WRITER = """
import os, sys, time
from pathlib import Path
from nbp_git_safe import agent
info = agent.AgentInfo("x", "AF_PIPE", os.urandom(32), os.getpid(), 1.0, 2.0, None)
state = Path(sys.argv[1])
errors = 0
for _ in range(int(sys.argv[2])):
    try:
        agent.write_agent_info(state, info)
    except OSError:
        errors += 1
print(errors)
"""


def _info() -> agent.AgentInfo:
    return agent.AgentInfo("x", "AF_PIPE", os.urandom(32), os.getpid(), 1.0, 2.0, None)


class Flaky:
    """Fails the first ``failures`` calls with PermissionError, then delegates."""

    def __init__(self, real, failures: int) -> None:  # type: ignore[no-untyped-def]
        self.real, self.left, self.calls = real, failures, 0

    def __call__(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        self.calls += 1
        if self.left > 0:
            self.left -= 1
            raise PermissionError(13, "Permission denied")
        return self.real(*args, **kwargs)


def test_read_waits_out_a_transient_sharing_violation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    info = _info()
    agent.write_agent_info(tmp_path, info)
    flaky = Flaky(Path.read_bytes, 3)
    monkeypatch.setattr(Path, "read_bytes", lambda self: flaky(self))
    assert agent.read_agent_info(tmp_path) == info
    assert flaky.calls == 4


def test_replace_and_unlink_wait_out_a_transient_sharing_violation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    info = _info()
    flaky_replace = Flaky(os.replace, 3)
    monkeypatch.setattr(os, "replace", flaky_replace)
    agent.write_agent_info(tmp_path, info)
    assert flaky_replace.calls == 4 and agent.read_agent_info(tmp_path) == info
    monkeypatch.undo()
    flaky_unlink = Flaky(Path.unlink, 2)
    monkeypatch.setattr(Path, "unlink", lambda self, *a, **k: flaky_unlink(self, *a, **k))
    agent.remove_agent_info(tmp_path)
    assert flaky_unlink.calls == 3 and not agent.agent_json_path(tmp_path).exists()


def test_a_persistent_permission_error_is_still_an_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent.write_agent_info(tmp_path, _info())
    monkeypatch.setattr(agent, "SHARING_RETRY_WINDOW", 0.05)
    monkeypatch.setattr(Path, "read_bytes", Flaky(Path.read_bytes, 10**9))
    with pytest.raises(PermissionError):
        agent.read_agent_info(tmp_path)


def test_failed_write_leaves_no_temp_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent, "SHARING_RETRY_WINDOW", 0.05)
    monkeypatch.setattr(os, "replace", Flaky(os.replace, 10**9))
    with pytest.raises(PermissionError):
        agent.write_agent_info(tmp_path, _info())
    monkeypatch.undo()
    assert list(tmp_path.iterdir()) == []


def test_shutdown_exits_even_if_agent_json_cannot_be_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exited: list[int] = []
    server = agent.AgentServer(tmp_path, 60, exit_func=exited.append)
    monkeypatch.setattr(
        agent, "remove_agent_info", lambda _d: (_ for _ in ()).throw(PermissionError(13, "x"))
    )
    server.shutdown("test")
    assert exited == [0]


def test_reader_racing_a_replacing_writer_never_sees_an_error(tmp_path: Path) -> None:
    """The real thing: two processes, atomic replaces against polling reads (before the fix this
    produced PermissionError for the reader and for the writer within a few hundred rounds)."""
    writes = 400
    proc = subprocess.Popen(
        [sys.executable, "-c", WRITER, str(tmp_path), str(writes)],
        stdout=subprocess.PIPE,
        text=True,
    )
    reads = 0
    deadline = time.monotonic() + 120
    while proc.poll() is None and time.monotonic() < deadline:
        agent.read_agent_info(tmp_path)  # must never raise
        reads += 1
    out, _ = proc.communicate(timeout=30)
    assert proc.returncode == 0 and out.strip() == "0"  # no writer errors either
    assert reads > 0
