# SPDX-License-Identifier: MIT
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from nbp_git_safe import plainfile, statefile


def test_atomic_write_replaces_and_leaves_no_temporary_file(tmp_path: Path) -> None:
    target = tmp_path / "state.json"
    statefile.atomic_write(target, b"one")
    statefile.atomic_write(target, b"two")
    assert target.read_bytes() == b"two"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["state.json"]


def test_a_failed_replace_keeps_the_old_file_and_removes_the_temporary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "state.json"
    target.write_bytes(b"old")

    def fail(_src: object, _dst: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(OSError, match="disk full"):
        statefile.atomic_write(target, b"new")
    monkeypatch.undo()
    assert target.read_bytes() == b"old"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["state.json"]


def test_read_small_absent_plain_and_too_big(tmp_path: Path) -> None:
    assert statefile.read_small(tmp_path / "none", 10) is None
    (tmp_path / "ok").write_bytes(b"12345")
    assert statefile.read_small(tmp_path / "ok", 10) == b"12345"
    (tmp_path / "big").write_bytes(b"x" * 11)
    with pytest.raises(plainfile.UnsafeFileError):
        statefile.read_small(tmp_path / "big", 10)
    with pytest.raises(plainfile.UnsafeFileError):
        statefile.read_small(tmp_path, 10)  # a directory is not a plain file


def test_read_small_reports_an_unreadable_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "f").write_bytes(b"abc")

    def deny(_self: Path) -> bytes:
        raise PermissionError(13, "Access is denied")

    monkeypatch.setattr(Path, "read_bytes", deny)
    # a persistent sharing violation is retried for a while and then reported, not hidden
    monkeypatch.setattr("nbp_git_safe.agent.SHARING_RETRY_WINDOW", 0.05)
    with pytest.raises(statefile.StateFileError, match="cannot read"):
        statefile.read_small(tmp_path / "f", 10)


def test_file_lock_is_released_even_when_the_body_raises(tmp_path: Path) -> None:
    lock = tmp_path / "x.lock"
    with pytest.raises(RuntimeError), statefile.file_lock(lock):
        assert lock.exists()
        raise RuntimeError("boom")
    # the lock is the operating system's, not the file: the (empty) file stays, and is free again
    assert lock.read_bytes() == b""
    with statefile.file_lock(lock, wait=0.5):
        pass


HOLDER = (
    "import sys, time\n"
    "from pathlib import Path\n"
    "from nbp_git_safe import statefile\n"
    "with statefile.file_lock(Path(sys.argv[1])):\n"
    "    print('held', flush=True)\n"
    "    time.sleep(120)\n"
)


def start_holder(lock: Path) -> subprocess.Popen[str]:
    proc = subprocess.Popen(
        [sys.executable, "-c", HOLDER, str(lock)],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert proc.stdout is not None and proc.stdout.readline().strip() == "held"
    return proc


def test_a_live_holder_blocks_and_a_dead_one_frees_the_lock_at_once(tmp_path: Path) -> None:
    """Review (informational): the old lock was "a file that exists" and a leftover one was taken
    over after two minutes by whoever looked first; two contenders could both take it. The
    operating system now drops the lock the moment its holder dies: nothing to guess."""
    lock = tmp_path / "w.lock"
    proc = start_holder(lock)
    try:
        started = time.monotonic()
        live = pytest.raises(statefile.StateFileError, match="another process")  # a live holder
        with live, statefile.file_lock(lock, wait=0.3):
            pass
        assert time.monotonic() - started < 5
        proc.kill()  # the holder dies without cleaning up (a crash)
        proc.wait(10)
        started = time.monotonic()
        with statefile.file_lock(lock, wait=5):  # free at once: no stale period to wait out
            pass
        assert time.monotonic() - started < 3
    finally:
        proc.kill()
        proc.wait(10)
        if proc.stdout:
            proc.stdout.close()


def test_two_threads_never_hold_the_lock_together(tmp_path: Path) -> None:
    lock = tmp_path / "t.lock"
    inside = 0
    overlap = []
    guard = threading.Lock()

    def worker() -> None:
        nonlocal inside
        for _ in range(15):
            with statefile.file_lock(lock, wait=30):
                with guard:
                    inside += 1
                    overlap.append(inside)
                time.sleep(0.002)
                with guard:
                    inside -= 1

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    assert overlap and max(overlap) == 1
