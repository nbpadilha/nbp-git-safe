# SPDX-License-Identifier: MIT
from __future__ import annotations

import os
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
    assert not lock.exists()
    with statefile.file_lock(lock):  # and can be taken again
        pass
