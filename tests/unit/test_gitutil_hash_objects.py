# SPDX-License-Identifier: MIT
"""``hash_objects`` writes many blobs with one process; ids must equal ``hash-object -w`` and
the failure modes must be errors, never guesses. Fake data only."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from nbp_git_safe import gitutil
from nbp_git_safe.gitutil import Git, GitError, hash_object, hash_objects
from tests.conftest import IsolatedGit

PAYLOADS = [b"", b"x", b"line\r\nwith crlf\n", os.urandom(70_000), os.urandom(300_000), b"\0\0\0"]


@pytest.fixture
def repo_git(git_repo: Callable[..., Path], isolated_git: IsolatedGit) -> Git:
    return Git(git_repo("repo"), isolated_git.env)


def test_ids_equal_hash_object_and_blobs_are_stored(repo_git: Git, isolated_git: IsolatedGit):
    ids = hash_objects(repo_git, PAYLOADS)
    assert len(ids) == len(PAYLOADS)
    for sha, payload in zip(ids, PAYLOADS, strict=True):
        assert sha == hash_object(Git(repo_git.cwd, isolated_git.env), payload)
        stored = subprocess.run(
            ["git", "cat-file", "blob", sha],
            cwd=repo_git.cwd,
            env=isolated_git.env,
            capture_output=True,
            check=True,
        ).stdout
        assert stored == payload


def test_empty_list_spawns_nothing(repo_git: Git, monkeypatch: pytest.MonkeyPatch):
    def boom(*_a: object, **_k: object) -> None:
        raise AssertionError("no process expected")

    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(subprocess, "run", boom)
    assert hash_objects(repo_git, []) == []


def test_many_blobs_use_a_constant_number_of_processes(
    repo_git: Git, monkeypatch: pytest.MonkeyPatch
):
    calls: list[list[str]] = []
    real_popen = subprocess.Popen

    def counting(argv: list[str], *args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        calls.append(list(argv))
        return real_popen(argv, *args, **kwargs)  # type: ignore[call-overload]

    monkeypatch.setattr(subprocess, "Popen", counting)
    blobs = [f"blob number {i}".encode() * 40 for i in range(250)]
    ids = hash_objects(repo_git, blobs)
    assert len(set(ids)) == 250
    # a constant number of processes (format probe, the import, the check), whatever the count
    assert [c[1] for c in calls] == ["rev-parse", "fast-import", "cat-file"]


def test_duplicate_and_already_stored_blobs_are_fine(repo_git: Git):
    first = hash_objects(repo_git, [b"same content", b"same content"])
    assert first[0] == first[1]
    assert hash_objects(repo_git, [b"same content"]) == [first[0]]


def test_fast_import_failure_is_a_git_error(tmp_path: Path, isolated_git: IsolatedGit):
    not_a_repo = tmp_path / "plain-dir"
    not_a_repo.mkdir()
    with pytest.raises(GitError):
        hash_objects(Git(not_a_repo, isolated_git.env), [b"data"])


def test_a_blob_git_does_not_report_is_an_error(repo_git: Git, monkeypatch: pytest.MonkeyPatch):
    real_text = Git.text

    def fake_text(self: Git, *args: str, **kwargs: object) -> str:
        if args[:2] == ("cat-file", "--batch-check"):
            return "0" * 40 + " missing\n"
        return real_text(self, *args, **kwargs)

    monkeypatch.setattr(Git, "text", fake_text)
    with pytest.raises(GitError, match="did not store"):
        hash_objects(repo_git, [b"data"])


def test_non_sha1_repositories_fall_back_to_hash_object(
    repo_git: Git, monkeypatch: pytest.MonkeyPatch
):
    seen: list[bytes] = []

    def fake_hash_object(_git: Git, data: bytes) -> str:
        seen.append(data)
        return "f" * 40

    monkeypatch.setattr(gitutil, "_object_format", lambda _git: "sha256")
    monkeypatch.setattr(gitutil, "hash_object", fake_hash_object)
    assert hash_objects(repo_git, [b"a", b"b"]) == ["f" * 40, "f" * 40]
    assert seen == [b"a", b"b"]
