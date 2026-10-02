# SPDX-License-Identifier: MIT
"""Prove the leak harness works: it must detect a canary planted on purpose in each kind of
target (bare repo, local .git, arbitrary directory), in every encoding, and it must not
report anything on clean data."""

from __future__ import annotations

import base64
import os
import secrets
from collections.abc import Callable
from pathlib import Path

import pytest

from tests.conftest import IsolatedGit
from tests.leak.harness import LeakScanner, assert_no_leaks, make_canaries, variants

RepoFactory = Callable[..., Path]


@pytest.fixture
def canaries() -> list[str]:
    return make_canaries(3)


@pytest.fixture
def scanner(canaries: list[str], isolated_git: IsolatedGit) -> LeakScanner:
    return LeakScanner(canaries, git_env=isolated_git.env)


def _commit(git: IsolatedGit, repo: Path, message: str = "clean commit") -> None:
    git.run("add", "-A", cwd=repo)
    git.run("commit", "--quiet", "-m", message, cwd=repo)


def test_make_canaries_shape_and_uniqueness() -> None:
    a, b = make_canaries(3), make_canaries(3)
    assert len(a) == 3
    assert all(c.startswith(f"CANARY_{i}_") for i, c in enumerate(a, 1))
    assert not set(a) & set(b)


def test_scanner_requires_canaries() -> None:
    with pytest.raises(ValueError, match="canary"):
        LeakScanner([])


def test_default_git_env_is_inherited() -> None:
    assert LeakScanner(["CANARY_1_x"])._git_env["PATH"] == os.environ["PATH"]


def test_every_variant_detected_inside_larger_data(
    scanner: LeakScanner, canaries: list[str]
) -> None:
    raw = canaries[0].encode()
    for name, needle in variants(canaries[0]).items():
        assert needle, name
        for pad in range(3):
            hits = scanner.scan_bytes(b"\x01" * pad + needle + b"\x02", "blob")
            assert any(h.canary == canaries[0] and h.variant == name for h in hits), name
    # base64 of the canary embedded at each real alignment inside a bigger stream
    for prefix in (b"", b"A", b"AB"):
        for encoder in (base64.b64encode, base64.urlsafe_b64encode):
            stream = encoder(prefix + raw + b"tail")
            hits = scanner.scan_bytes(stream, "stream")
            assert any(h.variant.startswith("base64") for h in hits), (prefix, encoder)


def test_utf16_and_hex_detected(scanner: LeakScanner, canaries: list[str]) -> None:
    c = canaries[1]
    assert any(h.variant == "utf-16le" for h in scanner.scan_bytes(c.encode("utf-16"), "x"))
    assert any(h.variant == "utf-16be" for h in scanner.scan_bytes(c.encode("utf-16-be"), "x"))
    upper = c.encode().hex().upper().encode()
    assert any(h.variant == "hex-upper" for h in scanner.scan_bytes(upper, "x"))


def test_no_false_positives_on_random_and_near_miss_data(
    scanner: LeakScanner, canaries: list[str]
) -> None:
    assert scanner.scan_bytes(secrets.token_bytes(1 << 16), "random") == []
    near = canaries[0][:-1] + ("0" if canaries[0][-1] != "0" else "1")
    assert scanner.scan_bytes(near.encode(), "near") == []
    assert scanner.scan_bytes(b"CANARY_1_", "prefix-only") == []


def test_hit_string_never_contains_scanned_data(scanner: LeakScanner, canaries: list[str]) -> None:
    hits = scanner.scan_bytes(b"SECRET-CONTEXT" + canaries[0].encode(), "w")
    (hit,) = [h for h in hits if h.variant == "utf-8"]
    assert "SECRET-CONTEXT" not in str(hit)
    assert canaries[0] in str(hit)


def test_assert_no_leaks(scanner: LeakScanner, canaries: list[str]) -> None:
    assert_no_leaks([])
    with pytest.raises(AssertionError, match="leak"):
        assert_no_leaks(scanner.scan_bytes(canaries[0].encode(), "somewhere"))


# ------------------------------------------------------------------ directory scan


def test_dir_clean_has_no_hits(scanner: LeakScanner, tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "a.txt").write_text("nothing to see")
    assert_no_leaks(scanner.scan_dir(tmp_path))


def test_dir_detects_planted_content_and_name(
    scanner: LeakScanner, canaries: list[str], tmp_path: Path
) -> None:
    (tmp_path / "content.bin").write_bytes(canaries[0].encode("utf-16-le"))
    (tmp_path / f"{canaries[1]}.txt").write_text("x")
    (tmp_path / canaries[2]).mkdir()
    hits = scanner.scan_dir(tmp_path)
    assert {(h.canary, h.variant) for h in hits} >= {
        (canaries[0], "utf-16le"),
        (canaries[1], "utf-8"),
        (canaries[2], "utf-8"),
    }
    assert any("(name)" in h.where for h in hits)


def test_dir_unreadable_entry_is_skipped(
    scanner: LeakScanner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "f.txt"
    target.write_text("x")
    real = Path.read_bytes

    def boom(self: Path) -> bytes:
        if self == target:
            raise PermissionError
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", boom)
    assert scanner.scan_dir(tmp_path) == []


# ---------------------------------------------------------------- git repositories


def _make_clean_repo(git: IsolatedGit, git_repo: RepoFactory) -> Path:
    repo = git_repo("work")
    (repo / "readme.txt").write_text("harmless content\n")
    _commit(git, repo)
    return repo


def test_clean_repo_and_bare_remote_have_zero_false_positives(
    scanner: LeakScanner, isolated_git: IsolatedGit, git_repo: RepoFactory
) -> None:
    repo = _make_clean_repo(isolated_git, git_repo)
    bare = git_repo("remote.git", bare=True)
    isolated_git.run("push", "--quiet", str(bare), "main", cwd=repo)
    assert_no_leaks(scanner.scan_git_dir(repo / ".git"))
    assert_no_leaks(scanner.scan_bare_repo(bare))


def test_bare_repo_detects_content_name_and_message(
    scanner: LeakScanner,
    canaries: list[str],
    isolated_git: IsolatedGit,
    git_repo: RepoFactory,
) -> None:
    repo = git_repo("work")
    (repo / "plain.txt").write_text(f"data {canaries[0]} data\n")  # content (blob)
    (repo / f"{canaries[1]}.txt").write_text("harmless\n")  # file name (tree)
    _commit(isolated_git, repo, f"message {canaries[2]}")  # commit message
    bare = git_repo("remote.git", bare=True)
    isolated_git.run("push", "--quiet", str(bare), "main", cwd=repo)
    hits = scanner.scan_bare_repo(bare)
    assert {h.canary for h in hits} == set(canaries)
    assert any(h.where.endswith("(blob)") and h.canary == canaries[0] for h in hits)
    assert any(h.where.endswith("(tree)") and h.canary == canaries[1] for h in hits)
    assert any(h.where.endswith("(commit)") and h.canary == canaries[2] for h in hits)


def test_bare_repo_detects_annotated_tag_and_branch_name(
    scanner: LeakScanner,
    canaries: list[str],
    isolated_git: IsolatedGit,
    git_repo: RepoFactory,
) -> None:
    repo = _make_clean_repo(isolated_git, git_repo)
    isolated_git.run("tag", "-a", "v1", "-m", f"tag {canaries[0]}", cwd=repo)
    isolated_git.run("branch", f"br-{canaries[1]}", cwd=repo)
    bare = git_repo("remote.git", bare=True)
    isolated_git.run("push", "--quiet", str(bare), "--all", cwd=repo)
    isolated_git.run("push", "--quiet", str(bare), "--tags", cwd=repo)
    hits = scanner.scan_bare_repo(bare)
    assert any(h.where == "for-each-ref" and h.canary == canaries[1] for h in hits)
    assert any(h.where.endswith("(tag)") and h.canary == canaries[0] for h in hits)
    isolated_git.run("pack-refs", "--all", cwd=bare)
    hits = scanner.scan_bare_repo(bare)
    assert any(h.where == "packed-refs" and h.canary == canaries[1] for h in hits)


def test_local_git_dir_detects_packed_object_and_state_files(
    scanner: LeakScanner,
    canaries: list[str],
    isolated_git: IsolatedGit,
    git_repo: RepoFactory,
) -> None:
    repo = git_repo("work")
    payload = base64.b64encode(b"prefix-" + canaries[0].encode()).decode()
    (repo / "enc.txt").write_text(payload)  # canary present only base64-encoded
    _commit(isolated_git, repo)
    isolated_git.run("gc", "--quiet", "--aggressive", cwd=repo)  # objects now in a pack
    git_dir = repo / ".git"
    assert list((git_dir / "objects" / "pack").glob("*.pack"))
    hits = scanner.scan_git_dir(git_dir)
    assert any(
        h.canary == canaries[0] and h.where.startswith("object") and h.variant.startswith("base64")
        for h in hits
    )
    # non-object state: info/, config, a state file whose *name* carries a canary
    (git_dir / "info").mkdir(exist_ok=True)
    (git_dir / "info" / "exclude").write_text(f"# {canaries[1]}\n")
    isolated_git.run("config", "--local", "custom.value", canaries[2], cwd=repo)
    (git_dir / "nbp-safe").mkdir()
    (git_dir / "nbp-safe" / f"{canaries[2]}.state").write_bytes(b"x")
    hits = scanner.scan_git_dir(git_dir)
    assert {h.canary for h in hits} == set(canaries)
    assert any(h.where.endswith("(name)") for h in hits)
    assert any(h.where == "config" and h.canary == canaries[2] for h in hits)


def test_unreachable_object_is_detected(
    scanner: LeakScanner,
    canaries: list[str],
    isolated_git: IsolatedGit,
    git_repo: RepoFactory,
) -> None:
    repo = _make_clean_repo(isolated_git, git_repo)
    isolated_git.run(
        "hash-object", "-w", "--stdin", cwd=repo, input=f"orphan {canaries[0]}".encode()
    )
    hits = scanner.scan_git_dir(repo / ".git")
    assert any(h.canary == canaries[0] and h.variant == "utf-8" for h in hits)


def test_git_failure_is_reported_not_swallowed(scanner: LeakScanner, tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="cat-file"):
        scanner.scan_objects(tmp_path / "not-a-repo")
    with pytest.raises(RuntimeError, match="for-each-ref"):
        scanner.scan_refs(tmp_path / "not-a-repo")
