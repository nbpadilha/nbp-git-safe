# SPDX-License-Identifier: MIT
"""Tampering with the vault on the remote (blobs, index, tree, forged-but-correctly-encrypted
indexes) must be detected by ``open``, which then writes NOTHING."""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable
from pathlib import Path

import pytest

from nbp_git_safe import crypto, vault
from tests.helpers import NbpRepo
from tests.integration.conftest import Env

CloneFactory = Callable[..., NbpRepo]
Files = dict[str, bytes]


def read_vault(repo: NbpRepo, ref: str = "refs/heads/nbp-safe") -> Files:
    out = repo.git.run("ls-tree", "-r", "-z", ref, cwd=repo.path)
    files: Files = {}
    for record in out.split("\0"):
        if record:
            meta, path = record.split("\t", 1)
            blob = _cat(repo, meta.split()[2])
            files[path] = blob
    return files


def _cat(repo: NbpRepo, sha: str) -> bytes:
    import subprocess

    return subprocess.run(
        ["git", "cat-file", "blob", sha],
        cwd=repo.path,
        env=repo.git.env,
        capture_output=True,
        check=True,
    ).stdout


def write_vault_commit(repo: NbpRepo, files: Files, parent: str | None = None) -> str:
    """Plumbing: commit ``files`` (path -> bytes) on top of ``parent`` and move the ref. Used to
    simulate a hostile or buggy writer; mirrors the real builder but accepts anything."""
    import subprocess

    index_file = repo.path / ".git" / f"forge-index-{secrets.token_hex(4)}"
    env = {**repo.git.env, "GIT_INDEX_FILE": str(index_file)}

    def git(*args: str, input: bytes | None = None) -> str:
        proc = subprocess.run(
            ["git", *args],
            cwd=repo.path,
            env=env,
            input=input,
            capture_output=True,
            check=True,
        )
        return proc.stdout.decode().strip()

    try:
        for path, data in files.items():
            sha = git("hash-object", "-w", "--stdin", "--no-filters", input=data)
            git("update-index", "--add", "--cacheinfo", f"100644,{sha},{path}")
        tree = git("write-tree")
        args = ["commit-tree", tree, "-m", "forged"]
        if parent:
            args += ["-p", parent]
        commit = git(*args)
        git("update-ref", "refs/heads/nbp-safe", commit)
        return commit
    finally:
        index_file.unlink(missing_ok=True)


def tamper_and_push(env: Env, mutate: Callable[[Files], Files]) -> None:
    parent = env.tip()
    write_vault_commit(env.repo, mutate(read_vault(env.repo)), parent)
    env.gate()  # fast-forward push of the tampered tip; no leak either


def snapshot(root: Path) -> set[str]:
    return {p.relative_to(root).as_posix() for p in root.rglob("*") if ".git" not in p.parts}


def store_paths(files: Files) -> list[str]:
    return sorted(p for p in files if p.startswith("store/"))


def flip(data: bytes, position: int = -1) -> bytes:
    raw = bytearray(data)
    raw[position] ^= 0x01
    return bytes(raw)


def _swap(files: Files) -> Files:
    a, b = store_paths(files)[:2]
    files[a], files[b] = files[b], files[a]
    return files


def _drop_blob(files: Files) -> Files:
    del files[store_paths(files)[0]]
    return files


MUTATIONS: dict[str, Callable[[Files], Files]] = {
    "flipped-store-blob": lambda f: {**f, store_paths(f)[0]: flip(f[store_paths(f)[0]])},
    "flipped-store-blob-header": lambda f: {**f, store_paths(f)[0]: flip(f[store_paths(f)[0]], 12)},
    "truncated-store-blob": lambda f: {**f, store_paths(f)[0]: f[store_paths(f)[0]][:20]},
    "swapped-store-blobs": _swap,
    "flipped-index": lambda f: {**f, "nbp-safe/index": flip(f["nbp-safe/index"])},
    "garbage-index": lambda f: {**f, "nbp-safe/index": b"not an index"},
    "extra-file-in-tree": lambda f: {**f, "evil.txt": b"x"},
    "extra-hook-path": lambda f: {**f, ".githooks/pre-commit": b"#!/bin/sh\nexit 0\n"},
    "bad-store-name": lambda f: {**f, "store/NOT-A-HEX-ID": b"x"},
    "modified-gitattributes": lambda f: {**f, ".gitattributes": b"* filter=evil\n"},
    "modified-readme": lambda f: {**f, "README.md": b"# something else\n"},
    "missing-gitattributes": lambda f: {k: v for k, v in f.items() if k != ".gitattributes"},
    "missing-index": lambda f: {k: v for k, v in f.items() if k != "nbp-safe/index"},
    "missing-store-blob": _drop_blob,
}


BLOB_LEVEL = {
    "flipped-store-blob",
    "flipped-store-blob-header",
    "truncated-store-blob",
    "swapped-store-blobs",
    "missing-store-blob",
}


@pytest.mark.parametrize("name", sorted(MUTATIONS))
def test_open_detects_tampering_and_writes_nothing(
    env: Env,
    clone_factory: CloneFactory,
    name: str,
    unlock_fast: Callable[..., object],
) -> None:
    assert env.seal().code == 0
    env.push()  # clean-push leak gates live in test_vault_cycle; here the gate runs after tampering
    tamper_and_push(env, MUTATIONS[name])

    clone = clone_factory(env)
    unlock_fast(clone)
    before = snapshot(clone.path)
    result = clone.cli("open")
    assert result.code == 1, (name, result.out)
    assert "error" in result.err
    assert snapshot(clone.path) == before  # nothing materialized, not even temp files
    if name not in BLOB_LEVEL:  # `ls`/`status` read only the tree and the authenticated index
        assert clone.cli("ls").code != 0
        assert clone.cli("status").code != 0


def clone_of_main(env: Env, clone_factory: CloneFactory) -> NbpRepo:
    """A second machine whose remote has only the main branch (patterns present, no vault)."""
    # exclude block first: protected files stay out of main; no hooks, so that committing does not
    # seal a vault (this remote must have the main branch only)
    assert env.repo.cli("init", "--no-hooks").code == 0
    env.push()
    return clone_factory(env)


def forged_vault(
    repo: NbpRepo, entries: dict[str, tuple[str, bytes]], *, mac_of: dict[str, bytes] | None = None
) -> str:
    """A vault encrypted with the REAL key but with hand-made entries: ``{fid: (path, data)}``.
    ``mac_of`` overrides the content that the index claims (to forge a mismatching blob)."""
    keys = crypto.KeySet(repo.master)
    index_entries = {}
    files: Files = {
        ".gitattributes": vault.GITATTRIBUTES,
        "README.md": vault.README,
    }
    for fid, (path, data) in entries.items():
        claimed = (mac_of or {}).get(fid, data)
        index_entries[fid] = {
            "path": path,
            "mode": "100644",
            "size": len(claimed),
            "mac": crypto.content_mac(keys, claimed).hex(),
            "created": 0,
            "updated": 0,
        }
        files[f"store/{fid}"] = crypto.encrypt_blob(keys, fid, data)
    index = {"v": 1, "key_id": keys.key_id.hex(), "entries": index_entries}
    files["nbp-safe/index"] = crypto.encrypt_index(keys, index)
    return write_vault_commit(repo, files)


EVIL_PATHS = {
    "parent-traversal": "../escape.txt",
    "inner-traversal": "reports/../../escape.txt",
    "git-hook": ".git/hooks/post-checkout",
    "git-config": "reports/../.git/config",
    "absolute-path": "/etc/escape.txt",
    "drive-letter": "C:/escape.txt",
    "outside-protected-set": "docs/not-protected.txt",
    "reserved-windows-name": "reports/CON",
    "reserved-with-extension": "reports/aux.txt",
    "trailing-dot": "reports/file.",
    "gitattributes-anywhere": "reports/.gitattributes",
    "nbp-config": ".nbp-safe",
    "tmp-suffix": "reports/x.nbp-tmp",
    "backslash": "reports\\x.txt",
    "nfd-path": "reports/cafe\u0301.txt",
    "dotdot-component": "reports/..",
    "empty-component": "reports//x.txt",
    "nul-byte": "reports/a\x00b",
}


@pytest.mark.parametrize("name", sorted(EVIL_PATHS))
def test_forged_index_with_evil_path_is_refused(
    env: Env,
    clone_factory: CloneFactory,
    name: str,
    unlock_fast: Callable[..., object],
) -> None:
    clone = clone_of_main(env, clone_factory)
    forged_vault(clone, {"a" * 32: (EVIL_PATHS[name], b"payload")})
    unlock_fast(clone)
    before = snapshot(clone.path)
    outside = clone.path.parent / "escape.txt"
    result = clone.cli("open")
    assert result.code == 1 and "error" in result.err, name
    expected = (
        "outside the protected set" if name == "outside-protected-set" else "failed validation"
    )
    assert expected in result.err, (name, result.err)
    assert snapshot(clone.path) == before
    assert not outside.exists()


def test_forged_index_case_collision_and_file_dir_conflict_refused(
    env: Env,
    clone_factory: CloneFactory,
    unlock_fast: Callable[..., object],
) -> None:
    clone = clone_of_main(env, clone_factory)
    forged_vault(
        clone,
        {"a" * 32: ("reports/Dup.txt", b"1"), "b" * 32: ("reports/dup.TXT", b"2")},
    )
    unlock_fast(clone)
    assert clone.cli("open").code == 1
    forged_vault(clone, {"a" * 32: ("reports/x", b"1"), "b" * 32: ("reports/x/y", b"2")})
    assert clone.cli("open").code == 1
    assert not (clone.path / "reports").exists()


def test_forged_tracked_path_is_refused(
    env: Env, clone_factory: CloneFactory, unlock_fast: Callable[..., object]
) -> None:
    """Even if a pattern covers it, a file tracked on the main branch is never overwritten."""
    env.repo.write("tracked-doc.txt", "versioned normally")
    env.repo.write(
        ".nbp-safe", "reports/\ndata-private/**\n!data-private/keep-public.txt\ntracked-*\n"
    )
    env.repo.sh("add", ".nbp-safe", "tracked-doc.txt")
    env.repo.sh("commit", "-q", "-m", "tracked file that matches a pattern")
    env.repo.sh("push", "-q", "origin", "main")
    clone = clone_of_main(env, clone_factory)
    forged_vault(clone, {"a" * 32: ("tracked-doc.txt", b"overwritten!")})
    unlock_fast(clone)
    result = clone.cli("open")
    assert result.code == 1 and "tracked on the main branch" in result.err
    assert clone.read("tracked-doc.txt") == b"versioned normally"


def test_blob_that_does_not_match_the_authenticated_index_is_refused(
    env: Env,
    clone_factory: CloneFactory,
    unlock_fast: Callable[..., object],
) -> None:
    clone = clone_of_main(env, clone_factory)
    forged_vault(
        clone,
        {"a" * 32: ("reports/lie.txt", b"actual content")},
        mac_of={"a" * 32: b"what the index claims"},
    )
    unlock_fast(clone)
    result = clone.cli("open")
    assert result.code == 1 and "does not match the authenticated index" in result.err
    assert not (clone.path / "reports").exists()


def test_index_for_another_key_id_is_refused(
    env: Env, clone_factory: CloneFactory, unlock_fast: Callable[..., object]
) -> None:
    clone = clone_of_main(env, clone_factory)
    keys = crypto.KeySet(clone.master)
    index = {"v": 1, "key_id": "00" * 8, "entries": {}}
    write_vault_commit(
        clone,
        {
            ".gitattributes": vault.GITATTRIBUTES,
            "README.md": vault.README,
            "nbp-safe/index": crypto.encrypt_index(keys, index),
        },
    )
    unlock_fast(clone)
    assert clone.cli("open").code == 1


def test_valid_forged_vault_with_good_paths_is_opened(
    env: Env,
    clone_factory: CloneFactory,
    unlock_fast: Callable[..., object],
) -> None:
    """Control for the forging helper: a well-formed vault made by the helper opens fine."""
    clone = clone_of_main(env, clone_factory)
    forged_vault(clone, {"c" * 32: ("reports/ok file.txt", b"fine")})
    unlock_fast(clone)
    assert clone.cli("open").code == 0
    assert clone.read("reports/ok file.txt") == b"fine"


def test_open_without_any_vault(
    env: Env, clone_factory: CloneFactory, unlock_fast: Callable[..., object]
) -> None:
    clone = clone_of_main(env, clone_factory)
    unlock_fast(clone)
    result = clone.cli("open")
    assert result.code == 1 and "no vault" in result.err


def test_open_survives_a_garbage_agent_json_gracefully(
    env: Env, clone_factory: CloneFactory
) -> None:
    clone = clone_factory(env)
    clone.state_dir.mkdir(parents=True, exist_ok=True)
    (clone.state_dir / "agent.json").write_text(json.dumps({"v": 1}))
    assert clone.cli("open").code == 3
    assert not (clone.state_dir / "agent.json").exists()
