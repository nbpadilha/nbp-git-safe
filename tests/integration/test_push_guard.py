# SPDX-License-Identifier: MIT
"""Guard on the main branch, push side: ``pre-push`` repeats the path/content checks over every
commit that would be sent, validates the vault branch that would be sent, seals first when the
agent is unlocked, and never blocks the code push because the vault is merely out of date.
The bare remote is scanned for canaries after every scenario where nothing may have leaked."""

from __future__ import annotations

import pytest

from nbp_git_safe import crypto, vault
from tests.integration.conftest import Env
from tests.integration.guardkit import assert_remote_clean, commit, first_protected, remote_refs
from tests.integration.test_vault_tamper import flip, read_vault, store_paths, write_vault_commit


def bypass_commit(env: Env, message: str = "bypass") -> None:
    """Commit whatever is staged with the pre-commit hook skipped (the documented hole)."""
    result = commit(env.repo, message, "--no-verify")
    assert result.returncode == 0, result.stderr


# -------------------------------------------------------------------------- happy paths


def test_normal_push_of_code_and_vault_passes(hooked: Env) -> None:
    result = hooked.repo.raw("push", "origin", "main", "nbp-safe")
    assert result.returncode == 0, result.stderr
    refs = remote_refs(hooked)
    assert refs["refs/heads/nbp-safe"] == hooked.tip()
    hooked.repo.assert_no_leak(hooked.bare)


def test_deleting_a_remote_branch_and_pushing_tags_are_not_in_the_way(hooked: Env) -> None:
    repo = hooked.repo
    assert repo.raw("push", "-q", "origin", "main", "main:scratch").returncode == 0
    assert repo.raw("push", "-q", "origin", ":scratch").returncode == 0
    repo.sh("tag", "v1")
    assert repo.raw("push", "-q", "origin", "v1").returncode == 0
    assert "refs/tags/v1" in remote_refs(hooked)
    repo.assert_no_leak(hooked.bare)


# ------------------------------------------------------------------ protected material


def test_push_is_blocked_when_a_protected_path_is_in_the_history(hooked: Env) -> None:
    repo = hooked.repo
    secret = f"reports/{repo.canaries[0]}-leak.csv"
    repo.write(secret, f"id,{repo.canaries[0]}\n")
    repo.sh("add", "-f", secret)
    bypass_commit(hooked)
    blocked = repo.raw("push", "origin", "main")
    assert blocked.returncode != 0
    assert "push blocked" in blocked.stderr and "matches the protected set" in blocked.stderr
    assert "refs/heads/main" not in remote_refs(hooked)  # nothing was sent
    assert_remote_clean(hooked)
    # a later commit that removes the file does not help: the history still has it
    repo.sh("rm", "-q", "--cached", secret)
    assert commit(repo, "untrack").returncode == 0
    again = repo.raw("push", "origin", "main")
    assert again.returncode != 0 and "commit" in again.stderr
    assert_remote_clean(hooked)
    # a tag on the bad commit is refused too
    repo.sh("tag", "bad-tag")
    assert repo.raw("push", "origin", "bad-tag").returncode != 0
    assert_remote_clean(hooked)


def test_push_is_blocked_when_a_renamed_copy_is_in_the_history(hooked: Env) -> None:
    repo = hooked.repo
    source = first_protected(repo, ".csv")
    repo.write("public/renamed-copy.txt", repo.read(source))
    repo.sh("add", "public/renamed-copy.txt")
    bypass_commit(hooked)
    blocked = repo.raw("push", "origin", "main")
    assert blocked.returncode != 0 and "same content as a protected file" in blocked.stderr
    assert "public/renamed-copy.txt" in blocked.stderr
    assert "refs/heads/main" not in remote_refs(hooked)
    assert_remote_clean(hooked)


def test_locked_push_cannot_content_check_and_says_so(hooked: Env) -> None:
    """Documented limit: without the key only paths are checked (and the user is told)."""
    repo = hooked.repo
    repo.write("public/another-copy.txt", repo.read(first_protected(repo, ".csv")))
    repo.sh("add", "public/another-copy.txt")
    bypass_commit(hooked)
    hooked.agent.stop()
    result = repo.raw("push", "origin", "main")
    assert result.returncode == 0, result.stderr
    assert "not sealed or content-checked" in result.stderr and "unlock" in result.stderr


def test_a_new_branch_is_checked_over_its_whole_unpushed_history(hooked: Env) -> None:
    repo = hooked.repo
    repo.sh("checkout", "-q", "-b", "feature")
    repo.write("reports/on-feature.csv", "a\n")
    repo.sh("add", "-f", "reports/on-feature.csv")
    bypass_commit(hooked)
    repo.write("docs/later.md", "later\n")
    repo.sh("add", "docs/later.md")
    assert commit(repo, "later").returncode == 0
    blocked = repo.raw("push", "origin", "feature")
    assert blocked.returncode != 0 and "reports/on-feature.csv" in blocked.stderr
    assert "refs/heads/feature" not in remote_refs(hooked)
    assert_remote_clean(hooked)


# ---------------------------------------------------------------------- the vault branch

# Each of these makes the vault branch NOT a valid vault: the push must be refused and the
# remote must keep the previous tip.
INVALID_VAULTS = {
    "extra-file-in-tree": lambda f: {**f, "evil.txt": b"x"},
    "extra-hook-path": lambda f: {**f, ".githooks/pre-commit": b"#!/bin/sh\nexit 0\n"},
    "bad-store-name": lambda f: {**f, "store/NOT-A-HEX-ID": b"x"},
    "plaintext-blob-in-store": lambda f: {**f, "store/" + "0" * 32: b"plain text, no magic"},
    "garbage-index": lambda f: {**f, "nbp-safe/index": b"not an index"},
    "modified-gitattributes": lambda f: {**f, ".gitattributes": b"* filter=evil\n"},
    "modified-readme": lambda f: {**f, "README.md": b"# something else\n"},
    "missing-gitattributes": lambda f: {k: v for k, v in f.items() if k != ".gitattributes"},
    "missing-index": lambda f: {k: v for k, v in f.items() if k != "nbp-safe/index"},
    "truncated-store-blob": lambda f: {**f, store_paths(f)[0]: f[store_paths(f)[0]][:20]},
    "corrupted-magic": lambda f: {**f, store_paths(f)[0]: flip(f[store_paths(f)[0]], 0)},
    "mixed-key-ids": lambda f: {**f, store_paths(f)[0]: flip(f[store_paths(f)[0]], 12)},
    "missing-store-blob": lambda f: {k: v for k, v in f.items() if k != store_paths(f)[0]},
}


@pytest.mark.parametrize("name", sorted(INVALID_VAULTS))
def test_an_invalid_vault_branch_is_never_pushed(hooked: Env, name: str) -> None:
    repo = hooked.repo
    assert repo.raw("push", "-q", "origin", "main", "nbp-safe").returncode == 0
    good_tip = remote_refs(hooked)["refs/heads/nbp-safe"]
    write_vault_commit(repo, INVALID_VAULTS[name](read_vault(repo)), hooked.tip())
    blocked = repo.raw("push", "origin", "nbp-safe")
    assert blocked.returncode != 0, (name, blocked.stderr)
    assert "push blocked" in blocked.stderr and "vault" in blocked.stderr
    assert remote_refs(hooked)["refs/heads/nbp-safe"] == good_tip
    # pushing only the code is not held up by a bad local vault (it is not being sent)
    assert repo.raw("push", "-q", "origin", "main").returncode == 0
    repo.assert_no_leak(hooked.bare)


def test_a_tampered_index_is_caught_only_with_the_key(hooked: Env) -> None:
    repo = hooked.repo
    assert repo.raw("push", "-q", "origin", "main", "nbp-safe").returncode == 0
    write_vault_commit(
        repo,
        {**read_vault(repo), "nbp-safe/index": flip(read_vault(repo)["nbp-safe/index"])},
        hooked.tip(),
    )
    unlocked = repo.raw("push", "origin", "nbp-safe")
    assert unlocked.returncode != 0 and "does not verify" in unlocked.stderr
    hooked.agent.stop()
    locked = repo.raw("push", "origin", "nbp-safe")
    assert locked.returncode == 0, locked.stderr  # structure is fine; authentication needs the key
    assert "structurally only" in locked.stderr


def test_blob_payload_tampering_without_the_key_is_stopped_by_the_index_chain(hooked: Env) -> None:
    """pre-push checks structure and the authenticated index; per-blob authentication is what
    `open`/`status` do (test_vault_tamper). A keyless tamper reuses the parent's index, whose
    `seq` then does not increase: since the index chain (review M1) the unlocked push guard
    refuses it, where it used to pass and be left to `open`."""
    repo = hooked.repo
    files = read_vault(repo)
    write_vault_commit(
        repo, {**files, store_paths(files)[0]: flip(files[store_paths(files)[0]])}, hooked.tip()
    )
    blocked = repo.raw("push", "-q", "origin", "nbp-safe")
    assert blocked.returncode != 0 and "older than its parent" in blocked.stderr


# ----------------------------------------------------------------- vault out of date


def test_code_push_with_a_stale_vault_passes_with_a_warning_when_locked(hooked: Env) -> None:
    repo = hooked.repo
    repo.write(first_protected(repo, ".json"), '{"changed": true}\n')
    tip = hooked.tip()
    hooked.agent.stop()
    result = repo.raw("push", "origin", "main")
    assert result.returncode == 0, result.stderr
    assert "not sealed" in result.stderr
    assert hooked.tip() == tip  # locked: nothing was sealed
    assert set(remote_refs(hooked)) == {"refs/heads/main"}
    repo.assert_no_leak(hooked.bare)


def test_pre_push_seals_first_when_unlocked(hooked: Env) -> None:
    repo = hooked.repo
    repo.write(first_protected(repo, ".json"), '{"changed": "before push"}\n')
    assert hooked.commits() == 1
    assert repo.raw("push", "-q", "origin", "main").returncode == 0
    assert hooked.commits() == 2  # sealed by the hook, although only `main` was pushed
    repo.write(first_protected(repo, ".json"), '{"changed": "again"}\n')
    both = repo.raw("push", "origin", "main", "nbp-safe")
    assert both.returncode == 0
    assert "push again" in both.stderr  # the pushed vault tip predates the pre-push seal
    assert hooked.commits() == 3
    assert remote_refs(hooked)["refs/heads/nbp-safe"] != hooked.tip()
    assert repo.raw("push", "-q", "origin", "nbp-safe").returncode == 0
    assert remote_refs(hooked)["refs/heads/nbp-safe"] == hooked.tip()
    repo.assert_no_leak(hooked.bare)


def test_hook_keeps_working_after_the_pipe_and_args_changes(hooked: Env) -> None:
    """The hook receives `<remote> <url>` and the ref lines on stdin from a config hook."""
    other = hooked.repo.path.parent / "second-remote.git"
    hooked.git.init(other, bare=True)
    hooked.repo.sh("remote", "add", "second", str(other))
    assert hooked.repo.raw("push", "-q", "second", "main", "nbp-safe").returncode == 0
    # and by URL instead of by remote name
    assert hooked.repo.raw("push", "-q", str(other), "main:alias").returncode == 0
    hooked.repo.assert_no_leak(other)


def test_key_id_sanity_of_the_vault_used_in_these_tests(hooked: Env) -> None:
    with hooked.backend() as backend:
        assert backend.key_id() == crypto.KeySet(hooked.repo.master).key_id
    assert vault.INDEX_PATH in hooked.vault_files()
