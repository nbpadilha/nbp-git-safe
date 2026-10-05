# SPDX-License-Identifier: MIT
"""``rotate`` (new key, new ref, verifiable re-encryption), ``purge`` (history rewrite behind a
typed confirmation, remote needs a forced push that the tool only prints), ``init --auto-push``
and the automatic vault sync after ``git pull``."""

from __future__ import annotations

import shlex
import sys
import time
from pathlib import Path

import pytest

from nbp_git_safe import crypto, multi, vault
from nbp_git_safe.config import load_config
from nbp_git_safe.gitutil import discover
from tests import helpers
from tests.helpers import NbpRepo, ThreadAgent
from tests.integration.conftest import Env
from tests.integration.guardkit import commit, first_protected, remote_refs
from tests.integration.test_multi import Machines, machines, seal_by_commit  # noqa: F401
from tests.leak.harness import LeakScanner, assert_no_leaks

YEAR = time.gmtime().tm_year


def keys_leak_scan(env: Env, *masters: bytes) -> None:
    """The master keys (raw and base64) must be nowhere in the local .git nor in the remote."""
    needles = {}
    for n, master in enumerate(masters):
        needles[f"key-{n}-raw"] = master
        needles[f"key-{n}-b64"] = crypto.encode_key(master).encode("ascii")
    scanner = LeakScanner(env.repo.canaries, git_env=env.git.env, raw_needles=needles)
    hits = scanner.scan_git_dir(env.repo.path / ".git") + scanner.scan_bare_repo(env.bare)
    assert_no_leaks(hits)


def new_vault_state(env: Env, ref: str, master: bytes) -> tuple[vault.VaultState, str]:
    _repo, git = discover(env.repo.path, env.git.env)
    tip = env.repo.sh("rev-parse", ref).strip()
    return vault.load_commit(git, multi.KeySetBackend(crypto.KeySet(master)), tip), tip


def contents_of(env: Env, ref: str, master: bytes) -> dict[str, bytes]:
    """Decrypt a vault ref with ``master`` (library, not the agent): ``{path: plaintext}``."""
    _repo, git = discover(env.repo.path, env.git.env)
    backend = multi.KeySetBackend(crypto.KeySet(master))
    state = vault.load_commit(git, backend, env.repo.sh("rev-parse", ref).strip())
    return {
        e.path: backend.dec_blob(fid, git.run("cat-file", "blob", state.files[f"store/{fid}"]))
        for fid, e in state.index.entries.items()
    }


# -------------------------------------------------------------------------------- rotate


def test_rotate_reencrypts_into_a_new_ref_that_only_the_new_key_opens(hooked: Env) -> None:
    repo = hooked.repo
    old_master = repo.master
    old_tip = hooked.tip()
    old_entries = hooked.entries()
    old_blobs = {p for p in hooked.vault_files() if p.startswith("store/")}
    result = repo.cli("rotate")
    assert result.code == 0, result.err
    new_master = crypto.decode_key(result.out.strip())
    assert new_master != old_master and "shown ONCE" in result.err
    ref = f"refs/heads/nbp-safe-{YEAR}"
    assert hooked.tip() == old_tip  # the old branch is untouched
    assert repo.sh("rev-list", "--count", ref).strip() == "1"  # orphan, current state only
    assert repo.sh("log", "-1", "--format=%s", ref).strip() == "nbp-safe: rotate"

    state, new_tip = new_vault_state(hooked, ref, new_master)
    assert len(state.index.entries) == len(old_entries)
    new_by_path = {e.path: (fid, e) for fid, e in state.index.entries.items()}
    plain_old = {p: repo.read(p) for p in old_entries}
    for path, (old_id, old_entry) in old_entries.items():
        new_id, new_entry = new_by_path[path]
        assert new_id != old_id  # fresh file ids
        assert new_entry.mac != old_entry.mac  # the MAC key changed with the key
        assert (new_entry.size, new_entry.mode) == (old_entry.size, old_entry.mode)
        assert (new_entry.created, new_entry.updated) == (old_entry.created, old_entry.updated)
    assert contents_of(hooked, ref, new_master) == plain_old
    new_blobs = set(repo.sh("ls-tree", "-r", "--name-only", ref).split()) - {
        ".gitattributes",
        "README.md",
        "nbp-safe/index",
    }
    assert new_blobs.isdisjoint(old_blobs)

    _repo, git = discover(repo.path, hooked.git.env)
    with pytest.raises(crypto.NbpCryptoError):  # the old key cannot open the new ref ...
        vault.load_commit(git, multi.KeySetBackend(crypto.KeySet(old_master)), new_tip)
    with pytest.raises(crypto.NbpCryptoError):  # ... and the new key cannot open the old one
        vault.load_commit(git, multi.KeySetBackend(crypto.KeySet(new_master)), old_tip)
    keys_leak_scan(hooked, old_master, new_master)
    repo.assert_no_leak(hooked.bare)


def test_rotated_vault_is_usable_after_switching_key_and_ref(hooked: Env) -> None:
    repo = hooked.repo
    result = repo.cli("rotate")
    new_master = crypto.decode_key(result.out.strip())
    ref = f"refs/heads/nbp-safe-{YEAR}"
    # the pre-push guard validates with the key in the agent: the old key cannot authenticate the
    # new branch, so the owner switches first (the documented order of the next steps)
    blocked = repo.raw("push", "origin", f"nbp-safe-{YEAR}")  # old key in the agent: refused
    assert blocked.returncode != 0 and "does not verify" in blocked.stderr
    hooked.agent.stop()
    repo.set_config("nbp-safe.vaultRef", ref)
    new_agent = ThreadAgent(repo.state_dir, new_master)
    try:
        status = repo.cli("status")
        assert status.code == 0 and f"vault: {ref}" in status.out
        # the key changed ON PURPOSE: until the owner says so (the documented next step, which
        # names the new key's public id) the registered id of the old key refuses the new one
        new_id = helpers.key_id_of(new_master)
        assert f"key-id --accept {new_id}" in result.err
        refused = repo.raw("push", "-q", "origin", f"nbp-safe-{YEAR}")
        assert refused.returncode != 0 and f"key-id --accept {new_id}" in refused.stderr
        accepted = repo.cli("key-id", "--accept", new_id, "--confirm", f"accept key id {new_id}")
        assert accepted.code == 0, accepted.err
        pushed = repo.raw("push", "-q", "origin", f"nbp-safe-{YEAR}")
        assert pushed.returncode == 0, pushed.stderr
        assert remote_refs(hooked)[ref] == repo.sh("rev-parse", ref).strip()
        target = first_protected(repo, ".csv")
        repo.write(target, "after,rotation\n")
        seal_by_commit(repo)
        assert (
            repo.sh("rev-list", "--count", ref).strip() == "2"
        )  # history continues on the new ref
        (repo.path / target).unlink()
        assert repo.cli("open").code == 0 and repo.read(target) == b"after,rotation\n"
        keys_leak_scan(hooked, repo.master, new_master)
        repo.assert_no_leak(hooked.bare)
    finally:
        new_agent.stop()


def test_rotating_twice_in_a_year_picks_a_free_name(hooked: Env) -> None:
    assert hooked.repo.cli("rotate").code == 0
    assert hooked.repo.cli("rotate").code == 0
    refs = hooked.repo.sh("for-each-ref", "--format=%(refname)", "refs/heads/nbp-safe-*").split()
    assert sorted(refs) == [f"refs/heads/nbp-safe-{YEAR}", f"refs/heads/nbp-safe-{YEAR}-2"]
    named = hooked.repo.cli("rotate", "--name", "nbp-safe-custom")
    assert named.code == 0 and "refs/heads/nbp-safe-custom" in named.err
    bad = hooked.repo.cli("rotate", "--name", "not-a-vault-name")
    assert bad.code == 1 and "must look like" in bad.err


def test_rotate_locked_fails_closed_without_printing_a_key(hooked: Env) -> None:
    hooked.agent.stop()
    result = hooked.repo.cli("rotate")
    assert result.code == 3 and result.out == ""
    assert hooked.repo.sh("for-each-ref", "refs/heads/nbp-safe-*").strip() == ""


def test_rotate_without_a_vault_is_refused(env: Env) -> None:
    result = env.repo.cli("rotate")
    assert result.code == 1 and "no vault" in result.err


def test_deleting_the_old_branch_needs_the_typed_confirmation(
    hooked: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = hooked.repo
    old_tip = hooked.tip()
    password_manager_updated(monkeypatch)
    wrong = repo.cli("rotate", "--delete-old", "--confirm", "delete everything")
    assert wrong.code == 1 and 'type exactly "delete nbp-safe"' in wrong.err
    assert wrong.out == "" and repo.sh("for-each-ref", "refs/heads/nbp-safe-*").strip() == ""
    no_tty = repo.cli("rotate", "--delete-old")  # rotates, but cannot ask: the old branch stays
    assert no_tty.code == 1 and "typed confirmation" in no_tty.err and hooked.tip() == old_tip

    class FakeTty:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(sys, "stdin", FakeTty())
    monkeypatch.setattr("builtins.input", lambda _prompt="": "delete nbp-safe")
    interactive = repo.cli("rotate", "--delete-old", "--name", "nbp-safe-three")
    assert interactive.code == 0 and "deleted local refs/heads/nbp-safe" in interactive.err
    assert repo.sh("for-each-ref", "refs/heads/nbp-safe").strip() == ""
    assert "refs/heads/nbp-safe-three" in repo.sh("for-each-ref", "--format=%(refname)")
    assert remote_refs(hooked) == {}  # the tool never touched the remote
    monkeypatch.undo()


def password_manager_updated(monkeypatch: pytest.MonkeyPatch) -> bytes:
    """The next ``rotate`` generates a key the test knows, and ``keyCommand`` already returns it
    (as it does once the user has stored the new key in the password manager item)."""
    new = crypto.generate_key()
    monkeypatch.setattr(crypto, "generate_key", lambda: new)
    monkeypatch.setenv("NBP_SAFE_TEST_KEY", crypto.encode_key(new))
    return new


def test_old_branch_is_kept_while_key_command_still_returns_the_old_key(hooked: Env) -> None:
    """Review B6: `--delete-old` used to delete at once, before the new key was stored anywhere."""
    old_tip = hooked.tip()
    result = hooked.repo.cli("rotate", "--delete-old", "--confirm", "delete nbp-safe")
    assert result.code == 1 and "still returns another key" in result.err
    assert "the old branch was kept" in result.err
    assert hooked.tip() == old_tip  # nothing was deleted
    assert "refs/heads/nbp-safe-" in hooked.repo.sh("for-each-ref", "--format=%(refname)")


def test_old_branch_is_kept_when_key_command_fails(
    hooked: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    old_tip = hooked.tip()
    hooked.repo.sh("config", "--local", "nbp-safe.keyCommand", '["definitely-not-a-program-xyz"]')
    result = hooked.repo.cli("rotate", "--delete-old", "--confirm", "delete nbp-safe")
    assert result.code == 1 and "could not be checked" in result.err
    assert hooked.tip() == old_tip


def test_rotate_with_confirm_flag_deletes_the_old_local_branch(
    hooked: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    password_manager_updated(monkeypatch)
    assert hooked.repo.raw("push", "-q", "origin", "main", "nbp-safe").returncode == 0
    remote_before = remote_refs(hooked)
    result = hooked.repo.cli("rotate", "--delete-old", "--confirm", "delete nbp-safe")
    assert result.code == 0, result.err
    assert hooked.repo.sh("for-each-ref", "refs/heads/nbp-safe").strip() == ""
    assert "git push origin :refs/heads/nbp-safe" in result.err
    assert remote_refs(hooked) == remote_before


# -------------------------------------------------------------------------------- purge


def make_history(env: Env) -> tuple[str, str, list[str]]:
    """Seal the JSON file three times; returns (its path, its content canary, the old tips)."""
    repo = env.repo
    target = first_protected(repo, ".json")
    tips = [env.tip()]
    for n in (2, 3):
        repo.write(target, f'{{"version": {n}, "marker": "{repo.canaries[2]}"}}\n')
        seal_by_commit(repo, f"v{n}")
        tips.append(env.tip())
    assert env.commits() == 3
    return target, repo.canaries[2], tips


def all_blob_shas_for(env: Env, tips: list[str], fid: str) -> set[str]:
    shas = set()
    for tip in tips:
        out = env.repo.raw("rev-parse", f"{tip}:store/{fid}")
        if out.returncode == 0:
            shas.add(out.stdout.strip())
    return shas


def printed_commands(stderr: str) -> list[str]:
    """The git commands a command prints for the owner (indented ``git ...`` lines)."""
    return [ln.strip() for ln in stderr.splitlines() if ln.strip().startswith("git ")]


def run_printed(env: Env, line: str, cwd: Path) -> None:
    """Run one printed command as the owner would (the trailing ``# explanation`` is a comment)."""
    args = shlex.split(line.split("#", 1)[0])
    assert args[0] == "git", line
    env.git.run(*args[1:], cwd=cwd)


def assert_gone_from_the_object_database(repo: NbpRepo, shas: set[str]) -> None:
    """``git cat-file -e`` fails for every sha. If one is still there it must at least be
    unreachable (checked by the caller); ``gc --prune=now`` is repeated a few times for a file that
    was locked by a scanner, and the failure message says whether the object is loose or packed."""
    for _attempt in range(3):
        if all(repo.raw("cat-file", "-e", sha).returncode != 0 for sha in shas):
            return
        repo.sh("gc", "-q", "--prune=now")
    lingering = {sha: repo.raw("cat-file", "-e", sha).returncode == 0 for sha in shas}
    loose = {
        sha: (repo.path / ".git" / "objects" / sha[:2] / sha[2:]).exists()
        for sha, here in lingering.items()
        if here
    }
    raise AssertionError(
        f"purged blobs still in the object database: loose={loose}, "
        f"count-objects={repo.sh('count-objects', '-v')!r}"
    )


def test_purge_rewrites_the_history_and_prints_what_the_owner_must_do(hooked: Env) -> None:
    repo = hooked.repo
    target, _marker, tips = make_history(hooked)
    assert repo.raw("push", "-q", "origin", "main", "nbp-safe").returncode == 0
    remote_tip = remote_refs(hooked)["refs/heads/nbp-safe"]
    fid = hooked.entries()[target][0]
    old_blobs = all_blob_shas_for(hooked, tips, fid)
    assert len(old_blobs) == 3
    others_before = {p: e for p, (_i, e) in hooked.entries().items() if p != target}

    denied = repo.cli("purge", target)  # no terminal, no --confirm
    assert (
        denied.code == 1 and '--confirm "purge nbp-safe"' in denied.err and hooked.tip() == tips[-1]
    )
    wrong = repo.cli("purge", target, "--confirm", "yes")
    assert wrong.code == 1 and hooked.tip() == tips[-1]
    missing = repo.cli("purge", "reports/never-existed.csv", "--confirm", "purge nbp-safe")
    assert (
        missing.code == 1 and "no entry with that path" in missing.err and hooked.tip() == tips[-1]
    )

    done = repo.cli("purge", target, "--confirm", "purge nbp-safe")
    assert done.code == 0 and "purged 1 entry" in done.out, done.err
    assert f"--force-with-lease=refs/heads/nbp-safe:{remote_tip}" in done.err  # printed, not run
    assert (
        "git reflog expire --expire=now refs/heads/nbp-safe refs/remotes/origin/nbp-safe"
        in done.err
    )
    assert "would be sealed again" in done.err
    assert remote_refs(hooked)["refs/heads/nbp-safe"] == remote_tip  # the remote is untouched

    new_tip = hooked.tip()
    assert new_tip != tips[-1]
    # no commit of the new history has the entry: neither its blob nor its index row
    assert repo.sh("log", "--format=%H", new_tip, "--", f"store/{fid}").strip() == ""
    found_repo, git = discover(repo.path, hooked.git.env)
    cfg = load_config(git, found_repo)
    with hooked.backend() as backend:
        for commit_id in repo.sh("rev-list", new_tip).split():
            state = vault.load_commit(git, backend, commit_id)
            assert fid not in state.index.entries
            assert all(e.path != target for e in state.index.entries.values())
        tip_state = vault.load_vault(git, backend, cfg)
    assert {e.path: e for e in tip_state.index.entries.values()} == others_before
    assert hooked.commits() == 1  # the two commits that only touched the entry are gone
    (repo.path / target).unlink()  # as the output says: otherwise the next seal brings it back
    # the rest of the vault is intact and still opens
    (repo.path / first_protected(repo, ".csv")).unlink()
    assert repo.cli("open").code == 0
    # a normal push is now rejected (not forced) and `sync` refuses to undo the purge
    rejected = repo.cli("push")
    assert rejected.code == 1 and "never forces" in rejected.err
    refused = repo.cli("sync", "--no-open")
    assert refused.code == 1 and "purged this vault locally" in refused.err
    assert "purged this vault locally" in repo.cli("status").out
    assert hooked.tip() == new_tip

    # the owner finishes: forced push with a lease, then expunge locally
    forced = repo.raw(
        "push",
        f"--force-with-lease=refs/heads/nbp-safe:{remote_tip}",
        "origin",
        "refs/heads/nbp-safe:refs/heads/nbp-safe",
    )
    assert forced.returncode == 0, forced.stderr
    assert remote_refs(hooked)["refs/heads/nbp-safe"] == new_tip
    # then the commands the tool PRINTED, literally (the product's instruction is what is tested,
    # not a hand-made variant of it): expire the reflogs, then gc with --prune=now
    for line in printed_commands(done.err)[1:]:
        run_printed(hooked, line, repo.path)
    hooked.git.run("gc", "-q", "--prune=now", cwd=hooked.bare)
    reachable = hooked.git.run("rev-list", "--objects", "refs/heads/nbp-safe", cwd=hooked.bare)
    assert not any(sha in reachable for sha in old_blobs)  # gone from the remote history
    # The guarantee is REACHABILITY: no ref, no reflog, no index and no stash can lead to a purged
    # blob any more. (Whether the unreachable loose file is already unlinked is the file system's
    # business: on Windows an antivirus scanner or the search indexer may hold a freshly written
    # object for a moment and git skips it with a warning, so that is retried below.)
    alive = repo.sh("rev-list", "--objects", "--all", "--reflog", "--indexed-objects")
    assert not any(sha in alive for sha in old_blobs)
    assert_gone_from_the_object_database(repo, old_blobs)
    assert "sync: up-to-date" in repo.cli("sync", "--no-open").out
    repo.assert_no_leak(hooked.bare)


def test_purge_by_a_path_that_exists_only_in_history_and_merge_commits(
    machines: Machines,  # noqa: F811
) -> None:
    a, b = machines.a, machines.b
    victim = first_protected(a, ".bin")
    a.write("reports/keep-a.csv", "a\n")
    seal_by_commit(a)
    assert a.cli("push").code == 0
    b.write("reports/keep-b.csv", "b\n")
    seal_by_commit(b)
    assert b.cli("sync").code == 0  # a merge commit with two parents in B's history
    assert len(b.sh("rev-list", "--parents", "-n", "1", "refs/heads/nbp-safe").split()) == 3
    assert b.cli("rm", "--force", victim).code == 0  # gone from the tip, still in the history
    assert victim not in {p for p in (b.cli("ls").out)} and "plain.bin" not in b.cli("ls").out
    done = b.cli("purge", victim, "--confirm", "purge nbp-safe")
    assert done.code == 0, done.err
    _repo, git = discover(b.path, b.git.env)
    with machines.agent_b.client() as backend:
        for commit_id in b.sh("rev-list", "refs/heads/nbp-safe").split():
            state = vault.load_commit(git, backend, commit_id)
            assert all(e.path != victim for e in state.index.entries.values())
    assert (
        len(b.sh("rev-list", "--min-parents=2", "refs/heads/nbp-safe").split()) == 1
    )  # merge kept
    assert "keep-b.csv" in b.cli("ls").out and "keep-a.csv" in b.cli("ls").out


def test_purge_marker_is_cleared_once_origin_has_our_history(hooked: Env) -> None:
    repo = hooked.repo
    target, _marker, _tips = make_history(hooked)
    assert repo.raw("push", "-q", "origin", "nbp-safe").returncode == 0
    remote_tip = remote_refs(hooked)["refs/heads/nbp-safe"]
    assert repo.cli("purge", target, "--confirm", "purge nbp-safe").code == 0
    assert (repo.state_dir / multi.PURGED_FILE).exists()
    repo.sh("push", f"--force-with-lease=refs/heads/nbp-safe:{remote_tip}", "origin", "nbp-safe")
    assert repo.cli("sync", "--no-open").code == 0
    assert not (repo.state_dir / multi.PURGED_FILE).exists()


# -------------------------------------------------------------------------- auto-push


def test_auto_push_makes_a_plain_git_push_carry_the_vault(hooked: Env) -> None:
    repo = hooked.repo
    result = repo.cli("init", "--auto-push")
    assert (
        result.code == 0
        and "refspecs added: HEAD, refs/heads/nbp-safe:refs/heads/nbp-safe" in result.err
    )
    assert repo.sh("config", "--local", "--get-all", "remote.origin.push").split() == [
        "HEAD",
        "refs/heads/nbp-safe:refs/heads/nbp-safe",
    ]
    assert "(already configured)" in repo.cli("init", "--auto-push").err  # idempotent
    pushed = repo.raw("push", "-q", "origin")  # a plain `git push`
    assert pushed.returncode == 0, pushed.stderr
    refs = remote_refs(hooked)
    assert refs["refs/heads/main"] == repo.sh("rev-parse", "main").strip()
    assert refs["refs/heads/nbp-safe"] == hooked.tip()
    repo.assert_no_leak(hooked.bare)
    out = repo.cli("uninstall", "--yes").out
    assert "push refspec removed: HEAD" in out
    assert repo.raw("config", "--local", "--get-all", "remote.origin.push").stdout.strip() == ""


def test_auto_push_keeps_the_users_own_refspecs(hooked: Env) -> None:
    repo = hooked.repo
    repo.sh("config", "--local", "--add", "remote.origin.push", "refs/heads/main:refs/heads/main")
    assert repo.cli("init", "--auto-push").code == 0
    assert repo.sh("config", "--local", "--get-all", "remote.origin.push").split() == [
        "refs/heads/main:refs/heads/main",
        "refs/heads/nbp-safe:refs/heads/nbp-safe",
    ]
    repo.cli("uninstall", "--yes")
    assert repo.sh("config", "--local", "--get-all", "remote.origin.push").split() == [
        "refs/heads/main:refs/heads/main"
    ]


# ----------------------------------------------------------- git pull does the sync


def test_git_pull_merges_the_vault_and_opens_new_files_by_itself(machines: Machines) -> None:  # noqa: F811
    a, b = machines.a, machines.b
    changed = first_protected(a, ".json")
    a.write(changed, '{"edited": "on A"}\n')
    a.write("reports/brand-new.csv", "new\n")
    a.write("docs/news.md", "news on main\n")
    a.sh("add", "docs/news.md")
    assert commit(a, "news + vault").returncode == 0
    assert a.raw("push", "-q", "origin", "main", "nbp-safe").returncode == 0
    pulled = b.raw("pull", "-q")
    assert pulled.returncode == 0, pulled.stderr
    assert "vault fast-forward with origin" in pulled.stderr and "vault opened" in pulled.stderr
    assert b.read("reports/brand-new.csv") == b"new\n"
    assert b.read(changed) == b'{"edited": "on A"}\n'  # the stale local copy was updated in place
    b.assert_no_leak(machines.bare)


def test_git_pull_merges_diverged_vaults(machines: Machines) -> None:  # noqa: F811
    a, b = machines.a, machines.b
    a.write("reports/from-a.csv", "a\n")
    a.write("docs/a.md", "a\n")
    a.sh("add", "docs/a.md")
    assert commit(a, "A").returncode == 0
    assert a.raw("push", "-q", "origin", "main", "nbp-safe").returncode == 0
    b.write("reports/from-b.csv", "b\n")
    seal_by_commit(b, "B")  # B's vault diverges from the remote's
    pulled = b.raw("pull", "-q", "--no-rebase", "--no-edit")
    assert pulled.returncode == 0, pulled.stderr
    assert "vault merged with origin" in pulled.stderr
    assert b.read("reports/from-a.csv") == b"a\n" and b.read("reports/from-b.csv") == b"b\n"
    assert b.cli("push").code == 0
    assert a.cli("sync").code == 0 and (a.path / "reports/from-b.csv").read_bytes() == b"b\n"


def test_post_merge_does_not_follow_a_rolled_back_remote(machines: Machines) -> None:  # noqa: F811
    a, b = machines.a, machines.b
    old_tip = remote_refs(machines.env)["refs/heads/nbp-safe"]
    a.write("reports/second.csv", "2\n")
    a.write("docs/second.md", "2\n")
    a.sh("add", "docs/second.md")
    assert commit(a, "second").returncode == 0
    assert a.raw("push", "-q", "origin", "main", "nbp-safe").returncode == 0
    assert b.cli("sync").code == 0
    machines.env.git.run("update-ref", "refs/heads/nbp-safe", old_tip, cwd=machines.bare)
    a.write("docs/third.md", "3\n")
    a.sh("add", "docs/third.md")
    assert commit(a, "third").returncode == 0
    assert a.raw("push", "-q", "origin", "main").returncode == 0
    tip = b.sh("rev-parse", "refs/heads/nbp-safe").strip()
    pulled = b.raw("pull", "-q")
    assert pulled.returncode == 0  # a post-merge hook never fails git
    assert "BACK in time" in pulled.stderr
    assert b.sh("rev-parse", "refs/heads/nbp-safe").strip() == tip
