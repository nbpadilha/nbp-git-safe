# SPDX-License-Identifier: MIT
"""Multi-machine behaviour: ``sync`` (three-way merge, no force), ``push``, the clone flow, rollback
and tampering on the remote. Machine A is the ``hooked`` repository, machine B a clone with its own
agent. Every scenario ends with the leak gate on the bare remote and on the local ``.git``."""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from nbp_git_safe import crypto, vault
from nbp_git_safe.config import load_config
from nbp_git_safe.gitutil import discover
from tests.helpers import NbpRepo, ThreadAgent
from tests.integration.conftest import Env
from tests.integration.guardkit import commit, first_protected, remote_refs
from tests.integration.test_vault_tamper import flip, read_vault, store_paths, write_vault_commit


@dataclass
class Machines:
    env: Env
    a: NbpRepo
    b: NbpRepo
    agent_b: ThreadAgent

    @property
    def bare(self) -> Path:
        return self.env.bare


@pytest.fixture
def machines(
    hooked: Env, clone_factory: Callable[..., NbpRepo], unlock_fast: Callable[..., ThreadAgent]
) -> Machines:
    assert hooked.repo.raw("push", "-q", "origin", "main", "nbp-safe").returncode == 0
    b = clone_factory(hooked)
    assert b.cli("init").code == 0
    agent_b = unlock_fast(b)
    assert b.cli("open").code == 0
    return Machines(hooked, hooked.repo, b, agent_b)


def protected_map(repo: NbpRepo) -> dict[str, bytes]:
    found = {}
    for sub in ("reports", "data-private"):
        for path in sorted((repo.path / sub).rglob("*")):
            if path.is_file() and path.name != "keep-public.txt":
                found[path.relative_to(repo.path).as_posix()] = path.read_bytes()
    return found


def vault_tip(repo: NbpRepo) -> str:
    return repo.sh("rev-parse", "refs/heads/nbp-safe").strip()


def seal_by_commit(repo: NbpRepo, message: str = "work") -> None:
    result = commit(repo, message, "--allow-empty")
    assert result.returncode == 0, result.stderr


def entries_of(repo: NbpRepo, agent: ThreadAgent, ref: str | None = None) -> dict[str, vault.Entry]:
    found, git = discover(repo.path, repo.git.env)
    cfg = load_config(git, found)
    with agent.client() as backend:
        if ref is None:
            state = vault.load_vault(git, backend, cfg)
        else:
            state = vault.load_commit(git, backend, ref)
    return {e.path: e for e in state.index.entries.values()}


def gate(machines: Machines) -> None:
    machines.a.assert_no_leak(machines.bare)
    machines.b.assert_no_leak(machines.bare)


# ------------------------------------------------------------------------ convergence


def test_two_diverged_clones_converge_without_force(machines: Machines) -> None:
    a, b = machines.a, machines.b
    json_file, bin_file = first_protected(a, ".json"), first_protected(a, ".bin")
    a.write("reports/from-a.csv", f"a,{a.canaries[0]}\n")
    a.write(json_file, '{"edited": "on A"}\n')
    seal_by_commit(a, "A work")
    b.write("reports/from-b.csv", f"b,{b.canaries[1]}\n")
    b.write(bin_file, "edited on B\n")
    seal_by_commit(b, "B work")
    assert vault_tip(a) != vault_tip(b)

    pushed = a.cli("push")
    assert pushed.code == 0 and "no force" in pushed.out, pushed.err
    a_tip = remote_refs(machines.env)["refs/heads/nbp-safe"]
    assert a_tip == vault_tip(a)

    rejected = b.cli("push")  # non-fast-forward: the tool reports it and does NOT force
    assert (
        rejected.code == 1
        and "nbp-git-safe sync" in rejected.err
        and "never forces" in rejected.err
    )
    assert remote_refs(machines.env)["refs/heads/nbp-safe"] == a_tip  # untouched

    synced = b.cli("sync")
    assert synced.code == 0 and "sync: merged" in synced.out, synced.err
    parents = b.sh("rev-list", "--parents", "-n", "1", "refs/heads/nbp-safe").split()
    assert len(parents) == 3 and set(parents[1:]) == {a_tip, vault_tip_before(b, parents)}
    assert b.read("reports/from-a.csv") == a.read("reports/from-a.csv")  # opened by sync
    assert b.read(json_file) == b'{"edited": "on A"}\n'
    assert a.read("reports/from-a.csv") and not (a.path / "reports/from-b.csv").exists()

    assert b.cli("push").code == 0
    assert remote_refs(machines.env)["refs/heads/nbp-safe"] == vault_tip(b)

    caught_up = a.cli("sync")
    assert caught_up.code == 0 and "sync: fast-forward" in caught_up.out, caught_up.err
    assert protected_map(a) == protected_map(b)
    assert vault_tip(a) == vault_tip(b) == remote_refs(machines.env)["refs/heads/nbp-safe"]
    assert "sync: up-to-date" in a.cli("sync").out
    assert "sync: up-to-date" in b.cli("sync").out
    gate(machines)


def vault_tip_before(repo: NbpRepo, merge_parents: list[str]) -> str:
    """The parent of the merge commit that is not the remote tip (the local one)."""
    return next(p for p in merge_parents[1:] if p != remote_tip_seen(repo))


def remote_tip_seen(repo: NbpRepo) -> str:
    return repo.sh("rev-parse", "refs/remotes/origin/nbp-safe").strip()


def test_the_same_file_edited_on_both_machines_keeps_both_versions(machines: Machines) -> None:
    a, b = machines.a, machines.b
    target = first_protected(a, ".csv")
    stem, ext = target.rsplit(".", 1)
    a.write(target, f"id,score\n1,from-A-{a.canaries[0]}\n")
    seal_by_commit(a, "A edits")
    b.write(target, f"id,score\n1,from-B-{b.canaries[1]}\n")
    seal_by_commit(b, "B edits")
    assert a.cli("push").code == 0

    synced = b.cli("sync")
    assert synced.code == 0 and "1 conflict(s) kept as copies" in synced.out, synced.err
    assert "changed on both sides" in synced.err
    entries = entries_of(b, machines.agent_b)
    copies = [p for p in entries if ".conflict-" in p]
    assert (
        len(copies) == 1 and copies[0].startswith(stem + ".conflict-") and copies[0].endswith(ext)
    )
    assert b.read(target) == f"id,score\n1,from-B-{b.canaries[1]}\n".encode()  # ours stays in place
    assert b.read(copies[0]) == f"id,score\n1,from-A-{a.canaries[0]}\n".encode()  # theirs preserved
    assert entries[target].mac != entries[copies[0]].mac

    assert b.cli("push").code == 0
    a_sync = a.cli(
        "sync"
    )  # A fast-forwards to B's merge; its own differing file is not overwritten
    assert a_sync.code == 0, a_sync.err
    seen = {p.name: p.read_bytes() for p in (a.path / "reports").rglob("*") if p.is_file()}
    blobs = set(seen.values())
    assert f"id,score\n1,from-A-{a.canaries[0]}\n".encode() in blobs
    assert f"id,score\n1,from-B-{b.canaries[1]}\n".encode() in blobs  # as .nbp-theirs or in place
    gate(machines)


def test_sync_seals_unsaved_local_edits_first_and_opens_afterwards(machines: Machines) -> None:
    a, b = machines.a, machines.b
    a.write("reports/new-from-a.csv", "n\n")
    seal_by_commit(a)
    assert a.cli("push").code == 0
    b.write(first_protected(b, ".json"), '{"unsealed": true}\n')  # no commit, not sealed
    result = b.cli("sync")
    assert (
        result.code == 0 and "sealed local changes" in result.out and "sync: merged" in result.out
    )
    assert b.read("reports/new-from-a.csv") == b"n\n"
    assert entries_of(b, machines.agent_b)[first_protected(b, ".json")].size == len(
        '{"unsealed": true}\n'
    )


def test_fast_forward_ahead_and_no_remote(machines: Machines) -> None:
    a, b = machines.a, machines.b
    a.write("reports/ff.csv", "ff\n")
    seal_by_commit(a)
    assert a.cli("push").code == 0
    assert "sync: fast-forward" in b.cli("sync").out and b.read("reports/ff.csv") == b"ff\n"
    b.write("reports/b-only.csv", "b\n")
    seal_by_commit(b)
    tip = vault_tip(b)
    ahead = b.cli("sync")
    assert "sync: ahead" in ahead.out and vault_tip(b) == tip  # local ahead: nothing to merge
    assert "ahead of origin" in b.cli("status").out
    gate(machines)


def test_sync_without_any_remote_vault_is_a_clear_no_op(
    env: Env, unlock_fast: Callable[..., ThreadAgent]
) -> None:
    result = env.repo.cli("sync")
    assert result.code == 0 and "sync: no-remote" in result.out
    assert "origin has no vault branch yet" in result.err


def test_status_and_doctor_show_the_relation_with_origin(machines: Machines) -> None:
    a, b = machines.a, machines.b
    assert "origin: in sync with origin" in b.cli("status").out
    a.write("reports/s.csv", "s\n")
    seal_by_commit(a)
    assert a.cli("push").code == 0
    assert b.raw("fetch", "-q").returncode == 0
    assert "behind origin" in b.cli("status").out
    assert any("behind origin" in line for line in b.cli("doctor").out.splitlines())


# ------------------------------------------------------------------ the clone flow


def test_clone_on_another_machine_with_a_real_agent_reconstructs_the_names(
    machines: Machines, clone_factory: Callable[..., NbpRepo]
) -> None:
    a = machines.a
    fresh = clone_factory(machines.env)  # a third "machine": new directory, new agent process
    tree = fresh.sh("ls-tree", "-r", "--name-only", "refs/remotes/origin/nbp-safe")
    assert "CANARY" not in tree  # without the key only opaque names are visible
    assert fresh.cli("init").code == 0
    assert fresh.cli("open").code == 3  # locked: fails closed, nothing materialized
    assert not (fresh.path / "reports").exists()
    assert fresh.cli("unlock").code == 0  # the real detached agent + keyCommand
    opened = fresh.cli("open")
    assert opened.code == 0 and "4 written" in opened.out, opened.err
    assert protected_map(fresh) == protected_map(a)
    assert fresh.cli("lock").code == 0
    fresh.assert_no_leak(machines.bare)


# ----------------------------------------------------------- tampering on the remote


def test_rollback_of_the_remote_vault_is_detected_and_not_followed(machines: Machines) -> None:
    a, b = machines.a, machines.b
    old_tip = remote_refs(machines.env)["refs/heads/nbp-safe"]
    a.write("reports/second.csv", "2\n")
    seal_by_commit(a)
    assert a.cli("push").code == 0
    new_tip = vault_tip(a)
    assert "sync: fast-forward" in b.cli("sync").out  # B has now seen new_tip
    machines.env.git.run("update-ref", "refs/heads/nbp-safe", old_tip, cwd=machines.bare)  # reset!

    refused = b.cli("sync")
    assert (
        refused.code == 1
        and "BACK in time" in refused.err
        and "--accept-remote-rewrite" in refused.err
    )
    assert vault_tip(b) == new_tip  # local vault untouched
    status = b.cli("status")
    assert "WARNING" in status.err and "went BACK in time" in status.out
    doctor = b.cli("doctor")
    assert doctor.code == 1 and "went BACK in time" in doctor.out
    # re-publishing our newer history is an ordinary fast-forward and repairs the remote
    assert b.cli("push").code == 0
    assert remote_refs(machines.env)["refs/heads/nbp-safe"] == new_tip
    assert "sync: up-to-date" in b.cli("sync").out
    gate(machines)


def test_accepting_a_rollback_keeps_local_history(machines: Machines) -> None:
    a, b = machines.a, machines.b
    old_tip = remote_refs(machines.env)["refs/heads/nbp-safe"]
    a.write("reports/second.csv", "2\n")
    seal_by_commit(a)
    assert a.cli("push").code == 0
    b.cli("sync")
    machines.env.git.run("update-ref", "refs/heads/nbp-safe", old_tip, cwd=machines.bare)
    accepted = b.cli("sync", "--accept-remote-rewrite")
    assert accepted.code == 0 and "sync: ahead" in accepted.out
    assert vault_tip(b) != old_tip and b.read("reports/second.csv") == b"2\n"


def test_replaced_remote_history_is_refused(machines: Machines) -> None:
    b = machines.b
    # an attacker (or an owner after a purge) force-pushes an unrelated, well-formed vault
    forger = machines.env.git.init(machines.bare.parent / "forger")
    forger_repo = NbpRepo(forger, machines.env.git, b.canaries, b.master)
    keys = crypto.KeySet(b.master)
    files = {
        ".gitattributes": vault.GITATTRIBUTES,
        "README.md": vault.README,
        "nbp-safe/index": crypto.encrypt_index(
            keys, {"v": 1, "key_id": keys.key_id.hex(), "entries": {}}
        ),
    }
    write_vault_commit(forger_repo, files)
    forger_repo.sh("push", "-q", "--force", str(machines.bare), "nbp-safe")
    tip_before = vault_tip(b)
    refused = b.cli("sync")
    assert refused.code == 1 and "REPLACED" in refused.err
    assert vault_tip(b) == tip_before
    assert b.cli("sync", "--no-fetch").code == 1  # the fetched ref is judged the same way


def test_tampered_remote_blob_is_never_adopted(
    machines: Machines,
    clone_factory: Callable[..., NbpRepo],
    unlock_fast: Callable[..., ThreadAgent],
) -> None:
    a, b = machines.a, machines.b
    a.write("reports/third.csv", "3\n")
    seal_by_commit(a)
    assert a.cli("push").code == 0
    # a forged child of the remote tip with a flipped blob payload, fast-forward pushed by "C"
    attacker = clone_factory(machines.env)
    attacker.sh("branch", "nbp-safe", "origin/nbp-safe")
    files = read_vault(attacker, "refs/remotes/origin/nbp-safe")
    victim = store_paths(files)[0]
    files[victim] = flip(files[victim])
    write_vault_commit(attacker, files, attacker.sh("rev-parse", "origin/nbp-safe").strip())
    attacker.sh("push", "-q", "origin", "nbp-safe")
    before = (vault_tip(b), protected_map(b))
    refused = b.cli("sync")
    assert refused.code == 1 and "authentication failed" in refused.err
    assert (vault_tip(b), protected_map(b)) == before  # nothing adopted, nothing written


def test_tampered_remote_index_is_refused(machines: Machines) -> None:
    a, b = machines.a, machines.b
    a.write("reports/fourth.csv", "4\n")
    seal_by_commit(a)
    files = read_vault(a)
    write_vault_commit(a, {**files, "nbp-safe/index": flip(files["nbp-safe/index"])}, vault_tip(a))
    a.sh("push", "-q", "--no-verify", "origin", "nbp-safe")  # the hole in the sender, not in B
    before = vault_tip(b)
    refused = b.cli("sync")
    assert refused.code == 1 and "authentication failed" in refused.err
    assert vault_tip(b) == before


def test_remote_vault_with_paths_outside_our_patterns_asks_for_a_pull(
    machines: Machines,
) -> None:
    a, b = machines.a, machines.b
    a.write(".nbp-safe", a.read(".nbp-safe").decode() + "extra-private/\n")
    a.write("extra-private/x.txt", "x\n")
    seal_by_commit(a)  # the vault now has a path that B's .nbp-safe does not cover
    assert a.cli("push").code == 0
    before = vault_tip(b)
    refused = b.cli("sync")
    assert refused.code == 1 and "git pull" in refused.err and vault_tip(b) == before


# ------------------------------------------------------ never forced (all commands)


@pytest.fixture
def git_calls(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[list[str]]]:
    calls: list[list[str]] = []
    real = subprocess.run

    def spy(args, *a, **kw):  # type: ignore[no-untyped-def]
        if isinstance(args, list):
            calls.append([str(x) for x in args])
        return real(args, *a, **kw)

    monkeypatch.setattr("nbp_git_safe.gitutil.subprocess.run", spy)
    yield calls


FORCING = {"--force", "-f", "--force-with-lease", "--mirror", "--delete", "-d", "--prune"}


def forced_pushes(calls: list[list[str]]) -> list[list[str]]:
    bad = []
    for argv in calls:
        if "push" in argv[:3]:
            tokens = argv[argv.index("push") + 1 :]
            if any(t in FORCING or t.startswith(("+", ":", "--force")) for t in tokens):
                bad.append(argv)
    return bad


def test_no_command_ever_forces_a_push(machines: Machines, git_calls: list[list[str]]) -> None:
    a, b = machines.a, machines.b
    a.write("reports/p.csv", "p\n")
    seal_by_commit(a)
    b.write("reports/q.csv", "q\n")
    seal_by_commit(b)
    assert a.cli("push").code == 0
    assert b.cli("push").code == 1  # rejected, not forced
    assert b.cli("sync").code == 0 and b.cli("push").code == 0
    assert a.cli("sync").code == 0
    assert any("push" in c for c in git_calls)  # the spy saw the pushes ...
    assert forced_pushes(git_calls) == []  # ... and none of them was forced or a deletion
    assert not any(c[:2] == ["git", "push"] and "+" in "".join(c) for c in git_calls)
