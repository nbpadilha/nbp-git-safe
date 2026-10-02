# SPDX-License-Identifier: MIT
"""Second adversarial review, vault trust (M-R1 and the TOFU / record-file items).

M-R1: ``vault.ref`` used to be accepted from the versioned ``.nbp-safe.config`` while the record of
verified tips is per ref, so a commit that points the clone at ANOTHER ref holding an old, authentic
vault commit made ``sync``/``open`` restore the old content and ``doctor`` say "ok". The option is
local-only now, and a vault branch this clone never verified is adopted only with
``--confirm-first-adopt`` after the key id, seq and tip were shown.

TOFU: a fresh clone cannot know which tip is the newest; the confirmation shows what it can.
A damaged ``vault-seq.json`` used to read as "nothing verified" (``{}``) and re-opened exactly that
gap; it is an error now.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from nbp_git_safe import multi, vault
from nbp_git_safe.config import load_config
from nbp_git_safe.gitutil import discover
from tests.helpers import NbpRepo
from tests.integration.conftest import Env
from tests.integration.guardkit import commit, first_protected
from tests.integration.test_multi import Machines, machines  # noqa: F401

CloneFactory = Callable[..., NbpRepo]


def publish(env: Env) -> None:
    result = env.repo.raw("push", "-q", "origin", "main", "nbp-safe")
    assert result.returncode == 0, result.stderr


def two_vault_versions(hooked: Env) -> tuple[str, bytes, str, bytes]:
    """Seal v1, push, edit, seal v2, push: ``(rel, v1, v1_tip, v2)``."""
    repo = hooked.repo
    rel = first_protected(repo, ".csv")
    v1, v1_tip = repo.read(rel), hooked.tip()
    publish(hooked)
    repo.write(rel, v1 + b"\nNEWEST VERSION\n")
    assert commit(repo, "edit", "--allow-empty").returncode == 0
    assert hooked.tip() != v1_tip
    assert repo.cli("push").code == 0
    return rel, v1, v1_tip, repo.read(rel)


def test_r1_a_versioned_vault_ref_cannot_redirect_the_vault(
    hooked: Env, clone_factory: CloneFactory
) -> None:
    repo = hooked.repo
    rel, _v1, v1_tip, v2 = two_vault_versions(hooked)
    attacker = clone_factory(hooked)
    attacker.sh("fetch", "-q", "origin", "nbp-safe")
    assert attacker.raw("push", "-q", "origin", f"{v1_tip}:refs/heads/nbp-safe-x").returncode == 0
    attacker.write(".nbp-safe.config", "[vault]\n\tref = refs/heads/nbp-safe-x\n")
    attacker.sh("add", ".nbp-safe.config")
    assert attacker.raw("commit", "-q", "-m", "cfg").returncode == 0
    assert attacker.raw("push", "-q", "origin", "main").returncode == 0
    (repo.path / rel).unlink()
    pulled = repo.raw("pull", "-q", "--no-rebase", "origin", "main")
    assert pulled.returncode == 0, pulled.stderr
    assert (repo.path / ".nbp-safe.config").is_file()  # the redirect really arrived

    repo_obj, git = discover(repo.path, hooked.git.env)
    cfg = load_config(git, repo_obj)
    assert cfg.vault_ref == "refs/heads/nbp-safe" and "vault.ref" in cfg.ignored_versioned_keys

    synced = repo.cli("sync")
    assert synced.code == 0, synced.err
    assert "vault.ref in .nbp-safe.config is ignored" in synced.err  # said out loud
    assert repo.read(rel) == v2, "the old vault version was restored"
    doctor = repo.cli("doctor")
    assert "vault.ref in .nbp-safe.config is ignored" in doctor.out


def test_r1_a_vault_ref_chosen_locally_needs_the_confirmation(
    hooked: Env, clone_factory: CloneFactory
) -> None:
    """The same redirect done by configuration of THIS clone is allowed, but only knowingly."""
    repo = hooked.repo
    rel, v1, v1_tip, _v2 = two_vault_versions(hooked)
    attacker = clone_factory(hooked)
    attacker.sh("fetch", "-q", "origin", "nbp-safe")
    assert attacker.raw("push", "-q", "origin", f"{v1_tip}:refs/heads/nbp-safe-x").returncode == 0
    repo.set_config("nbp-safe.vaultRef", "refs/heads/nbp-safe-x")
    (repo.path / rel).unlink()
    refused = repo.cli("sync")
    assert refused.code != 0
    assert "never verified" in refused.err and "--confirm-first-adopt" in refused.err
    assert not (repo.path / rel).exists()  # nothing was restored
    assert repo.sh("for-each-ref", "refs/heads/nbp-safe-x").strip() == ""  # nor adopted
    allowed = repo.cli("sync", "--confirm-first-adopt")
    assert allowed.code == 0, allowed.err
    assert repo.read(rel) == v1  # the owner asked for exactly that branch


def test_tofu_a_fresh_clone_shows_key_seq_and_tip_and_needs_the_flag(
    hooked: Env, clone_factory: CloneFactory, unlock_fast: Callable[..., object]
) -> None:
    rel, _v1, _v1_tip, v2 = two_vault_versions(hooked)
    clone = clone_factory(hooked)
    init = clone.cli("init")
    assert init.code == 0 and "not adopted yet" in init.err
    repo_obj, _git = discover(clone.path, hooked.git.env)
    assert multi.read_seen(repo_obj) == {}  # nothing was recorded as seen without a verification
    assert vault.read_verified(repo_obj) == {}
    unlock_fast(clone)
    refused = clone.cli("open")
    assert refused.code != 0
    tip = clone.sh("rev-parse", "refs/heads/nbp-safe").strip()
    assert "key id" in refused.err and "seq 2" in refused.err and tip[:10] in refused.err
    assert "--confirm-first-adopt" in refused.err
    assert not (clone.path / rel).exists()
    assert vault.read_verified(repo_obj) == {}
    opened = clone.cli("open", "--confirm-first-adopt")
    assert opened.code == 0, opened.err
    assert clone.read(rel) == v2
    assert vault.read_verified(repo_obj)["refs/heads/nbp-safe"] == (tip, 2)
    again = clone.cli("open")  # adopted: no confirmation any more
    assert again.code == 0, again.err


def test_tofu_an_orphan_root_commit_is_visibly_an_old_one(
    hooked: Env, clone_factory: CloneFactory, unlock_fast: Callable[..., object]
) -> None:
    """The limit of trust on first use: an authentic first commit pushed as the branch looks like a
    valid vault to a clone that has seen nothing. The seq in the message is what gives it away."""
    _rel, _v1, v1_tip, _v2 = two_vault_versions(hooked)
    hooked.git.run("update-ref", "refs/heads/nbp-safe", v1_tip, cwd=hooked.bare)  # push access
    clone = clone_factory(hooked)
    assert clone.cli("init").code == 0
    unlock_fast(clone)
    refused = clone.cli("open")
    assert refused.code != 0 and "seq 1" in refused.err  # the owner knows it is already at 2


def test_tofu_sync_on_a_fresh_clone_needs_the_flag_too(
    hooked: Env, clone_factory: CloneFactory, unlock_fast: Callable[..., object]
) -> None:
    rel, _v1, _v1_tip, v2 = two_vault_versions(hooked)
    clone = clone_factory(hooked)  # no init: no local vault branch at all
    unlock_fast(clone)
    refused = clone.cli("sync")
    assert refused.code != 0 and "never verified" in refused.err and "seq 2" in refused.err
    assert clone.sh("for-each-ref", "refs/heads/nbp-safe").strip() == ""  # not adopted
    allowed = clone.cli("sync", "--confirm-first-adopt")
    assert allowed.code == 0, allowed.err
    assert clone.read(rel) == v2


def test_init_with_the_flag_verifies_before_it_records(
    hooked: Env, clone_factory: CloneFactory, unlock_fast: Callable[..., object]
) -> None:
    two_vault_versions(hooked)
    locked = clone_factory(hooked)
    refused = locked.cli("init", "--confirm-first-adopt")
    assert refused.code == 3 and "unlocked agent" in refused.err
    repo_obj, _git = discover(locked.path, hooked.git.env)
    assert multi.read_seen(repo_obj) == {} and vault.read_verified(repo_obj) == {}

    clone = clone_factory(hooked)
    unlock_fast(clone)
    done = clone.cli("init", "--confirm-first-adopt")
    assert done.code == 0 and "adopted nbp-safe" in done.err
    repo2, _ = discover(clone.path, hooked.git.env)
    assert vault.read_verified(repo2)["refs/heads/nbp-safe"][1] == 2
    assert "refs/heads/nbp-safe" in multi.read_seen(repo2)


@pytest.mark.parametrize(
    "damage", [b"{not json", b"[]", b'{"refs": 5}', b'{"refs": {"r": 1}}', b""]
)
def test_a_damaged_record_fails_closed_instead_of_reading_as_empty(
    hooked: Env, damage: bytes
) -> None:
    repo = hooked.repo
    repo_obj, _git = discover(repo.path, hooked.git.env)
    path = repo_obj.state_dir / vault.VERIFIED_FILE
    assert path.is_file()  # the baseline seal recorded the tip
    path.write_bytes(damage)
    with pytest.raises(vault.VerifiedStateError):
        vault.read_verified(repo_obj)
    assert vault.read_verified(repo_obj, strict=False) == {}  # only for the explicit re-adoption
    for command in ("open", "sync", "seal"):
        result = repo.cli(command)
        assert result.code != 0 and "unreadable" in result.err, (command, result.err)
    assert path.read_bytes() == damage  # nothing rewrote it silently
    findings = repo.cli("doctor")
    assert "unreadable" in findings.out

    healed = repo.cli("open", "--confirm-first-adopt")
    assert healed.code == 0, healed.err
    assert vault.read_verified(repo_obj)["refs/heads/nbp-safe"][0] == hooked.tip()
    assert repo.cli("open").code == 0


def test_a_missing_record_is_a_fresh_clone_not_an_error(hooked: Env) -> None:
    repo_obj, _git = discover(hooked.repo.path, hooked.git.env)
    (repo_obj.state_dir / vault.VERIFIED_FILE).unlink()
    assert vault.read_verified(repo_obj) == {}
    refused = hooked.repo.cli("open")
    assert refused.code != 0 and "never verified" in refused.err


# ------------------------------------- the other machines after a purge (docs/MULTI.md)


def purge_on_a(machines: Machines) -> tuple[str, str]:  # noqa: F811
    """A edits one file (second vault commit), pushes, purges it and force-pushes the rewrite.
    Returns ``(path, new remote tip)``. B has verified the pre-purge history."""
    a, b = machines.a, machines.b
    target = first_protected(a, ".json")
    a.write(target, a.read(target) + b"more\n")
    assert commit(a, "edit", "--allow-empty").returncode == 0
    assert a.cli("push").code == 0
    assert b.cli("sync").code == 0  # B has now verified the history that is about to be purged
    (b.path / target).unlink()  # the plain file is on every machine: it would be sealed again
    old_remote = a.sh("rev-parse", "refs/heads/nbp-safe").strip()
    done = a.cli("purge", target, "--confirm", "purge nbp-safe")
    assert done.code == 0, done.err
    (a.path / target).unlink()
    forced = a.raw(
        "push",
        f"--force-with-lease=refs/heads/nbp-safe:{old_remote}",
        "origin",
        "refs/heads/nbp-safe:refs/heads/nbp-safe",
    )
    assert forced.returncode == 0, forced.stderr
    return target, a.sh("rev-parse", "refs/heads/nbp-safe").strip()


def test_after_a_purge_deleting_the_branch_and_syncing_adopts_the_new_history(
    machines: Machines,  # noqa: F811
) -> None:
    """The documented way: `git branch -D nbp-safe`, then `sync --accept-remote-rewrite` (no
    `init`: it would only re-create the branch)."""
    b = machines.b
    target, new_tip = purge_on_a(machines)
    refused = b.cli("sync")
    assert refused.code == 1 and "REPLACED" in refused.err + refused.out  # not merged back
    b.sh("branch", "-D", "nbp-safe")
    adopted = b.cli("sync", "--accept-remote-rewrite")
    assert adopted.code == 0, adopted.err
    assert b.sh("rev-parse", "refs/heads/nbp-safe").strip() == new_tip
    repo_obj, git = discover(b.path, machines.env.git.env)
    assert vault.read_verified(repo_obj)["refs/heads/nbp-safe"][0] == new_tip
    assert b.cli("open").code == 0 and b.cli("doctor").code == 0
    with machines.agent_b.client() as backend:
        state = vault.load_vault(git, backend, load_config(git, repo_obj))
    assert all(e.path != target for e in state.index.entries.values())  # purged for good


def test_after_a_purge_init_alone_does_not_adopt_but_sync_with_the_flag_does(
    machines: Machines,  # noqa: F811
) -> None:
    """The earlier docs promised `delete the branch and run init`: init only re-creates the branch
    (and records nothing), `open` still refuses the replaced history, and `sync
    --accept-remote-rewrite` is what adopts it (also when the branch is already there)."""
    b = machines.b
    _target, new_tip = purge_on_a(machines)
    b.sh("fetch", "-q", "origin")
    b.sh("branch", "-D", "nbp-safe")
    assert b.cli("init").code == 0
    assert b.sh("rev-parse", "refs/heads/nbp-safe").strip() == new_tip
    refused = b.cli("open")
    assert refused.code != 0 and "replaced" in refused.err
    adopted = b.cli("sync", "--accept-remote-rewrite")
    assert adopted.code == 0, adopted.err
    assert b.cli("open").code == 0 and b.cli("sync").code == 0
