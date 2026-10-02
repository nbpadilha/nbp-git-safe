# SPDX-License-Identifier: MIT
"""The index chain: ``seq`` and ``prev`` (regression for review M1).

The index was not tied to its parent commit, so someone with push access (and no key) could create
a fast-forward commit that carries the tree, hence the encrypted index, of an OLDER vault state on
top of the newest one; ``sync`` accepted it and ``open`` rolled the working files back silently.
Now every index carries an authenticated, strictly increasing ``seq`` and the digest of its first
parent's index (``prev``); adopting a commit verifies the chain, and the newest verified tip is
remembered locally (``.git/nbp-safe/vault-seq.json``: commit ids and numbers only).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from itertools import pairwise
from pathlib import Path

import pytest

from nbp_git_safe import crypto, vault
from nbp_git_safe.config import load_config
from nbp_git_safe.gitutil import GitError, discover
from tests.helpers import NbpRepo
from tests.integration.conftest import Env
from tests.integration.guardkit import commit, first_protected
from tests.integration.test_multi import Machines, machines  # noqa: F401
from tests.integration.test_vault_tamper import read_vault, write_vault_commit


def forge_ff_replay(env: Env, old_tip: str, parent: str) -> str:
    """The attack: a new commit whose parent is ``parent`` (the newest tip) and whose tree is the
    one of ``old_tip``; no key involved, the old encrypted index is reused as it is."""
    git = env.git
    tree_old = git.run("rev-parse", f"{old_tip}^{{tree}}", cwd=env.bare).strip()
    forged = git.run(
        "commit-tree", tree_old, "-p", parent, "-m", "nbp-safe: seal", cwd=env.bare
    ).strip()
    git.run("update-ref", "refs/heads/nbp-safe", forged, cwd=env.bare)
    return forged


def test_fast_forward_replay_of_an_old_index_is_refused(hooked: Env) -> None:
    repo = hooked.repo
    rel = first_protected(repo, ".csv")
    v1_tip, v1 = hooked.tip(), repo.read(rel)
    repo.write(rel, v1 + b"\nNEWEST VERSION\n")
    assert commit(repo, "edit", "--allow-empty").returncode == 0
    v2_tip, v2 = hooked.tip(), repo.read(rel)
    assert v2_tip != v1_tip and v2 != v1
    assert repo.cli("push").code == 0  # the remote has v2, this clone has seen it

    forge_ff_replay(hooked, v1_tip, v2_tip)
    refused = repo.cli("sync")
    assert refused.code == 1, (refused.out, refused.err)
    assert "older than its parent" in refused.err
    assert repo.read(rel) == v2, "the working file was rolled back"
    assert hooked.tip() == v2_tip  # the local vault did not move either


def test_a_fresh_clone_refuses_the_replayed_vault_too(
    hooked: Env, clone_factory: Callable[..., NbpRepo], unlock_fast: Callable[..., object]
) -> None:
    repo = hooked.repo
    rel = first_protected(repo, ".csv")
    v1_tip = hooked.tip()
    repo.write(rel, repo.read(rel) + b"\nNEWEST VERSION\n")
    assert commit(repo, "edit", "--allow-empty").returncode == 0
    v2_tip = hooked.tip()
    assert repo.raw("push", "-q", "origin", "main", "nbp-safe").returncode == 0
    forge_ff_replay(hooked, v1_tip, v2_tip)

    fresh = clone_factory(hooked)
    assert fresh.cli("init").code == 0
    unlock_fast(fresh)
    opened = fresh.cli("open")
    assert opened.code == 1 and "older than its parent" in opened.err
    assert not (fresh.path / "reports").exists()  # nothing was written


def test_the_local_vault_branch_cannot_be_moved_back_silently(hooked: Env) -> None:
    repo = hooked.repo
    rel = first_protected(repo, ".csv")
    v1_tip = hooked.tip()
    repo.write(rel, repo.read(rel) + b"\nmore\n")
    assert commit(repo, "edit", "--allow-empty").returncode == 0
    assert repo.cli("open").code == 0  # the newest tip is verified and remembered
    repo.sh("update-ref", "refs/heads/nbp-safe", v1_tip)  # a hand-made rollback
    refused = repo.cli("open")
    assert refused.code == 1 and "behind a state this clone has verified" in refused.err
    findings = repo.cli("doctor")
    assert findings.code == 1 and "does not verify" in findings.out


def test_every_seal_extends_the_chain(hooked: Env) -> None:
    repo = hooked.repo
    rel = first_protected(repo, ".csv")
    for n in range(3):
        repo.write(rel, repo.read(rel) + f"\nedit {n}\n".encode())
        assert commit(repo, f"edit {n}", "--allow-empty").returncode == 0
    found, git = discover(repo.path, hooked.git.env)
    cfg = load_config(git, found)
    with hooked.backend() as backend:
        rows = git.text("rev-list", "--reverse", "--topo-order", cfg.vault_ref).split()
        indexes = [vault.load_commit(git, backend, c).index for c in rows]
        assert [i.seq for i in indexes] == list(range(1, len(rows) + 1))
        assert indexes[0].prev == ""
        for before, after in pairwise(indexes):
            assert after.prev == before.digest()
        assert vault.verify_chain(git, backend, rows[-1]) == len(rows)
    state = json.loads((repo.path / ".git" / "nbp-safe" / vault.VERIFIED_FILE).read_text())
    assert state["refs"][cfg.vault_ref] == {"tip": rows[-1], "seq": len(rows)}


def test_the_verified_state_holds_no_names(hooked: Env) -> None:
    text = (hooked.repo.path / ".git" / "nbp-safe" / vault.VERIFIED_FILE).read_text()
    assert not any(c in text for c in hooked.repo.canaries)
    hooked.repo.assert_no_leak(hooked.bare)


def test_merge_commits_outrank_both_parents(machines: Machines) -> None:  # noqa: F811
    a, b = machines.a, machines.b
    rel_a = first_protected(a, ".csv")
    a.write(rel_a, a.read(rel_a) + b"\nfrom A\n")
    assert commit(a, "a edit", "--allow-empty").returncode == 0
    b.write("reports/only-on-b.csv", "id,v\n1,from B " + "x" * 30 + "\n")
    assert commit(b, "b edit", "--allow-empty").returncode == 0
    assert a.cli("push").code == 0
    synced = b.cli("sync")  # diverged: a three-way merge
    assert synced.code == 0 and "merged" in synced.out, (synced.out, synced.err)
    found, git = discover(b.path, b.git.env)
    cfg = load_config(git, found)
    with machines.agent_b.client() as backend:
        tip = git.text("rev-parse", cfg.vault_ref).strip()
        parents = git.text("rev-list", "--parents", "-n", "1", tip).split()[1:]
        assert len(parents) == 2
        merged = vault.load_commit(git, backend, tip).index
        seqs = [vault.load_commit(git, backend, p).index.seq for p in parents]
        assert merged.seq == max(seqs) + 1
        first = vault.load_commit(git, backend, parents[0]).index
        assert merged.prev == first.digest()
        vault.verify_chain(git, backend, tip)  # the whole history, from the root
    assert b.cli("push").code == 0
    assert a.cli("sync").code == 0  # the other machine adopts the merge (fast-forward)


# ---------------------------------------------------------------- verify_chain, forged


def build_chain(repo: NbpRepo, specs: list[tuple[int, str | None]]) -> list[str]:
    """Commits written with the real key and hand-picked ``seq`` / ``prev`` (``None``: the digest
    of the previous commit's index, the honest value); returns the commit ids."""
    keys = crypto.KeySet(repo.master)
    commits: list[str] = []
    previous: vault.Index | None = None
    for seq, prev in specs:
        index = vault.Index(keys.key_id.hex(), {}, seq, "")
        index.prev = prev if prev is not None else (previous.digest() if previous else "")
        files = {
            ".gitattributes": vault.GITATTRIBUTES,
            "README.md": vault.README,
            "nbp-safe/index": crypto.encrypt_index(keys, index.to_dict()),
        }
        commits.append(write_vault_commit(repo, files, commits[-1] if commits else None))
        previous = index
    return commits


@pytest.mark.parametrize(
    ("specs", "message"),
    [
        ([(1, None), (2, None), (3, None)], None),  # honest
        ([(1, None), (5, None)], None),  # gaps are fine (a purge drops commits)
        ([(1, None), (1, None)], "older than its parent"),  # same seq: a replay
        ([(3, None), (2, None)], "older than its parent"),  # going back
        ([(1, None), (2, "00" * 32)], "does not link"),  # wrong prev
        ([(1, "00" * 32)], "must not link"),  # a root that claims a parent
    ],
)
def test_verify_chain_rules(
    hooked: Env, specs: list[tuple[int, str | None]], message: str | None
) -> None:
    commits = build_chain(hooked.repo, specs)
    _found, git = discover(hooked.repo.path, hooked.git.env)
    with hooked.backend() as backend:
        if message is None:
            assert vault.verify_chain(git, backend, commits[-1]) == specs[-1][0]
        else:
            with pytest.raises(vault.VaultRollbackError, match=message):
                vault.verify_chain(git, backend, commits[-1])


def test_a_chain_checked_incrementally_trusts_only_the_verified_tip(hooked: Env) -> None:
    commits = build_chain(hooked.repo, [(1, None), (2, None), (3, None)])
    _found, git = discover(hooked.repo.path, hooked.git.env)
    with hooked.backend() as backend:
        assert vault.verify_chain(git, backend, commits[-1], trusted=commits[0]) == 3
        with pytest.raises(GitError):  # not an object at all: nothing is trusted
            vault.verify_chain(git, backend, commits[-1], trusted="f" * 40)


def test_the_old_index_format_is_not_accepted(hooked: Env) -> None:
    """Nothing was published with version 1, so there is no compatibility path: a v1 index is
    simply an unsupported structure."""
    repo = hooked.repo
    keys = crypto.KeySet(repo.master)
    legacy = {"v": 1, "key_id": keys.key_id.hex(), "entries": {}}
    files = read_vault(repo)
    files["nbp-safe/index"] = crypto.encrypt_index(keys, legacy)
    write_vault_commit(repo, files, hooked.tip())
    refused = repo.cli("open")
    assert refused.code == 1 and "failed validation" in refused.err


def test_verified_file_is_tolerant_of_garbage(hooked: Env, tmp_path: Path) -> None:
    found, _git = discover(hooked.repo.path, hooked.git.env)
    path = found.state_dir / vault.VERIFIED_FILE
    for junk in (b"", b"[not json", b'{"refs": 3}', b'{"refs": {"a": {"tip": "zz", "seq": 1}}}'):
        path.write_bytes(junk)
        assert vault.read_verified(found) == {}
    vault.mark_verified(found, "refs/heads/nbp-safe", "a" * 40, 5)
    vault.mark_verified(found, "refs/heads/nbp-safe", "b" * 40, 3)  # never goes down ...
    assert vault.read_verified(found) == {"refs/heads/nbp-safe": ("a" * 40, 5)}
    vault.mark_verified(found, "refs/heads/nbp-safe", "b" * 40, 3, reset=True)  # ... unless reset
    assert vault.read_verified(found) == {"refs/heads/nbp-safe": ("b" * 40, 3)}
