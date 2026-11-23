# SPDX-License-Identifier: MIT
"""Multi-machine operations on the vault branch: ``sync``, ``push``, ``rotate``, ``purge``.

Principles:

* Nothing here ever forces anything on the remote. ``push`` sends ``refs/heads/nbp-safe`` without
  ``+`` and reports a rejection; ``sync`` merges, it never rewrites. ``purge`` and ``rotate`` print
  the exact commands the OWNER has to run for the remote side; the tool does not run them.
* ``sync`` is a three-way merge by index entries (base = merge base of the two vault tips): the
  merge commit has two parents and nothing is lost. When both sides changed the same file the
  local version keeps the id and the other becomes a second entry ``<name>.conflict-<short>``.
* Everything adopted from the remote is authenticated with the key first (index and every adopted
  blob), so a tampered remote cannot inject content into our history.
* The tips of the remote vault branch that this clone has seen are remembered (commit ids only, in
  ``.git/nbp-safe/remote-seen.json``) to notice a rollback or a rewrite of the remote branch.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from nbp_git_safe import crypto, protect, vault
from nbp_git_safe import index as index_mod
from nbp_git_safe.config import Config, is_vault_ref
from nbp_git_safe.gitutil import (
    FOREGROUND_TIMEOUT,
    Git,
    Repo,
    hash_object,
    is_ancestor,
    rev_parse,
)
from nbp_git_safe.index import Entry, Index, IndexValidationError

REMOTE = "origin"
SYNC_MESSAGE = "nbp-safe: sync"
ROTATE_MESSAGE = "nbp-safe: rotate"
SEEN_FILE = "remote-seen.json"
PURGED_FILE = "purged.json"
AUTOPUSH_FILE = "autopush.json"
CONFLICT_MARK = ".conflict-"
_SHA_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")

Matcher = Callable[[list[str]], set[str]]


class SyncError(vault.VaultError):
    """The merge cannot be done safely (nothing was changed)."""


class RemoteRewriteError(vault.VaultError):
    """The remote vault branch went backwards or was replaced (possible rollback/tampering)."""


class PushRejectedError(vault.VaultError):
    """The remote has vault commits this clone does not have."""


class PushRefusedError(vault.VaultError):
    """The remote declined the push by a rule of its own (a server-side hook, a protected branch):
    ``sync`` does not help, someone has to look at the remote."""


class ConfirmationError(vault.VaultError):
    """A typed confirmation was missing or wrong (nothing was changed)."""


def confirmation_text(verb: str, ref: str) -> str:
    """The exact phrase the owner has to type: ``<verb> <branch name>``."""
    return f"{verb} {ref.removeprefix('refs/heads/')}"


def check_confirmation(expected: str, given: str | None) -> None:
    if given is None or given != expected:
        raise ConfirmationError(f'confirmation required: type exactly "{expected}"')


# ----------------------------------------------------------------- remote tips seen so far


def _seen_path(repo: Repo) -> Path:
    return repo.state_dir / SEEN_FILE


def read_seen(repo: Repo) -> dict[str, str]:
    try:
        data = json.loads(_seen_path(repo).read_bytes().decode("utf-8"))
    except (OSError, ValueError):
        return {}
    refs = data.get("refs") if isinstance(data, dict) else None
    if not isinstance(refs, dict):
        return {}
    return {k: v for k, v in refs.items() if isinstance(k, str) and _SHA_RE.match(str(v))}


def record_seen(repo: Repo, ref: str, tip: str) -> None:
    refs = read_seen(repo)
    refs[ref] = tip
    repo.state_dir.mkdir(parents=True, exist_ok=True)
    path = _seen_path(repo)
    tmp = path.with_name(f"{SEEN_FILE}.{secrets.token_hex(4)}.tmp")
    with open(tmp, "wb") as handle:
        handle.write(json.dumps({"refs": refs}, sort_keys=True).encode("ascii"))
        handle.flush()
        os.fsync(handle.fileno())
    tmp.replace(path)


def read_purge_marker(repo: Repo) -> dict[str, str]:
    """``{vault ref: tip before the last purge}`` while the remote may still hold that history."""
    try:
        data = json.loads((repo.state_dir / PURGED_FILE).read_bytes().decode("ascii"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(k, str) and _SHA_RE.match(str(v))}


def _write_purge_marker(repo: Repo, markers: dict[str, str]) -> None:
    path = repo.state_dir / PURGED_FILE
    if not markers:
        path.unlink(missing_ok=True)
        return
    repo.state_dir.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json.dumps(markers, sort_keys=True).encode("ascii"))


def purge_pending(git: Git, repo: Repo, cfg: Config) -> bool:
    """Did we purge locally while origin still has the pre-purge history? (Clears the marker once
    origin's tip is part of our history again.)"""
    markers = read_purge_marker(repo)
    old = markers.get(cfg.vault_ref)
    remote = rev_parse(git, cfg.remote_vault_ref + "^{commit}")
    local = rev_parse(git, cfg.vault_ref + "^{commit}")
    if old is None or remote is None or local is None:
        return False
    if is_ancestor(git, remote, local):
        del markers[cfg.vault_ref]
        _write_purge_marker(repo, markers)
        return False
    return is_ancestor(git, remote, old)


@dataclass
class RemoteStatus:
    kind: str  # no-remote | no-local | in-sync | ahead | behind | diverged | rollback | rewritten
    message: str
    ahead: int = 0
    behind: int = 0

    @property
    def alarming(self) -> bool:
        return self.kind in ("rollback", "rewritten")


def remote_status(git: Git, repo: Repo, cfg: Config) -> RemoteStatus:
    """Relation of the local vault tip to ``origin``'s (keyless, offline: uses the remote-tracking
    ref and the remembered tips)."""
    local = rev_parse(git, cfg.vault_ref + "^{commit}")
    remote = rev_parse(git, cfg.remote_vault_ref + "^{commit}")
    if remote is None:
        return RemoteStatus("no-remote", "origin has no vault branch (or it was never fetched)")
    if purge_pending(git, repo, cfg):
        return RemoteStatus(
            "purge-pending",
            "you purged this vault locally and origin still has the old history: force-push the "
            "rewritten branch (see the purge output) before syncing, or the purge is undone",
        )
    seen = read_seen(repo).get(cfg.vault_ref)
    if seen is not None and seen != remote:
        if is_ancestor(git, remote, seen):
            return RemoteStatus(
                "rollback",
                "origin's vault went BACK in time (its tip is an ancestor of a tip seen before): "
                "possible rollback or tampering on the remote; nothing was merged",
            )
        if not is_ancestor(git, seen, remote):
            return RemoteStatus(
                "rewritten",
                "origin's vault history was REPLACED (its tip does not descend from the last tip "
                "seen): a purge/rotate by its owner, or tampering; nothing was merged",
            )
    if local is None:
        return RemoteStatus("no-local", "a vault exists on origin but there is no local branch")
    if local == remote:
        return RemoteStatus("in-sync", "in sync with origin")
    code, out, _ = git.run_status("rev-list", "--left-right", "--count", f"{local}...{remote}")
    if code != 0:
        return RemoteStatus("diverged", "local and remote vault histories are unrelated")
    ahead, behind = (int(x) for x in out.decode("ascii").split())
    if ahead and behind:
        return RemoteStatus(
            "diverged", f"diverged from origin ({ahead} ahead, {behind} behind)", ahead, behind
        )
    if behind:
        return RemoteStatus("behind", f"{behind} commit(s) behind origin", ahead, behind)
    return RemoteStatus("ahead", f"{ahead} commit(s) ahead of origin (not pushed)", ahead, behind)


# ------------------------------------------------------------------------ entry merging


@dataclass
class MergeOutcome:
    merged: dict[str, Entry]
    from_theirs: set[str] = field(default_factory=set)  # ids whose blob comes from their tree
    copies: dict[str, tuple[str, Entry]] = field(
        default_factory=dict
    )  # new id -> (their id, entry)
    notes: list[str] = field(default_factory=list)
    conflicts: int = 0


def _pick(o: Any, t: Any, b: Any) -> tuple[Any, bool]:
    """Three-way choice of one value. Returns ``(value, conflict)`` (ours on conflict)."""
    if o == t:
        return o, False
    if o == b:
        return t, False
    if t == b:
        return o, False
    return o, True


def _content(entry: Entry) -> tuple[str, int, str]:
    return entry.mode, entry.size, entry.mac


def conflict_path(path: str, tag: str, taken: set[str], matcher: Matcher) -> str:
    """A free, valid path next to ``path`` that is still inside the protected set:
    ``dir/stem.conflict-<tag>.ext`` first (keeps extension patterns working), then
    ``path.conflict-<tag>``."""
    head, _, name = path.rpartition("/")
    prefix = head + "/" if head else ""
    stem, dot, ext = name.rpartition(".")
    for attempt in range(1, 4):
        mark = f"{CONFLICT_MARK}{tag}" + ("" if attempt == 1 else f"-{attempt}")
        candidates = []
        if dot and stem:
            candidates.append(f"{prefix}{stem}{mark}.{ext}")
        candidates.append(f"{path}{mark}")
        for candidate in candidates:
            try:
                index_mod.validate_path(candidate)
            except IndexValidationError:
                continue
            if index_mod.collision_key(candidate) in taken:
                continue
            if candidate in matcher([candidate]):
                return candidate
    raise SyncError(
        "a conflicting copy would fall outside the protected set; add a pattern such as "
        "`*.conflict-*` to .nbp-safe (and push it to all machines), then run sync again"
    )


def merge_entries(
    base: Mapping[str, Entry],
    ours: Mapping[str, Entry],
    theirs: Mapping[str, Entry],
    matcher: Matcher,
    new_id: Callable[[], str] = crypto.new_file_id,
) -> MergeOutcome:
    """Three-way merge of two vault indexes against their common base (see module docstring)."""
    out = MergeOutcome({})
    merged = out.merged
    for fid in sorted(set(base) | set(ours) | set(theirs)):
        b, o, t = base.get(fid), ours.get(fid), theirs.get(fid)
        if o == t:
            if o is not None:
                merged[fid] = o
            continue
        if o == b:  # only they changed it (or removed it, or added it)
            if t is not None:
                merged[fid] = t
                out.from_theirs.add(fid)
            continue
        if t == b:  # only we changed it
            if o is not None:
                merged[fid] = o
            continue
        if o is None or t is None:  # one side removed it, the other modified it: keep the data
            keep = t if o is None else o
            assert keep is not None
            merged[fid] = keep
            if o is None:
                out.from_theirs.add(fid)
            out.notes.append(f"{keep.path}: removed on one side and modified on the other; kept")
            out.conflicts += 1
            continue
        path, path_conflict = _pick(o.path, t.path, b.path if b else None)
        content, content_conflict = _pick(_content(o), _content(t), _content(b) if b else None)
        created, updated = min(o.created, t.created), max(o.updated, t.updated)
        if not content_conflict:
            merged[fid] = Entry(path, content[0], content[1], content[2], created, updated)
            if content != _content(o):
                out.from_theirs.add(fid)
            if path_conflict:
                out.notes.append(f"{o.path}: moved to different paths on both sides; kept ours")
                out.conflicts += 1
            continue
        merged[fid] = replace(o, path=path, created=created)
        out.copies[new_id()] = (fid, t)
        out.notes.append(f"{o.path}: changed on both sides; the other version is kept as a copy")
        out.conflicts += 1
    _finalize_paths(out, set(ours), matcher)
    return out


def _finalize_paths(out: MergeOutcome, ours_ids: set[str], matcher: Matcher) -> None:
    """Give conflict copies their paths and resolve every remaining path collision."""
    entries = out.merged
    taken = {index_mod.collision_key(e.path) for e in entries.values()}
    for nid, (src, entry) in sorted(out.copies.items()):
        path = conflict_path(entry.path, entry.mac[:8], taken, matcher)
        taken.add(index_mod.collision_key(path))
        out.copies[nid] = (src, replace(entry, path=path))
        entries[nid] = out.copies[nid][1]
    for _ in range(10):
        groups: dict[str, list[str]] = {}
        for fid, entry in entries.items():
            groups.setdefault(index_mod.collision_key(entry.path), []).append(fid)
        dirs = {
            "/".join(key.split("/")[:i]) for key in groups for i in range(1, len(key.split("/")))
        }
        clash = [ids for ids in groups.values() if len(ids) > 1]
        file_vs_dir = [ids[0] for key, ids in groups.items() if key in dirs]
        if not clash and not file_vs_dir:
            return
        for ids in clash:
            ids.sort(key=lambda f: (f not in ours_ids, entries[f].updated, f))
            winner, losers = ids[0], ids[1:]
            for loser in losers:
                _demote(out, entries, loser, winner, matcher)
        for fid in file_vs_dir:
            if fid in entries:
                _demote(out, entries, fid, None, matcher)
    raise SyncError("the merged paths could not be made consistent")


def _demote(
    out: MergeOutcome, entries: dict[str, Entry], loser: str, winner: str | None, matcher: Matcher
) -> None:
    entry = entries[loser]
    if winner is not None and entries[winner].mac == entry.mac:
        del entries[loser]  # the same file added on both sides under different ids
        out.from_theirs.discard(loser)
        out.copies.pop(loser, None)
        out.notes.append(f"{entry.path}: identical file added on both sides; merged into one")
        return
    taken = {index_mod.collision_key(e.path) for e in entries.values()}
    path = conflict_path(entry.path, entry.mac[:8], taken, matcher)
    entries[loser] = replace(entry, path=path)
    if loser in out.copies:
        out.copies[loser] = (out.copies[loser][0], entries[loser])
    out.notes.append(f"{entry.path}: path taken by another file; kept as {path}")
    out.conflicts += 1


# ------------------------------------------------------------------------------- sync


@dataclass
class SyncResult:
    action: str  # no-remote | up-to-date | ahead | fast-forward | merged
    commit: str | None = None
    sealed: str | None = None
    notes: list[str] = field(default_factory=list)
    conflicts: int = 0
    adopted: int = 0
    known_macs: dict[str, frozenset[str]] = field(default_factory=dict)  # for vault.open_vault


def fetch_vault(
    git: Git, cfg: Config, remote: str = REMOTE, *, timeout: float = FOREGROUND_TIMEOUT
) -> bool:
    """Fetch the vault branch into its remote-tracking ref (force-updating a tracking ref is only
    a cache update; rollbacks are detected from the remembered tips). False: no such branch. A
    fetch that does not finish within ``timeout`` is stopped with everything it started
    (``GitTimeoutError``)."""
    code, _, err = git.run_status(
        "fetch", "--quiet", remote, f"+{cfg.vault_ref}:{cfg.remote_vault_ref}", timeout=timeout
    )
    if code == 0:
        return True
    text = err.decode("utf-8", "replace")
    if "couldn't find remote ref" in text:
        return False
    detail = " ".join(text.strip().splitlines()[:2])
    raise vault.VaultError(f"could not fetch the vault from {remote}: {detail}")


def _verified_blob(
    git: Git, backend: vault.Backend, state: vault.VaultState, fid: str, e: Entry
) -> tuple[str, bytes]:
    sha = state.files.get(vault.STORE_PREFIX + fid)
    if sha is None:
        raise vault.VaultTamperError("the remote vault is missing a blob its index references")
    plain = backend.dec_blob(fid, git.run("cat-file", "blob", sha))
    if len(plain) != e.size or backend.mac(plain).hex() != e.mac:
        raise vault.VaultTamperError("a remote vault blob does not match its authenticated index")
    return sha, plain


def _check_protected(git: Git, repo: Repo, index: Index) -> None:
    """The paths of a vault we are about to adopt must be inside OUR protected set, otherwise
    ``open`` would refuse the whole vault (``git pull`` brings the matching ``.nbp-safe``)."""
    try:
        index_mod.validate_against_protected(
            index,
            lambda paths: protect.match_paths(git, repo, paths),
            protect.tracked_files(git),
        )
    except IndexValidationError as exc:
        raise SyncError(
            f"the remote vault is not valid for this working tree ({exc}); run `git pull` so "
            ".nbp-safe is up to date, then sync again"
        ) from None


def _verify_adopted(
    git: Git, backend: vault.Backend, theirs: vault.VaultState, ours_files: Mapping[str, str]
) -> None:
    """Authenticate every blob of their tree that differs from ours before adopting it wholesale."""
    for fid, entry in theirs.index.entries.items():
        key = vault.STORE_PREFIX + fid
        if ours_files.get(key) != theirs.files.get(key):
            _verified_blob(git, backend, theirs, fid, entry)


def merge_vaults(
    git: Git,
    repo: Repo,
    cfg: Config,
    backend: vault.Backend,
    ours: vault.VaultState,
    theirs: vault.VaultState,
    *,
    now: float | None = None,
) -> tuple[str | None, MergeOutcome]:
    assert ours.tip is not None and theirs.tip is not None
    base_tip = git.try_run("merge-base", ours.tip, theirs.tip)
    base_entries: dict[str, Entry] = {}
    if base_tip is not None and base_tip.strip():
        base_entries = dict(
            vault.load_commit(git, backend, base_tip.decode("ascii").strip()).index.entries
        )

    def matcher(paths: list[str]) -> set[str]:
        return protect.match_paths(git, repo, paths)

    outcome = merge_entries(base_entries, ours.index.entries, theirs.index.entries, matcher)
    blob_shas: dict[str, str] = {}
    blobs: dict[str, bytes] = {}
    for fid in sorted(outcome.from_theirs):
        sha, _plain = _verified_blob(git, backend, theirs, fid, outcome.merged[fid])
        blob_shas[fid] = sha
    for nid, (src, entry) in sorted(outcome.copies.items()):
        _sha, plain = _verified_blob(git, backend, theirs, src, theirs.index.entries[src])
        blobs[nid] = backend.enc_blob(nid, plain, cfg.pad_bucket)
        outcome.merged[nid] = entry
    merged_index = ours.index.successor(outcome.merged, other_parents=[theirs.index.seq])
    try:
        Index.from_dict(merged_index.to_dict(), bytes.fromhex(ours.index.key_id))
        index_mod.validate_against_protected(merged_index, matcher, protect.tracked_files(git))
    except IndexValidationError as exc:
        raise SyncError(
            f"the merged vault would be invalid ({exc}); run `git pull` so that .nbp-safe is "
            "up to date, then sync again"
        ) from None
    remove_ids = [fid for fid in ours.index.entries if fid not in outcome.merged]
    index_blob = backend.enc_index(merged_index.to_dict(), cfg.pad_bucket)
    commit = vault.build_commit(
        git,
        repo,
        ref=cfg.vault_ref,
        parents=[ours.tip, theirs.tip],
        expect_old=ours.tip,
        base_tree=ours.tree,
        index_blob=index_blob,
        blobs=blobs,
        blob_shas=blob_shas,
        remove_ids=remove_ids,
        message=SYNC_MESSAGE,
        granularity=cfg.time_granularity,
        now=now,
    )
    return commit, outcome


def _verify_remote_chain(
    git: Git, backend: vault.Backend, repo: Repo, cfg: Config, remote: str
) -> int:
    """Verify the index chain of a remote vault tip before anything of it is adopted: only the
    commits this clone has not verified yet when the tip descends from the verified one, the whole
    history otherwise (a diverged but honest remote). A replayed older index fails here."""
    known = vault.read_verified(repo, strict=False).get(cfg.vault_ref)  # callers gated it already
    trusted = known[0] if known is not None and is_ancestor(git, known[0], remote) else None
    return vault.verify_chain(git, backend, remote, trusted=trusted)


def _gate_first_adoption(
    git: Git, backend: vault.Backend, repo: Repo, cfg: Config, tip: str, confirmed: bool
) -> bool:
    """Adopting a vault branch this clone has never verified needs the owner's confirmation (trust
    on first use). Returns True when it is a first adoption that was confirmed (the caller records
    it as a reset), False when the branch is already known; raises ``AdoptionRequiredError``
    (naming key id, seq and tip) otherwise."""
    if cfg.vault_ref in vault.read_verified(repo, strict=not confirmed):
        return False
    seq = vault.verify_chain(git, backend, tip)
    if not confirmed:
        raise vault.AdoptionRequiredError(
            vault.adoption_message(git, backend, cfg.vault_ref, tip, seq)
        )
    return True


def sync(
    git: Git,
    repo: Repo,
    cfg: Config,
    backend: vault.Backend,
    *,
    fetch: bool = True,
    seal_first: bool = True,
    accept_rewrite: bool = False,
    confirm_adopt: bool = False,
    now: float | None = None,
) -> SyncResult:
    """Seal local changes, fetch, then fast-forward or three-way merge. Never forces anything.
    A vault branch this clone has never verified is adopted only with ``confirm_adopt``."""
    protect.install_exclude_block(repo)
    result = SyncResult("up-to-date")
    if purge_pending(git, repo, cfg):  # before sealing: nothing may change until the owner pushes
        raise RemoteRewriteError(remote_status(git, repo, cfg).message)
    fetched: bool | None = None
    if fetch and rev_parse(git, cfg.vault_ref + "^{commit}") is None:
        fetched = fetch_vault(git, cfg)  # no local branch to seal into: look at origin first
    adopting = (
        rev_parse(git, cfg.vault_ref + "^{commit}") is None
        and rev_parse(git, cfg.remote_vault_ref + "^{commit}") is not None
    )
    if seal_first and not adopting:  # (a deleted local branch is re-adopted, sealing comes after)
        result.sealed, _analysis, _plan = vault.seal(
            git, repo, cfg, backend, now=now, allow_replaced=accept_rewrite
        )
    if fetch and fetched is None:
        fetched = fetch_vault(git, cfg)
    if fetched is False:
        result.notes.append("origin has no vault branch yet")
    remote = rev_parse(git, cfg.remote_vault_ref + "^{commit}")
    if remote is None:
        result.action = "no-remote"
        return result
    status = remote_status(git, repo, cfg)
    if status.kind == "purge-pending":
        raise RemoteRewriteError(status.message)
    if status.alarming and not accept_rewrite:
        raise RemoteRewriteError(status.message + " (use --accept-remote-rewrite after checking)")
    theirs = vault.load_commit(git, backend, remote)  # authenticates and validates their tip
    local = rev_parse(git, cfg.vault_ref + "^{commit}")
    ours_state = vault.load_commit(git, backend, local) if local is not None else None
    if local is not None:  # our own tip must not have gone back either
        first = confirm_adopt and cfg.vault_ref not in vault.read_verified(repo, strict=False)
        seq_local = vault.check_chain(
            git, backend, repo, cfg.vault_ref, local, allow_replaced=accept_rewrite, adopt=first
        )
        if first or accept_rewrite:
            # an explicit adoption (first use, or a history the owner knows was rewritten): the
            # local tip, which verified, is the new record (this is also what makes a branch that
            # `init` created from a purged remote usable)
            vault.mark_verified(repo, cfg.vault_ref, local, seq_local, reset=True)
    if ours_state is not None:
        for e in ours_state.index.entries.values():
            result.known_macs.setdefault(e.path, frozenset())
            result.known_macs[e.path] |= {e.mac}
    if local is None:
        first_adoption = _gate_first_adoption(git, backend, repo, cfg, remote, confirm_adopt)
        _check_protected(git, repo, theirs.index)
        _verify_adopted(git, backend, theirs, {})
        try:  # a tip older than what this clone verified is never brought back by a re-sync
            seq = vault.check_chain(
                git,
                backend,
                repo,
                cfg.vault_ref,
                remote,
                allow_replaced=accept_rewrite,
                adopt=first_adoption,
            )
        except vault.VaultRollbackError as exc:
            raise RemoteRewriteError(
                f"{exc}: origin's vault branch is older than, or does not contain, the newest "
                "vault state this clone verified (a rollback or a rewrite of the remote branch); "
                "nothing was adopted (use --accept-remote-rewrite only after checking)"
            ) from exc
        git.run("update-ref", "-m", "nbp-safe: sync", cfg.vault_ref, remote, "0" * len(remote))
        vault.mark_verified(
            repo, cfg.vault_ref, remote, seq, reset=accept_rewrite or first_adoption
        )
        result.action, result.commit, result.adopted = (
            "fast-forward",
            remote,
            len(theirs.index.entries),
        )
    elif local == remote or is_ancestor(git, remote, local):
        result.action = "up-to-date" if local == remote else "ahead"
    elif is_ancestor(git, local, remote):
        _check_protected(git, repo, theirs.index)
        assert ours_state is not None
        _verify_adopted(git, backend, theirs, ours_state.files)
        seq = _verify_remote_chain(git, backend, repo, cfg, remote)
        git.run("update-ref", "-m", "nbp-safe: sync", cfg.vault_ref, remote, local)
        vault.mark_verified(repo, cfg.vault_ref, remote, seq, reset=accept_rewrite)
        result.action, result.commit = "fast-forward", remote
    else:
        assert ours_state is not None
        _verify_remote_chain(git, backend, repo, cfg, remote)  # theirs must link up before merging
        commit, outcome = merge_vaults(git, repo, cfg, backend, ours_state, theirs, now=now)
        if commit is not None:
            merged_seq = max(ours_state.index.seq, theirs.index.seq) + 1
            vault.mark_verified(repo, cfg.vault_ref, commit, merged_seq, reset=accept_rewrite)
        result.action, result.commit = "merged", commit
        result.notes.extend(outcome.notes)
        result.conflicts = outcome.conflicts
    record_seen(repo, cfg.vault_ref, remote)
    return result


# ------------------------------------------------------------------------------- push


# git's own wording: a push the remote REFUSES because it has commits we do not ("! [rejected]
# ... (non-fast-forward)" or "(fetch first)") is not the same thing as one a server-side hook or
# rule declines ("! [remote rejected] ... (pre-receive hook declined)"): `sync` fixes the first only
_BEHIND_RE = re.compile(r"\[rejected\]|non-fast-forward|fetch first|stale info")


def push_vault(
    git: Git, repo: Repo, cfg: Config, remote: str = REMOTE, *, timeout: float = FOREGROUND_TIMEOUT
) -> str:
    """``git push <remote> <vault ref>:<vault ref>`` without ``+`` (and without ``--follow-tags``:
    the history carries upstream tags that must never travel). Returns the pushed tip. A push that
    does not finish within ``timeout`` is stopped with everything it started
    (``GitTimeoutError``)."""
    local = rev_parse(git, cfg.vault_ref + "^{commit}")
    if local is None:
        raise vault.VaultError("there is no local vault branch to push")
    code, _, err = git.run_status(
        "push",
        "--quiet",
        "--no-follow-tags",
        remote,
        f"{cfg.vault_ref}:{cfg.vault_ref}",
        timeout=timeout,
    )
    if code != 0:
        text = err.decode("utf-8", "replace")
        if "[remote rejected]" in text:
            raise PushRefusedError(
                "origin refused the push by a rule of its own (a server-side hook or a protected "
                "branch); syncing will not change that: look at the remote's rules"
            )
        if _BEHIND_RE.search(text):
            raise PushRejectedError(
                "origin has vault commits this clone does not have; run `nbp-git-safe sync`, "
                "then push again (the tool never forces)"
            )
        if "push blocked" in text:
            raise vault.VaultError("the pre-push guard refused the vault branch")
        detail = " ".join(text.strip().splitlines()[:2])
        raise vault.VaultError(f"git push failed: {detail}")
    record_seen(repo, cfg.vault_ref, local)
    return local


def enable_auto_push(git: Git, repo: Repo, cfg: Config, remote: str = REMOTE) -> list[str]:
    """Make a plain ``git push`` carry the vault: set ``remote.<name>.push`` refspecs (the current
    branch, if none were configured, plus the vault branch). Records exactly what was added so
    that ``uninstall`` can remove only that. Returns the refspecs added."""
    key = f"remote.{remote}.push"
    out = git.try_run("config", "--local", "--get-all", key)
    existing = out.decode("utf-8", "replace").splitlines() if out else []
    vault_spec = f"{cfg.vault_ref}:{cfg.vault_ref}"
    wanted = ([] if existing else ["HEAD"]) + [vault_spec]
    added = [spec for spec in wanted if spec not in existing]
    for spec in added:
        git.run("config", "--local", "--add", key, spec)
    git.run("config", "--local", "nbp-safe.autoPush", "true")
    state = _read_autopush(repo)
    state.setdefault(remote, [])
    state[remote] = sorted(set(state[remote]) | set(added))
    repo.state_dir.mkdir(parents=True, exist_ok=True)
    (repo.state_dir / AUTOPUSH_FILE).write_bytes(json.dumps(state, sort_keys=True).encode("ascii"))
    return added


def _read_autopush(repo: Repo) -> dict[str, list[str]]:
    try:
        data = json.loads((repo.state_dir / AUTOPUSH_FILE).read_bytes().decode("ascii"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: [s for s in v if isinstance(s, str)] for k, v in data.items() if isinstance(v, list)}


def disable_auto_push(git: Git, repo: Repo) -> list[str]:
    """Remove the refspecs ``enable_auto_push`` added (and nothing else)."""
    removed: list[str] = []
    for remote, specs in _read_autopush(repo).items():
        for spec in specs:
            code, _, _ = git.run_status(
                "config", "--local", "--fixed-value", "--unset-all", f"remote.{remote}.push", spec
            )
            if code == 0:
                removed.append(spec)
    path = repo.state_dir / AUTOPUSH_FILE
    if path.exists():
        path.unlink()
        git.try_run("config", "--local", "--unset-all", "nbp-safe.autoPush")
    return removed


# ----------------------------------------------------------------------------- rotate


class KeySetBackend:
    """A ``vault.Backend`` over a ``KeySet`` held in this process. Used only to verify a rotated
    vault with the new key (the agent holds the OLD key); it is dropped right after."""

    def __init__(self, keys: crypto.KeySet) -> None:
        self._keys = keys

    def mac(self, data: bytes) -> bytes:
        return crypto.content_mac(self._keys, data)

    def enc_blob(self, file_id: str, data: bytes, bucket: int = crypto.DEFAULT_BUCKET) -> bytes:
        return crypto.encrypt_blob(self._keys, file_id, data, bucket)

    def dec_blob(self, file_id: str, blob: bytes) -> bytes:
        return crypto.decrypt_blob(self._keys, file_id, blob)

    def enc_index(self, index: dict[str, Any], bucket: int = crypto.DEFAULT_BUCKET) -> bytes:
        return crypto.encrypt_index(self._keys, index, bucket)

    def dec_index(self, blob: bytes) -> dict[str, Any]:
        return crypto.decrypt_index(self._keys, blob)

    def key_id(self) -> bytes:
        return self._keys.key_id


def _free_ref(git: Git, name: str) -> str:
    for n in range(1, 100):
        candidate = f"refs/heads/{name}" + ("" if n == 1 else f"-{n}")
        if not is_vault_ref(candidate):
            raise vault.VaultError("the new branch name must look like nbp-safe-<suffix>")
        if rev_parse(git, candidate) is None:
            return candidate
    raise vault.VaultError("could not find a free branch name for the rotated vault")


@dataclass
class RotateResult:
    ref: str
    tip: str
    files: int
    old_ref: str
    old_tip: str


def rotate(
    git: Git,
    repo: Repo,
    cfg: Config,
    backend: vault.Backend,
    new_master: bytes,
    *,
    name: str | None = None,
    now: float | None = None,
) -> RotateResult:
    """Re-encrypt the CURRENT state under ``new_master`` into a new orphan branch
    (``nbp-safe-<year>``): fresh file ids, MACs recomputed, no history. The old branch is not
    touched. The result is verified with the new key before returning."""
    state = vault.load_vault(git, backend, cfg)
    if state.tip is None:
        raise vault.VaultError("there is no vault to rotate")
    new_keys = crypto.KeySet(new_master)
    if new_keys.key_id.hex() == state.index.key_id:
        raise vault.VaultError("the new key is the same as the current one")
    year = time.gmtime(time.time() if now is None else now).tm_year
    ref = _free_ref(git, name or f"nbp-safe-{year}")
    blobs: dict[str, bytes] = {}
    entries: dict[str, Entry] = {}
    for old_id, entry in sorted(state.index.entries.items(), key=lambda kv: kv[1].path):
        _sha, plain = _verified_blob(git, backend, state, old_id, entry)
        new_id = crypto.new_file_id()
        blobs[new_id] = crypto.encrypt_blob(new_keys, new_id, plain, cfg.pad_bucket)
        entries[new_id] = Entry(
            entry.path,
            entry.mode,
            len(plain),
            crypto.content_mac(new_keys, plain).hex(),
            entry.created,
            entry.updated,
        )
        del plain
    new_index = Index(new_keys.key_id.hex(), entries, 1, "")  # a new lineage: seq 1, no prev
    commit = vault.build_commit(
        git,
        repo,
        ref=ref,
        parents=[],
        expect_old=None,
        base_tree=None,
        index_blob=crypto.encrypt_index(new_keys, new_index.to_dict(), cfg.pad_bucket),
        blobs=blobs,
        message=ROTATE_MESSAGE,
        granularity=cfg.time_granularity,
        now=now,
    )
    assert commit is not None
    check = KeySetBackend(new_keys)
    verified = vault.load_commit(git, check, commit)
    for fid, entry in verified.index.entries.items():
        _verified_blob(git, check, verified, fid, entry)
    vault.mark_verified(repo, ref, commit, verified.index.seq)
    return RotateResult(ref, commit, len(entries), cfg.vault_ref, state.tip)


def delete_old_vault(git: Git, old_ref: str, old_tip: str) -> None:
    """Delete the old local vault branch (compare-and-swap on its tip). Objects stay in the
    database until they are pruned."""
    git.run("update-ref", "-d", old_ref, old_tip)


# ------------------------------------------------------------------------------ purge


@dataclass
class PurgeResult:
    old_tip: str
    new_tip: str | None
    removed_ids: list[str]
    rewritten: int
    remote_tip: str | None


def _write_tree(git: Git, repo: Repo, files: Mapping[str, str]) -> str:
    tmp = repo.state_dir / f"{vault.TMP_INDEX_PREFIX}{secrets.token_hex(6)}"
    env = {"GIT_INDEX_FILE": str(tmp)}
    repo.state_dir.mkdir(parents=True, exist_ok=True)
    try:
        items = [f"100644,{sha},{path}" for path, sha in sorted(files.items())]
        for i in range(0, len(items), vault.UPDATE_INDEX_CHUNK):
            args = ["update-index", "--add"]
            for item in items[i : i + vault.UPDATE_INDEX_CHUNK]:
                args += ["--cacheinfo", item]
            git.run(*args, extra_env=env)
        return git.text("write-tree", extra_env=env).strip()
    finally:
        protect.cleanup_tmp(tmp)
        protect.cleanup_tmp(tmp.with_name(tmp.name + ".lock"))


def purge(
    git: Git,
    repo: Repo,
    cfg: Config,
    backend: vault.Backend,
    paths: Sequence[str],
) -> PurgeResult:
    """Rewrite the whole local vault history without the entries (blobs and index rows) that ever
    had one of ``paths``. Local only: the caller prints the force-push command for the owner."""
    tip = rev_parse(git, cfg.vault_ref + "^{commit}")
    if tip is None:
        raise vault.VaultError("there is no local vault branch")
    commits = git.text("rev-list", "--reverse", "--topo-order", "--parents", tip).splitlines()
    order: list[tuple[str, list[str]]] = []
    for line in commits:
        sha, *parents = line.split()
        order.append((sha, parents))
    wanted = {index_mod.normalize_path(p.replace("\\", "/")) for p in paths}
    states = {sha: vault.load_commit(git, backend, sha) for sha, _ in order}
    targets = sorted(
        {fid for st in states.values() for fid, e in st.index.entries.items() if e.path in wanted}
    )
    if not targets:
        raise vault.VaultError("no entry with that path exists anywhere in the vault history")
    target_set = set(targets)
    mapping: dict[str, str] = {}
    new_indexes: dict[str, Index] = {}  # rewritten commit -> its index
    new_files: dict[str, dict[str, str]] = {}  # rewritten commit -> its tree minus the index
    for sha, parents in order:
        state = states[sha]
        entries = {f: e for f, e in state.index.entries.items() if f not in target_set}
        files = {
            path: blob
            for path, blob in state.files.items()
            if not (
                path.startswith(vault.STORE_PREFIX)
                and path[len(vault.STORE_PREFIX) :] in target_set
            )
        }
        body = {path: blob for path, blob in files.items() if path != vault.INDEX_PATH}
        new_parents = list(dict.fromkeys(mapping[p] for p in parents))
        if len(new_parents) == 1:
            only = new_parents[0]
            if new_indexes[only].entries == entries and new_files[only] == body:
                mapping[sha] = only  # the commit only touched purged data: drop it
                continue
        first = new_indexes[mapping[parents[0]]] if parents else None
        new_idx = Index(
            state.index.key_id,
            entries,
            state.index.seq,
            first.digest() if first is not None else "",
        )
        index_blob = backend.enc_index(new_idx.to_dict(), cfg.pad_bucket)
        files[vault.INDEX_PATH] = hash_object(git, index_blob)
        tree = _write_tree(git, repo, files)
        stamp = git.text("show", "-s", "--format=%ct", sha).strip() + " +0000"
        message = git.text("show", "-s", "--format=%s", sha).strip() or vault.SEAL_MESSAGE
        env = {**vault.VAULT_IDENT, "GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp}
        args = ["-c", "commit.gpgsign=false", "commit-tree", tree, "-m", message]
        for parent in new_parents:
            args += ["-p", parent]
        created = git.text(*args, extra_env=env).strip()
        mapping[sha] = created
        new_indexes[created] = new_idx
        new_files[created] = body
    new_tip = mapping[tip]
    rewritten = len({v for v in mapping.values()})
    verified = vault.load_commit(git, backend, new_tip)
    leftovers = [
        fid
        for fid in targets
        if git.text("log", "--format=%H", new_tip, "--", f"{vault.STORE_PREFIX}{fid}").strip()
        or fid in verified.index.entries
    ]
    if leftovers:
        raise vault.VaultError("internal error: purged entries are still in the rewritten history")
    git.run("update-ref", "-m", "nbp-safe: purge", cfg.vault_ref, new_tip, tip)
    vault.mark_verified(repo, cfg.vault_ref, new_tip, verified.index.seq, reset=True)
    markers = read_purge_marker(repo)
    markers[cfg.vault_ref] = tip
    _write_purge_marker(repo, markers)
    remote_tip = rev_parse(git, cfg.remote_vault_ref + "^{commit}")
    return PurgeResult(tip, new_tip, targets, rewritten, remote_tip)


def purge_instructions(cfg: Config, result: PurgeResult) -> list[str]:
    """What the OWNER must run to finish (the tool never force-pushes and never prunes)."""
    ref = cfg.vault_ref
    lines = []
    if result.remote_tip is not None:
        lines.append(f"git push --force-with-lease={ref}:{result.remote_tip} {REMOTE} {ref}:{ref}")
    # the remote-tracking ref (updated by the forced push) has a reflog of the old tips as well
    lines.append(f"git reflog expire --expire=now {ref} {cfg.remote_vault_ref}")
    lines.append(
        "git gc --prune=now   # repacks and removes ALL unreachable objects, loose or packed"
    )
    return lines
