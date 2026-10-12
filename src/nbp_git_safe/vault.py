# SPDX-License-Identifier: MIT
"""The vault: an orphan branch (``refs/heads/nbp-safe``) built only with git plumbing.

No worktree is used and neither the index nor the working tree of the main branch is touched:

1. ciphertext -> ``git hash-object -w --stdin --no-filters``
2. ``GIT_INDEX_FILE=<tmp> git update-index --add --cacheinfo 100644,<sha>,store/<id>``,
   ``git write-tree``, ``git commit-tree -p <parent>``
3. ``git update-ref <ref> <new> <old>`` (compare-and-swap)

The branch contains only ``.gitattributes``, a fixed generic ``README.md``, ``nbp-safe/index``
(encrypted) and ``store/<32 hex>`` (encrypted blobs). Plain text and real names never enter the
object database. All cryptography goes through a ``Backend`` (the key agent); this module never
holds a key.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import secrets
import stat
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Protocol

from nbp_git_safe import crypto, protect
from nbp_git_safe import index as index_mod
from nbp_git_safe.config import Config
from nbp_git_safe.gitutil import (
    Git,
    GitError,
    Repo,
    chunked,
    hash_objects,
    is_ancestor,
    rev_parse,
)
from nbp_git_safe.index import Entry, Index, IndexValidationError, normalize_path, validate_path
from nbp_git_safe.statcache import StatCache, path_key_input

SEAL_MESSAGE = "nbp-safe: seal"
GITATTRIBUTES = b"* -text -diff -merge\n"
README = (
    b"# nbp-safe\n\n"
    b"This branch holds encrypted data managed by nbp-git-safe.\n"
    b"Its content is opaque without the key.\n"
)
INDEX_PATH = "nbp-safe/index"
STORE_PREFIX = "store/"
_STORE_RE = re.compile(r"^store/[0-9a-f]{32}$")
_FIXED_PATHS = {".gitattributes", "README.md", INDEX_PATH}
VAULT_IDENT = {
    "GIT_AUTHOR_NAME": "nbp-safe",
    "GIT_AUTHOR_EMAIL": "nbp-safe@localhost.invalid",
    "GIT_COMMITTER_NAME": "nbp-safe",
    "GIT_COMMITTER_EMAIL": "nbp-safe@localhost.invalid",
}
TMP_INDEX_PREFIX = "index.tmp-"
UPDATE_INDEX_CHUNK = 50


class VaultError(Exception):
    """Operational problem with the vault."""


class VaultConflictError(VaultError):
    """The vault ref moved while sealing (compare-and-swap lost). Nothing was changed."""


class VaultTamperError(VaultError):
    """The vault does not have the expected shape or its content failed verification."""


class VaultRollbackError(VaultTamperError):
    """The vault went back in time or its history was replaced (a rollback, a replay of an older
    index, or a chain that does not link up)."""


class VerifiedStateError(VaultError):
    """``vault-seq.json`` (the record of the vault tips this clone has verified) exists but cannot
    be read. It is never read as "nothing verified": that would let an attacker who can damage
    one local file turn a rollback check into a first adoption."""


class AdoptionRequiredError(VaultError):
    """The clone has never verified this vault branch (a fresh clone, a ref chosen by
    configuration, a lost record). Trust on first use: the tip is authentic (it verifies under
    the key) but nothing here can say it is the NEWEST one, so the owner confirms it."""


class Backend(Protocol):
    """What the vault needs from the key agent (``agent.AgentClient`` implements it)."""

    def mac(self, data: bytes) -> bytes: ...
    def enc_blob(self, file_id: str, data: bytes, bucket: int = ...) -> bytes: ...
    def dec_blob(self, file_id: str, blob: bytes) -> bytes: ...
    def enc_index(self, index: dict[str, Any], bucket: int = ...) -> bytes: ...
    def dec_index(self, blob: bytes) -> dict[str, Any]: ...
    def key_id(self) -> bytes: ...


def round_time(now: float, granularity: int) -> int:
    return int(now) // granularity * granularity


# ------------------------------------------------------------------------ loading


@dataclass
class VaultState:
    tip: str | None
    tree: str | None
    files: dict[str, str]  # path inside the vault tree -> blob sha
    index: Index


def _parse_ls_tree(out: bytes) -> dict[str, str]:
    files: dict[str, str] = {}
    for record in out.split(b"\0"):
        if not record:
            continue
        meta, _, path_b = record.partition(b"\t")
        parts = meta.split(b" ")
        if len(parts) != 3 or parts[0] != b"100644" or parts[1] != b"blob":
            raise VaultTamperError("vault tree contains an unexpected object")
        path = path_b.decode("utf-8", "surrogateescape")
        if path not in _FIXED_PATHS and not _STORE_RE.match(path):
            raise VaultTamperError("vault tree contains an unexpected path")
        files[path] = parts[2].decode("ascii")
    return files


def _expected_sha(git: Git, content: bytes) -> str:
    return git.text("hash-object", "--stdin", "--no-filters", input=content).strip()


def resolve_tip(git: Git, cfg: Config, *, use_remote_fallback: bool) -> str | None:
    tip = rev_parse(git, cfg.vault_ref + "^{commit}")
    if tip is None and use_remote_fallback:
        tip = rev_parse(git, cfg.remote_vault_ref + "^{commit}")
    return tip


def load_vault(
    git: Git, backend: Backend, cfg: Config, *, use_remote_fallback: bool = False
) -> VaultState:
    """Read, authenticate and validate the vault tip (empty state if there is no vault)."""
    key_id = backend.key_id()
    tip = resolve_tip(git, cfg, use_remote_fallback=use_remote_fallback)
    if tip is None:
        if not use_remote_fallback and rev_parse(git, cfg.remote_vault_ref + "^{commit}"):
            raise VaultError(
                "a vault exists on origin but there is no local branch; create it with "
                f"`git branch {cfg.vault_ref.removeprefix('refs/heads/')} "
                f"{cfg.remote_vault_ref.removeprefix('refs/remotes/')}`"
            )
        return VaultState(None, None, {}, Index.empty(key_id))
    return load_commit(git, backend, tip)


def load_commit(git: Git, backend: Backend, commit: str) -> VaultState:
    tree = rev_parse(git, commit + "^{tree}")
    if tree is None:
        raise VaultTamperError("vault commit has no tree")
    files = _parse_ls_tree(git.run("ls-tree", "-r", "-z", tree))
    if not files.keys() >= _FIXED_PATHS:
        raise VaultTamperError("vault tree is incomplete")
    if files[".gitattributes"] != _expected_sha(git, GITATTRIBUTES):
        raise VaultTamperError("vault .gitattributes is not the expected one")
    if files["README.md"] != _expected_sha(git, README):
        raise VaultTamperError("vault README is not the expected one")
    blob = git.run("cat-file", "blob", files[INDEX_PATH])
    try:
        parsed = Index.from_dict(backend.dec_index(blob), backend.key_id())
    except IndexValidationError:
        raise VaultTamperError("vault index failed validation") from None
    stored = {path for path in files if path.startswith(STORE_PREFIX)}
    if stored - {STORE_PREFIX + fid for fid in parsed.entries}:
        # the tree must be exactly what the authenticated index describes (THREAT_MODEL.md):
        # a blob nobody references is never "harmless padding" a writer without the key may add
        raise VaultTamperError("vault tree has store blobs the index does not reference")
    return VaultState(commit, tree, files, parsed)


# ----------------------------------------------------------------------- scanning


@dataclass
class Observed:
    fs_path: str
    size: int
    mode: str
    mac: str | None  # None: present but not sealable right now (too large, not a regular file)
    note: str = ""


@dataclass
class Analysis:
    state: VaultState
    entries: dict[str, Entry]
    observed: dict[str, Observed]
    new: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)
    mode_only: list[str] = field(default_factory=list)
    moved: list[tuple[str, str]] = field(default_factory=list)  # (old path, new path)
    missing: list[str] = field(default_factory=list)
    removed_ids: list[str] = field(default_factory=list)  # explicit `rm`
    forgotten: list[str] = field(default_factory=list)  # paths of the explicit removals
    renamed: list[tuple[str, str]] = field(default_factory=list)  # explicit `mv`
    refused: list[tuple[str, str]] = field(default_factory=list)  # (path, reason)
    warnings: list[str] = field(default_factory=list)


def _is_link_like(path: str | Path) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(st, "st_file_attributes", 0) & 0x400)  # Windows reparse point


def _mode_of(st: os.stat_result, previous: str | None) -> str:
    if sys.platform == "win32":
        return previous or "100644"
    return "100755" if st.st_mode & 0o111 else "100644"


def _observe(
    repo: Repo,
    backend: Backend,
    cache: StatCache,
    entries_by_path: Mapping[str, Entry],
    protected: list[str],
    refused: list[tuple[str, str]],
) -> dict[str, Observed]:
    observed: dict[str, Observed] = {}
    for fs_rel in protected:
        path = normalize_path(fs_rel)
        try:
            validate_path(path)
        except IndexValidationError:
            refused.append((fs_rel, "path is not allowed in a vault"))
            continue
        full = repo.toplevel / fs_rel
        try:
            st = os.lstat(full)
        except OSError:
            continue  # vanished while scanning
        prev = entries_by_path.get(path)
        if _is_link_like(full) or not stat.S_ISREG(st.st_mode):
            observed[path] = Observed(fs_rel, st.st_size, "100644", None, "not a regular file")
            refused.append((fs_rel, "not a regular file (symlinks are never followed)"))
            continue
        mode = _mode_of(st, prev.mode if prev else None)
        if st.st_size > crypto.MAX_DATA_SIZE:
            observed[path] = Observed(fs_rel, st.st_size, mode, None, "too large")
            refused.append((fs_rel, "file is larger than the 64 MiB limit"))
            continue
        key = backend.mac(path_key_input(path)).hex()
        mac = cache.get(key, st.st_size, st.st_mtime_ns)
        if mac is None:
            try:
                data = full.read_bytes()
            except OSError:
                continue
            mac = backend.mac(data).hex()
            st_after = os.lstat(full)
            if (st_after.st_size, st_after.st_mtime_ns) == (st.st_size, st.st_mtime_ns):
                cache.put(key, st.st_size, st.st_mtime_ns, mac, time.time_ns())
        observed[path] = Observed(fs_rel, st.st_size, mode, mac)
    try:
        index_mod.check_collisions(observed)
    except IndexValidationError:
        raise VaultError("protected files collide on case-insensitive filesystems") from None
    return observed


def analyze(
    git: Git,
    repo: Repo,
    cfg: Config,
    backend: Backend,
    state: VaultState,
    *,
    renames: Mapping[str, str] | None = None,
    forget: frozenset[str] = frozenset(),
) -> Analysis:
    """Compare the working tree with the vault index (no writes except the stat cache)."""
    entries = dict(state.index.entries)
    removed_ids: list[str] = []
    forgotten: list[str] = []
    renamed: list[tuple[str, str]] = []
    by_path = {e.path: fid for fid, e in entries.items()}
    for old, new in (renames or {}).items():
        old_n, new_n = normalize_path(old), normalize_path(new)
        fid = by_path.get(old_n)
        if fid is None:
            raise VaultError("the source path is not in the vault")
        try:
            validate_path(new_n)
        except IndexValidationError as exc:
            raise VaultError(str(exc)) from None
        if new_n in by_path:
            raise VaultError("the destination path is already in the vault")
        if new_n not in protect.match_paths(git, repo, [new_n]):
            raise VaultError("the destination path is not in the protected set")
        entries[fid] = replace(entries[fid], path=new_n)
        renamed.append((old_n, new_n))
        by_path.pop(old_n)
        by_path[new_n] = fid
    for path in forget:
        fid = by_path.pop(normalize_path(path), None)
        if fid is None:
            raise VaultError("the path is not in the vault")
        entries.pop(fid)
        removed_ids.append(fid)
        forgotten.append(normalize_path(path))

    protected = [p for p in protect.list_protected(git, repo) if normalize_path(p) not in forget]
    cache = StatCache(repo.state_dir / "statcache", backend.key_id().hex())
    refused: list[tuple[str, str]] = []
    warnings: list[str] = []
    observed = _observe(
        repo, backend, cache, {e.path: e for e in entries.values()}, protected, refused
    )
    cache.save()

    result = Analysis(
        state,
        entries,
        observed,
        removed_ids=removed_ids,
        forgotten=forgotten,
        renamed=renamed,
        refused=refused,
    )
    result.warnings = warnings
    tracked = protect.tracked_matches(git, repo)
    if tracked:
        result.warnings.append(
            f"{len(tracked)} file(s) matching the protected patterns are tracked on the main "
            "branch and were NOT sealed; untrack them with `git rm --cached` (history may "
            "already contain them)"
        )
    for path, obs in sorted(observed.items()):
        fid = by_path.get(path)
        if fid is None:
            if obs.mac is not None:
                result.new.append(path)
        elif obs.mac is not None:
            if obs.mac != entries[fid].mac:
                result.changed.append(path)
            elif obs.mode != entries[fid].mode:
                result.mode_only.append(path)
    missing = sorted(p for p in by_path if p not in observed)

    # move detection: the vanished path and the new path share the content MAC, unambiguously
    gone_by_mac: dict[str, list[str]] = {}
    for path in missing:
        gone_by_mac.setdefault(entries[by_path[path]].mac, []).append(path)
    new_by_mac: dict[str, list[str]] = {}
    for path in result.new:
        mac = observed[path].mac
        assert mac is not None
        new_by_mac.setdefault(mac, []).append(path)
    for mac, gone in gone_by_mac.items():
        arrived = new_by_mac.get(mac, [])
        if len(gone) == 1 and len(arrived) == 1:
            result.moved.append((gone[0], arrived[0]))
    moved_old = {old for old, _ in result.moved}
    moved_new = {new for _, new in result.moved}
    result.new = [p for p in result.new if p not in moved_new]
    result.missing = [p for p in missing if p not in moved_old]
    result.moved.sort()

    if result.missing and cfg.on_missing == "keep":
        result.warnings.append(
            f"{len(result.missing)} sealed file(s) are missing from the working tree "
            "and were kept in the vault (onMissing=keep)"
        )
    return result


# ------------------------------------------------------------------------ sealing


@dataclass
class SealPlan:
    ref: str
    parent: str | None
    parent_tree: str | None
    blobs: dict[str, bytes]  # file id -> ciphertext
    remove_ids: list[str]
    index_blob: bytes
    analysis: Analysis
    new_index: Index
    removed_paths: list[str] = field(default_factory=list)


def _read(path: Path) -> bytes | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return data if len(data) <= crypto.MAX_DATA_SIZE else None


def plan_seal(
    repo: Repo,
    cfg: Config,
    backend: Backend,
    analysis: Analysis,
    *,
    now: float | None = None,
    ask: Callable[[str], bool] | None = None,
) -> SealPlan | None:
    """Do all cryptography first. Returns ``None`` when there is nothing to seal."""
    ts = round_time(time.time() if now is None else now, cfg.time_granularity)
    state = analysis.state
    entries = dict(analysis.entries)
    by_path = {e.path: fid for fid, e in entries.items()}
    blobs: dict[str, bytes] = {}
    remove_ids = list(analysis.removed_ids)
    removed_paths: list[str] = []

    for old, new in analysis.moved:
        fid = by_path[old]
        obs = analysis.observed[new]
        entries[fid] = replace(entries[fid], path=new, mode=obs.mode, updated=ts)
        by_path.pop(old)
        by_path[new] = fid

    for path in analysis.mode_only:
        fid = by_path[path]
        entries[fid] = replace(entries[fid], mode=analysis.observed[path].mode, updated=ts)

    def seal_file(fid: str, path: str, created: int) -> Entry | None:
        obs = analysis.observed[path]
        data = _read(repo.toplevel / obs.fs_path)
        if data is None:
            return None
        blobs[fid] = backend.enc_blob(fid, data, cfg.pad_bucket)
        return Entry(
            path=path,
            mode=obs.mode,
            size=len(data),
            mac=backend.mac(data).hex(),
            created=created,
            updated=ts,
        )

    for path in analysis.changed:
        fid = by_path[path]
        entry = seal_file(fid, path, entries[fid].created)
        if entry is not None:
            entries[fid] = entry
    for path in analysis.new:
        fid = crypto.new_file_id()
        entry = seal_file(fid, path, ts)
        if entry is not None:
            entries[fid] = entry

    if cfg.on_missing in ("remove", "ask"):
        for path in analysis.missing:
            if cfg.on_missing == "ask" and (ask is None or not ask(path)):
                continue
            fid = by_path[path]
            entries.pop(fid)
            remove_ids.append(fid)
            removed_paths.append(path)
    removed_paths.extend(analysis.forgotten)

    if state.tip is not None and entries == state.index.entries:
        return None
    if state.tip is None and not entries:
        return None
    new_index = state.index.successor(entries)
    return SealPlan(
        ref=cfg.vault_ref,
        parent=state.tip,
        parent_tree=state.tree,
        blobs=blobs,
        remove_ids=remove_ids,
        index_blob=backend.enc_index(new_index.to_dict(), cfg.pad_bucket),
        analysis=analysis,
        new_index=new_index,
        removed_paths=removed_paths,
    )


def build_commit(
    git: Git,
    repo: Repo,
    *,
    ref: str,
    parents: Sequence[str],
    expect_old: str | None,
    base_tree: str | None,
    index_blob: bytes,
    blobs: Mapping[str, bytes] | None = None,
    blob_shas: Mapping[str, str] | None = None,
    remove_ids: Sequence[str] = (),
    message: str = SEAL_MESSAGE,
    granularity: int = 3600,
    now: float | None = None,
    date: int | None = None,
) -> str | None:
    """Build a vault commit with plumbing; move ``ref`` from ``expect_old`` with compare-and-swap.

    The tree starts from ``base_tree`` (or empty), gets the fixed files, the new index and the
    blobs (``blobs``: ciphertext to write; ``blob_shas``: objects already in the database), and
    loses ``remove_ids``. ``date`` pins the commit time (history rewriting); otherwise ``now``
    rounded down to ``granularity``. Returns the new commit id, or ``None`` when the resulting
    tree equals ``base_tree`` and the commit would have at most one parent (the deterministic
    encryption makes identical content produce an identical tree)."""
    repo.state_dir.mkdir(parents=True, exist_ok=True)
    tmp_index = repo.state_dir / f"{TMP_INDEX_PREFIX}{secrets.token_hex(6)}"
    env = {"GIT_INDEX_FILE": str(tmp_index)}
    try:
        if base_tree is not None:
            git.run("read-tree", base_tree, extra_env=env)
        written = sorted((blobs or {}).items())
        shas = hash_objects(git, [GITATTRIBUTES, README, index_blob, *(b for _, b in written)])
        cacheinfo: list[str] = [
            f"100644,{shas[0]},.gitattributes",
            f"100644,{shas[1]},README.md",
            f"100644,{shas[2]},{INDEX_PATH}",
        ]
        for (fid, _blob), sha in zip(written, shas[3:], strict=True):
            cacheinfo.append(f"100644,{sha},{STORE_PREFIX}{fid}")
        for fid, sha in sorted((blob_shas or {}).items()):
            cacheinfo.append(f"100644,{sha},{STORE_PREFIX}{fid}")
        for chunk in chunked(cacheinfo, UPDATE_INDEX_CHUNK):
            args = ["update-index", "--add"]
            for item in chunk:
                args += ["--cacheinfo", item]
            git.run(*args, extra_env=env)
        for chunk in chunked([f"{STORE_PREFIX}{fid}" for fid in remove_ids], 100):
            git.run("update-index", "--force-remove", "--", *chunk, extra_env=env)
        tree = git.text("write-tree", extra_env=env).strip()
        if base_tree is not None and tree == base_tree and len(parents) <= 1:
            return None
        ts = (
            date
            if date is not None
            else round_time(time.time() if now is None else now, granularity)
        )
        stamp = f"{ts} +0000"
        commit_env = {**VAULT_IDENT, "GIT_AUTHOR_DATE": stamp, "GIT_COMMITTER_DATE": stamp}
        args = ["-c", "commit.gpgsign=false", "commit-tree", tree, "-m", message]
        for parent in parents:
            args += ["-p", parent]
        commit = git.text(*args, extra_env=commit_env).strip()
        old = expect_old if expect_old is not None else "0" * len(commit)
        try:
            git.run("update-ref", "-m", message, ref, commit, old, extra_env=commit_env)
        except GitError:
            raise VaultConflictError(
                "the vault changed while sealing (or the ref could not be updated); "
                "nothing was changed, run `seal` again"
            ) from None
        return commit
    finally:
        protect.cleanup_tmp(tmp_index)
        protect.cleanup_tmp(tmp_index.with_name(tmp_index.name + ".lock"))


def commit_plan(
    git: Git, repo: Repo, plan: SealPlan, cfg: Config, *, now: float | None = None
) -> str | None:
    """Commit a seal plan (see ``build_commit``)."""
    return build_commit(
        git,
        repo,
        ref=plan.ref,
        parents=[plan.parent] if plan.parent is not None else [],
        expect_old=plan.parent,
        base_tree=plan.parent_tree,
        index_blob=plan.index_blob,
        blobs=plan.blobs,
        remove_ids=plan.remove_ids,
        granularity=cfg.time_granularity,
        now=now,
    )


def seal(
    git: Git,
    repo: Repo,
    cfg: Config,
    backend: Backend,
    *,
    renames: Mapping[str, str] | None = None,
    forget: frozenset[str] = frozenset(),
    ask: Callable[[str], bool] | None = None,
    now: float | None = None,
    allow_replaced: bool = False,
) -> tuple[str | None, Analysis, SealPlan | None]:
    """Seal the protected files. Returns ``(commit or None, analysis, plan or None)``. A branch
    that is behind the verified record is refused unless ``allow_replaced`` (the caller adopts a
    replaced history on purpose)."""
    read_verified(repo)  # a damaged record stops here, before anything is written
    protect.install_exclude_block(repo)
    state = load_vault(git, backend, cfg)
    if state.tip is not None:  # never build on a branch that went back (a child would launder it)
        ensure_not_behind(git, repo, cfg.vault_ref, state.tip, allow_replaced=allow_replaced)
    analysis = analyze(git, repo, cfg, backend, state, renames=renames, forget=forget)
    plan = plan_seal(repo, cfg, backend, analysis, now=now, ask=ask)
    if plan is None:
        return None, analysis, None
    commit = commit_plan(git, repo, plan, cfg, now=now)
    if commit is not None and _was_verified(repo, plan.ref, plan.parent):
        mark_verified(repo, plan.ref, commit, plan.new_index.seq)  # our own child of a good tip
    return commit, analysis, plan


# -------------------------------------------------------------- the index chain (rollback)

VERIFIED_FILE = "vault-seq.json"
_SHA_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")


def _verified_path(repo: Repo) -> Path:
    return repo.state_dir / VERIFIED_FILE


def read_verified(repo: Repo, *, strict: bool = True) -> dict[str, tuple[str, int]]:
    """``{vault ref: (tip, seq)}`` of the newest vault tip whose whole chain this clone has
    verified. Commit ids and numbers only: no names, nothing secret. An absent file is an empty
    record (a clone that never verified anything); a file that exists but is unreadable or
    malformed raises ``VerifiedStateError`` (``strict=False``: only for an explicit, confirmed
    re-adoption, which writes the file again)."""
    path = _verified_path(repo)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return {}
    except OSError:
        raw = None
    out: dict[str, tuple[str, int]] = {}
    problem = False
    try:
        if raw is None:
            raise ValueError("unreadable")
        data = json.loads(raw.decode("ascii"))
        refs = data.get("refs") if isinstance(data, dict) else None
        if not isinstance(refs, dict):
            raise ValueError("no refs")
        for ref, item in refs.items():
            tip, seq = item.get("tip"), item.get("seq")
            if not (isinstance(tip, str) and _SHA_RE.match(tip) and isinstance(seq, int)):
                raise ValueError("bad entry")
            out[str(ref)] = (tip, seq)
    except (ValueError, AttributeError):
        problem = True
    if problem:
        if strict:
            raise VerifiedStateError(
                f"{VERIFIED_FILE} (the record of the vault tips this clone verified) is "
                "unreadable, so no rollback check can be trusted; compare the vault's key id and "
                "seq with another machine (`status`), then re-adopt it with "
                "--confirm-first-adopt (or delete the file)"
            )
        return {}
    return out


def mark_verified(repo: Repo, ref: str, tip: str, seq: int, *, reset: bool = False) -> None:
    """Remember ``tip`` as verified. The recorded number only goes up, unless ``reset`` (an
    explicit adoption of a replaced history: purge, ``--accept-remote-rewrite``)."""
    known = read_verified(repo, strict=not reset)
    if not reset and ref in known and known[ref][1] > seq:
        return
    known[ref] = (tip, seq)
    path = _verified_path(repo)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{VERIFIED_FILE}.{secrets.token_hex(4)}.tmp")
    payload = {"refs": {r: {"tip": t, "seq": n} for r, (t, n) in sorted(known.items())}}
    with open(tmp, "wb") as handle:
        handle.write(json.dumps(payload, sort_keys=True).encode("ascii"))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def _was_verified(repo: Repo, ref: str, tip: str | None) -> bool:
    """Is ``tip`` the verified tip of ``ref`` (a root, ``None``, starts a chain of our own)?"""
    if tip is None:
        return ref not in read_verified(repo)
    return read_verified(repo).get(ref, ("", 0))[0] == tip


def verify_chain(git: Git, backend: Backend, tip: str, *, trusted: str | None = None) -> int:
    """Check the index chain of every commit reachable from ``tip`` (or, with ``trusted``, only
    those that are not reachable from that already verified tip). The index of each commit is
    authenticated (it needs the key, so only the owner can have written it) and must say:

    * ``seq`` strictly greater than the ``seq`` of every parent, ``prev`` equal to the digest of
      the first parent's index; a root commit has ``prev == ""``.

    A commit that replays an older tree under a newer parent (the fast-forward rollback an
    attacker with push access can make without the key) fails the first rule. Returns the ``seq``
    of ``tip``."""
    args = ["rev-list", "--reverse", "--topo-order", "--parents", tip]
    if trusted is not None:
        args += ["--not", trusted]
    rows = [line.split() for line in git.text(*args).splitlines() if line.strip()]
    indexes: dict[str, Index] = {}

    def index_of(commit: str) -> Index:
        if commit not in indexes:
            indexes[commit] = load_commit(git, backend, commit).index
        return indexes[commit]

    for commit, *parents in rows:
        idx = index_of(commit)
        if not parents:
            if idx.prev != "":
                raise VaultRollbackError("a root vault commit must not link to an earlier index")
            continue
        parent_indexes = [index_of(p) for p in parents]
        if idx.seq <= max(p.seq for p in parent_indexes):
            raise VaultRollbackError(
                "the vault index is older than its parent's (a rollback or a replay)"
            )
        if idx.prev != parent_indexes[0].digest():
            raise VaultRollbackError("the vault index does not link to its parent's index")
    return index_of(tip).seq


def ensure_not_behind(
    git: Git, repo: Repo, ref: str, tip: str, *, allow_replaced: bool = False
) -> None:
    """Refuse a ``tip`` that is behind, or does not descend from, the newest tip this clone
    verified for ``ref`` (keyless: it only compares commit ids). Without a record there is nothing
    to compare. ``allow_replaced``: the caller adopts a replaced history on purpose."""
    known = read_verified(repo).get(ref)
    if known is None or known[0] == tip or is_ancestor(git, known[0], tip) or allow_replaced:
        return
    if is_ancestor(git, tip, known[0]):
        raise VaultRollbackError("the vault is behind a state this clone has verified")
    raise VaultRollbackError("the vault history was replaced (it does not descend from it)")


def adoption_message(git: Git, backend: Backend, ref: str, tip: str, seq: int) -> str:
    """What the owner needs to decide on a first adoption: the key id the vault was written with,
    its ``seq`` and the tip. Compare them with ``status`` on a machine that already has the vault
    (the same key id, a ``seq`` at least as high as anything seen there)."""
    key_id = load_commit(git, backend, tip).index.key_id
    return (
        f"this clone has never verified {ref.removeprefix('refs/heads/')}: its tip {tip[:10]} "
        f"verifies under the unlocked key (key id {key_id}, seq {seq}) but nothing here can say "
        "it is the newest one (an older, authentic tip would look the same). Compare these "
        "values with another machine's `status`, then repeat the command with "
        "--confirm-first-adopt"
    )


def check_chain(
    git: Git,
    backend: Backend,
    repo: Repo,
    ref: str,
    tip: str,
    *,
    allow_replaced: bool = False,
    adopt: bool = False,
) -> int:
    """Verify ``tip`` against what this clone has verified before. A branch it has never verified
    is only adopted with ``adopt`` (trust on first use: ``AdoptionRequiredError`` says which key,
    which ``seq`` and which tip, for the owner to compare with another machine). A tip that is
    behind, or that does not descend from, the verified one is a rollback / replaced history and
    is refused (``allow_replaced``: the caller is adopting such a history on purpose and calls
    ``mark_verified(..., reset=True)`` afterwards). Returns the ``seq`` of ``tip``. Records
    nothing."""
    known = read_verified(repo, strict=not adopt).get(ref)
    if known is None:
        seq = verify_chain(git, backend, tip)
        if not adopt:
            raise AdoptionRequiredError(adoption_message(git, backend, ref, tip, seq))
        return seq
    trusted: str | None = None
    if known[0] == tip:
        return known[1]
    if is_ancestor(git, tip, known[0]):
        if not allow_replaced:
            raise VaultRollbackError("the vault is behind a state this clone has verified")
    elif is_ancestor(git, known[0], tip):
        trusted = known[0]
    elif not allow_replaced:
        raise VaultRollbackError("the vault history was replaced (it does not descend from it)")
    return verify_chain(git, backend, tip, trusted=trusted)


# ------------------------------------------------------------------------- opening


@dataclass
class OpenResult:
    written: list[str] = field(default_factory=list)
    unchanged: int = 0
    theirs: list[str] = field(default_factory=list)  # local files that diverged
    errors: list[str] = field(default_factory=list)


def _target_problem(toplevel: Path, rel: str) -> str | None:
    """Reason a write to ``rel`` is unsafe (symlink/junction in the way, directory, file as dir)."""
    current = toplevel
    parts = rel.split("/")
    for i, part in enumerate(parts):
        current = current / part
        if not os.path.lexists(current):
            return None
        if _is_link_like(current):
            return "a symbolic link or junction is in the way"
        last = i == len(parts) - 1
        if last and current.is_dir():
            return "a directory is in the way"
        if not last and not current.is_dir():
            return "a file is in the way of a parent directory"
    return None


TMP_SUFFIX = ".nbp-tmp"


def _atomic_write(toplevel: Path, rel: str, data: bytes, mode: str) -> None:
    """Write ``rel`` (relative to ``toplevel``) through a temporary file in the same directory.

    The destination and every directory on the way are checked for links, junctions and reparse
    points before the directories are created, after, and once more right before the final
    rename; the temporary file has a random name and is created with ``O_EXCL`` (and
    ``O_NOFOLLOW`` where it exists), so a link planted at a guessed name is never opened. The data
    is flushed to disk before the rename. Raises ``OSError`` when anything is in the way."""
    if _target_problem(toplevel, rel):
        raise OSError("blocked")
    target = toplevel / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    if _target_problem(toplevel, rel):
        raise OSError("blocked")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    for _ in range(8):
        tmp = target.with_name(f".{secrets.token_hex(6)}{TMP_SUFFIX}")
        try:
            fd = os.open(tmp, flags, 0o666)
        except FileExistsError:
            continue
        break
    else:
        raise OSError("no free temporary name")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if sys.platform != "win32" and mode == "100755":
            os.chmod(tmp, 0o755)  # noqa: S103 - executable bit of a sealed script
        if _target_problem(toplevel, rel):
            raise OSError("blocked")
        os.replace(tmp, target)
    except BaseException:
        protect.cleanup_tmp(tmp)
        raise


def open_vault(
    git: Git,
    repo: Repo,
    cfg: Config,
    backend: Backend,
    known_macs: Mapping[str, frozenset[str]] | None = None,
    *,
    adopt: bool = False,
) -> OpenResult:
    """Materialize the vault at the real paths. Never overwrites diverging local plaintext.

    ``known_macs`` (``path -> content MACs of versions this clone has already sealed``, given by
    ``sync``) lets a local file that still equals an OLDER vault version be updated in place: it
    has no local edits, so it is not "diverging".

    Everything is authenticated and validated before the first byte is written; a failure at
    that stage aborts with nothing written. A vault branch this clone has never verified is
    opened only with ``adopt`` (``--confirm-first-adopt``): see ``check_chain``."""
    state = load_vault(git, backend, cfg, use_remote_fallback=True)
    if state.tip is None:
        raise VaultError("no vault found (branch nbp-safe does not exist)")
    first = adopt and cfg.vault_ref not in read_verified(repo, strict=False)
    seq = check_chain(git, backend, repo, cfg.vault_ref, state.tip, adopt=adopt)
    mark_verified(repo, cfg.vault_ref, state.tip, seq, reset=first)
    protect.install_exclude_block(repo)
    idx = state.index
    try:
        index_mod.validate_against_protected(
            idx,
            lambda paths: protect.match_paths(git, repo, paths),
            protect.tracked_files(git),
        )
    except IndexValidationError as exc:
        raise VaultTamperError(str(exc)) from None
    for fid in idx.entries:
        if STORE_PREFIX + fid not in state.files:
            raise VaultTamperError("the vault is missing a blob referenced by the index")

    cache = StatCache(repo.state_dir / "statcache", backend.key_id().hex())
    result = OpenResult()
    pending: dict[str, tuple[Entry, bytes, bool]] = {}  # fid -> (entry, plaintext, diverged)
    for fid, entry in sorted(idx.entries.items(), key=lambda kv: kv[1].path):
        problem = _target_problem(repo.toplevel, entry.path)
        if problem:
            result.errors.append(f"{entry.path}: {problem}")
            continue
        local = repo.toplevel / entry.path
        diverged = False
        if local.exists():
            st = os.lstat(local)
            stale = known_macs.get(entry.path, frozenset()) if known_macs else frozenset()
            diverged = True
            if st.st_size == entry.size or stale:
                data = _read(local)
                local_mac = backend.mac(data).hex() if data is not None else None
                if local_mac == entry.mac:
                    result.unchanged += 1
                    continue
                diverged = local_mac not in stale  # an older sealed version: no local edits
        blob = git.run("cat-file", "blob", state.files[STORE_PREFIX + fid])
        plain = backend.dec_blob(fid, blob)  # raises on tampering / wrong key: nothing written yet
        if backend.mac(plain).hex() != entry.mac or len(plain) != entry.size:
            raise VaultTamperError("a vault blob does not match the authenticated index")
        pending[fid] = (entry, plain, diverged)

    for fid in list(pending):
        entry, plain, diverged = pending.pop(fid)
        rel = entry.path + (".nbp-theirs" if diverged else "")
        target = repo.toplevel / rel
        try:
            if diverged and target.exists() and _read(target) == plain:
                result.theirs.append(rel)
                continue
            _atomic_write(repo.toplevel, rel, plain, entry.mode)
        except OSError:
            result.errors.append(f"{rel}: could not be written")
            continue
        if diverged:
            result.theirs.append(rel)
        else:
            result.written.append(entry.path)
            st = os.lstat(target)
            key = backend.mac(path_key_input(entry.path)).hex()
            cache.put(key, st.st_size, st.st_mtime_ns, entry.mac, time.time_ns())
    cache.save()
    return result


# ------------------------------------------------------------ read-only commands


def status_summary(analysis: Analysis) -> dict[str, list[Any]]:
    return {
        "new": analysis.new,
        "changed": analysis.changed,
        "moved": [f"{a} -> {b}" for a, b in analysis.moved],
        "missing": analysis.missing,
        "mode": analysis.mode_only,
        "refused": [p for p, _ in analysis.refused],
    }


def list_entries(state: VaultState) -> list[Entry]:
    return sorted(state.index.entries.values(), key=lambda e: e.path)


def find_entry(state: VaultState, path: str) -> tuple[str, Entry]:
    wanted = normalize_path(path.replace("\\", "/"))
    for fid, entry in state.index.entries.items():
        if entry.path == wanted:
            return fid, entry
    raise VaultError("the path is not in the vault")


def file_history(
    git: Git, backend: Backend, state: VaultState, path: str
) -> list[tuple[str, int, Entry]]:
    """Commits that changed the file's blob: ``(commit, timestamp, entry-at-that-commit)``."""
    fid, _ = find_entry(state, path)
    assert state.tip is not None
    out = git.text("log", "--format=%H %ct", state.tip, "--", f"{STORE_PREFIX}{fid}")
    rows: list[tuple[str, int, Entry]] = []
    for line in out.splitlines():
        commit, _, ts = line.partition(" ")
        past = load_commit(git, backend, commit)
        entry = past.index.entries.get(fid)
        if entry is not None:
            rows.append((commit, int(ts), entry))
    return rows


def vault_content(git: Git, backend: Backend, state: VaultState, path: str) -> bytes:
    fid, entry = find_entry(state, path)
    blob = git.run("cat-file", "blob", state.files[STORE_PREFIX + fid])
    plain = backend.dec_blob(fid, blob)
    if backend.mac(plain).hex() != entry.mac:
        raise VaultTamperError("a vault blob does not match the authenticated index")
    return plain


def diff_text(
    old: bytes, new: bytes, label: str, old_label: str = "vault", new_label: str = "work"
) -> str | None:
    """Unified diff computed in memory. ``None`` if equal; a note if either side is binary."""
    if old == new:
        return None
    try:
        a, b = old.decode("utf-8"), new.decode("utf-8")
    except UnicodeDecodeError:
        return f"Binary files differ ({label})\n"
    lines = difflib.unified_diff(
        a.splitlines(keepends=True),
        b.splitlines(keepends=True),
        fromfile=f"{old_label}:{label}",
        tofile=f"{new_label}:{label}",
    )
    return "".join(
        line if line.endswith("\n") else line + "\n\\ No newline at end of file\n" for line in lines
    )
