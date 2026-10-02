# SPDX-License-Identifier: MIT
"""``nbp-git-safe doctor``: read-only health check with actionable messages.

Levels: ``ok`` (fine), ``info`` (worth knowing), ``warn`` (should be looked at), ``problem``
(the protection is weakened or broken: the command exits non-zero). Nothing here changes the
repository, and nothing prints file names of protected content or any secret.
"""

from __future__ import annotations

import os
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from nbp_git_safe import agent, crypto, guard, hooks, protect, unlock, vault
from nbp_git_safe import index as index_mod
from nbp_git_safe.config import Config
from nbp_git_safe.gitutil import Git, GitError, Repo, rev_parse, split_z

OK, INFO, WARN, PROBLEM = "ok", "info", "warn", "problem"
LISTED = 10

# Folder names of cloud-sync clients (compared case-insensitively, as a path component prefix).
_CLOUD_PREFIXES = {
    "onedrive": "OneDrive",
    "dropbox": "Dropbox",
    "google drive": "Google Drive",
    "googledrive": "Google Drive",
    "my drive": "Google Drive",
    "icloud drive": "iCloud",
    "iclouddrive": "iCloud",
    "com~apple~clouddocs": "iCloud",
    "mobile documents": "iCloud",
}
_CLOUD_ENV = ("OneDrive", "OneDriveConsumer", "OneDriveCommercial")


@dataclass(frozen=True)
class Finding:
    level: str
    message: str


def cloud_sync_client(path: Path, environ: Mapping[str, str] | None = None) -> str | None:
    """Heuristic: is ``path`` inside a cloud-synced folder? (by folder name and by the
    ``OneDrive*`` environment variables). Returns the client's name or ``None``."""
    env = os.environ if environ is None else environ
    for part in Path(os.path.realpath(path)).parts:
        folded = part.casefold()
        for prefix, label in _CLOUD_PREFIXES.items():
            if (
                folded == prefix
                or folded.startswith(prefix + " ")
                or folded.startswith(prefix + "-")
            ):
                return label
    for name in _CLOUD_ENV:
        root = env.get(name)
        if root:
            try:
                Path(os.path.realpath(path)).relative_to(os.path.realpath(root))
            except ValueError:
                continue
            return "OneDrive"
    return None


def _stash_findings(git: Git, sources: list[bytes]) -> Finding | None:
    out = git.try_run("stash", "list", "--format=%H")
    if not out or not sources:
        return None
    names: set[str] = set()
    for stash in out.decode("ascii").split():
        diff = git.try_run(
            "diff-tree", "-r", "--name-only", "-z", "--no-commit-id", stash + "^1", stash
        )
        names.update(split_z(diff or b""))
        untracked = git.try_run("ls-tree", "-r", "--name-only", "-z", stash + "^3")
        names.update(split_z(untracked or b""))
    hit = guard.protected_among(git, sources, sorted(names))
    if hit:
        return Finding(
            PROBLEM,
            f"{len(hit)} protected file(s) are inside a stash (plain text in the object "
            "database); drop those stashes (git stash drop) and avoid `git stash -a/-u` here",
        )
    return None


def _vault_divergence(git: Git, cfg: Config) -> Finding | None:
    local = rev_parse(git, cfg.vault_ref + "^{commit}")
    remote = rev_parse(git, cfg.remote_vault_ref + "^{commit}")
    if local is None and remote is None:
        return None
    if local is None:
        return Finding(
            WARN, "a vault exists on origin but there is no local branch; run `nbp-git-safe init`"
        )
    if remote is None or local == remote:
        return None
    counts = git.try_run("rev-list", "--left-right", "--count", f"{local}...{remote}")
    if counts is None:
        return Finding(WARN, "the local and remote vault histories could not be compared")
    ahead, behind = (int(x) for x in counts.decode("ascii").split())
    if ahead and behind:
        return Finding(
            WARN, f"the vault diverged from origin ({ahead} ahead, {behind} behind); run sync"
        )
    if behind:
        return Finding(INFO, f"the vault is {behind} commit(s) behind origin; run sync")
    return Finding(INFO, f"the vault is {ahead} commit(s) ahead of origin (not pushed yet)")


def run_doctor(
    git: Git, repo: Repo, cfg: Config, environ: Mapping[str, str] | None = None
) -> list[Finding]:
    found: list[Finding] = []

    def add(level: str, message: str) -> None:
        found.append(Finding(level, message))

    # --- git and hooks
    try:
        version = hooks.git_version(git)
        supported = version >= hooks.MIN_GIT
        add(
            OK if supported else WARN,
            f"git {version[0]}.{version[1]}: "
            + (
                "hooks by git config are supported"
                if supported
                else f"older than {hooks.MIN_GIT[0]}.{hooks.MIN_GIT[1]}: shim fallback is used"
            ),
        )
    except GitError as exc:
        add(PROBLEM, f"could not run git: {exc}")
        return found
    hooks_path = hooks.hooks_path_setting(git)
    if hooks_path:
        add(INFO, "core.hooksPath is set; config hooks run next to the hooks in that directory")
    for status in hooks.inspect_hooks(git, repo):
        if status.ok:
            add(OK, f"hook {status.event}: {status.detail}")
        else:
            add(PROBLEM, f"hook {status.event}: {status.detail}")
    if sorted(s.event for s in hooks.inspect_hooks(git, repo) if s.mechanism == "shim"):
        add(
            INFO,
            "shim hooks run only where git reads hook files; some GUI clients ignore config hooks",
        )

    # --- exclude block and patterns
    if not (repo.toplevel / protect.VERSIONED_PATTERNS).is_file() and not any(
        protect.pattern_files(repo)
    ):
        add(WARN, "no .nbp-safe (and no .git/info/nbp-safe): nothing is protected yet")
    if not protect.has_exclude_block(repo):
        add(
            PROBLEM,
            "the managed exclude block is missing from .git/info/exclude; run `nbp-git-safe init`",
        )
    elif not protect.exclude_block_current(repo):
        add(WARN, "the exclude block is out of date with the patterns; run `nbp-git-safe init`")
    else:
        add(OK, "exclude block present and current")
    versioned = repo.toplevel / protect.VERSIONED_PATTERNS
    if versioned.is_file():
        for warning in guard.lint_patterns(versioned.read_bytes()):
            add(WARN, warning)
    if cfg.ignored_versioned_keys:
        add(
            WARN,
            f"{len(cfg.ignored_versioned_keys)} key(s) in .nbp-safe.config are ignored "
            "(not allowed there)",
        )

    # --- tracked clear files and stash
    try:
        tracked = protect.tracked_matches(git, repo)
    except GitError:
        tracked = []
    if tracked:
        listed = ", ".join(tracked[:LISTED]) + (" ..." if len(tracked) > LISTED else "")
        add(
            PROBLEM,
            f"{len(tracked)} protected file(s) are tracked on the main branch ({listed}); "
            "untrack with `git rm --cached` (history may already contain them: see purge)",
        )
    else:
        add(OK, "no protected file is tracked on the main branch")
    sources = guard.pattern_sources(git, repo)
    stash = _stash_findings(git, sources)
    if stash:
        found.append(stash)

    # --- core settings and location
    autocrlf = git.try_run("config", "--get", "core.autocrlf")
    if autocrlf and autocrlf.strip():
        add(
            INFO,
            f"core.autocrlf={autocrlf.decode().strip()}: the vault is unaffected (no filters, "
            "binary-safe), main-branch text files are converted as usual",
        )
    client = cloud_sync_client(repo.toplevel, environ)
    if client:
        add(
            WARN,
            f"the repository is inside a {client} folder: protected files sit in plain text "
            "in the working tree and would be synced/indexed; move the repository out of it",
        )

    # --- agent and vault
    info = None
    try:
        info = agent.read_agent_info(repo.state_dir)
    except agent.AgentError:
        add(WARN, "agent.json is corrupted (it is removed by the next unlock)")
    if info is not None and (not agent.pid_alive(info.pid) or time.time() >= info.expires_at):
        add(WARN, "agent.json is stale (the agent is gone); the next command removes it")
    status = unlock.current_status(repo.state_dir) if info is not None else None
    if cfg.key_command is None:
        add(
            WARN,
            "no keyCommand configured (git config nbp-safe.keyCommand '[...]'): unlock cannot run",
        )
    if status is None or status.get("locked"):
        add(INFO, "agent is locked: run `nbp-git-safe unlock` for content checks and sealing")
    else:
        add(OK, f"agent unlocked (key {status['key_id']})")
        try:
            with agent.AgentClient.connect(repo.state_dir) as backend:
                state = vault.load_vault(git, backend, cfg, use_remote_fallback=True)
            if state.tip is None:
                add(INFO, "no vault yet (nothing sealed)")
            else:
                add(
                    OK,
                    f"vault verifies: {len(state.index.entries)} file(s), key {state.index.key_id}",
                )
        except (vault.VaultError, crypto.NbpCryptoError, index_mod.IndexValidationError) as exc:
            add(PROBLEM, f"the vault does not verify: {exc}")
        except agent.AgentError as exc:
            add(WARN, f"could not query the agent: {exc}")
    divergence = _vault_divergence(git, cfg)
    if divergence:
        found.append(divergence)
    return found


def exit_code(findings: list[Finding]) -> int:
    return 1 if any(f.level == PROBLEM for f in findings) else 0
