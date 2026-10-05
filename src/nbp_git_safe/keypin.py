# SPDX-License-Identifier: MIT
"""Registering and checking the key id around an unlock (see ``keyid``)."""

from __future__ import annotations

from typing import Any

from nbp_git_safe import agent, keyid, vault
from nbp_git_safe.config import Config
from nbp_git_safe.gitutil import Git, Repo


def require_known(git: Git, cfg: Config) -> None:
    """Before a GROUP's key command runs: a repository with no registered key id and no vault
    cannot say which key is its own, so it is refused (``KeyIdMissingError``) instead of being
    handed a key that may belong to another repository."""
    if cfg.key_id is None and vault.resolve_tip(git, cfg, use_remote_fallback=True) is None:
        raise keyid.KeyIdMissingError(keyid.missing_message())


def after_unlock(
    git: Git, repo: Repo, cfg: Config, status: dict[str, Any], *, first_use_ok: bool
) -> None:
    """Right after a key was delivered. With a registered id there is nothing to do (it was
    enforced before delivery). Otherwise: an existing vault must open under the key (and then the
    id is recorded), and a repository without a vault records it on first use when
    ``first_use_ok`` (``unlock`` run inside the repository). A failure here makes ``unlock`` lock
    the agent again."""
    if cfg.key_id is not None:
        return
    actual = str(status.get("key_id", ""))
    if vault.resolve_tip(git, cfg, use_remote_fallback=True) is None:
        if not first_use_ok:
            raise keyid.KeyIdMissingError(keyid.missing_message())
    else:
        with agent.AgentClient.connect(repo.state_dir) as backend:
            vault.load_vault(git, backend, cfg, use_remote_fallback=True)  # authenticates the key
    keyid.record(git, actual)
