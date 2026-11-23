# SPDX-License-Identifier: MIT
"""The public fingerprint of a repository's key: which key this repository is supposed to use.

``keyCommand`` decides which key reaches the agent, but nothing about the COMMAND proves it is the
right key for THIS repository: two repositories can share an argv (and so be grouped by
``unlock --all`` and the tray) and still be meant to use different keys, or a relative path in the
argv can resolve to a different file from another working directory. The key id (8 bytes of an HKDF
output, already stored in every vault blob header and printed by ``status``) says which key it is
without being the key. Each repository records its own in the LOCAL ``.git/config``
(``nbp-safe.keyId``); every delivery of a key and every seal is checked against it, so the grouping
is safe whatever the commands are.

Recorded, in order of trust: by the ``unlock`` run inside the repository (its own ``keyCommand``,
its own working directory), by the first successful ``seal`` (which also proves the key opens the
vault), or deliberately with ``nbp-git-safe key-id --accept``. Never read from a versioned file.
"""

from __future__ import annotations

import re

from nbp_git_safe import crypto
from nbp_git_safe.agent import AgentError
from nbp_git_safe.gitutil import Git

CONFIG_KEY = "nbp-safe.keyId"
_KEY_ID_RE = re.compile(r"^[0-9a-f]{16}$")


class KeyIdError(AgentError):
    """The key does not match the key id registered for the repository (or none can be trusted).
    An ``AgentError``: every place that already refuses to go on without a trustworthy agent
    (hooks, commands, the tray) handles it as one."""


class KeyIdMismatchError(KeyIdError):
    """A key whose id differs from the registered one was refused; nothing was unlocked."""


class KeyIdMissingError(KeyIdError):
    """No key id is registered and the key would come from a group: refused before asking for it."""


def is_valid(text: str) -> bool:
    return _KEY_ID_RE.match(text) is not None


def of_key(master: bytes) -> str:
    """The key id (16 hex digits) of a 64-byte master key."""
    return crypto.KeySet(master).key_id.hex()


def mismatch_message(registered: str, actual: str) -> str:
    return (
        f"the key (key id {actual}) is not the key registered for this repository (key id "
        f"{registered}); nothing was unlocked or sealed. If that is the wrong key, fix this "
        "repository's keyCommand (a relative path in it resolves from the repository root, never "
        "from anywhere else) and `nbp-git-safe lock`; if the key was changed on purpose (rotate, "
        f"a new key), accept it here with: nbp-git-safe key-id --accept {actual}"
    )


def check(registered: str | None, actual: str) -> None:
    """Raise ``KeyIdMismatchError`` when a key id is registered and ``actual`` differs."""
    if registered is not None and actual != registered:
        raise KeyIdMismatchError(mismatch_message(registered, actual))


def missing_message() -> str:
    return (
        "no key id is registered for this repository and it has no vault yet, so the key of a "
        "group cannot be trusted for it: run `nbp-git-safe unlock` inside this repository once "
        "(it records the key id), or `nbp-git-safe key-id --accept <id>`"
    )


def record(git: Git, key_id: str) -> None:
    """Write the key id into the local ``.git/config`` (a public value, never the key)."""
    if not is_valid(key_id):
        raise KeyIdError("not a key id")
    git.run("config", "--local", CONFIG_KEY, key_id)
