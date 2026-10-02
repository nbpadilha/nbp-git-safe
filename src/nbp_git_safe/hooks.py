# SPDX-License-Identifier: MIT
"""Installing, inspecting and removing the git hooks, and the handlers behind ``hook <event>``.

Two mechanisms, config first:

* **Hooks by git config** (``hook.<name>.command`` + ``hook.<name>.event``, introduced in git 2.54;
  ``git hook run`` and the commands that were converted to the hook API run them in addition to,
  and not instead of, the script in the hooks directory). Nothing in the hooks directory is touched,
  so husky-style ``core.hooksPath``, the pre-commit framework or a hand-written hook keep working.
  The friendly name must differ from the event name, so there is one name per event
  (``nbp-git-safe-<event>``).
* **Shim fallback** for a git without that feature: a tiny script written to the hooks directory
  ONLY if no file is there. A foreign file is never overwritten, and ``uninstall`` removes only a
  file that has exactly the shape of ours.

The command runs the interpreter that installed it (``python -I -m nbp_git_safe hook <event>``):
no PATH lookup, and ``-I`` keeps a hostile working tree from shadowing modules through the current
directory. The string is a shell one-liner for git, so the path is POSIX-quoted.

Handlers never ask the password manager on their own (``autoUnlock`` is opt-in). ``pre-commit`` and
``pre-push`` fail closed (non-zero blocks the operation); the ``post-*`` handlers never fail git.
"""

from __future__ import annotations

import os
import re
import sys
import traceback
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from nbp_git_safe import agent, crypto, guard, multi, protect, unlock, vault
from nbp_git_safe import index as index_mod
from nbp_git_safe.config import Config, ConfigError, load_config
from nbp_git_safe.gitutil import Git, GitError, Repo, discover, rev_parse

EVENTS = ("pre-commit", "pre-push", "post-commit", "post-merge", "post-checkout")
MIN_GIT = (2, 54)  # git config hooks (RelNotes 2.54.0); verified in practice on 2.55.0 only
NAME_PREFIX = "nbp-git-safe-"
SHIM_MARKER = "# nbp-git-safe hook shim v1 (managed; remove with `nbp-git-safe uninstall`)"
_SHIM_RE = re.compile(
    r"\A#!/bin/sh\n"
    + re.escape(SHIM_MARKER)
    + r"\nexec ('(?:[^']|'\\'')*') -I -m nbp_git_safe hook ("
    + "|".join(EVENTS)
    + r') "\$@"\n\Z'
)


def hook_name(event: str) -> str:
    return NAME_PREFIX + event


# ----------------------------------------------------------------------------- git facts


def git_version(git: Git) -> tuple[int, int]:
    out = git.text("--version")
    match = re.search(r"(\d+)\.(\d+)", out)
    if not match:
        raise GitError("could not parse the git version")
    return int(match.group(1)), int(match.group(2))


def supports_config_hooks(git: Git) -> bool:
    return git_version(git) >= MIN_GIT


def hooks_dir(git: Git) -> Path:
    """The directory git reads hook files from (honours ``core.hooksPath``)."""
    out = git.text("rev-parse", "--path-format=absolute", "--git-path", "hooks").strip()
    return Path(out)


def hooks_path_setting(git: Git) -> str | None:
    out = git.try_run("config", "--get", "core.hooksPath")
    return out.decode("utf-8", "replace").strip() if out else None


def _inside(child: Path, parent: Path) -> bool:
    try:
        Path(os.path.realpath(child)).relative_to(os.path.realpath(parent))
    except ValueError:
        return False
    return True


# -------------------------------------------------------------------- command and shim text


def posix_quote(text: str) -> str:
    """Quote ``text`` as one POSIX shell word (git runs the config command through ``sh``)."""
    return "'" + text.replace("'", "'\\''") + "'"


def hook_python() -> str:
    exe = Path(sys.executable)
    if sys.platform == "win32" and exe.name.lower() == "pythonw.exe":
        console = exe.with_name("python.exe")
        if console.is_file():
            exe = console
    return exe.as_posix()


def hook_command(event: str, python: str | None = None) -> str:
    return f"{posix_quote(python or hook_python())} -I -m nbp_git_safe hook {event}"


def shim_text(event: str, python: str | None = None) -> str:
    return (
        "#!/bin/sh\n"
        + SHIM_MARKER
        + f"\nexec {posix_quote(python or hook_python())} -I -m nbp_git_safe hook {event} "
        + '"$@"\n'
    )


def is_our_shim(text: str, event: str | None = None) -> bool:
    match = _SHIM_RE.match(text)
    return match is not None and (event is None or match.group(2) == event)


# ------------------------------------------------------------------------------ inspection


@dataclass
class HookStatus:
    event: str
    mechanism: str  # "config" | "shim" | "none"
    ok: bool
    detail: str
    foreign_file: bool = False


def _config_values(git: Git, key: str) -> list[str]:
    out = git.try_run("config", "--get-all", key)
    return out.decode("utf-8", "replace").splitlines() if out else []


def _read_shim(path: Path) -> str | None:
    try:
        return path.read_bytes().decode("utf-8", "replace").replace("\r\n", "\n")
    except OSError:
        return None


def inspect_event(git: Git, repo: Repo, event: str) -> HookStatus:
    name = hook_name(event)
    command = _config_values(git, f"hook.{name}.command")
    events = _config_values(git, f"hook.{name}.event")
    file = hooks_dir(git) / event
    text = _read_shim(file)
    foreign = text is not None and not is_our_shim(text, event)

    if command or events:
        enabled = _config_values(git, f"hook.{name}.enabled")
        event_enabled = _config_values(git, f"hook.{event}.enabled")
        if enabled and enabled[-1].lower() in ("false", "no", "off", "0"):
            return HookStatus(
                event, "config", False, "hook is disabled (hook.<name>.enabled)", foreign
            )
        if event_enabled and event_enabled[-1].lower() in ("false", "no", "off", "0"):
            return HookStatus(event, "config", False, f"all {event} hooks are disabled", foreign)
        if events != [event]:
            return HookStatus(event, "config", False, "config hook has unexpected events", foreign)
        if command[-1:] != [hook_command(event)]:
            return HookStatus(
                event,
                "config",
                False,
                "config hook command differs from the expected one (the Python moved, or the "
                "config was changed); run `nbp-git-safe init` to refresh it",
                foreign,
            )
        if supports_config_hooks(git):
            listed = git.try_run("hook", "list", event)
            if listed is None or name not in listed.decode("utf-8", "replace").split():
                return HookStatus(event, "config", False, "git does not list the hook", foreign)
        return HookStatus(event, "config", True, "installed (git config)", foreign)
    match = _SHIM_RE.match(text) if text is not None else None
    if match is not None and match.group(2) == event:
        if match.group(1) != posix_quote(hook_python()):
            return HookStatus(event, "shim", False, "shim points at another Python; run init")
        return HookStatus(event, "shim", True, "installed (hook file shim)")
    if foreign:
        return HookStatus(event, "none", False, "another hook is in the way (not ours)", True)
    return HookStatus(event, "none", False, "not installed")


def inspect_hooks(git: Git, repo: Repo) -> list[HookStatus]:
    return [inspect_event(git, repo, event) for event in EVENTS]


# ------------------------------------------------------------------------------ install


@dataclass
class InstallResult:
    mechanisms: dict[str, str] = field(default_factory=dict)  # event -> config | shim | none
    warnings: list[str] = field(default_factory=list)


def _set_config_hook(git: Git, event: str) -> None:
    name = hook_name(event)
    git.run("config", "--local", f"hook.{name}.command", hook_command(event))
    git.run("config", "--local", "--replace-all", f"hook.{name}.event", event)
    git.try_run("config", "--local", "--unset-all", f"hook.{name}.enabled")  # ours: never disabled


def _remove_config_hook(git: Git, event: str) -> bool:
    name = hook_name(event)
    return git.try_run("config", "--local", "--remove-section", f"hook.{name}") is not None


def _install_shim(git: Git, repo: Repo, event: str, result: InstallResult) -> str:
    directory = hooks_dir(git)
    if not _inside(directory, repo.common_dir):
        result.warnings.append(
            f"{event}: core.hooksPath points outside this repository's .git (a versioned or "
            "shared directory); no shim is written there"
        )
        return "none"
    target = directory / event
    wanted = shim_text(event)
    current = _read_shim(target)
    if current is not None and not is_our_shim(current, event):
        result.warnings.append(f"{event}: a hook file that is not ours exists; it was left alone")
        return "none"
    directory.mkdir(parents=True, exist_ok=True)
    if current != wanted:
        target.write_bytes(wanted.encode("utf-8"))
    if sys.platform != "win32":
        target.chmod(0o755)
    return "shim"


def install_hooks(git: Git, repo: Repo, *, with_shim: bool = False) -> InstallResult:
    """Install the five hooks. Config hooks when git supports them, shims otherwise; ``with_shim``
    adds the shims even so (for clients that ignore config hooks). Idempotent."""
    result = InstallResult()
    config_ok = supports_config_hooks(git)
    for event in EVENTS:
        mechanism = "none"
        if config_ok:
            _set_config_hook(git, event)
            listed = git.try_run("hook", "list", event)
            if listed is not None and hook_name(event) in listed.decode("utf-8", "replace").split():
                mechanism = "config"
            else:
                _remove_config_hook(git, event)
                result.warnings.append(f"{event}: git did not accept the config hook")
        if mechanism == "none" or with_shim:
            shim = _install_shim(git, repo, event, result)
            if mechanism == "none":
                mechanism = shim
        else:  # config hooks work: drop a shim an earlier run may have left (ours only)
            _remove_shim(git, event)
        result.mechanisms[event] = mechanism
    if not config_ok:
        result.warnings.append(
            f"git is older than {MIN_GIT[0]}.{MIN_GIT[1]}: hooks use the shim fallback"
        )
    return result


def _remove_shim(git: Git, event: str) -> bool:
    target = hooks_dir(git) / event
    text = _read_shim(target)
    if text is not None and is_our_shim(text, event):
        target.unlink()
        return True
    return False


def uninstall_hooks(git: Git) -> list[str]:
    """Remove only what is ours: our config hooks and shim files of our exact shape."""
    removed: list[str] = []
    for event in EVENTS:
        if _remove_config_hook(git, event):
            removed.append(f"{event}: config hook removed")
        if _remove_shim(git, event):
            removed.append(f"{event}: hook shim removed")
    return removed


# ------------------------------------------------------------------------------- handlers


def _say(message: str) -> None:
    sys.stderr.write(f"nbp-git-safe: {message}\n")


def _env_without_index() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k != "GIT_INDEX_FILE"}


def acquire_backend(repo: Repo, cfg: Config) -> tuple[agent.AgentClient | None, str]:
    """A connected, unlocked agent client, or ``(None, reason)``. Only ``autoUnlock=true`` may run
    the keyCommand (with its timeout); otherwise a locked agent simply means no content checks."""
    reason = ""
    for attempt in range(2):
        try:
            client = agent.AgentClient.connect(repo.state_dir)
        except agent.AgentError as exc:
            reason = str(exc)
        else:
            try:
                client.key_id()
                return client, ""
            except agent.AgentError as exc:
                reason = str(exc)
                client.close()
        if attempt == 0 and cfg.auto_unlock and cfg.key_command:
            try:
                unlock.unlock(
                    repo.state_dir,
                    cfg.key_command,
                    ttl=cfg.ttl,
                    idle_timeout=cfg.idle_timeout,
                    key_timeout=cfg.key_command_timeout,
                )
            except (unlock.KeyCommandError, agent.AgentError, OSError) as exc:
                return None, f"autoUnlock failed: {exc}"
            continue
        break
    return None, reason


def _context(env: dict[str, str] | None = None) -> tuple[Repo, Git, Config]:
    repo, git = discover(Path.cwd(), env)
    return repo, git, load_config(git, repo)


def _locked_hint(reason: str) -> str:
    base = "locked: run `nbp-git-safe unlock`"
    return f"{base} ({reason})" if reason and "unlock" not in reason else base


def pre_commit() -> int:
    try:
        repo, git, cfg = _context()
        sources = guard.pattern_sources(git, repo)
        backend: agent.AgentClient | None = None
        reason = ""
        if sources:
            backend, reason = acquire_backend(repo, cfg)
        try:
            report = guard.check_commit(git, repo, cfg, backend)
        finally:
            if backend is not None:
                backend.close()
    except (
        vault.VaultError,
        crypto.NbpCryptoError,
        index_mod.IndexValidationError,
        agent.AgentError,
        ConfigError,
        GitError,
        OSError,
    ) as exc:
        _say(f"pre-commit could not verify the commit ({exc}); nothing was committed")
        return 1
    except Exception:  # fail closed on anything unexpected, without echoing data
        _say(f"pre-commit failed unexpectedly ({traceback.format_exc().splitlines()[-1]})")
        return 1
    for warning in report.warnings:
        _say(f"warning: {warning}")
    if sources and backend is None:
        _say(f"warning: content check skipped, vault {_locked_hint(reason)}")
    if report.violations:
        _say("commit blocked: protected material would enter the main branch:")
        for line in guard.format_report(report):
            sys.stderr.write(line + "\n")
        _say(
            "unstage it (git restore --staged -- <path>); a file staged with `git add -f` leaves "
            "its content in .git/objects until `git prune --expire now`"
        )
        return 1
    return 0


def pre_push(args: Sequence[str], stdin_text: str) -> int:
    remote = args[0] if args else "origin"
    try:
        repo, git, cfg = _context()
        updates = guard.parse_push_stdin(stdin_text)
        backend, reason = acquire_backend(repo, cfg)
        warnings: list[str] = []
        try:
            if backend is not None:
                try:
                    commit, _analysis, _plan = vault.seal(git, repo, cfg, backend)
                except (
                    vault.VaultError,
                    crypto.NbpCryptoError,
                    index_mod.IndexValidationError,
                ) as exc:
                    warnings.append(f"the vault could not be sealed before the push ({exc})")
                else:
                    pushed = [u for u in updates if u.local_ref == cfg.vault_ref]
                    if commit is not None and any(u.local_oid != commit for u in pushed):
                        warnings.append(
                            "the vault changed while preparing this push; push again to send "
                            "the new vault commit"
                        )
            else:
                warnings.append(
                    f"the vault was not sealed or content-checked: {_locked_hint(reason)}"
                )
            report = guard.check_push(git, repo, cfg, backend, updates, remote)
        finally:
            if backend is not None:
                backend.close()
    except (
        vault.VaultError,
        crypto.NbpCryptoError,
        index_mod.IndexValidationError,
        agent.AgentError,
        ConfigError,
        GitError,
        OSError,
    ) as exc:
        _say(f"pre-push could not verify the push ({exc}); nothing was pushed")
        return 1
    except Exception:
        _say(f"pre-push failed unexpectedly ({traceback.format_exc().splitlines()[-1]})")
        return 1
    for warning in [*warnings, *report.warnings]:
        _say(f"warning: {warning}")
    if report.violations:
        _say("push blocked:")
        for line in guard.format_report(report):
            sys.stderr.write(line + "\n")
        return 1
    return 0


def post_commit() -> int:
    """Seal after a commit when the agent is unlocked. Never fails the commit."""
    try:
        repo, git, cfg = _context(_env_without_index())
        if not guard.pattern_sources(git, repo):
            return 0
        backend, reason = acquire_backend(repo, cfg)
        if backend is None:
            if protect.list_protected(git, repo):
                _say(f"protected files were not sealed: {_locked_hint(reason)}")
            return 0
        with backend:
            commit, analysis, plan = vault.seal(git, repo, cfg, backend)
        for path, why in analysis.refused:
            _say(f"refused {path!r}: {why}")
        if commit is not None and plan is not None:
            _say(
                f"vault sealed: {len(analysis.new)} new, {len(analysis.changed)} changed "
                f"-> {commit[:10]}"
            )
    except Exception as exc:  # post-commit must never break the user's commit
        _say(f"warning: could not seal after the commit ({type(exc).__name__}: {exc})")
    return 0


def post_refresh(args: Sequence[str]) -> int:
    """``post-merge`` / ``post-checkout``: refresh the exclude block and, if unlocked, ``open``."""
    try:
        if len(args) >= 3 and args[2] == "0":
            return 0  # post-checkout of single files, not a branch switch
        repo, git, cfg = _context(_env_without_index())
        if not guard.pattern_sources(git, repo):
            return 0
        protect.install_exclude_block(repo)
        dropped = protect.sticky_only(repo)
        if dropped:
            _say(
                f"WARNING: {len(dropped)} protected pattern(s) are no longer in .nbp-safe (a pull "
                "or checkout removed them, or you did) but this clone STILL protects them. If "
                "that was not you, find out who changed .nbp-safe (git log -p -- .nbp-safe); to "
                "drop a pattern for real run `nbp-git-safe unprotect <pattern>`; "
                "`nbp-git-safe doctor` lists them"
            )
        has_vault = rev_parse(git, cfg.vault_ref + "^{commit}") or rev_parse(
            git, cfg.remote_vault_ref + "^{commit}"
        )
        if not has_vault:
            return 0
        backend, reason = acquire_backend(repo, cfg)
        if backend is None:
            _say(f"vault not opened: {_locked_hint(reason)}, then `nbp-git-safe open`")
            return 0
        with backend:
            known: dict[str, frozenset[str]] = {}
            try:  # bring in what `git pull` just fetched (offline, never forces)
                synced = multi.sync(git, repo, cfg, backend, fetch=False, seal_first=False)
                known = synced.known_macs
                if synced.action in ("fast-forward", "merged"):
                    _say(f"vault {synced.action} with origin ({synced.conflicts} conflict(s))")
            except (vault.VaultError, crypto.NbpCryptoError, index_mod.IndexValidationError) as exc:
                _say(f"warning: the vault was not synced with origin ({exc})")
            result = vault.open_vault(git, repo, cfg, backend, known)
        if result.written or result.theirs:
            _say(f"vault opened: {len(result.written)} file(s) written")
        for rel in result.theirs:
            _say(f"local file differs; vault version saved as {rel!r}")
        for problem in result.errors:
            _say(f"warning: {problem}")
    except Exception as exc:
        _say(f"warning: could not open the vault ({type(exc).__name__}: {exc})")
    return 0


def _utf8_when_piped() -> None:
    """Git forwards a hook's stderr as it is, and git itself speaks UTF-8: when stderr is a pipe
    (not a console, which has its own wide-character path) write UTF-8, whatever the locale."""
    stream = sys.stderr
    if hasattr(stream, "reconfigure") and not stream.isatty():
        stream.reconfigure(encoding="utf-8", errors="replace")


def run_hook(event: str, args: Sequence[str], stdin_text: str = "") -> int:
    _utf8_when_piped()
    if event == "pre-commit":
        return pre_commit()
    if event == "pre-push":
        return pre_push(args, stdin_text)
    if event == "post-commit":
        return post_commit()
    if event in ("post-merge", "post-checkout"):
        return post_refresh(args)
    _say(f"unknown hook event {event!r}")
    return 2
