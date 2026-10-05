# SPDX-License-Identifier: MIT
"""Operations over several registered repositories (``status --all``, ``unlock --all`` ... and the
tray). Neutral: no window, no platform call.

Each repository is handled on its own and its own configuration (``.git/config`` of THAT
repository) decides everything, including ``keyCommand``; the registry only says where to look.
A failure in one repository is reported and the others continue. Nothing here prints or returns a
key, and the messages come from the library's fixed texts.

``unlock_all`` runs the key command ONCE per group of repositories with an identical, portable
``keyCommand`` argv (a relative path makes a repository a group of its own, and the command always
runs from the repository's root) and hands the resulting key to the agent of every repository of the
group, so the password manager asks once per distinct key. The grouping is an optimisation, never
the safeguard: each repository's registered key id (``keyid``) is checked before a key is delivered.
The key passes through this process only for the duration of the call (the same as
``nbp-git-safe unlock``) and goes only over the authenticated channel to an agent this process just
started; the tray runs this function in a short-lived child process (``unlockchild``).
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nbp_git_safe import (
    agent,
    crypto,
    doctor,
    gitutil,
    keyid,
    keypin,
    multi,
    registry,
    unlock,
    vault,
)
from nbp_git_safe import index as index_mod
from nbp_git_safe.config import Config, ConfigError, load_config
from nbp_git_safe.gitutil import Git, GitError, GitTimeoutError, Repo, discover
from nbp_git_safe.registry import Entry

OK, SKIPPED, FAILED, WARN = "ok", "skipped", "failed", "warn"


@dataclass
class Outcome:
    """The result of one operation on one repository. ``code`` is a short, fixed word (used by the
    tray and its log); ``message`` is the library's own text (no key, no content)."""

    index: int
    name: str
    kind: str
    message: str = ""
    code: str = ""
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class RepoHandle:
    index: int  # 1-based position in the registry
    path: Path
    name: str
    repo: Repo
    git: Git
    cfg: Config
    key: str  # agent.repo_key: stable identity of the repository's agent

    @property
    def root(self) -> Path:
        """The repository's top-level folder: where its ``keyCommand`` runs."""
        return self.path


def short_name(path: str | os.PathLike[str]) -> str:
    text = os.fspath(path)
    return os.path.basename(text.rstrip("\\/")) or text


def classify(exc: BaseException) -> tuple[str, str]:
    """``(code, message)`` for an exception. Only fixed library messages are passed on; an
    exception of an unknown kind is reduced to its class name."""
    if isinstance(exc, unlock.KeyCommandError):
        return "key-command", str(exc)
    if isinstance(exc, keyid.KeyIdMissingError):
        return "no-key-id", str(exc)
    if isinstance(exc, keyid.KeyIdError):
        return "key-id-mismatch", str(exc)
    if isinstance(exc, GitTimeoutError):
        return "git-timeout", str(exc)
    if isinstance(exc, agent.InsecureStateError):
        return "insecure-state", (
            f"{exc}; nothing was read from it (fix the owner and permissions of that folder; "
            "`nbp-git-safe doctor` says more)"
        )
    if isinstance(exc, agent.ProcessInspectionError):
        return "other-elevation", str(exc)
    if isinstance(exc, agent.HandshakeError):
        return "agent-auth", str(exc)
    if isinstance(
        exc, agent.AgentNotRunningError | agent.AgentLockedError | agent.AgentExpiredError
    ):
        return "locked", str(exc)
    if isinstance(exc, agent.AgentError):
        return "agent", str(exc)
    if isinstance(exc, ConfigError):
        return "config", str(exc)
    if isinstance(exc, vault.VaultError | crypto.NbpCryptoError | index_mod.IndexValidationError):
        return "vault", str(exc)
    if isinstance(exc, GitError):
        return "git", str(exc)
    if isinstance(exc, OSError):
        return "io", exc.strerror or "I/O error"
    return "unexpected", f"unexpected error ({type(exc).__name__})"


class HandleError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def open_handle(
    path: str | os.PathLike[str],
    index: int,
    flags: Mapping[str, str | None] | None = None,
) -> RepoHandle:
    """Discover the repository at ``path`` and read ITS configuration. ``HandleError`` carries a
    short code: ``missing`` (no such folder), ``not-a-repo`` or ``config``.

    The registered folder must be the top of the repository found there. Discovery is not allowed
    to climb above it (``GIT_CEILING_DIRECTORIES``: a folder whose ``.git`` was deleted must not
    make the tool operate on the repository that contains it), and the top level git reports is
    compared with the registered path as a second check."""
    if not os.path.isdir(path):
        raise HandleError("missing", "the folder does not exist")
    try:
        # (the real path: git does not resolve links in the entries of this variable)
        above = os.path.realpath(os.path.dirname(os.path.abspath(path)))
        ceiling = {**os.environ, "GIT_CEILING_DIRECTORIES": above}
        repo, git = discover(path, ceiling)
        if registry.key_of(os.path.realpath(repo.toplevel)) != registry.key_of(
            os.path.realpath(path)
        ):
            raise HandleError(
                "not-a-repo",
                "the folder is not the top of a git repository (its .git is gone, or it is a "
                "subfolder of another one)",
            )
        cfg = load_config(git, repo, flags)
    except ConfigError as exc:
        raise HandleError("config", str(exc)) from None
    except GitError:
        raise HandleError("not-a-repo", "not a git repository (or git failed)") from None
    except OSError as exc:
        raise HandleError("io", exc.strerror or "I/O error") from None
    return RepoHandle(
        index,
        Path(path),
        short_name(path),
        repo,
        git,
        cfg,
        agent.repo_key(repo.state_dir),
    )


def open_all(
    entries: Sequence[Entry], flags: Mapping[str, str | None] | None = None
) -> tuple[list[RepoHandle], list[Outcome]]:
    """Handles for every entry that can be opened, and a failed outcome for each one that cannot.
    Entries that are worktrees of one repository (the same agent) appear once."""
    handles: list[RepoHandle] = []
    failures: list[Outcome] = []
    seen: set[str] = set()
    for position, entry in enumerate(entries, start=1):
        try:
            handle = open_handle(entry.path, position, flags)
        except HandleError as exc:
            kind = WARN if exc.code == "missing" else FAILED  # a gone folder: `registry prune`
            failures.append(Outcome(position, short_name(entry.path), kind, str(exc), exc.code))
            continue
        if handle.key in seen:
            continue
        seen.add(handle.key)
        handles.append(handle)
    return handles, failures


# ------------------------------------------------------------------------------- agent state


@dataclass(frozen=True)
class AgentView:
    state: str  # "unlocked", "locked" or "error"
    expires_at: float | None = None
    key_id: str = ""
    code: str = ""
    message: str = ""


def read_agent(handle: RepoHandle) -> AgentView:
    """The agent of a repository, read in this process (no child process)."""
    try:
        status = unlock.current_status(handle.repo.state_dir)
    except Exception as exc:  # every failure becomes a state, never a crash
        code, message = classify(exc)
        return AgentView("error", code=code, message=message)
    if status is None or status.get("locked"):
        return AgentView("locked")
    expires = status.get("expires_at")
    return AgentView(
        "unlocked",
        float(expires) if isinstance(expires, int | float) else None,
        str(status.get("key_id", "")),
    )


# ------------------------------------------------------------------------------- unlock


class GroupKey:
    """The key of one group of repositories, produced on first use by running the key command once.
    A failure is remembered and raised again for the rest of the group (a refused prompt is not
    asked a second time). ``wipe`` zeroes the buffer this class owns and drops the references;
    Python cannot reach the immutable copies the interpreter made on the way (the same limit as the
    single-repository ``unlock``)."""

    def __init__(self, produce: Callable[[], bytes]) -> None:
        self._produce = produce
        self._buffer: bytearray | None = None
        self._failure: tuple[type[unlock.KeyCommandError], str] | None = None
        self.runs = 0

    def get(self) -> bytes:
        if self._failure is not None:
            raise self._failure[0](self._failure[1])
        if self._buffer is None:
            self.runs += 1
            try:
                self._buffer = bytearray(self._produce())
            except BaseException as exc:
                # only the kind and the (key-free) message are kept: an exception object holds its
                # traceback, the traceback holds the frames, and a frame of the key command runner
                # holds what the command printed
                if isinstance(exc, unlock.KeyCommandError):
                    self._failure = (type(exc), str(exc))
                else:
                    self._failure = (
                        unlock.KeyCommandError,
                        f"the key command failed ({type(exc).__name__})",
                    )
                raise
        return bytes(self._buffer)

    def wipe(self) -> None:
        if self._buffer is not None:
            for position in range(len(self._buffer)):
                self._buffer[position] = 0
        self._buffer = None
        self._failure = None
        self._produce = _gone

    def __repr__(self) -> str:
        return "GroupKey(<redacted>)"


def _gone() -> bytes:
    raise unlock.KeyCommandError("the key was wiped")


def group_by_key_command(handles: Sequence[RepoHandle]) -> list[list[RepoHandle]]:
    """Repositories grouped by identical ``keyCommand`` argv (order of first appearance).

    An identical argv is the same command only when it means the same thing from every working
    directory. One that holds a relative path (``tools/key.py``, ``python key.py`` where the file
    sits in the repository) runs from the repository root, and is a different command in each
    repository, so such a repository is a group of its own (one prompt for it). The grouping is
    therefore an optimisation, never the safeguard: the registered key id (``keyid``) is checked
    for every repository whatever the commands are."""
    groups: dict[tuple[tuple[str, ...] | None, str | None], list[RepoHandle]] = {}
    for handle in handles:
        argv = handle.cfg.key_command
        own = argv is not None and unlock.depends_on_cwd(argv, handle.root)
        ident = (argv, registry.key_of(handle.root) if own else None)
        groups.setdefault(ident, []).append(handle)
    return list(groups.values())


def unlock_all(
    handles: Sequence[RepoHandle],
    *,
    key_runner: Callable[..., bytes] = unlock.run_key_command,
    spawn: Callable[[Path, float, float | None], agent.AgentInfo] = agent.spawn_agent,
    on_outcome: Callable[[Outcome], None] | None = None,
) -> list[Outcome]:
    """Unlock every repository, running each distinct ``keyCommand`` once. Groups run one after
    the other (one password-manager prompt at a time). Returns one outcome per repository."""
    outcomes: list[Outcome] = []

    def report(outcome: Outcome) -> None:
        outcomes.append(outcome)
        if on_outcome is not None:
            on_outcome(outcome)

    for group in group_by_key_command(handles):
        argv = group[0].cfg.key_command
        if argv is None:
            for handle in group:
                report(
                    Outcome(
                        handle.index,
                        handle.name,
                        FAILED,
                        "no keyCommand configured (git config nbp-safe.keyCommand)",
                        "key-command",
                    )
                )
            continue
        timeout = max(h.cfg.key_command_timeout for h in group)
        trees = [h.repo.toplevel for h in group]
        where = group[0].root  # the command is portable (see group_by_key_command): any root
        source = GroupKey(
            lambda argv=argv, timeout=timeout, trees=trees, where=where: key_runner(
                argv, timeout, avoid=trees, cwd=where
            )
        )
        try:
            for handle in group:
                report(_unlock_one(handle, argv, source, spawn))
        finally:
            source.wipe()
    return outcomes


def _unlock_one(
    handle: RepoHandle,
    argv: Sequence[str],
    source: GroupKey,
    spawn: Callable[[Path, float, float | None], agent.AgentInfo],
) -> Outcome:
    cfg = handle.cfg

    def key_for_this_repository() -> bytes:
        # a repository that cannot say which key is its own is not handed the group's key
        keypin.require_known(handle.git, cfg)
        return source.get()

    try:
        newly, status = unlock.unlock(
            handle.repo.state_dir,
            argv,
            ttl=cfg.ttl,
            idle_timeout=cfg.idle_timeout,
            key_timeout=cfg.key_command_timeout,
            spawn=spawn,
            key_source=key_for_this_repository,
            cwd=handle.root,
            expected_key_id=cfg.key_id,
            on_delivered=lambda status: keypin.after_unlock(
                handle.git, handle.repo, cfg, status, first_use_ok=False
            ),
        )
    except Exception as exc:  # one repository never stops the others
        code, message = classify(exc)
        return Outcome(handle.index, handle.name, FAILED, message, code)
    return Outcome(
        handle.index,
        handle.name,
        OK,
        ("unlocked" if newly else "already unlocked") + f" (key {status['key_id']})",
        "unlocked" if newly else "already-unlocked",
        {"expires_at": status.get("expires_at"), "newly": newly},
    )


# --------------------------------------------------------------------------- lock / status


def lock_one(handle: RepoHandle) -> Outcome:
    try:
        stopped = unlock.lock(handle.repo.state_dir)
    except Exception as exc:
        code, message = classify(exc)
        return Outcome(handle.index, handle.name, FAILED, message, code)
    return Outcome(
        handle.index,
        handle.name,
        OK,
        "locked" if stopped else "agent was not running",
        "locked" if stopped else "not-running",
    )


def pending_count(analysis: vault.Analysis, cfg: Config) -> int:
    """How many protected files a seal would write (a missing file counts only when ``onMissing``
    would remove it; refused ones are reported separately). ``onMissing=ask`` counts none: the
    seals of ``--all`` and of the tray are not interactive, and without anyone to ask they keep the
    file (as ``keep`` does), so counting it would show a pending file that no seal ever clears."""
    count = (
        len(analysis.new) + len(analysis.changed) + len(analysis.moved) + len(analysis.mode_only)
    )
    if cfg.on_missing == "remove":
        count += len(analysis.missing)
    return count


def status_one(handle: RepoHandle) -> Outcome:
    """Agent, vault and pending counts (no file names). ``skipped`` means locked."""
    view = read_agent(handle)
    if view.state == "error":
        return Outcome(handle.index, handle.name, FAILED, view.message, view.code)
    lines: list[str] = []
    try:
        remote = multi.remote_status(handle.git, handle.repo, handle.cfg)
        if view.state == "locked":
            kind, lead = SKIPPED, "agent: locked"
        else:
            kind = OK
            lead = f"agent: unlocked (key {view.key_id})"
            if view.expires_at is not None:
                stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(view.expires_at))
                lead += f", expires {stamp}"
            with agent.AgentClient.connect(handle.repo.state_dir) as backend:
                state = vault.load_vault(handle.git, backend, handle.cfg, use_remote_fallback=True)
                analysis = vault.analyze(handle.git, handle.repo, handle.cfg, backend, state)
            tip = state.tip[:10] if state.tip else "none"
            lines.append(
                f"vault: {handle.cfg.vault_ref} @ {tip} ({len(state.index.entries)} file(s))"
            )
            pending = pending_count(analysis, handle.cfg)
            lines.append(f"pending: {pending}" if pending else "pending: nothing")
        lines.insert(0, lead)
        if remote.kind != "no-remote":
            lines.append(f"origin: {remote.message}")
    except Exception as exc:
        code, message = classify(exc)
        return Outcome(handle.index, handle.name, FAILED, message, code)
    return Outcome(handle.index, handle.name, kind, "\n".join(lines), view.state)


def doctor_one(handle: RepoHandle) -> Outcome:
    try:
        findings = doctor.run_doctor(handle.git, handle.repo, handle.cfg, names=False)
    except Exception as exc:
        code, message = classify(exc)
        return Outcome(handle.index, handle.name, FAILED, message, code)
    problems = sum(1 for f in findings if f.level == doctor.PROBLEM)
    lines = [
        f"[{f.level.upper() if f.level == doctor.PROBLEM else f.level}] {f.message}"
        for f in findings
    ]
    return Outcome(
        handle.index,
        handle.name,
        FAILED if problems else OK,
        "\n".join(lines),
        "problems" if problems else "clean",
        {"problems": problems},
    )


# ------------------------------------------------------------------------------- seal / push


PUSH_TIMEOUT = gitutil.PUSH_TIMEOUT


def _push_env(env: Mapping[str, str], *, ssh_default: bool = True) -> dict[str, str]:
    """A push started by a background process must never wait for a person or for a stalled
    connection: no terminal prompt, no credential-manager window, slow HTTP transfers abandoned,
    and (unless the user chose their own ssh command, which is never overridden) an ``ssh`` that
    never asks and gives up on a dead connection."""
    return gitutil.network_env(env, ssh_default=ssh_default)


def push_one(handle: RepoHandle, *, timeout: float = PUSH_TIMEOUT) -> Outcome:
    """``git push origin refs/heads/nbp-safe`` without force, only where ``autoPush`` is set and an
    ``origin`` exists. A push that cannot reach the remote is reported, not fatal, and one that
    does not finish within ``timeout`` seconds is stopped with everything it started."""
    if not handle.cfg.auto_push:
        return Outcome(
            handle.index, handle.name, SKIPPED, "push: autoPush is not set", "no-autopush"
        )
    git = Git(
        handle.git.cwd,
        _push_env(handle.git.env, ssh_default=not gitutil.ssh_is_user_defined(handle.git)),
    )
    try:
        if git.try_run("remote", "get-url", multi.REMOTE) is None:
            return Outcome(
                handle.index, handle.name, SKIPPED, "push: no origin remote", "no-remote"
            )
        tip = multi.push_vault(git, handle.repo, handle.cfg, timeout=timeout)
    except multi.PushRejectedError as exc:
        return Outcome(handle.index, handle.name, FAILED, f"push: {exc}", "push-rejected")
    except multi.PushRefusedError as exc:
        return Outcome(handle.index, handle.name, FAILED, f"push: {exc}", "push-refused")
    except GitTimeoutError:
        return Outcome(
            handle.index,
            handle.name,
            WARN,
            f"push: gave up after {timeout:g} s (origin or a credential helper is not "
            "answering); run `nbp-git-safe push` there",
            "push-timeout",
        )
    except vault.VaultError as exc:
        text = str(exc)
        if "no local vault branch" in text:
            return Outcome(handle.index, handle.name, SKIPPED, "push: no vault yet", "no-vault")
        if "guard refused" in text:
            return Outcome(handle.index, handle.name, FAILED, f"push: {text}", "push-guard")
        return Outcome(
            handle.index,
            handle.name,
            WARN,
            "push: could not reach origin (offline, or refused); run `nbp-git-safe push` there",
            "push-offline",
        )
    except Exception as exc:
        code, message = classify(exc)
        return Outcome(handle.index, handle.name, FAILED, message, code)
    return Outcome(handle.index, handle.name, OK, f"pushed @ {tip[:10]} (no force)", "pushed")


def seal_one(handle: RepoHandle, *, push: bool = False) -> Outcome:
    """Seal one repository if (and only if) its agent is unlocked. A locked repository is
    skipped: this never starts an unlock. With ``push`` the vault branch is then pushed (where
    ``autoPush`` is set and an origin exists)."""
    try:
        client = agent.AgentClient.connect(handle.repo.state_dir)
    except agent.AgentNotRunningError:
        return Outcome(handle.index, handle.name, SKIPPED, "locked", "locked")
    except Exception as exc:
        code, message = classify(exc)
        return Outcome(handle.index, handle.name, FAILED, message, code)
    try:
        with client:
            client.key_id()  # a running agent without a key (or an expired one) is "locked"
            commit, analysis, plan = vault.seal(handle.git, handle.repo, handle.cfg, client)
    except (agent.AgentLockedError, agent.AgentExpiredError, agent.AgentNotRunningError):
        return Outcome(handle.index, handle.name, SKIPPED, "locked", "locked")
    except Exception as exc:
        code, message = classify(exc)
        return Outcome(handle.index, handle.name, FAILED, message, code)
    data: dict[str, Any] = {"refused": len(analysis.refused)}
    if commit is None:
        message = "nothing to seal"
    else:
        assert plan is not None
        moved = len(analysis.moved) + len(analysis.renamed)
        message = (
            f"sealed: {len(analysis.new)} new, {len(analysis.changed)} changed, "
            f"{moved} moved, {len(plan.removed_paths)} removed -> {commit[:10]}"
        )
        data["sealed"] = len(analysis.new) + len(analysis.changed) + moved
    kind, code = OK, "sealed" if commit else "nothing"
    if analysis.refused:
        kind, code = FAILED, "refused"
        message += f"; {len(analysis.refused)} file(s) refused (too large or not regular)"
    if push and kind == OK:
        pushed = push_one(handle)
        message += f"\n{pushed.message}"
        data["push"] = pushed.code
        if pushed.kind == FAILED:
            kind, code = FAILED, pushed.code
    return Outcome(handle.index, handle.name, kind, message, code, data)


def seal_all(handles: Sequence[RepoHandle], *, push: bool = False) -> list[Outcome]:
    return [seal_one(h, push=push) for h in handles]


# ------------------------------------------------------------------------------- deep check


@dataclass(frozen=True)
class DeepCheck:
    problems: int
    divergent: bool
    pending: int | None  # None: not measured (locked)


def deep_check(handle: RepoHandle) -> DeepCheck:
    """The slower look the tray takes now and then: doctor's problems, the vault's relation to
    origin and (unlocked only) how many protected files wait to be sealed."""
    findings = doctor.run_doctor(handle.git, handle.repo, handle.cfg, names=False)
    problems = sum(1 for f in findings if f.level == doctor.PROBLEM)
    remote = multi.remote_status(handle.git, handle.repo, handle.cfg)
    divergent = remote.alarming or remote.kind == "diverged"
    pending: int | None = None
    if read_agent(handle).state == "unlocked":
        with agent.AgentClient.connect(handle.repo.state_dir) as backend:
            state = vault.load_vault(handle.git, backend, handle.cfg, use_remote_fallback=True)
            analysis = vault.analyze(handle.git, handle.repo, handle.cfg, backend, state)
        pending = pending_count(analysis, handle.cfg)
    return DeepCheck(problems, divergent, pending)


def set_auto_unlock(handle: RepoHandle, enabled: bool) -> None:
    """``git config --local nbp-safe.autoUnlock``: a deliberate user action (a tray menu item)."""
    handle.git.run("config", "--local", "nbp-safe.autoUnlock", "true" if enabled else "false")
