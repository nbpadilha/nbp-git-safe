# SPDX-License-Identifier: MIT
"""Encrypted, name-hiding vault for sensitive files inside a Git repository (command line)."""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from nbp_git_safe import (
    __version__,
    agent,
    crypto,
    doctor,
    fleetcli,
    guard,
    hooks,
    multi,
    protect,
    registry,
    unlock,
    vault,
)
from nbp_git_safe import index as index_mod
from nbp_git_safe.config import Config, ConfigError, load_config
from nbp_git_safe.gitutil import Git, GitError, Repo, discover, rev_parse

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_LOCKED = 3
ADOPT_HELP = (
    "adopt a vault branch this clone has never verified (trust on first use: the error shows "
    "its key id, seq and tip first; compare them with another machine)"
)


class CliError(Exception):
    """A user-facing failure (printed as ``nbp-git-safe: error: ...``)."""

    def __init__(self, message: str, code: int = EXIT_ERROR) -> None:
        super().__init__(message)
        self.code = code


def _out(text: str = "") -> None:
    sys.stdout.write(text + "\n")


def _err(text: str) -> None:
    sys.stderr.write(text + "\n")


def _context(args: argparse.Namespace) -> tuple[Repo, Git, Config]:
    start = Path(args.directory) if args.directory else Path.cwd()
    repo, git = discover(start)
    flags = {
        "ttl": getattr(args, "ttl", None),
        "idletimeout": getattr(args, "idle_timeout", None),
        "onmissing": getattr(args, "on_missing", None),
        "padbucket": getattr(args, "pad_bucket", None),
        "vaultref": getattr(args, "vault_ref", None),
    }
    cfg = load_config(git, repo, flags)
    if "vault.ref" in cfg.ignored_versioned_keys:
        _err(
            "nbp-git-safe: warning: vault.ref in .nbp-safe.config is ignored; which vault branch "
            "this clone trusts is local: git config nbp-safe.vaultRef <ref>"
        )
    return repo, git, cfg


def _connect(repo: Repo) -> agent.AgentClient:
    return agent.AgentClient.connect(repo.state_dir)


def _relpath(repo: Repo, raw: str, args: argparse.Namespace) -> str:
    base = Path(args.directory) if args.directory else Path.cwd()
    full = Path(os.path.abspath(base / raw))
    try:
        rel = full.relative_to(os.path.abspath(repo.toplevel))
    except ValueError:
        raise CliError("path is outside the repository") from None
    return rel.as_posix()


def _fmt_time(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


# ------------------------------------------------------------------------ commands


def cmd_keygen(_args: argparse.Namespace) -> int:
    key = crypto.encode_key(crypto.generate_key())
    _err(
        "nbp-git-safe: this key is shown ONCE and is not saved anywhere. Pipe it straight into "
        "your password manager now (it cannot be recovered)."
    )
    _out(key)
    return EXIT_OK


def cmd_init(args: argparse.Namespace) -> int:
    repo, git, cfg = _context(args)
    repo.state_dir.mkdir(parents=True, exist_ok=True)
    changed = protect.install_exclude_block(repo)
    _err(
        "nbp-git-safe: exclude block "
        + ("installed" if changed else "already up to date")
        + f" ({protect.exclude_path(repo)})"
    )
    if args.gitignore_block:
        changed = protect.install_gitignore_block(repo)
        _err(
            "nbp-git-safe: .gitignore block "
            + ("installed" if changed else "already up to date")
            + " (a versioned file: commit it)"
        )
    working = protect.working_patterns(repo)
    if working is None:
        _err("nbp-git-safe: note: no .nbp-safe file yet; add gitignore-style patterns there")
    else:
        for warning in guard.lint_patterns(working):
            _err(f"nbp-git-safe: warning: {warning}")
    _adopt_remote_vault(git, repo, cfg, confirm=args.confirm_first_adopt)
    if not args.no_hooks:
        result = hooks.install_hooks(git, repo, with_shim=args.shim)
        by_mechanism: dict[str, list[str]] = {}
        for event, mechanism in result.mechanisms.items():
            by_mechanism.setdefault(mechanism, []).append(event)
        for mechanism, events in by_mechanism.items():
            label = {
                "config": "git config hooks",
                "shim": "hook-file shims",
                "none": "NOT installed",
            }
            _err(f"nbp-git-safe: {label[mechanism]}: {', '.join(events)}")
        for warning in result.warnings:
            _err(f"nbp-git-safe: warning: {warning}")
    if args.auto_push:
        added = multi.enable_auto_push(git, repo, cfg)
        _err(
            "nbp-git-safe: auto-push enabled: `git push` also sends the vault"
            + (f" (refspecs added: {', '.join(added)})" if added else " (already configured)")
        )
    _register(repo)
    if args.generate_key:
        return cmd_keygen(args)
    return EXIT_OK


def _register(repo: Repo) -> None:
    """Remember the repository in the per-user registry (discovery for `--all` and the tray). The
    protection never depends on it, so a registry that cannot be written is a warning."""
    try:
        added = registry.add(repo.toplevel)
    except registry.RegistryError as exc:
        _err(f"nbp-git-safe: warning: not added to the repository registry: {exc}")
        return
    if added:
        _err("nbp-git-safe: repository added to the per-user registry (`registry list`)")


def _adopt_remote_vault(git: Git, repo: Repo, cfg: Config, *, confirm: bool = False) -> None:
    """A vault on origin and no local branch (a fresh clone): track it, so `open` works.

    Nothing is recorded as verified or seen here: the branch is only a pointer until an operation
    with the key checks its chain (``open``/``sync`` with ``--confirm-first-adopt``). With
    ``confirm`` the agent must be unlocked: the chain and the authentication are verified first
    and only then is the tip recorded."""
    if rev_parse(git, cfg.vault_ref) is not None:
        return
    if rev_parse(git, cfg.remote_vault_ref + "^{commit}") is None:
        return
    name = cfg.vault_ref.removeprefix("refs/heads/")
    git.run("branch", "--track", name, cfg.remote_vault_ref.removeprefix("refs/remotes/"))
    _err(f"nbp-git-safe: created local branch {name} tracking the vault on origin")
    tip = rev_parse(git, cfg.vault_ref + "^{commit}")
    if tip is None:
        return
    if not confirm:
        _err(
            "nbp-git-safe: the vault is not adopted yet: unlock, then `nbp-git-safe open` shows "
            "its key id, seq and tip; compare them with another machine and repeat with "
            "--confirm-first-adopt"
        )
        return
    try:
        with _connect(repo) as backend:
            seq = vault.check_chain(git, backend, repo, cfg.vault_ref, tip, adopt=True)
    except agent.AgentError:
        raise CliError(
            "--confirm-first-adopt needs the unlocked agent (the chain and the authentication "
            "are verified first): run `nbp-git-safe unlock`, then init again",
            EXIT_LOCKED,
        ) from None
    vault.mark_verified(repo, cfg.vault_ref, tip, seq, reset=True)
    multi.record_seen(repo, cfg.vault_ref, tip)
    _err(f"nbp-git-safe: adopted {name} @ {tip[:10]} (verified, seq {seq})")


def cmd_hook(args: argparse.Namespace) -> int:
    stdin_text = ""
    if args.event == "pre-push" and sys.stdin and not sys.stdin.isatty():
        stdin_text = sys.stdin.read()
    return hooks.run_hook(args.event, args.hook_args, stdin_text)


def cmd_doctor(args: argparse.Namespace) -> int:
    if args.all:
        return fleetcli.run_all("doctor", args)
    repo, git, cfg = _context(args)
    findings = doctor.run_doctor(git, repo, cfg)
    for finding in findings:
        _out(
            f"[{finding.level.upper() if finding.level == doctor.PROBLEM else finding.level}] "
            f"{finding.message}"
        )
    problems = sum(1 for f in findings if f.level == doctor.PROBLEM)
    _out(f"{problems} problem(s)" if problems else "no problems found")
    return doctor.exit_code(findings)


def cmd_uninstall(args: argparse.Namespace) -> int:
    repo, git, _cfg = _context(args)
    if not args.yes:
        if not sys.stdin or not sys.stdin.isatty():
            raise CliError("uninstall asks for confirmation: run it in a terminal or pass --yes")
        _err(
            "This removes the nbp-git-safe hooks and the exclude block. Protected files will be "
            "visible to `git status` / `git add -A` again. The vault branch and your files are "
            "not touched."
        )
        if input("type 'uninstall' to continue: ").strip() != "uninstall":
            raise CliError("not confirmed; nothing changed")
    removed = hooks.uninstall_hooks(git)
    removed.extend(f"push refspec removed: {spec}" for spec in multi.disable_auto_push(git, repo))
    if protect.remove_exclude_block(repo):
        removed.append("exclude block removed")
    if protect.remove_gitignore_block(repo):
        removed.append(".gitignore block removed (a versioned file: commit the change)")
    try:
        if registry.remove(repo.toplevel):
            removed.append("removed from the per-user registry")
    except registry.RegistryError as exc:
        _err(f"nbp-git-safe: warning: the repository registry was not updated: {exc}")
    for line in removed or ["nothing of ours was installed"]:
        _out(line)
    return EXIT_OK


ACCEPT_CURRENT_PHRASE = "unprotect --accept-current"


def cmd_unprotect(args: argparse.Namespace) -> int:
    repo, git, _cfg = _context(args)
    if args.accept_current == bool(args.pattern):
        raise CliError("give a pattern, or --accept-current (not both)", EXIT_USAGE)
    if args.accept_current:
        _typed_confirmation(ACCEPT_CURRENT_PHRASE, args.confirm, "unprotect")
        accepted = protect.accept_current(git, repo)
        protect.install_exclude_block(repo)
        _out(
            "accepted: the current .nbp-safe is the only base now; "
            f"{accepted.forgotten_versions} earlier version(s) and "
            f"{accepted.forgotten_patterns} pattern(s) are forgotten for good"
        )
        if accepted.differs_from_head:
            _err(
                "nbp-git-safe: HEAD still has another version of .nbp-safe: it keeps protecting "
                "until the commit that changes it is made (the guard refuses a commit that "
                "removes patterns unless you deliberately allow it, see docs/GUARD.md)"
            )
        _err(
            "nbp-git-safe: files already sealed stay in the vault; untracked ones are visible to "
            "`git add -A` from now on"
        )
        return EXIT_OK
    pattern = args.pattern
    _typed_confirmation(f"unprotect {pattern}", args.confirm, "unprotect")
    outcome = protect.unprotect(git, repo, pattern)
    if outcome.status == "still-versioned":
        raise CliError(
            "that pattern is still in .nbp-safe: remove it there first; this command only "
            "forgets patterns the file no longer has"
        )
    if outcome.status == "unknown":
        raise CliError("no such remembered pattern (`nbp-git-safe doctor` lists them)")
    protect.install_exclude_block(repo)
    _out("forgotten: the clone's memory of earlier versions of .nbp-safe no longer has it")
    if outcome.live:
        _err(
            f"nbp-git-safe: still protected through {' and '.join(outcome.live)}, which carry it: "
            "it stays protected until the commit that removes it from .nbp-safe is made (the "
            "guard refuses that commit unless you deliberately allow it, see docs/GUARD.md)"
        )
    else:
        _err(
            "nbp-git-safe: files already sealed stay in the vault; untracked ones are visible "
            "to `git add -A` from now on"
        )
    return EXIT_OK


def cmd_unlock(args: argparse.Namespace) -> int:
    if args.all:
        return fleetcli.run_all("unlock", args)
    repo, _git, cfg = _context(args)
    newly, status = unlock.unlock(
        repo.state_dir,
        cfg.key_command,
        ttl=cfg.ttl,
        idle_timeout=cfg.idle_timeout,
        key_timeout=cfg.key_command_timeout,
    )
    verb = "unlocked" if newly else "already unlocked"
    _out(f"{verb} (key {status['key_id']}), expires {_fmt_time(status['expires_at'])}")
    return EXIT_OK


def cmd_lock(args: argparse.Namespace) -> int:
    if args.all:
        return fleetcli.run_all("lock", args)
    repo, _git, _cfg = _context(args)
    _out("locked" if unlock.lock(repo.state_dir) else "agent was not running")
    return EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    if args.all:
        return fleetcli.run_all("status", args)
    repo, git, cfg = _context(args)
    status = unlock.current_status(repo.state_dir)
    remote = multi.remote_status(git, repo, cfg)
    if status is None or status["locked"]:
        _out("agent: locked (run `nbp-git-safe unlock`)")
        _report_remote(remote)
        return EXIT_LOCKED
    _out(f"agent: unlocked (key {status['key_id']}), expires {_fmt_time(status['expires_at'])}")
    with _connect(repo) as backend:
        state = vault.load_vault(git, backend, cfg, use_remote_fallback=True)
        tip = state.tip[:10] if state.tip else "none"
        _out(f"vault: {cfg.vault_ref} @ {tip} ({len(state.index.entries)} file(s))")
        analysis = vault.analyze(git, repo, cfg, backend, state)
    _report_remote(remote)
    summary = vault.status_summary(analysis)
    pending = {k: v for k, v in summary.items() if v}
    if not pending:
        _out("pending: nothing")
    for kind, paths in pending.items():
        _out(f"pending {kind}: {len(paths)}")
        for path in paths:
            _out(f"  {path}")
    for warning in analysis.warnings:
        _err(f"nbp-git-safe: warning: {warning}")
    return EXIT_OK


def _report_remote(remote: multi.RemoteStatus) -> None:
    if remote.kind == "no-remote":
        return
    _out(f"origin: {remote.message}")
    if remote.alarming:
        _err(f"nbp-git-safe: WARNING: {remote.message}")


def _asker() -> Callable[[str], bool] | None:
    if not sys.stdin or not sys.stdin.isatty():
        return None

    def ask(path: str) -> bool:
        return input(f"remove missing file {path!r} from the vault? [y/N] ").strip().lower() == "y"

    return ask


def cmd_seal(args: argparse.Namespace) -> int:
    if args.all:
        return fleetcli.run_all("seal", args)
    if args.push:
        raise CliError("--push goes with --all (for one repository: nbp-git-safe push)", EXIT_USAGE)
    repo, git, cfg = _context(args)
    with _connect(repo) as backend:
        commit, analysis, plan = vault.seal(git, repo, cfg, backend, ask=_asker())
    return _report_seal(commit, analysis, plan)


def _report_seal(commit: str | None, analysis: vault.Analysis, plan: vault.SealPlan | None) -> int:
    for warning in analysis.warnings:
        _err(f"nbp-git-safe: warning: {warning}")
    for path, reason in analysis.refused:
        _err(f"nbp-git-safe: refused {path!r}: {reason}")
    if commit is None:
        _out("nothing to seal")
    else:
        assert plan is not None
        moved = len(analysis.moved) + len(analysis.renamed)
        _out(
            f"sealed: {len(analysis.new)} new, {len(analysis.changed)} changed, "
            f"{moved} moved, {len(plan.removed_paths)} removed -> {commit[:10]}"
        )
    return EXIT_ERROR if analysis.refused else EXIT_OK


def cmd_open(args: argparse.Namespace) -> int:
    repo, git, cfg = _context(args)
    with _connect(repo) as backend:
        result = vault.open_vault(git, repo, cfg, backend, adopt=args.confirm_first_adopt)
    if (
        args.confirm_first_adopt
    ):  # the adopted tip is verified now: it is also the tip "seen" on origin
        remote = rev_parse(git, cfg.remote_vault_ref + "^{commit}")
        adopted = rev_parse(git, cfg.vault_ref + "^{commit}") or remote
        if remote is not None and remote == adopted and cfg.vault_ref not in multi.read_seen(repo):
            multi.record_seen(repo, cfg.vault_ref, remote)
    _out(f"opened: {len(result.written)} written, {result.unchanged} unchanged")
    for rel in result.theirs:
        _err(f"nbp-git-safe: local file differs; vault version saved as {rel!r}")
    for problem in result.errors:
        _err(f"nbp-git-safe: error: {problem}")
    return EXIT_ERROR if result.errors else EXIT_OK


def cmd_ls(args: argparse.Namespace) -> int:
    repo, git, cfg = _context(args)
    with _connect(repo) as backend:
        state = vault.load_vault(git, backend, cfg, use_remote_fallback=True)
    for entry in vault.list_entries(state):
        _out(f"{entry.size}\t{_fmt_time(entry.updated)}\t{entry.path}")
    return EXIT_OK


def cmd_log(args: argparse.Namespace) -> int:
    repo, git, cfg = _context(args)
    path = _relpath(repo, args.path, args)
    with _connect(repo) as backend:
        state = vault.load_vault(git, backend, cfg, use_remote_fallback=True)
        rows = vault.file_history(git, backend, state, path)
    for commit, ts, entry in rows:
        _out(f"{commit[:10]}\t{_fmt_time(ts)}\t{entry.size}\t{entry.path}")
    return EXIT_OK


def cmd_diff(args: argparse.Namespace) -> int:
    repo, git, cfg = _context(args)
    path = _relpath(repo, args.path, args)
    with _connect(repo) as backend:
        state = vault.load_vault(git, backend, cfg, use_remote_fallback=True)
        if args.from_commit:
            full = git.text("rev-parse", "--verify", "--end-of-options", args.from_commit).strip()
            state = vault.load_commit(git, backend, full)
        old = vault.vault_content(git, backend, state, path)
    try:
        new = (repo.toplevel / path).read_bytes()
    except OSError:
        raise CliError("the working-tree file does not exist") from None
    text = vault.diff_text(old, new, path)
    if text is None:
        return EXIT_OK
    sys.stdout.write(text)
    return 1 if args.exit_code else EXIT_OK


def cmd_mv(args: argparse.Namespace) -> int:
    repo, git, cfg = _context(args)
    old, new = _relpath(repo, args.old, args), _relpath(repo, args.new, args)
    src, dst = repo.toplevel / old, repo.toplevel / new
    if os.path.lexists(dst):
        raise CliError("the destination already exists")
    with _connect(repo) as backend:
        moved_on_disk = False
        if src.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            os.replace(src, dst)
            moved_on_disk = True
        try:
            commit, analysis, plan = vault.seal(git, repo, cfg, backend, renames={old: new})
        except BaseException:
            if moved_on_disk and dst.exists() and not src.exists():
                os.replace(dst, src)
            raise
    return _report_seal(commit, analysis, plan)


def cmd_rm(args: argparse.Namespace) -> int:
    repo, git, cfg = _context(args)
    path = _relpath(repo, args.path, args)
    local = repo.toplevel / path
    with _connect(repo) as backend:
        state = vault.load_vault(git, backend, cfg)
        _fid, entry = vault.find_entry(state, path)
        if (
            local.is_file()
            and not args.force
            and backend.mac(local.read_bytes()).hex() != entry.mac
        ):
            raise CliError("the local file has unsealed changes; seal first or use --force")
        commit, analysis, plan = vault.seal(git, repo, cfg, backend, forget=frozenset({entry.path}))
    if local.is_file():
        local.unlink()
    return _report_seal(commit, analysis, plan)


def cmd_sync(args: argparse.Namespace) -> int:
    repo, git, cfg = _context(args)
    with _connect(repo) as backend:
        result = multi.sync(
            git,
            repo,
            cfg,
            backend,
            fetch=not args.no_fetch,
            accept_rewrite=args.accept_remote_rewrite,
            confirm_adopt=args.confirm_first_adopt,
        )
        for note in result.notes:
            _err(f"nbp-git-safe: note: {note}")
        if result.sealed:
            _out(f"sealed local changes -> {result.sealed[:10]}")
        detail = f" -> {result.commit[:10]}" if result.commit else ""
        extra = f", {result.conflicts} conflict(s) kept as copies" if result.conflicts else ""
        _out(f"sync: {result.action}{detail}{extra}")
        if not args.no_open and rev_parse(git, cfg.vault_ref + "^{commit}"):
            opened = vault.open_vault(
                git, repo, cfg, backend, result.known_macs, adopt=args.confirm_first_adopt
            )
            _out(f"opened: {len(opened.written)} written, {opened.unchanged} unchanged")
            for rel in opened.theirs:
                _err(f"nbp-git-safe: local file differs; vault version saved as {rel!r}")
            for problem in opened.errors:
                _err(f"nbp-git-safe: error: {problem}")
            if opened.errors:
                return EXIT_ERROR
    return EXIT_OK


def cmd_push(args: argparse.Namespace) -> int:
    repo, git, cfg = _context(args)
    try:
        with _connect(repo) as backend:
            vault.seal(git, repo, cfg, backend)
    except (agent.AgentNotRunningError, agent.AgentLockedError, agent.AgentExpiredError):
        _err("nbp-git-safe: note: locked, so nothing new was sealed; pushing the vault as it is")
    tip = multi.push_vault(git, repo, cfg)
    _out(f"pushed {cfg.vault_ref} @ {tip[:10]} (no force)")
    return EXIT_OK


def _typed_confirmation(expected: str, given: str | None, what: str) -> None:
    """``--confirm`` text or, in a terminal, a prompt. Anything else is refused."""
    if given is None:
        if not sys.stdin or not sys.stdin.isatty():
            raise multi.ConfirmationError(
                f'{what} needs a typed confirmation: pass --confirm "{expected}"'
            )
        given = input(f'{what}: type "{expected}" to continue: ').strip()
    multi.check_confirmation(expected, given)


def cmd_rotate(args: argparse.Namespace) -> int:
    repo, git, cfg = _context(args)
    old_ref = cfg.vault_ref
    expected = multi.confirmation_text("delete", old_ref)
    if args.delete_old and args.confirm is not None:
        multi.check_confirmation(expected, args.confirm)  # fail before doing any work
    with _connect(repo) as backend:
        backend.key_id()  # fail closed (locked) before any key is generated or shown
        new_master = crypto.generate_key()
        _err(
            "nbp-git-safe: the NEW key is shown ONCE (stdout) and is not saved anywhere. Store it "
            "in your password manager now; the old branch stays until you delete it."
        )
        _out(crypto.encode_key(new_master))
        sys.stdout.flush()
        result = multi.rotate(git, repo, cfg, backend, new_master, name=args.name)
    new_key_id = crypto.KeySet(new_master).key_id
    del new_master
    short = result.ref.removeprefix("refs/heads/")
    _err(
        f"nbp-git-safe: {result.files} file(s) re-encrypted into {result.ref} @ "
        f"{result.tip[:10]} (verified with the new key; fresh file ids, no history)"
    )
    _err("next steps:")
    _err("  1. replace the key in your password manager item used by keyCommand")
    _err(f"  2. git config nbp-safe.vaultRef {result.ref}")
    _err("  3. nbp-git-safe lock && nbp-git-safe unlock")
    _err(f"  4. git push origin {short}   (never forced)")
    if args.delete_old:
        _typed_confirmation(expected, args.confirm, "delete the old local vault branch")
        _prove_new_key(cfg, new_key_id)
        multi.delete_old_vault(git, old_ref, result.old_tip)
        _err(
            f"nbp-git-safe: deleted local {old_ref}. Its objects stay until pruned; the "
            f"remote copy is deleted only by you: git push origin :{old_ref}"
        )
    else:
        _err("  5. when sure, delete the old branch yourself, or re-run with --delete-old")
    return EXIT_OK


def _prove_new_key(cfg: Config, new_key_id: bytes) -> None:
    """The old branch goes only after ``keyCommand`` is seen to return the NEW key (so the new key
    really is in the password manager item): in a terminal the user is asked to store it first."""
    if sys.stdin and sys.stdin.isatty():
        input("store the NEW key in the password manager item keyCommand reads, then press Enter: ")
    try:
        proven = unlock.run_key_command(cfg.key_command or (), cfg.key_command_timeout)
    except unlock.KeyCommandError as exc:
        raise CliError(
            f"the old branch was kept: keyCommand could not be checked ({exc})"
        ) from None
    if crypto.KeySet(proven).key_id != new_key_id:
        raise CliError(
            "the old branch was kept: keyCommand still returns another key. Store the new key in "
            "your password manager first; then delete the old branch yourself "
            "(git update-ref -d <old ref>)"
        )


def cmd_purge(args: argparse.Namespace) -> int:
    repo, git, cfg = _context(args)
    expected = multi.confirmation_text("purge", cfg.vault_ref)
    _err(
        "nbp-git-safe: purge REWRITES the local history of the vault branch to erase the chosen "
        "paths. The remote then needs a FORCED push, which this tool never does for you."
    )
    _typed_confirmation(expected, args.confirm, "purge")
    paths = [_relpath(repo, p, args) for p in args.paths]
    with _connect(repo) as backend:
        result = multi.purge(git, repo, cfg, backend, paths)
    noun = "entry" if len(result.removed_ids) == 1 else "entries"
    _out(
        f"purged {len(result.removed_ids)} {noun}; "
        f"{cfg.vault_ref} is now @ {(result.new_tip or '')[:10]}"
    )
    _err("nbp-git-safe: still to do by YOU (owner):")
    for line in multi.purge_instructions(cfg, result):
        _err(f"  {line}")
    _err(
        "nbp-git-safe: the plain file(s) in the working tree are untouched and would be sealed "
        "again: delete them or take them out of the protected set"
    )
    return EXIT_OK


# ------------------------------------------------------------------------- parser


def _all_flag(p: argparse.ArgumentParser, text: str) -> None:
    p.add_argument("--all", action="store_true", help=text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nbp-git-safe", description=__doc__)
    parser.add_argument("--version", action="version", version=f"nbp-git-safe {__version__}")
    parser.add_argument("-C", dest="directory", metavar="DIR", help="run as if started in DIR")
    sub = parser.add_subparsers(dest="command")

    def add(
        name: str, func: Callable[[argparse.Namespace], int], help_: str
    ) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_, description=help_)
        p.set_defaults(func=func)
        return p

    add("keygen", cmd_keygen, "print a new random key once (stdout) and store nothing")
    p = add("init", cmd_init, "prepare the repository (exclude block, hooks, vault branch)")
    p.add_argument("--generate-key", action="store_true", help="also print a new key (stdout only)")
    p.add_argument(
        "--gitignore-block",
        action="store_true",
        help="also write the managed block into the versioned .gitignore",
    )
    p.add_argument(
        "--shim",
        action="store_true",
        help="also install hook-file shims (for clients that ignore hooks set by git config)",
    )
    p.add_argument("--no-hooks", action="store_true", help="do not install any hook")
    p.add_argument(
        "--confirm-first-adopt",
        action="store_true",
        help="verify (agent unlocked) and adopt the vault found on origin of a fresh clone",
    )
    p.add_argument(
        "--auto-push",
        action="store_true",
        help="make a plain `git push` carry the vault branch (sets remote.origin.push)",
    )
    p = add("unlock", cmd_unlock, "run keyCommand and hand the key to the agent")
    p.add_argument("--ttl", help="agent lifetime, e.g. 8h, 30m (default 8h)")
    p.add_argument("--idle-timeout", dest="idle_timeout", help="lock after this much inactivity")
    _all_flag(p, "unlock every registered repository (one keyCommand run per distinct command)")
    p = add("lock", cmd_lock, "stop the agent (the key is gone)")
    _all_flag(p, "lock every registered repository")
    p = add("status", cmd_status, "agent and vault status")
    _all_flag(p, "status of every registered repository")
    p = add("seal", cmd_seal, "seal protected files into the vault branch")
    p.add_argument("--on-missing", dest="on_missing", choices=["keep", "remove", "ask"])
    p.add_argument("--pad-bucket", dest="pad_bucket")
    _all_flag(p, "seal every registered repository whose agent is unlocked (never unlocks)")
    p.add_argument(
        "--push",
        action="store_true",
        help="with --all: then push the vault branch (no force) where autoPush is set",
    )
    p = add("open", cmd_open, "materialize vault files at their real paths")
    p.add_argument("--confirm-first-adopt", action="store_true", help=ADOPT_HELP)
    add("ls", cmd_ls, "list files in the vault")
    p = add("log", cmd_log, "history of one file")
    p.add_argument("path")
    p = add("diff", cmd_diff, "diff of the vault version against the working file")
    p.add_argument("path")
    p.add_argument("--from", dest="from_commit", help="vault commit to compare (default: tip)")
    p.add_argument("--exit-code", action="store_true", help="exit 1 when there are differences")
    p = add("mv", cmd_mv, "move a protected file and keep its identity in the vault")
    p.add_argument("old")
    p.add_argument("new")
    p = add("rm", cmd_rm, "remove a file from the vault and delete it from the working tree")
    p.add_argument("path")
    p.add_argument("--force", action="store_true", help="even if the local file has unsealed edits")
    p = add("sync", cmd_sync, "fetch, merge (three-way, no force) and open the vault")
    p.add_argument("--confirm-first-adopt", action="store_true", help=ADOPT_HELP)
    p.add_argument("--no-fetch", action="store_true", help="merge what was already fetched")
    p.add_argument("--no-open", action="store_true", help="do not materialize files afterwards")
    p.add_argument(
        "--accept-remote-rewrite",
        action="store_true",
        help="proceed although origin's vault went backwards or was replaced (check first!)",
    )
    add("push", cmd_push, "push the vault branch to origin (never forced)")
    p = add("rotate", cmd_rotate, "re-encrypt the current state under a new key into a new branch")
    p.add_argument("--name", help="new branch name (default nbp-safe-<year>)")
    p.add_argument("--delete-old", action="store_true", help="then delete the old local branch")
    p.add_argument("--confirm", help='typed confirmation for --delete-old ("delete <branch>")')
    p = add("purge", cmd_purge, "erase paths from the whole vault history (typed confirmation)")
    p.add_argument("paths", nargs="+")
    p.add_argument("--confirm", help='typed confirmation ("purge <branch>")')
    p = add(
        "unprotect",
        cmd_unprotect,
        "forget a pattern (or every earlier version of .nbp-safe) that is only protected here "
        "by this clone's memory",
    )
    p.add_argument("pattern", nargs="?", help="the exact pattern line to forget")
    p.add_argument(
        "--accept-current",
        action="store_true",
        help="take the current .nbp-safe as the only base and forget every earlier version",
    )
    p.add_argument(
        "--confirm",
        help='typed confirmation ("unprotect <pattern>" / "unprotect --accept-current")',
    )
    p = add("hook", cmd_hook, "run a hook handler (called by git, not by hand)")
    p.add_argument("event", choices=hooks.EVENTS)
    p.add_argument("hook_args", nargs=argparse.REMAINDER)
    p = add("doctor", cmd_doctor, "check the setup and print actionable findings")
    _all_flag(p, "check every registered repository")
    p = add("uninstall", cmd_uninstall, "remove our hooks and exclude block (vault untouched)")
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    p = add(
        "registry", fleetcli.cmd_registry, "the per-user list of repositories (for --all, tray)"
    )
    p.set_defaults(registry_command=None)
    reg = p.add_subparsers(dest="registry_command")
    reg.add_parser("list", help="show the registered repositories")
    for name, text in (
        ("add", "register a repository (default: the current one)"),
        ("remove", "forget a repository (default: the current one)"),
    ):
        q = reg.add_parser(name, help=text)
        q.add_argument("path", nargs="?", help="a path inside the repository")
    reg.add_parser("prune", help="forget entries that are gone or are not git repositories")
    p = add("autostart", fleetcli.cmd_autostart, "start the tray at login (Windows)")
    p.set_defaults(autostart_command="status")
    auto = p.add_subparsers(dest="autostart_command")
    auto.add_parser("install", help="add the tray to your own startup (no administrator needed)")
    auto.add_parser("remove", help="remove it again")
    auto.add_parser("status", help="show whether it is installed")
    p = add("tray", fleetcli.cmd_tray, "status icon in the notification area (Windows)")
    p.add_argument(
        "--config",
        action="store_true",
        help="show (or, with name=value arguments, change) the tray configuration and exit",
    )
    p.add_argument("settings", nargs="*", metavar="name=value")
    return parser


def main(argv: Sequence[str] = ()) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(list(argv))
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else EXIT_USAGE
    if args.command is None:
        print(f"nbp-git-safe {__version__}")
        return EXIT_OK
    try:
        return int(args.func(args))
    except CliError as exc:
        _err(f"nbp-git-safe: error: {exc}")
        return exc.code
    except (agent.AgentNotRunningError, agent.AgentLockedError, agent.AgentExpiredError) as exc:
        _err(f"nbp-git-safe: error: {exc}")
        return EXIT_LOCKED
    except (
        agent.AgentError,
        crypto.NbpCryptoError,
        vault.VaultError,
        index_mod.IndexValidationError,
        unlock.KeyCommandError,
        ConfigError,
        GitError,
        OSError,
    ) as exc:
        _err(f"nbp-git-safe: error: {exc}")
        return EXIT_ERROR


def console() -> None:
    sys.exit(main(sys.argv[1:]))
