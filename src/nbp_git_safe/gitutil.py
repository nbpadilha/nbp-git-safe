# SPDX-License-Identifier: MIT
"""Thin, shell-free wrapper around the ``git`` executable (plumbing only).

Every call is an argv list executed without a shell. No clean/smudge filters are ever
configured or invoked by this tool; blobs are written with ``--no-filters``.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import signal
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

STATE_DIRNAME = "nbp-safe"

# Variables that tie a git process to ONE repository. A hook in a linked worktree runs with
# ``GIT_DIR=<repo>/.git/worktrees/<name>`` (and commit hooks with ``GIT_INDEX_FILE``): a scratch
# repository created by this tool must never inherit them, or ``git init`` re-initialises the REAL
# repository. One list, used by everything that spawns a git that is not about the user's repo.
GIT_REPO_ENV = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_PREFIX",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_INTERNAL_SUPER_PREFIX",
    "GIT_GRAFT_FILE",
    "GIT_SHALLOW_FILE",
    "GIT_REPLACE_REF_BASE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_QUARANTINE_PATH",
)
_GIT_REPO_ENV_PREFIXES = ("GIT_PUSH_OPTION_",)

# Variables that inject configuration or make git run another program. They are dropped (with the
# repository-binding ones) only for the AUXILIARY git processes this tool starts about a scratch
# repository (``Git.clean``): those need none of the user's configuration, and a value planted in
# the environment of a hook (``GIT_CONFIG_COUNT``/``KEY_n``/``VALUE_n`` or
# ``GIT_CONFIG_PARAMETERS`` set ``core.fsmonitor``, ``core.hooksPath``, ``core.pager``...) must not
# run anything there. The calls about the USER'S repository keep the whole environment: fetch,
# push and ``git config`` legitimately depend on ``GIT_ASKPASS``, ``GIT_SSH_COMMAND``,
# ``GIT_CONFIG_*`` and friends. ``GIT_CONFIG_GLOBAL``/``GIT_CONFIG_SYSTEM``/``GIT_CONFIG_NOSYSTEM``
# stay: they only choose WHICH config files are read (the tests' isolation uses them).
GIT_INJECTION_ENV = (
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_EXTERNAL_DIFF",
    "GIT_PAGER",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_EDITOR",
    "GIT_SEQUENCE_EDITOR",
    "GIT_PROXY_COMMAND",
)
_GIT_INJECTION_PREFIXES = ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_", "GIT_TRACE")


NO_CWD_EXE = "NoDefaultCurrentDirectoryInExePath"
CREATE_NO_WINDOW = 0x08000000
_hide_windows = False


def hide_child_windows(on: bool = True) -> None:
    """A process without a console (the tray runs under ``pythonw``) must start its console children
    (git, the key command) with ``CREATE_NO_WINDOW``, or each one flashes a console window."""
    global _hide_windows
    _hide_windows = on


def window_flags() -> dict[str, int]:
    """``creationflags`` for a child process (empty unless ``hide_child_windows`` was called)."""
    if _hide_windows and sys.platform == "win32":
        return {"creationflags": CREATE_NO_WINDOW}
    return {}


def _norm(path: str | os.PathLike[str]) -> str:
    return os.path.normcase(os.path.realpath(path))


def _cwd() -> str:
    """The normalised current directory ("" when it no longer exists: then nothing equals it)."""
    try:
        return _norm(os.getcwd())
    except OSError:
        return ""


def _inside(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def repository_root_of(start: str | os.PathLike[str]) -> str | None:
    """The nearest directory at or above ``start`` that has a ``.git`` entry (a directory, or the
    file of a linked worktree), or ``None`` outside any repository. Found by walking up, not by
    running git (this is used to decide WHICH git to run)."""
    current = _norm(start)
    while True:
        if os.path.lexists(os.path.join(current, ".git")):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent


def resolve_executable(
    name: str,
    env: Mapping[str, str] | None = None,
    *,
    avoid: Sequence[str | os.PathLike[str]] = (),
) -> str:
    """Absolute path of ``name`` found on ``PATH``, never in the current directory and never inside
    the repository tree.

    Windows' ``CreateProcess`` (and so ``subprocess``) looks in the CURRENT directory before
    ``PATH``: a ``git.exe`` planted in a repository's working tree would run instead of git. Empty
    and relative ``PATH`` entries are skipped, as is any entry that is the current directory, and
    any entry INSIDE the tree of the repository around the current directory or of the
    repositories in ``avoid`` (a project's ``node_modules/.bin`` or ``bin/``, put on ``PATH`` by
    an activated environment, is as hostile as the working directory itself). A name that already
    has a directory part is returned unchanged; when nothing is found the bare name is returned
    (children still get ``NoDefaultCurrentDirectoryInExePath=1``)."""
    if os.path.dirname(name):
        return name
    source = os.environ if env is None else env
    cwd = _cwd()
    roots = [_norm(path) for path in avoid]
    around = repository_root_of(cwd) if cwd else None
    if around is not None:
        roots.append(around)
    exts = [""]
    if sys.platform == "win32":
        exts = [e.lower() for e in source.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";") if e]
        if os.path.splitext(name)[1].lower() in exts:
            exts = [""]
    for entry in source.get("PATH", "").split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            continue
        real = _norm(entry)
        if real == cwd or any(_inside(real, root) for root in roots):
            continue
        for ext in exts:
            candidate = os.path.join(entry, name + ext)
            if os.path.isfile(candidate) and (
                sys.platform == "win32" or os.access(candidate, os.X_OK)
            ):
                return candidate
    return name


_untrusted_roots: list[str] = []
_git_exe: dict[tuple[str, ...], str] = {}


def declare_repository(toplevel: str | os.PathLike[str]) -> None:
    """Tell ``git_executable`` that ``toplevel`` is a repository whose tree must not provide the
    git to run (``nbp-git-safe -C <repo>`` runs from anywhere, so the current directory says
    nothing about it)."""
    root = _norm(toplevel)
    if root not in _untrusted_roots:
        _untrusted_roots.append(root)


def git_executable() -> str:
    """The git to run, resolved once per set of repositories (see ``resolve_executable``)."""
    key = (_cwd(), *_untrusted_roots)
    if key not in _git_exe:
        _git_exe[key] = resolve_executable("git", avoid=_untrusted_roots)
    return _git_exe[key]


def child_env(env: Mapping[str, str]) -> dict[str, str]:
    """``env`` plus ``NoDefaultCurrentDirectoryInExePath=1`` for a child process."""
    return {**env, NO_CWD_EXE: "1"}


def clean_env(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """A copy of ``env`` (default: the process environment) without the repository-binding git
    variables (``GIT_REPO_ENV``) and without the ones that inject configuration or programs
    (``GIT_INJECTION_ENV``). Identity, the choice of config files and locale variables are kept."""
    source = os.environ if env is None else env
    drop = set(GIT_REPO_ENV) | set(GIT_INJECTION_ENV)
    prefixes = _GIT_REPO_ENV_PREFIXES + _GIT_INJECTION_PREFIXES
    return {k: v for k, v in source.items() if k not in drop and not k.startswith(prefixes)}


class GitError(Exception):
    """A git invocation failed (message carries git's own stderr, never file contents)."""


class GitTimeoutError(GitError):
    """A git invocation did not finish within its time limit and was stopped (with its children)."""


def _taskkill() -> str:
    root = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or r"C:\Windows"
    return str(Path(root) / "System32" / "taskkill.exe")


def kill_tree(proc: subprocess.Popen[bytes]) -> None:
    """Stop ``proc`` AND everything it started (an ``ssh`` or a credential helper holding the pipes
    open would otherwise keep a ``communicate`` waiting after the parent was killed). On POSIX the
    child must have been started with ``start_new_session=True``."""
    if sys.platform == "win32":
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            subprocess.run(  # noqa: S603
                [_taskkill(), "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=15,
                **window_flags(),
            )
    else:
        with contextlib.suppress(OSError, ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)  # type: ignore[attr-defined]
    with contextlib.suppress(OSError):
        proc.kill()


def _execute(
    args: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    input: bytes | None,
    timeout: float | None,
) -> tuple[int, bytes, bytes]:
    """Run ``git <args>`` and return ``(exit code, stdout, stderr)``. Without ``timeout`` this is a
    plain ``subprocess.run``. With one the process is started in its own group and, when the time
    is up, the WHOLE tree is killed (``GitTimeoutError``): ``subprocess.run(timeout=...)`` kills
    only the direct child and then waits for pipes that a grandchild still holds."""
    argv = [git_executable(), *args]
    if timeout is None:
        done = subprocess.run(  # noqa: S603 - argv list, no shell
            argv,
            cwd=cwd,
            env=child_env(env),
            input=input,
            capture_output=True,
            check=False,
            **window_flags(),
        )
        return done.returncode, done.stdout, done.stderr
    kwargs: dict[str, Any] = dict(window_flags())
    if sys.platform != "win32":
        kwargs["start_new_session"] = True
    child = subprocess.Popen(  # noqa: S603 - argv list, no shell
        argv,
        cwd=cwd,
        env=child_env(env),
        stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **kwargs,
    )
    try:
        out, err = child.communicate(input, timeout=timeout)
    except subprocess.TimeoutExpired:
        kill_tree(child)
        with contextlib.suppress(Exception):
            child.communicate(timeout=5)
        raise GitTimeoutError(
            f"git {args[0] if args else ''} did not finish within {timeout:g} s and was stopped"
        ) from None
    except BaseException:
        kill_tree(child)
        raise
    return child.returncode, out, err


# What a git that talks to a remote from a BACKGROUND process (the tray, ``seal --all --push``)
# runs on: nothing may wait for a person. ``ConnectTimeout`` and ``ServerAlive*`` make a dead
# ``ssh`` give up by itself; the hard limit of ``_execute`` is the backstop.
SSH_NONINTERACTIVE = (
    "ssh -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=3"
)
PUSH_TIMEOUT = 120.0  # seconds, for the background push
FOREGROUND_TIMEOUT = 600.0  # seconds, for a push or fetch a person started and may be watching


@dataclass(frozen=True)
class Repo:
    """Resolved locations of a repository (worktree-aware)."""

    toplevel: Path
    git_dir: Path
    common_dir: Path

    @property
    def state_dir(self) -> Path:
        """``<common-dir>/nbp-safe``: shared by all worktrees of the repository."""
        return self.common_dir / STATE_DIRNAME


class Git:
    """Run git in ``cwd`` with an optional environment."""

    def __init__(self, cwd: Path | str, env: Mapping[str, str] | None = None) -> None:
        self.cwd = Path(cwd)
        self.env = dict(env) if env is not None else dict(os.environ)

    def run(
        self,
        *args: str,
        input: bytes | None = None,
        extra_env: Mapping[str, str] | None = None,
        check: bool = True,
        timeout: float | None = None,
    ) -> bytes:
        env = self.env
        if extra_env:
            env = {**env, **extra_env}
        code, out, err = _execute(args, cwd=self.cwd, env=env, input=input, timeout=timeout)
        if check and code != 0:
            detail = err.decode("utf-8", "replace").strip().splitlines()
            raise GitError(f"git {args[0]} failed ({code}): {' '.join(detail[:3])}")
        return out

    def text(self, *args: str, **kwargs: object) -> str:
        return self.run(*args, **kwargs).decode("utf-8", "surrogateescape")  # type: ignore[arg-type]

    def run_status(
        self,
        *args: str,
        input: bytes | None = None,
        extra_env: Mapping[str, str] | None = None,
        timeout: float | None = None,
    ) -> tuple[int, bytes, bytes]:
        """Run git and return ``(exit code, stdout, stderr)`` without raising (a ``timeout`` that
        runs out raises ``GitTimeoutError`` after the whole process tree was killed)."""
        env = {**self.env, **extra_env} if extra_env else self.env
        return _execute(args, cwd=self.cwd, env=env, input=input, timeout=timeout)

    def clean(self, cwd: Path | str) -> Git:
        """A ``Git`` for another directory (a scratch repository) with a clean environment."""
        return Git(cwd, clean_env(self.env))

    def try_run(self, *args: str, input: bytes | None = None) -> bytes | None:
        """Return stdout, or ``None`` when git exits non-zero."""
        code, out, _err = _execute(args, cwd=self.cwd, env=self.env, input=input, timeout=None)
        return out if code == 0 else None


def ssh_is_user_defined(git: Git) -> bool:
    """Did the user choose how git runs ssh (``GIT_SSH_COMMAND``, ``GIT_SSH`` or
    ``core.sshCommand``)? That choice is never overridden."""
    if git.env.get("GIT_SSH_COMMAND") or git.env.get("GIT_SSH"):
        return True
    configured = git.try_run("config", "--get", "core.sshCommand")
    return bool(configured and configured.strip())


def network_env(env: Mapping[str, str], *, ssh_default: bool = True) -> dict[str, str]:
    """``env`` for a git process that reaches a remote without anyone watching: no terminal prompt
    (``GIT_TERMINAL_PROMPT=0``), no Git Credential Manager window (``GCM_INTERACTIVE=never``), slow
    HTTP transfers abandoned, and (``ssh_default``: the user chose no ssh command) an ``ssh`` that
    never asks and gives up on a dead connection."""
    merged = dict(env)
    merged["GIT_TERMINAL_PROMPT"] = "0"
    merged["GCM_INTERACTIVE"] = "never"
    merged.setdefault("GIT_HTTP_LOW_SPEED_LIMIT", "1000")
    merged.setdefault("GIT_HTTP_LOW_SPEED_TIME", "60")
    if ssh_default:
        merged["GIT_SSH_COMMAND"] = SSH_NONINTERACTIVE
    return merged


def discover(cwd: Path | str, env: Mapping[str, str] | None = None) -> tuple[Repo, Git]:
    """Locate the repository around ``cwd`` (also from a linked worktree)."""
    git = Git(cwd, env)
    try:
        out = git.text(
            "rev-parse",
            "--path-format=absolute",
            "--show-toplevel",
            "--git-dir",
            "--git-common-dir",
        )
    except GitError:
        raise GitError("not inside a git work tree") from None
    lines = out.splitlines()
    if len(lines) != 3:
        raise GitError("unexpected output from git rev-parse")
    repo = Repo(Path(lines[0]), Path(lines[1]), Path(lines[2]))
    declare_repository(repo.toplevel)
    return repo, Git(repo.toplevel, env)


def split_z(data: bytes) -> list[str]:
    """Split NUL-terminated git output into decoded strings (no empty trailing item)."""
    return [p.decode("utf-8", "surrogateescape") for p in data.split(b"\0") if p]


def hash_object(git: Git, data: bytes) -> str:
    """Write ``data`` as a blob without any filter and return its object id."""
    return git.text("hash-object", "-w", "--stdin", "--no-filters", input=data).strip()


def _object_format(git: Git) -> str:
    out = git.try_run("rev-parse", "--show-object-format")
    return out.decode("ascii").strip() if out else "sha1"


def hash_objects(git: Git, blobs: Sequence[bytes]) -> list[str]:
    """Write many blobs (no filter) with ONE ``git fast-import`` process; return their ids in order.

    ``hash-object -w`` costs a process per blob (about 40 ms on Windows), which made the first seal
    of thousands of files take minutes. The ids are computed here (SHA-1 object format; any other
    format falls back to one ``hash-object`` per blob) and then checked against the object
    database: an id git cannot find is an error, never a guess."""
    if not blobs:
        return []
    if _object_format(git) != "sha1":
        return [hash_object(git, blob) for blob in blobs]
    ids = [
        hashlib.sha1(b"blob %d\0" % len(blob) + blob, usedforsecurity=False).hexdigest()
        for blob in blobs
    ]
    proc = subprocess.Popen(  # noqa: S603 - argv list, no shell
        [git_executable(), "fast-import", "--quiet", "--done"],
        cwd=git.cwd,
        env=child_env(git.env),
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        **window_flags(),
    )
    if proc.stdin is None or proc.stderr is None:
        raise GitError("git fast-import: no pipes")
    try:
        for blob in blobs:
            proc.stdin.write(b"blob\ndata %d\n" % len(blob))
            proc.stdin.write(blob)
            proc.stdin.write(b"\n")
        proc.stdin.write(b"done\n")
        proc.stdin.close()
    except OSError:  # BrokenPipeError: git exited early, its stderr says why
        pass
    err = proc.stderr.read()
    code = proc.wait()
    proc.stderr.close()
    if code != 0:
        detail = err.decode("utf-8", "replace").strip().splitlines()
        raise GitError(f"git fast-import failed ({code}): {' '.join(detail[:3])}")
    wanted = "".join(f"{sha}\n" for sha in ids).encode("ascii")
    checked = git.text("cat-file", "--batch-check", input=wanted).splitlines()
    if len(checked) != len(ids) or any(" blob " not in line for line in checked):
        raise GitError("git fast-import did not store every blob")
    return ids


def rev_parse(git: Git, rev: str) -> str | None:
    out = git.try_run("rev-parse", "--verify", "-q", "--end-of-options", rev)
    return out.decode("ascii").strip() if out else None


def rev_exists(git: Git, rev: str) -> bool:
    """Does ``rev`` name a commit? ``False`` only for "no such revision" (for example an unborn
    ``HEAD``); any other git failure raises, so a broken repository never reads as "absent"."""
    code, _, _ = git.run_status(
        "rev-parse", "--verify", "-q", "--end-of-options", rev + "^{commit}"
    )
    if code == 0:
        return True
    if code == 1:
        return False
    raise GitError(f"git rev-parse failed ({code})")


def optional_blob(git: Git, path: str, rev: str | None = None) -> bytes | None:
    """Content of ``path`` (repo-relative) at ``rev``, or in the index when ``rev`` is ``None``.

    ``None`` means exactly "that path does not exist there". Every other failure raises
    ``GitError``: the callers are security checks and must not treat a broken repository as an
    empty answer (``try_run`` cannot tell the two apart)."""
    if rev is None:
        code, out, _ = git.run_status("ls-files", "-s", "-z", "--", path)
    else:
        if not rev_exists(git, rev):
            return None
        code, out, _ = git.run_status("ls-tree", "-z", "--full-tree", rev, "--", path)
    if code != 0:
        raise GitError(f"git could not look up the pattern file ({code})")
    record = out.split(b"\0", 1)[0]
    if not record:
        return None
    meta = record.partition(b"\t")[0].split(b" ")
    sha = (meta[1] if rev is None else meta[2]).decode("ascii", "replace")
    return git.run("cat-file", "blob", sha)


def is_ancestor(git: Git, ancestor: str, descendant: str) -> bool:
    """``ancestor`` is reachable from ``descendant`` (a commit is its own ancestor)."""
    code, _, _ = git.run_status("merge-base", "--is-ancestor", ancestor, descendant)
    return code == 0


def cat_blob(git: Git, spec: str) -> bytes:
    return git.run("cat-file", "blob", spec)


def chunked(items: Sequence[str], size: int) -> list[Sequence[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]
