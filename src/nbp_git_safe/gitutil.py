# SPDX-License-Identifier: MIT
"""Thin, shell-free wrapper around the ``git`` executable (plumbing only).

Every call is an argv list executed without a shell. No clean/smudge filters are ever
configured or invoked by this tool; blobs are written with ``--no-filters``.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

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


NO_CWD_EXE = "NoDefaultCurrentDirectoryInExePath"


def resolve_executable(name: str, env: Mapping[str, str] | None = None) -> str:
    """Absolute path of ``name`` found on ``PATH``, never in the current directory.

    Windows' ``CreateProcess`` (and so ``subprocess``) looks in the CURRENT directory before
    ``PATH``: a ``git.exe`` planted in a repository's working tree would run instead of git. Empty
    and relative ``PATH`` entries are skipped, as is any entry that is the current directory. A
    name that already has a directory part is returned unchanged; when nothing is found the bare
    name is returned (children still get ``NoDefaultCurrentDirectoryInExePath=1``)."""
    if os.path.dirname(name):
        return name
    source = os.environ if env is None else env
    cwd = os.path.normcase(os.path.realpath(os.getcwd()))
    exts = [""]
    if sys.platform == "win32":
        exts = [e.lower() for e in source.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";") if e]
        if os.path.splitext(name)[1].lower() in exts:
            exts = [""]
    for entry in source.get("PATH", "").split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            continue
        if os.path.normcase(os.path.realpath(entry)) == cwd:
            continue
        for ext in exts:
            candidate = os.path.join(entry, name + ext)
            if os.path.isfile(candidate) and (
                sys.platform == "win32" or os.access(candidate, os.X_OK)
            ):
                return candidate
    return name


_git_exe: list[str] = []


def git_executable() -> str:
    """The git to run, resolved once (see ``resolve_executable``)."""
    if not _git_exe:
        _git_exe.append(resolve_executable("git"))
    return _git_exe[0]


def child_env(env: Mapping[str, str]) -> dict[str, str]:
    """``env`` plus ``NoDefaultCurrentDirectoryInExePath=1`` for a child process."""
    return {**env, NO_CWD_EXE: "1"}


def clean_env(env: Mapping[str, str] | None = None) -> dict[str, str]:
    """A copy of ``env`` (default: the process environment) without the repository-binding git
    variables (``GIT_REPO_ENV``). Identity, config and locale variables are kept."""
    source = os.environ if env is None else env
    drop = set(GIT_REPO_ENV)
    return {
        k: v
        for k, v in source.items()
        if k not in drop and not k.startswith(_GIT_REPO_ENV_PREFIXES)
    }


class GitError(Exception):
    """A git invocation failed (message carries git's own stderr, never file contents)."""


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
    ) -> bytes:
        env = self.env
        if extra_env:
            env = {**env, **extra_env}
        proc = subprocess.run(  # noqa: S603 - argv list, no shell
            [git_executable(), *args],
            cwd=self.cwd,
            env=child_env(env),
            input=input,
            capture_output=True,
            check=False,
        )
        if check and proc.returncode != 0:
            detail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
            raise GitError(f"git {args[0]} failed ({proc.returncode}): {' '.join(detail[:3])}")
        return proc.stdout

    def text(self, *args: str, **kwargs: object) -> str:
        return self.run(*args, **kwargs).decode("utf-8", "surrogateescape")  # type: ignore[arg-type]

    def run_status(
        self,
        *args: str,
        input: bytes | None = None,
        extra_env: Mapping[str, str] | None = None,
    ) -> tuple[int, bytes, bytes]:
        """Run git and return ``(exit code, stdout, stderr)`` without raising."""
        env = {**self.env, **extra_env} if extra_env else self.env
        proc = subprocess.run(  # noqa: S603 - argv list, no shell
            [git_executable(), *args],
            cwd=self.cwd,
            env=child_env(env),
            input=input,
            capture_output=True,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def clean(self, cwd: Path | str) -> Git:
        """A ``Git`` for another directory (a scratch repository) with a clean environment."""
        return Git(cwd, clean_env(self.env))

    def try_run(self, *args: str, input: bytes | None = None) -> bytes | None:
        """Return stdout, or ``None`` when git exits non-zero."""
        proc = subprocess.run(  # noqa: S603
            [git_executable(), *args],
            cwd=self.cwd,
            env=child_env(self.env),
            input=input,
            capture_output=True,
            check=False,
        )
        return proc.stdout if proc.returncode == 0 else None


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
