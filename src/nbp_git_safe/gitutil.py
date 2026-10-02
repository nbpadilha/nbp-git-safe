# SPDX-License-Identifier: MIT
"""Thin, shell-free wrapper around the ``git`` executable (plumbing only).

Every call is an argv list executed without a shell. No clean/smudge filters are ever
configured or invoked by this tool; blobs are written with ``--no-filters``.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

STATE_DIRNAME = "nbp-safe"


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
            ["git", *args],  # noqa: S607 - git is resolved via PATH on purpose
            cwd=self.cwd,
            env=env,
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
            ["git", *args],  # noqa: S607
            cwd=self.cwd,
            env=env,
            input=input,
            capture_output=True,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def try_run(self, *args: str, input: bytes | None = None) -> bytes | None:
        """Return stdout, or ``None`` when git exits non-zero."""
        proc = subprocess.run(  # noqa: S603
            ["git", *args],  # noqa: S607
            cwd=self.cwd,
            env=self.env,
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
    proc = subprocess.Popen(
        ["git", "fast-import", "--quiet", "--done"],  # noqa: S607 - git is resolved via PATH
        cwd=git.cwd,
        env=git.env,
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


def is_ancestor(git: Git, ancestor: str, descendant: str) -> bool:
    """``ancestor`` is reachable from ``descendant`` (a commit is its own ancestor)."""
    code, _, _ = git.run_status("merge-base", "--is-ancestor", ancestor, descendant)
    return code == 0


def cat_blob(git: Git, spec: str) -> bytes:
    return git.run("cat-file", "blob", spec)


def chunked(items: Sequence[str], size: int) -> list[Sequence[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]
