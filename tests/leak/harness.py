# SPDX-License-Identifier: MIT
"""Reusable leak-detection harness.

Given a set of random canaries (``CANARY_<n>_<rand>``) that were placed in file
contents AND file names of fake data, scan:

* a bare repository (every object via ``git cat-file --batch-all-objects --batch``,
  refs via ``for-each-ref``, ``packed-refs``, and every file of the directory),
* a local ``.git`` directory (same, plus loose files, config, info/, state),
* any directory (file contents and path names).

Every canary is searched in these encodings: UTF-8, UTF-16 LE/BE, base64 (standard
and URL-safe alphabets, at the 3 possible byte alignments) and hex (lower/upper).

The harness only ever reports *which* canary leaked, *where* and *in which encoding*;
it never prints the scanned data. It is proven to work by ``test_harness.py``, which
plants a canary on purpose in each of the three kinds of target.
"""

from __future__ import annotations

import base64
import os
import secrets
import subprocess
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Hit:
    where: str
    canary: str
    variant: str

    def __str__(self) -> str:
        return f"{self.canary} found as {self.variant} in {self.where}"


def make_canaries(count: int = 3) -> list[str]:
    """Fresh random canaries, e.g. ``CANARY_1_9f3a6c0e41b2d7aa``."""
    return [f"CANARY_{i}_{secrets.token_hex(8)}" for i in range(1, count + 1)]


def _b64_stable(canary: bytes, alignment: int, urlsafe: bool) -> bytes:
    """Base64 substring of ``canary`` that is independent of preceding bytes.

    ``alignment`` is the number of bytes (0-2) that precede the canary in the
    encoded stream; only characters whose 6 bits lie wholly inside the canary
    are kept (so the result is a substring of the encoding at that alignment).
    """
    encoder = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    encoded = encoder(b"\x00" * alignment + canary).rstrip(b"=")
    start = -(-8 * alignment // 6)
    end = (8 * (alignment + len(canary))) // 6
    return encoded[start:end]


def variants(canary: str) -> dict[str, bytes]:
    """All byte encodings of ``canary`` to search for, keyed by encoding name."""
    raw = canary.encode("utf-8")
    out: dict[str, bytes] = {
        "utf-8": raw,
        "utf-16le": canary.encode("utf-16-le"),
        "utf-16be": canary.encode("utf-16-be"),
        "hex-lower": raw.hex().encode("ascii"),
        "hex-upper": raw.hex().upper().encode("ascii"),
    }
    for alignment in range(3):
        out[f"base64-a{alignment}"] = _b64_stable(raw, alignment, urlsafe=False)
        out[f"base64url-a{alignment}"] = _b64_stable(raw, alignment, urlsafe=True)
    return out


class LeakScanner:
    """Scan targets for any of the canaries (in any encoding)."""

    def __init__(self, canaries: Sequence[str], git_env: Mapping[str, str] | None = None) -> None:
        if not canaries:
            raise ValueError("at least one canary is required")
        self.canaries = list(canaries)
        self._needles: list[tuple[str, str, bytes]] = [
            (canary, name, needle)
            for canary in self.canaries
            for name, needle in variants(canary).items()
        ]
        self._git_env = dict(git_env) if git_env is not None else dict(os.environ)

    # ------------------------------------------------------------------ primitives
    def scan_bytes(self, data: bytes, where: str) -> list[Hit]:
        return [
            Hit(where, canary, name) for canary, name, needle in self._needles if needle in data
        ]

    def scan_text_name(self, name: str, where: str) -> list[Hit]:
        """Scan a path/ref name (file names are as sensitive as contents)."""
        return self.scan_bytes(name.encode("utf-8", "surrogateescape"), f"{where} (name)")

    # ------------------------------------------------------------------- directory
    def scan_dir(self, root: Path | str) -> list[Hit]:
        """Scan every file's contents and every file/directory name under ``root``."""
        root = Path(root)
        hits: list[Hit] = []
        for dirpath, dirnames, filenames in os.walk(root):
            for entry in (*dirnames, *filenames):
                full = Path(dirpath, entry)
                rel = full.relative_to(root).as_posix()
                hits += self.scan_text_name(entry, rel)
            for filename in filenames:
                full = Path(dirpath, filename)
                rel = full.relative_to(root).as_posix()
                try:
                    data = full.read_bytes()
                except OSError:
                    continue
                hits += self.scan_bytes(data, rel)
        return hits

    # ------------------------------------------------------------------------- git
    def _git(self, git_dir: Path, *args: str) -> subprocess.Popen[bytes]:
        return subprocess.Popen(
            ["git", f"--git-dir={git_dir}", *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._git_env,
        )

    def _iter_objects(self, git_dir: Path) -> Iterator[tuple[str, str, bytes]]:
        """Yield (sha, type, decompressed content) for every object, reachable or not."""
        proc = self._git(git_dir, "cat-file", "--batch-all-objects", "--batch")
        assert proc.stdout is not None
        try:
            while True:
                header = proc.stdout.readline()
                if not header:
                    break
                sha, objtype, size = header.decode("ascii").split()
                content = proc.stdout.read(int(size))
                proc.stdout.read(1)  # trailing newline
                yield sha, objtype, content
        finally:
            proc.stdout.close()
            err = proc.stderr.read() if proc.stderr else b""
            code = proc.wait()
            if proc.stderr:
                proc.stderr.close()
        if code != 0:
            raise RuntimeError(f"git cat-file failed ({code}): {err.decode('utf-8', 'replace')}")

    def scan_objects(self, git_dir: Path | str) -> list[Hit]:
        hits: list[Hit] = []
        for sha, objtype, content in self._iter_objects(Path(git_dir)):
            hits += self.scan_bytes(content, f"object {sha[:12]} ({objtype})")
        return hits

    def scan_refs(self, git_dir: Path | str) -> list[Hit]:
        """Scan ref names/targets/tag+commit subjects via ``for-each-ref`` and packed-refs."""
        git_dir = Path(git_dir)
        proc = self._git(
            git_dir,
            "for-each-ref",
            "--format=%(refname)%00%(objectname)%00%(contents)%00%(taggername)%00%(authorname)",
        )
        out, err = proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"git for-each-ref failed: {err.decode('utf-8', 'replace')}")
        hits = self.scan_bytes(out, "for-each-ref")
        packed = git_dir / "packed-refs"
        if packed.is_file():
            hits += self.scan_bytes(packed.read_bytes(), "packed-refs")
        return hits

    def scan_git_dir(self, git_dir: Path | str) -> list[Hit]:
        """Scan a local ``.git`` directory: objects (loose and packed), refs and every file."""
        git_dir = Path(git_dir)
        return self.scan_objects(git_dir) + self.scan_refs(git_dir) + self.scan_dir(git_dir)

    def scan_bare_repo(self, repo: Path | str) -> list[Hit]:
        """Scan a bare repository (the 'remote'): objects, refs, packed-refs, all files."""
        return self.scan_git_dir(repo)


def assert_no_leaks(hits: Iterable[Hit]) -> None:
    """Fail with a report of canary/where/encoding only (never the scanned data)."""
    found = list(hits)
    assert not found, "canary leak(s) detected:\n" + "\n".join(f"  {h}" for h in found)
