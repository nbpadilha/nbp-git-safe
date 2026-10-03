# SPDX-License-Identifier: MIT
"""Guard on the main branch: keep protected files (and their content) out of ordinary commits
and pushes, and refuse to push a vault branch that is not a valid vault.

Layers (defence in depth, see ``PLAN-SPEC.md``):

1. the managed exclude block (``protect.py``) keeps ``git add -A`` away from protected files;
2. ``pre-commit`` by PATH: a staged file that matches the protected set is refused;
3. ``pre-commit`` by CONTENT (agent unlocked): a staged blob whose MAC equals the MAC of a
   protected file (sealed in the vault or present in the working tree) is refused, which catches a
   renamed or copied file;
4. ``pre-push`` repeats 2 and 3 over every commit that would be sent, and validates the vault
   branch being sent (allowed paths only, magic on every blob, known ``.gitattributes``/README);
5. an optional managed block in the versioned ``.gitignore``.

``git commit --no-verify`` skips layers 2-4 but not 1 (``git add -A`` stays safe); ``git add -f``
followed by ``--no-verify`` leaks (documented limit, see ``docs/GUARD.md``).

Nothing here prints file contents; messages name only paths of the user's own working tree.
"""

from __future__ import annotations

import os
import re
import unicodedata
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from nbp_git_safe import crypto, protect, vault
from nbp_git_safe import index as index_mod
from nbp_git_safe.config import Config
from nbp_git_safe.gitutil import (
    Git,
    GitError,
    Repo,
    chunked,
    is_ancestor,
    optional_blob,
    rev_parse,
)

ALLOW_UNPROTECT_ENV = "NBP_SAFE_ALLOW_UNPROTECT"
VERSIONED_PATTERNS = protect.VERSIONED_PATTERNS
_ZERO_RE = re.compile(r"^0+$")
_OID_RE = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
GITLINK_MODE = "160000"
MAX_LISTED = 20  # violations listed per kind before "and N more"
BATCH = 200
# Content check: files shorter than this are not fingerprinted. A whole-file match on a
# handful of bytes ("1\n", "{}\n", a VERSION file) says nothing about being a copy and
# would block ordinary files; sensitive files are larger.
MIN_FINGERPRINT_SIZE = 16


class GuardBackend(Protocol):
    """The part of the key agent the guard uses (``agent.AgentClient`` implements it)."""

    def mac(self, data: bytes) -> bytes: ...
    def key_id(self) -> bytes: ...
    def enc_blob(self, file_id: str, data: bytes, bucket: int = ...) -> bytes: ...
    def dec_blob(self, file_id: str, blob: bytes) -> bytes: ...
    def enc_index(self, index: dict, bucket: int = ...) -> bytes: ...  # type: ignore[type-arg]
    def dec_index(self, blob: bytes) -> dict: ...  # type: ignore[type-arg]


@dataclass(frozen=True)
class Violation:
    kind: str  # "path" | "content" | "unprotect" | "vault"
    subject: str  # a path of the user's tree, or a short commit id; never file content
    detail: str

    def render(self) -> str:
        return (
            f"{self.kind}: {self.subject}: {self.detail}"
            if self.subject
            else (f"{self.kind}: {self.detail}")
        )


@dataclass
class Report:
    violations: list[Violation] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.violations

    def extend(self, other: Report) -> None:
        self.violations.extend(other.violations)
        self.warnings.extend(other.warnings)


# ------------------------------------------------------------------------ small git helpers


@dataclass(frozen=True)
class Change:
    path: str
    mode: str
    sha: str
    status: str
    commit: str | None = None


def parse_raw(out: bytes) -> list[Change]:
    """Parse ``--raw -z`` output of ``diff``/``diff-tree`` (``diff-tree --stdin`` also emits the
    commit id before each group)."""
    tokens = out.split(b"\0")
    changes: list[Change] = []
    commit: str | None = None
    i = 0
    while i < len(tokens):
        token = tokens[i]
        i += 1
        if not token:
            continue
        if token.startswith(b":"):
            meta = token[1:].decode("ascii", "replace").split(" ")
            if len(meta) != 5 or i >= len(tokens):
                continue
            path = tokens[i].decode("utf-8", "surrogateescape")
            i += 1
            changes.append(Change(path, meta[1], meta[3], meta[4][:1], commit))
        else:
            text = token.decode("ascii", "replace").strip()
            if _OID_RE.match(text):
                commit = text
    return changes


def staged_changes(git: Git, filter_: str = "ACMRT") -> list[Change]:
    """Files added/modified/copied/type-changed in the index relative to HEAD (a rename is
    reported as an addition of the new path; works on an unborn branch)."""
    out = git.run(
        "diff",
        "--cached",
        "--raw",
        "-z",
        "--no-renames",
        "--no-abbrev",
        f"--diff-filter={filter_}",
    )
    return [c for c in parse_raw(out) if c.mode != GITLINK_MODE]


def blob_sizes(git: Git, shas: Iterable[str]) -> dict[str, int]:
    unique = list(dict.fromkeys(shas))
    sizes: dict[str, int] = {}
    for chunk in chunked(unique, 1000):
        out = git.text(
            "cat-file",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
            input=("\n".join(chunk) + "\n").encode("ascii"),
        )
        for line in out.splitlines():
            parts = line.split(" ")
            if len(parts) == 3 and parts[1] == "blob" and parts[2].isdigit():
                sizes[parts[0]] = int(parts[2])
    return sizes


def read_blobs(git: Git, shas: Sequence[str]) -> Iterator[tuple[str, bytes]]:
    """Yield ``(sha, content)`` for each blob (in chunks, to bound memory)."""
    for chunk in chunked(list(dict.fromkeys(shas)), 50):
        out = git.run("cat-file", "--batch", input=("\n".join(chunk) + "\n").encode("ascii"))
        pos = 0
        while pos < len(out):
            end = out.index(b"\n", pos)
            header = out[pos:end].decode("ascii", "replace").split(" ")
            pos = end + 1
            if len(header) != 3 or not header[2].isdigit():
                continue  # "<sha> missing"
            size = int(header[2])
            yield header[0], out[pos : pos + size]
            pos += size + 1


# ------------------------------------------------------------------------- protected set


def pattern_sources(
    git: Git, repo: Repo, revs: Iterable[str] = (), *, refresh: bool = True
) -> list[bytes]:
    """Every version of the pattern files that counts: ``.nbp-safe`` at HEAD, in the index, in
    the working tree and at ``revs`` (pushed tips), the local ``.git/info/nbp-safe`` and every
    earlier version of ``.nbp-safe`` this clone has seen (``protect.record_versions``). Each is
    matched on its own and the results are unioned (a removal, a local negation or a negation
    that only a newer version has never unprotects). Versions another one already covers are
    dropped (they add nothing). ``refresh=False`` leaves the memory alone (read-only callers)."""
    texts: list[bytes] = []
    local_versions: list[bytes] = []
    for rev in ("HEAD", None, *revs):  # None: the index
        data = optional_blob(git, VERSIONED_PATTERNS, rev)  # raises on a broken repository
        if data is not None:
            texts.append(data)
            if rev in ("HEAD", None):
                local_versions.append(data)
    if refresh:
        protect.record_versions(repo, local_versions)
    texts.extend(protect.pattern_texts(repo))
    unique = [t for t in dict.fromkeys(protect.normalize_pattern_text(t) for t in texts) if t]
    keep = protect.prune_dominated([protect.lines_of(t) for t in unique])
    return [unique[i] for i in keep]


def protected_among(git: Git, sources: Sequence[bytes], paths: Iterable[str]) -> set[str]:
    """Which of ``paths`` are protected. Git compares bytes, so a name in another Unicode form
    (macOS writes NFD, most patterns are typed NFC) would slip past a pattern: every path is also
    matched in its NFC and NFD forms, and counts as protected if any form matches."""
    originals = list(dict.fromkeys(paths))
    forms = {
        p: {p, unicodedata.normalize("NFC", p), unicodedata.normalize("NFD", p)} for p in originals
    }
    query = sorted({form for variants in forms.values() for form in variants})
    matched = protect.match_paths_texts(git, sources, query)
    return {p for p, variants in forms.items() if variants & matched}


@dataclass
class Fingerprints:
    """MACs of the protected content: sealed in the vault or present in the working tree."""

    macs: dict[str, int] = field(default_factory=dict)  # mac hex -> size
    paths: set[str] = field(default_factory=set)  # collision keys (NFC, case-folded) of the index

    @property
    def sizes(self) -> set[int]:
        return set(self.macs.values())

    def has_path(self, path: str) -> bool:
        return index_mod.collision_key(path) in self.paths


def protected_fingerprints(
    git: Git, repo: Repo, cfg: Config, backend: GuardBackend
) -> Fingerprints:
    """Vault index entries plus the protected files currently on disk (the stat cache makes the
    latter cheap). Files shorter than ``MIN_FINGERPRINT_SIZE`` are ignored (empty files,
    ``.gitkeep`` and one-line placeholders would match unrelated files)."""
    state = vault.load_vault(git, backend, cfg)  # type: ignore[arg-type]
    prints = Fingerprints()
    for entry in state.index.entries.values():
        prints.paths.add(index_mod.collision_key(entry.path))
        if entry.size >= MIN_FINGERPRINT_SIZE:
            prints.macs[entry.mac] = entry.size
    analysis = vault.analyze(git, repo, cfg, backend, state)  # type: ignore[arg-type]
    for obs in analysis.observed.values():
        if obs.mac is not None and obs.size >= MIN_FINGERPRINT_SIZE:
            prints.macs.setdefault(obs.mac, obs.size)
    return prints


def content_violations(
    git: Git, backend: GuardBackend, prints: Fingerprints, changes: Sequence[Change]
) -> list[Violation]:
    """Staged/pushed blobs whose MAC equals protected content (a renamed or copied file)."""
    if not prints.macs or not changes:
        return []
    sizes = blob_sizes(git, (c.sha for c in changes))
    wanted = prints.sizes
    candidates = [s for s, n in sizes.items() if n in wanted and n <= crypto.MAX_DATA_SIZE]
    matched = {
        sha for sha, data in read_blobs(git, candidates) if backend.mac(data).hex() in prints.macs
    }
    seen: set[tuple[str, str | None]] = set()
    found: list[Violation] = []
    for change in changes:
        key = (change.path, change.commit)
        if change.sha in matched and key not in seen:
            seen.add(key)
            where = f" (commit {change.commit[:10]})" if change.commit else ""
            found.append(
                Violation(
                    "content",
                    change.path,
                    "has the same content as a protected file" + where,
                )
            )
    return found


# ---------------------------------------------------------------- pattern file protection


def pattern_lines(data: bytes | None) -> list[str]:
    """Meaningful pattern lines of a ``.nbp-safe`` text, read exactly as git reads them (the one
    implementation is ``protect.lines_of``)."""
    return [] if data is None else protect.lines_of(data)


def unprotect_check(git: Git, environ: dict[str, str] | None = None) -> Report:
    """Removing a pattern (or adding a negation) while committing is refused, so that "unprotect
    and commit the file in one go" cannot happen by accident. Override:
    ``NBP_SAFE_ALLOW_UNPROTECT=1`` (a deliberate act, never suggested by the tool's messages)."""
    report = Report()
    touched = git.run(
        "diff", "--cached", "--raw", "-z", "--no-renames", "--no-abbrev", "--", VERSIONED_PATTERNS
    )
    if not touched.strip(b"\0"):
        return report
    old = optional_blob(git, VERSIONED_PATTERNS, "HEAD")
    new = optional_blob(git, VERSIONED_PATTERNS)
    old_lines, new_lines = pattern_lines(old), pattern_lines(new)
    old_set, new_set = set(old_lines), set(new_lines)
    removed = [line for line in old_lines if line not in new_set]
    # a brand-new pattern file has nothing earlier to unprotect, so its negations are fine
    negations = (
        [line for line in new_lines if line.startswith("!") and line not in old_set]
        if old is not None
        else []
    )
    if not removed and not negations:
        return report
    env = os.environ if environ is None else environ
    summary = []
    if removed:
        summary.append(f"{len(removed)} pattern(s) removed")
    if negations:
        summary.append(f"{len(negations)} negation(s) added")
    if env.get(ALLOW_UNPROTECT_ENV) == "1":
        report.warnings.append(
            f"{VERSIONED_PATTERNS}: {', '.join(summary)} (allowed by {ALLOW_UNPROTECT_ENV}=1)"
        )
    else:
        report.violations.append(
            Violation(
                "unprotect",
                VERSIONED_PATTERNS,
                f"{', '.join(summary)} in this commit; unprotecting and committing in one step "
                "is refused. Commit the pattern change on its own after moving the files, or set "
                f"{ALLOW_UNPROTECT_ENV}=1 for this one commit if it is deliberate",
            )
        )
    return report


_EMAIL_RE = re.compile(r"[^\s/@]+@[^\s/@]+\.[A-Za-z]{2,}")
_CAP = r"[A-ZÀ-ÖØ-Þ][a-zà-öø-ÿ]{1,}"
_NAME_RE = re.compile(rf"(?<![A-Za-zÀ-ÿ]){_CAP}[ _.\-]+{_CAP}(?![A-Za-zÀ-ÿ])")


def lint_patterns(text: bytes | str) -> list[str]:
    """Warnings (never errors) for patterns that look like a person's name or an e-mail address.

    Heuristic, deliberately simple: a line is flagged when it contains an e-mail-looking token, or
    two or more consecutive Capitalized words (``Maria Silva``, ``Joao_Silva``) inside one path
    segment. It can over-warn (``Final_Report``); patterns should be generic anyway. Only line
    numbers are reported, so the warning itself leaks nothing into logs."""
    raw = text.decode("utf-8", "surrogateescape") if isinstance(text, bytes) else text
    raw = raw.removeprefix(chr(0xFEFF))  # git skips a leading BOM
    warnings: list[str] = []
    for number, raw_line in enumerate(raw.split("\n"), start=1):
        line = protect.clean_pattern_line(raw_line)
        if line is None:
            continue
        if protect.BLOCK_BEGIN in line or protect.BLOCK_END in line:
            warnings.append(
                f"{VERSIONED_PATTERNS} line {number} contains a marker of the managed exclude "
                "block; it is escaped there (the pattern still means the same)"
            )
        elif _EMAIL_RE.search(line):
            warnings.append(
                f"{VERSIONED_PATTERNS} line {number} looks like an e-mail address; keep patterns "
                "generic (put personal names in .git/info/nbp-safe)"
            )
        elif any(_NAME_RE.search(segment) for segment in line.split("/")):
            warnings.append(
                f"{VERSIONED_PATTERNS} line {number} looks like a person's name; keep patterns "
                "generic (put personal names in .git/info/nbp-safe)"
            )
        elif not line.isascii():
            warnings.append(
                f"{VERSIONED_PATTERNS} line {number} has non-ASCII characters; git compares "
                "bytes, so a name in another Unicode form (NFC/NFD) is only caught by the "
                "commit guard, not by `git add -A`: prefer ASCII globs"
            )
    return warnings


# ------------------------------------------------------------------------------ pre-commit


def check_commit(
    git: Git,
    repo: Repo,
    cfg: Config,
    backend: GuardBackend | None,
    environ: dict[str, str] | None = None,
) -> Report:
    """What ``pre-commit`` enforces. ``backend`` is ``None`` when the agent is locked (only the
    path checks run)."""
    report = unprotect_check(git, environ)
    sources = pattern_sources(git, repo)
    if not sources:
        return report
    changes = staged_changes(git)
    prints = (
        protected_fingerprints(git, repo, cfg, backend) if backend is not None and changes else None
    )
    _check_changes(
        git, backend, sources, prints, changes, report, lambda change: "must not be committed"
    )
    new_patterns = optional_blob(git, VERSIONED_PATTERNS)
    if new_patterns is not None and any(c.path == VERSIONED_PATTERNS for c in changes):
        report.warnings.extend(lint_patterns(new_patterns))
    return report


def _check_changes(
    git: Git,
    backend: GuardBackend | None,
    sources: Sequence[bytes],
    prints: Fingerprints | None,
    changes: Sequence[Change],
    report: Report,
    where: Callable[[Change], str],
) -> set[tuple[str, str | None]]:
    """The checks every staged or pushed change goes through: its path matches a protected
    pattern, or is a path of the vault index (a sealed file stays protected even when no pattern
    covers it any more), or (agent unlocked) its content equals protected content. Violations are
    appended to ``report``; returns the ``(path, commit)`` keys that were flagged."""
    # Our own configuration files are never "protected PATHS" (a broad pattern from the remote must
    # not make the commit that repairs ``.nbp-safe`` impossible). The exemption is by path only:
    # their CONTENT is still compared with the protected content below, so copying a protected
    # file's bytes into ``.nbp-safe.config`` does not get it through. The comparison is
    # ``protect.is_exempt`` folds case only where the file system does (``core.ignorecase``): on a
    # case-sensitive one ``.NBP-SAFE`` is a different, ordinary file, and counts as protected when
    # a pattern covers it (the decision is to protect more).
    everything = list(changes)
    fold = protect.ignore_case(git)
    changes = [c for c in changes if not protect.is_exempt(c.path, fold)]
    if sources:  # our own temp and conflict files never go to the main branch either
        sources = [*sources, protect.managed_suffix_text()]
    matched = protected_among(git, sources, (c.path for c in changes)) if sources else set()
    seen: set[tuple[str, str | None]] = set()
    for change in changes:
        key = (change.path, change.commit)
        if key in seen:
            continue
        if change.path in matched:
            detail = "matches the protected set and " + where(change)
        elif prints is not None and prints.has_path(change.path):
            detail = "is a path of the vault and " + where(change)
        else:
            continue
        seen.add(key)
        report.violations.append(Violation("path", change.path, detail))
    if backend is not None and prints is not None:
        rest = [c for c in everything if (c.path, c.commit) not in seen]
        report.violations.extend(content_violations(git, backend, prints, rest))
    return seen


# ------------------------------------------------------------------------------- pre-push


@dataclass(frozen=True)
class RefUpdate:
    local_ref: str
    local_oid: str
    remote_ref: str
    remote_oid: str

    @property
    def is_delete(self) -> bool:
        return bool(_ZERO_RE.match(self.local_oid))


def parse_push_stdin(data: bytes | str) -> list[RefUpdate]:
    text = data.decode("utf-8", "replace") if isinstance(data, bytes) else data
    updates = []
    for line in text.splitlines():
        parts = line.split(" ")
        if len(parts) == 4:
            updates.append(RefUpdate(*parts))
    return updates


def _remote_exists(git: Git, name: str) -> bool:
    return git.try_run("config", "--get", f"remote.{name}.url") is not None


def new_commits(git: Git, update: RefUpdate, remote_name: str) -> list[str]:
    """Commits ``update`` would add on the remote (oldest first). When the remote tip is not
    known locally, or the ref is new, everything not reachable from a remote-tracking ref."""
    remotes = f"--remotes={remote_name}" if _remote_exists(git, remote_name) else "--remotes"
    if not _ZERO_RE.match(update.remote_oid):
        out = git.try_run("rev-list", "--reverse", update.local_oid, "--not", update.remote_oid)
        if out is not None:
            return out.decode("ascii").split()
    out = git.try_run("rev-list", "--reverse", update.local_oid, "--not", remotes)
    if out is None:
        raise GitError("could not list the commits to be pushed")
    return out.decode("ascii").split()


def commit_changes(git: Git, commits: Sequence[str]) -> list[Change]:
    changes: list[Change] = []
    for chunk in chunked(list(commits), 500):
        out = git.run(
            "diff-tree",
            "--stdin",
            "-r",
            "--raw",
            "-z",
            "--no-renames",
            "--no-abbrev",
            "-m",
            "--root",
            "--diff-filter=ACMRT",
            input=("\n".join(chunk) + "\n").encode("ascii"),
        )
        changes.extend(c for c in parse_raw(out) if c.mode != GITLINK_MODE)
    return changes


def check_code_ref(
    git: Git,
    repo: Repo,
    cfg: Config,
    backend: GuardBackend | None,
    update: RefUpdate,
    remote_name: str,
) -> Report:
    """Path (and, with the agent unlocked, content) checks over everything being pushed: every new
    commit, or, for a ref that does not point at a commit (a tag of a tree or a blob), every object
    it makes reachable that the remote does not have."""
    report = Report()
    final, kind = peel(git, update.local_oid)
    if kind != "commit":
        return check_object_ref(git, repo, cfg, backend, update, final, kind, remote_name)
    commits = new_commits(git, update, remote_name)
    if not commits:
        return report
    sources = pattern_sources(git, repo, revs=[update.local_oid])
    if not sources:
        return report
    changes = commit_changes(git, commits)
    prints = protected_fingerprints(git, repo, cfg, backend) if backend is not None else None

    def where(change: Change) -> str:
        short = change.commit[:10] if change.commit else "?"
        return f"is in commit {short} that would be pushed"

    _check_changes(git, backend, sources, prints, changes, report, where)
    return report


def peel(git: Git, oid: str) -> tuple[str, str]:
    """Follow annotated tags to the final object: ``(object id, "commit" | "tree" | "blob")``.
    Anything that cannot be resolved raises ``GitError`` (the callers block)."""
    final = git.text("rev-parse", "--verify", "--end-of-options", oid + "^{}").strip()
    kind = git.text("cat-file", "-t", final).strip()
    if kind not in ("commit", "tree", "blob"):
        raise GitError("unexpected object type")
    return final, kind


def check_object_ref(
    git: Git,
    repo: Repo,
    cfg: Config,
    backend: GuardBackend | None,
    update: RefUpdate,
    final: str,
    kind: str,
    remote_name: str,
) -> Report:
    """A ref that points at a tree or a blob (usually a tag): list the objects the push would
    bring (``rev-list --objects``, minus what the remote-tracking refs already have) and check the
    blobs' paths and contents like those of a commit. A blob has no path, so with the agent locked
    it cannot be verified at all and the push is refused."""
    report = Report()
    if kind == "blob":
        changes = [Change("", "100644", final, "A")]
        if backend is None:
            report.violations.append(
                Violation(
                    "object",
                    update.local_ref,
                    "points at a bare file (no path to check): unlock the agent so its content "
                    "can be compared, or push it from an unlocked session",
                )
            )
            return report
    else:
        remotes = f"--remotes={remote_name}" if _remote_exists(git, remote_name) else "--remotes"
        out = git.text("rev-list", "--objects", final, "--not", remotes)
        listed = [line.partition(" ") for line in out.splitlines() if line]
        shas = [sha for sha, _sp, path in listed if path]
        kinds = _object_types(git, shas)
        changes = [
            Change(path, "100644", sha, "A")
            for sha, _sp, path in listed
            if path and kinds.get(sha) == "blob"
        ]
    if not changes:
        return report
    sources = pattern_sources(git, repo, revs=[update.local_oid]) if kind != "blob" else []
    prints = protected_fingerprints(git, repo, cfg, backend) if backend is not None else None
    if kind == "blob" and prints is not None:
        report.violations.extend(content_violations(git, backend, prints, changes))  # type: ignore[arg-type]
        return report
    if not sources and prints is None:
        return report
    _check_changes(
        git,
        backend,
        sources,
        prints,
        changes,
        report,
        lambda change: f"is reachable from {update.local_ref}, which would be pushed",
    )
    return report


def _object_types(git: Git, shas: Sequence[str]) -> dict[str, str]:
    kinds: dict[str, str] = {}
    for chunk in chunked(list(dict.fromkeys(shas)), 1000):
        out = git.text(
            "cat-file",
            "--batch-check=%(objectname) %(objecttype)",
            input=("\n".join(chunk) + "\n").encode("ascii"),
        )
        for line in out.splitlines():
            parts = line.split(" ")
            if len(parts) == 2:
                kinds[parts[0]] = parts[1]
    return kinds


def validate_vault_commit(
    git: Git, commit: str, cache: dict[str, bytes | None]
) -> tuple[str | None, bytes | None]:
    """Keyless structural validation of one vault commit. Returns ``(problem, key_id)``.

    Checks: tree has only the allowed paths/modes, fixed ``.gitattributes``/README, an index, and
    the magic/version header on every ``store/*`` blob and on the index. ``cache`` maps blob
    id -> key_id (or ``None`` if the blob is not valid) so a blob is read once per push."""
    tree = rev_parse(git, commit + "^{tree}")
    if tree is None:
        return "commit has no tree", None
    try:
        files = vault._parse_ls_tree(git.run("ls-tree", "-r", "-z", tree))
    except vault.VaultTamperError as exc:
        return str(exc), None
    if not files.keys() >= vault._FIXED_PATHS:
        return "vault tree is incomplete", None
    if files[".gitattributes"] != vault._expected_sha(git, vault.GITATTRIBUTES):
        return "vault .gitattributes is not the canonical one", None
    if files["README.md"] != vault._expected_sha(git, vault.README):
        return "vault README is not the canonical one", None
    pending = [sha for path, sha in files.items() if _needs_magic(path) and sha not in cache]
    for sha, data in read_blobs(git, pending):
        try:
            cache[sha] = crypto.parse_header(data)
        except crypto.NbpCryptoError:
            cache[sha] = None
    for sha in pending:
        cache.setdefault(sha, None)
    key_ids = set()
    for path, sha in files.items():
        if not _needs_magic(path):
            continue
        key_id = cache.get(sha)
        if key_id is None:
            return "a vault blob does not carry the nbp-safe header", None
        key_ids.add(key_id)
    if len(key_ids) > 1:
        return "vault blobs were written with different keys", None
    return None, (next(iter(key_ids)) if key_ids else None)


def _needs_magic(path: str) -> bool:
    return path == vault.INDEX_PATH or path.startswith(vault.STORE_PREFIX)


def check_vault_ref(
    git: Git,
    repo: Repo,
    cfg: Config,
    backend: GuardBackend | None,
    update: RefUpdate,
    remote_name: str,
) -> Report:
    """Validate the vault branch that would be sent: every new commit structurally, and the tip
    cryptographically when the agent is unlocked."""
    report = Report()
    commits = new_commits(git, update, remote_name)
    cache: dict[str, bytes | None] = {}
    for commit in commits:
        problem, _ = validate_vault_commit(git, commit, cache)
        if problem:
            report.violations.append(Violation("vault", commit[:10], problem))
            return report
    if backend is None:
        report.warnings.append(
            "the vault branch was checked structurally only (locked: run `nbp-git-safe unlock` "
            "to authenticate its index before pushing)"
        )
        return report
    try:
        state = vault.load_commit(git, backend, update.local_oid)  # type: ignore[arg-type]
        # the index chain: a replayed older index or a branch that went back is not pushed
        known = vault.read_verified(repo).get(update.local_ref)
        # The branch as it is NOW (the hook sealed before this check, so it may be newer than the
        # commit git is pushing): it must contain the newest tip this clone verified. A pushed
        # commit older than that is this clone's own past, not a rollback of the branch.
        now = rev_parse(git, update.local_ref + "^{commit}") or update.local_oid
        if known is not None and not (known[0] == now or is_ancestor(git, known[0], now)):
            report.violations.append(
                Violation(
                    "vault",
                    update.local_oid[:10],
                    "the vault branch does not contain the newest vault state this clone "
                    "verified (it went back, or its history was replaced); pushing it would roll "
                    "origin back. If that is deliberate, adopt it first with `nbp-git-safe sync "
                    "--accept-remote-rewrite`",
                )
            )
            return report
        trusted = known[0] if known else None
        vault.verify_chain(git, backend, update.local_oid, trusted=trusted)  # type: ignore[arg-type]
    except (vault.VaultError, crypto.NbpCryptoError) as exc:
        report.violations.append(
            Violation("vault", update.local_oid[:10], f"does not verify: {exc}")
        )
        return report
    if any(vault.STORE_PREFIX + fid not in state.files for fid in state.index.entries):
        report.violations.append(
            Violation("vault", update.local_oid[:10], "the index references a missing blob")
        )
    return report


def check_push(
    git: Git,
    repo: Repo,
    cfg: Config,
    backend: GuardBackend | None,
    updates: Sequence[RefUpdate],
    remote_name: str,
) -> Report:
    from nbp_git_safe.config import is_vault_ref

    report = Report()
    for update in updates:
        if update.is_delete:
            continue
        try:
            if is_vault_ref(update.local_ref):
                report.extend(check_vault_ref(git, repo, cfg, backend, update, remote_name))
            else:
                report.extend(check_code_ref(git, repo, cfg, backend, update, remote_name))
        except GitError:
            # fail closed: an object that cannot be examined is not an object that is allowed
            report.violations.append(
                Violation(
                    "object",
                    update.local_ref,
                    "could not be verified (git failed while examining it); not pushed",
                )
            )
    return report


def format_report(report: Report, limit: int = MAX_LISTED) -> list[str]:
    lines: list[str] = []
    shown = report.violations[:limit]
    for violation in shown:
        lines.append("  " + violation.render())
    extra = len(report.violations) - len(shown)
    if extra > 0:
        lines.append(f"  ... and {extra} more")
    return lines
