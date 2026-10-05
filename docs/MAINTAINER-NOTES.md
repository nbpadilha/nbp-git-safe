<!-- SPDX-License-Identifier: MIT -->
# Maintainer notes: state and how to resume

Written when the work was paused, so that a fresh session (human or tool) can pick it up with no other
context. Read this, then `PLAN-SPEC.md` (the original design contract), `THREAT_MODEL.md` and `ROADMAP.md`.

## 1. What this is

`nbp-git-safe` versions sensitive files in a Git repository **encrypted**, with file names and structure hidden
from the remote, the key held only in the RAM of a local agent, and hooks that fail closed. Design in one
paragraph: plain files stay at their real paths and are hidden from the main branch by a managed block in
`.git/info/exclude`; an orphan branch (`nbp-safe`) is built with git plumbing and contains only
`store/<random id>` blobs (AES-SIV) and one encrypted index (id to real path); `seal` writes it, `open`
reads it; guards on `pre-commit`/`pre-push` stop plaintext from reaching the main branch. See `README.md`,
`docs/FORMAT.md`, `docs/GUARD.md`, `docs/MULTI.md`.

Non-negotiable invariants (keep them in every change):

1. The encryption key is **never written to disk, argv, environment of long-lived processes, logs or error
   messages**. It reaches the agent from a configurable command's stdout over a pipe.
2. **Fail closed.** Missing agent, wrong key id, authentication failure, malformed index: non-zero exit,
   nothing written, never plaintext.
3. Nothing that executes a command may come from a versioned file (`keyCommand` is read only from local
   `.git/config`).
4. No force-push except `purge`/`rotate` flows with typed confirmation, and the tool never runs the forced
   push itself. Never `--no-verify`. Never `git push --tags` (the history carries upstream tags).
5. 100% deterministic code: no LLM, no network, no telemetry.
6. Runtime dependency: `cryptography` only. Every dependency pinned with `==`, released more than 7 days
   ago, lockfile committed (`uv.lock`, never deleted).
7. `SPDX-License-Identifier: MIT` in every source file. **Clean room for GPL/MPL projects** (git-crypt,
   git-remote-gcrypt, sops): ideas only, never read or copy their code. MIT code (transcrypt, git-secret) may
   be adapted with attribution (`LICENSE`, `NOTICE`, `THIRD_PARTY.md`). `scripts/check_licenses.py` enforces
   headers in CI.
8. Nothing specific to any organisation or person in code, docs, tests or examples; fake data and
   placeholders only.

## 2. Repository state when paused

- Public repository: `github.com/nbpadilha/nbp-git-safe`. Release `v0.1.0` is tagged and pushed.
- `main` carried the `0.1.1` development line; all jobs of the CI matrix (Windows, macOS, Linux,
  Python 3.11, 3.12, 3.13, plus the `quick` job) were green on it.
- The branch `ci-final` (four commits on top: deterministic fuzz tests with two small typed-error fixes,
  PyPI-ready package metadata plus a `package` CI job, documentation-as-tests that run the README quickstart,
  and a rewritten purge test) was green in CI and was **merged into `main`** together with this file.
  Remote working branches `ci-final` and `ci-posix-fix` were deleted afterwards.
- A `0.1.1` tag **does not exist yet** (see `ROADMAP.md` section 1).
- Test suite: about 900 tests; the full run takes ~25-30 minutes locally on Windows, ~5 min on Linux CI,
  ~12 min on macOS, ~30 min on Windows CI. `crypto.py` must stay at 100% branch coverage (CI gate).
- Dogfooding on a private repository (about 60 files, 10 MiB): first `seal` took 2-6 s, a clean clone without
  the key showed only opaque `store/<hex>` names, and with the key restored every file byte for byte; a
  scan with ~900 real file names, e-mails and content snippets found zero occurrences in the vault branch.

## 3. Review history (so nothing is re-discovered)

Four adversarial reviews were run by a separate reviewer with executable proofs of concept:

1. **Review 1** (before `9df751e`): critical C1 (guard open in linked worktrees: inherited `GIT_DIR` re-initialised
   the real repo and failed open), C2 (`rmtree` driven by a planted `agent.json`); high A1 (fake agent receives the
   key), A2 (import hijack in the key-holding process), A3 (silent unprotection when a pattern is removed
   upstream); medium M1 (rollback by fast-forward of an old index), M2 (symlink in `open`), M3 (pre-push failed
   open for tags to trees/blobs), M4-M7, lows B1-B10. All fixed with regression tests.
2. **Review 2**: H1 (the A3 fix was bypassed by *adding a negation* upstream), M-R1 (`vault.ref` from a versioned
   file bypassed rollback protection), lows (a broad pattern locked `.nbp-safe`, `unprotect` silently undone,
   TOFU and corrupted verified-state handling, DACL aliases, PATH inside the repo, git environment, Linux state
   root). Fixed: patterns are remembered as **versions** of `.nbp-safe`, `vault.ref` is local-only,
   `--confirm-first-adopt` gate, index v2 with `seq`/`prev` chain.
3. **Review 3**: M-N1 (the pattern normaliser removed all trailing CRs while git removes one; a protective
   version was pruned as "equal"), lows (rollback on `sync` without a local branch, marker injection in the
   exclude block, symlinked `.nbp-safe`, dropped positive pattern, swallowed read errors, unbounded memory).
   Fixed.
4. **Review 4 (POSIX and release readiness): started, did not finish.** It is the first thing to redo.

Known backlog items from these reviews that were deliberately left open are listed in `ROADMAP.md`.

## 4. How to resume (checklist)

1. `git status`, `git branch -a`, `git log --oneline -15`, `gh run list` to confirm the state above.
2. Dev environment: Python 3.11+, `uv`, git 2.54+ (for config hooks; older git uses the shim).
   `uv sync --frozen`, then `uv run ruff check`, `uv run ruff format --check`, `uv run pytest -q --no-cov tests/unit`
   (fast). Run `tests/integration` in slices or in the background; it is slow.
3. Re-run the independent security review over `git diff 4430743..HEAD`, with the POSIX focus list from
   `ROADMAP.md` section 2. Fix findings with regression tests that fail before the fix (prove it by running
   them against the previous commit in a throwaway worktree).
4. Do the `0.1.1` release (`ROADMAP.md` section 1).
5. Then pick from the backlog; start with the POSIX items and the real-second-user tests.

## 5. Practical gotchas learned the hard way

- **AF_UNIX paths are short** (104 bytes on macOS, 108 on Linux). Sockets live in `/tmp/nbp-<euid>` (or
  `<runtime root>/s` when `NBP_SAFE_RUNTIME_DIR` is set). Tests that set the runtime root must use a *short*
  directory, not pytest's long temp path.
- **Test isolation:** `tests/conftest.py` fixtures isolate git config and the agent state root; a test that
  escapes isolation and creates the real per-user state directory fails on purpose.
- **Never leave agents behind in tests.** The `reap_agents` fixture exists for that. When listing processes
  to check for strays, exclude the checking process itself (a query whose command line contains the search
  string matches itself).
- **Windows:** paths with spaces, `core.autocrlf=true` (the vault is binary-safe and unaffected), sharing
  violations on `agent.json` (retry for up to 3 s), junctions and symlinks need privileges in tests.
- **macOS** composes file names as NFC (git precomposes), so a test that relies on an NFD name behaves
  differently there.
- **`git add -A` in a maintainer's own shell** can sweep unrelated work-in-progress into a commit: stage
  explicit paths.
- The CI matrix is slow; use a branch named `ci-*` (the `quick` job runs on those) and only fast-forward to
  `main` once everything is green.
- Do **not** use the GitHub "Fork" button for upstream lineage: the history was imported with
  `git clone` and the upstream base is tagged `upstream-base` (local; keep it out of pushes).
