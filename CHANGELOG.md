# Changelog

All notable changes. The format follows "Keep a Changelog"; versions follow SemVer once 0.1.0 is out.

## 0.1.0 - 2026-10-03

First version (tagged locally, not published yet: see `docs/RELEASING.md`). Python rewrite of an idea
started as a fork of transcrypt (MIT). Before this tag the code went through three rounds of
adversarial review by a second model with working proofs of concept; every finding of the three
rounds was fixed with a regression test that fails without the fix. They are listed below, round by
round.

### Added

- Crypto core: AES-SIV (RFC 5297) blobs with the file id bound as associated data, HKDF-SHA256 key
  separation, authenticated canonical-JSON index, HMAC content MACs, size-bucket padding
  (`docs/FORMAT.md`). RFC 5297 test vectors; 100% branch coverage gate on `crypto.py`.
- Key agent: key only in the memory of a detached process, mutual HMAC handshake over a named pipe
  (Windows) or Unix socket (POSIX), TTL / idle timeout / `lock`, `keyCommand` run without a shell.
- Vault: orphan branch `nbp-safe` written with git plumbing (no worktree, compare-and-swap ref
  update), opaque `store/<hex>` names, encrypted index, move detection by content MAC, stat cache
  keyed by path HMAC, `seal`, `open`, `status`, `ls`, `log`, `diff`, `mv`, `rm`.
- Main-branch guard: managed `.git/info/exclude` block, `pre-commit` (path and content), `pre-push`
  (every pushed commit, plus vault validation), hooks by git config with a shim fallback,
  `post-commit` / `post-merge` / `post-checkout` automation, `doctor`, `uninstall`
  (`docs/GUARD.md`).
- Multi-machine: `sync` (three-way merge by file id, conflict copies, no force), `push`, opt-in
  `init --auto-push`, `rotate`, `purge` with typed confirmation, rollback / replacement detection
  of the remote vault (`docs/MULTI.md`).
- Leak-test harness (random canaries scanned in the bare remote and in `.git`, in UTF-8, UTF-16,
  base64 and hex) used as a gate by the integration tests.
- Documentation: README, SECURITY, THREAT_MODEL, CONTRIBUTING.
- CI: matrix (Windows, Ubuntu, macOS x Python 3.11-3.13), actions pinned by commit SHA, frozen
  lockfile, ruff, tests with the `crypto.py` coverage gate, licence check
  (`scripts/check_licenses.py`).

### Security fixes from the adversarial review (before the first release)

- Guard failed open in a linked worktree (git exports `GIT_DIR` to hooks, the matcher's scratch
  repository re-initialised the real one and a failed `check-ignore` read as "nothing protected"):
  clean git environment for auxiliary repositories, any status other than 0/1 fails closed.
- A planted `agent.json` could make the program delete directories, or point the client at an
  impostor that received the master key and plaintext: agent state moved to a verified per-user
  directory, authkey derived from a secret instead of stored, key delivered only to an agent the
  CLI started itself over a stdin pipe, server pid/user check, Windows pipe with DACL / remote
  clients rejected / name claim, no `rmtree` driven by file contents.
- The agent could import a package planted in the temp or current directory: started with
  `python -I`, state directory as cwd, minimal environment.
- Removing a pattern upstream silently unprotected files after `git pull`: sticky local pattern
  memory, `unprotect` command, vault-index paths blocked, loud warning, `doctor` listing.
- Rollback by a fast-forward commit carrying an older index: authenticated `seq` / `prev` chain
  (index format version 2) verified on `open`, `sync` and push; local verified-tip state.
- `open` could write through a symlink at a predictable `*.nbp-tmp` name: random `O_EXCL` temp files,
  link/junction checks right before the write, fsync before the rename.
- `pre-push` let a tag of a tree or blob through on a git failure: such refs are walked with
  `rev-list --objects`, annotated tags followed, and anything that cannot be examined blocks.
- Hardening: `doctor` reports protected files git does not ignore and values raised to the privacy
  floors; NFC/NFD path matching; `.nbp-safe.config` cannot weaken padding/rounding or set
  `onMissing`; executables resolved outside the current directory; conflict/temp files guarded;
  no names in the OS temp dir; `rotate --delete-old` waits for `keyCommand` to return the new key;
  purge instructions use `git gc --prune=now`.

### Security fixes from the second adversarial review

- A pushed `.nbp-safe` with `reports/` followed by `!reports/` / `!reports/**` defeated the pattern
  memory (it stored lines, negations included) and `git add -A`, commit and push published the
  files: the memory now keeps VERSIONS of `.nbp-safe`, each one a separate source of the union (a
  negation of a newer version never cancels an older version's protection; a negation inside its
  own version keeps working); `post-merge`/`post-checkout`/`doctor` warn when the current version
  removed or defeated earlier protection. `unprotect` is durable (a later hook cannot bring the
  pattern back from an older `HEAD`/index), says what still protects and asks for the typed
  confirmation; new `unprotect --accept-current`. Changed behaviour: a negation you add yourself in
  a new version needs `unprotect --accept-current` to take effect.
- `vault.ref` in the versioned `.nbp-safe.config` redirected the clone to another ref holding an old,
  authentic vault commit (the rollback record is per ref): the option is local-only now (ignored and
  reported when versioned), and a vault ref the clone never verified is adopted only with
  `--confirm-first-adopt` (`open`, `sync`, `init`), after the error showed key id, seq and tip.
  Changed behaviour: the first `open`/`sync` of a fresh clone needs the flag; `init` no longer records
  an unverified tip as seen.
- A damaged `vault-seq.json` read as "nothing verified"; it is an error now (`open`, `sync`, `seal`,
  the push guard, `doctor`).
- A broad pattern from the remote (`*`) made `.nbp-safe` itself a protected path, so the commit that
  repairs it was refused: `.nbp-safe` and `.nbp-safe.config` are never protected paths.
- An agent running at another elevation level than the hook failed the identity check as an
  "impostor"; it now degrades to the path check with an "agent unavailable ... elevation" message.
- `_dacl_problem` refused the built-in Administrator printed as the SDDL alias `LA` (and other
  aliases): trustees are resolved to SIDs before the comparison.
- `PATH` entries inside the repository tree are ignored when resolving `git` and the `keyCommand`
  executable; the auxiliary git no longer inherits `GIT_CONFIG_PARAMETERS`/`COUNT`/`KEY_*`/`VALUE_*`,
  `GIT_EXTERNAL_DIFF`, `GIT_PAGER`, `GIT_ASKPASS`, `SSH_ASKPASS`, `GIT_SSH*`, `GIT_EDITOR`, `GIT_TRACE*`.
- On POSIX the agent state root no longer depends on `$XDG_RUNTIME_DIR` (present in a login
  session, absent in a GUI-started hook): `~/.cache/nbp-git-safe-<uid>` (home from the password
  database), `NBP_SAFE_RUNTIME_DIR` to override.
- Docs: the post-purge flow on other machines is `git branch -D nbp-safe` + `sync
  --accept-remote-rewrite` (the earlier "delete the branch and run `init`" did not work, and
  `sync --accept-remote-rewrite` now also adopts a branch `init` had re-created); `git gc
  --prune=now` instead of `git prune --expire now` for packed objects.
- Tests: any test that creates the developer's real agent state directory now fails right there.

### Security fixes from the third adversarial review

- Medium: the tool read `.nbp-safe` differently from git (it removed every trailing CR, git removes
  one). A collaborator who changed `reports/` to `reports/<CR><CR>` made the old version look
  "equal", so it was pruned, while git saw a useless pattern: `list_protected`, `match_paths` and
  `tracked_matches` lost `reports/`, new files were not sealed, `open` / `post-merge` failed
  ("outside the protected set"), no warning was printed and a renamed copy of a not yet sealed file
  passed `pre-commit` and `pre-push`. There is now ONE reader (`protect.lines_of`: BOM, one CR, NUL,
  trailing spaces, tabs, blank and comment lines exactly as git) and ONE normalized text that every
  comparison and every call to git uses (never the raw file); a seeded property test checks the
  evaluation of the normalized text against `git check-ignore` on 500 random files.
- Low: `sync` with no local vault branch adopted an origin tip older than the verified record, `seal`
  built on it and `pre-push` let it out (a forced push would roll origin back): `sync`, `seal` and the
  push guard now compare with the verified record (`--accept-remote-rewrite` is the explicit way).
- Low: a pattern line that contained a marker of the exclude block (`x# <<< ...`) made every install
  duplicate the rest of the block and left residue on uninstall: the markers are whole lines, and
  such a pattern is written with the first `<`/`>` escaped (and linted).
- Low: a `.nbp-safe` / `.nbp-safe.config` that was a symbolic link, junction, directory, special
  file (a FIFO or `/dev/zero` would hang every hook) or larger than 1 MiB was followed and copied
  into the pattern memory and `.git/info/exclude`: they are inspected with `lstat` and refused
  unread.
- Low: the exclude block omitted a positive that its own version negated and added again
  (`keys/`, `!keys/`, `keys/`): only a negation AFTER the last occurrence drops it now.
- Low: a remembered version that could not be read vanished from the block and the guard (fail
  open): `PatternMemoryError` stops the hooks instead.
- Low: the memory of versions had no bound (300 independent versions cost over a second per call,
  plus one git run per version): covered versions are removed from the disk, at most 64 independent
  versions are kept (the next one stops the hooks with a message about
  `unprotect --accept-current`; nothing is dropped silently), and all versions are evaluated with one
  `check-ignore` run (64 versions: a few hundred milliseconds in total, it used to be seconds).
- Info: the exemption of `.nbp-safe` / `.nbp-safe.config` is by path only, the content check still
  runs on blobs with those names; names are compared with case folding only where the repository
  does (`core.ignorecase`).
- Docs: `docs/RELEASING.md` (publish `main` and our own tags by name, never `--tags`: the repository
  carries the upstream transcrypt tags), complete development-dependency licences and the note that
  the `cryptography` wheels embed OpenSSL (Apache-2.0) in `THIRD_PARTY.md`.

### Fixed

- `agent.json` sharing violations on Windows made `unlock` fail intermittently.
- Sealing spawned one `git hash-object` process per blob (about 40 ms each on Windows): the first
  seal of 5,000 files took almost four minutes. Blobs are now written with one `git fast-import`
  batch and every id is verified against the object database afterwards (5,000 files: under a
  minute; a commit with hooks on a 2,000-file vault: from 9 s to under 3 s). Found by an end-to-end
  rehearsal; regression tests added.

### Known limits

See "Limitations" in the README and `THREAT_MODEL.md`. Not audited by any third party.
