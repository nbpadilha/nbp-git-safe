# Changelog

All notable changes. The format follows "Keep a Changelog"; versions follow SemVer once 0.1.0 is out.

## 0.1.0 (in preparation, not released)

First public version. Python rewrite of an idea started as a fork of transcrypt (MIT).

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

### Fixed

- `agent.json` sharing violations on Windows made `unlock` fail intermittently.
- Sealing spawned one `git hash-object` process per blob (about 40 ms each on Windows): the first
  seal of 5,000 files took almost four minutes. Blobs are now written with one `git fast-import`
  batch and every id is verified against the object database afterwards (5,000 files: under a
  minute; a commit with hooks on a 2,000-file vault: from 9 s to under 3 s). Found by an end-to-end
  rehearsal; regression tests added.

### Known limits

See "Limitations" in the README and `THREAT_MODEL.md`. Not audited by any third party.
