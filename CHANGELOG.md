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

### Fixed

- `agent.json` sharing violations on Windows made `unlock` fail intermittently.
- Sealing spawned one `git hash-object` process per blob (about 40 ms each on Windows): the first
  seal of 5,000 files took almost four minutes. Blobs are now written with one `git fast-import`
  batch and every id is verified against the object database afterwards (5,000 files: under a
  minute; a commit with hooks on a 2,000-file vault: from 9 s to under 3 s). Found by an end-to-end
  rehearsal; regression tests added.

### Known limits

See "Limitations" in the README and `THREAT_MODEL.md`. Not audited by any third party.
