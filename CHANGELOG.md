# Changelog

## Unreleased

- Phase 0: forked history from transcrypt (tag `upstream-base`), MIT attribution.
- Phase 1: Python package skeleton, `crypto` module (AES-SIV blobs and index, HKDF, HMAC),
  `docs/FORMAT.md`, leak-test harness, CI workflow. The transcrypt Bash core was removed.
- Phase 4: guard on the main branch (`init`, hooks by git config with shim fallback, `pre-commit`/
  `pre-push` by path and content, vault validation, `doctor`, `uninstall`), see `docs/GUARD.md`.
- Fix: `agent.json` sharing violations on Windows made `unlock` fail intermittently.
- Phase 5: multi-machine (`sync` three-way merge, `push` without force, `init --auto-push`, `rotate`,
  `purge` with typed confirmation, rollback detection of the remote vault), see `docs/MULTI.md`.
