# Changelog

All notable changes. The format follows "Keep a Changelog"; versions follow SemVer once 0.1.0 is out.

## 0.2.0 - 2026-10-05

Everything since 0.1.0: the POSIX fixes that were prepared as `0.1.1` (that version was never tagged
or published), the multi-repository work and the Windows tray, and the fixes of the fifth adversarial
review (below). Nothing was released between 0.1.0 and this version.

### Security fixes from the fifth adversarial review (the `ci-tray` delta)

Every finding below was reproduced and fixed with a regression test that fails on the previous
commit. Two were rated medium.

- **M1. `unlock --all` and the tray trusted an identical `keyCommand` argv to mean the same key.**
  A command with a relative path (`["python", "tools/key.py"]`, `["sh", ".git/key.sh"]`) worked in
  `unlock` (the working directory was the repository) but ran once, from the tray's folder, for a
  whole group under `--all`, and a repository without a vault could then create its vault under the
  key of ANOTHER repository, without an error. Now: every `keyCommand` runs from the root of the
  repository it is for (`unlock`, hooks, `--all`, the tray); a relative argv makes each repository its
  own group; and **each repository records the public id of its key** (`nbp-safe.keyId` in the local
  `.git/config`, recorded by the first `unlock` run inside it or the first `seal`), which is checked
  before a key is delivered (a running agent holding another key is replaced, never kept) and at every
  seal, so the grouping is only an optimisation. A repository with neither a registered id nor a
  vault is not handed a group's key. New `nbp-git-safe key-id [--accept <id>]` (typed confirmation)
  for a deliberate change, printed by the `rotate` next steps; `doctor` reports a missing id, a relative
  path in `keyCommand` and an agent holding another key. The statement in `THREAT_MODEL.md` that an
  identical argv gives the same key "by construction" was false and is corrected.
- **M2. A `git` that never answers froze the tray's queue.** `git push` (and `fetch`) had no time limit,
  so one stuck `ssh` or a credential-manager window blocked refresh, deep checks and sealing. Now: a hard
  limit (120 s in the background, 10 min for a push or sync you start) that kills the whole process
  tree, not only `git`; a non-interactive environment for the background push (`GIT_TERMINAL_PROMPT=0`,
  `GCM_INTERACTIVE=never`, and an `ssh` with `BatchMode`, `ConnectTimeout` and `ServerAlive*` only
  when you set no ssh command of your own); the vault is pushed with `--no-follow-tags`; and in the tray
  the push has its **own worker lane**, so a push that hangs never stops the icon, the state or the
  warnings (`push-timeout`, a warning code and a discreet balloon).
- B1. An exception in the tray's deep check left the icon green: the failure is now a code on the
  repository and a red state (not a clean bill of health).
- B2. With `onMissing=ask`, files deleted locally were counted as pending although no non-interactive
  seal ever removes them, which made the tray flip red each cycle: they are no longer counted (the tray
  and `--all` treat `ask` as `keep`).
- B3. An access-denied single-instance mutex was treated as "already running" and the tray left in
  silence: it is now told apart, reported (message box and log) and has its own exit code (4).
- B4. An agent state directory that is not private was shown as "locked": `AgentClient.connect` now
  raises `InsecureStateError`, shown as the error `insecure-state` (red) in `status --all`, `seal --all`
  and the tray, with an actionable message.
- B5. `open_handle` could operate on the repository ABOVE a registered folder whose `.git` was deleted:
  git discovery is capped at the registered folder (`GIT_CEILING_DIRECTORIES`) and the top level is
  compared with the registered path.
- B6. A tray repository's configuration was re-read every ten minutes only: it is read again right
  before every unlock and every push.
- B7. `autostart install` registered `pythonw.exe` without looking at who can change it: it now refuses
  an interpreter or folder that another account can write to (`--allow-writable` overrides), and
  `autostart status` reports that, and a stored value whose program no longer exists.
- B8. Documents that promised more than the code did: `doctor --all` printed the names of tracked
  protected files (now counts and an instruction); `THREAT_MODEL.md` said a window message "can at most
  redraw" (it can open the menu; UIPI separates integrity levels, not users: corrected, and the message
  must carry the icon's id); "the tray holds no key" and "adds no new copy" contradicted the group key
  held inside the tray (rewritten, and fixed: the tray now unlocks in a short-lived child process,
  `unlock-batch`, so the key never enters it).
- Informational: the file lock is now an operating-system lock (a stale-lock takeover could be made by
  two contenders at once), `tray.json` is read and written under one lock, the failure remembered for a
  key group no longer keeps a traceback (and the frames that held what a key command printed), a
  hook-declined push is no longer reported as "run sync" (`push-refused`), the registry's message for a
  mapped network drive says what it is, and the tray can hide folder names from balloons
  (`notifications=minimal`; Windows keeps a history of notifications).

### Changed

- `gitutil.hide_child_windows()` (used by the tray, which runs without a console) starts git and the
  key command with `CREATE_NO_WINDOW`; nothing changes for the command line.
- `rotate` prints the new key's public id and the `key-id --accept` step.

### Fixed

- POSIX: the agent socket path exceeded `sun_path` (`AF_UNIX path too long`) under long state roots.
  Sockets now live in a short, verified 0700 directory (`/tmp/nbp-<uid>`, or `<state root>/s` with
  `NBP_SAFE_RUNTIME_DIR`), named `<12 hex>-<12 hex>.sock`, never more than 100 bytes; a root that is
  too long gives a clear error. Squatting of that directory fails closed.
- POSIX: the listener's backlog was 1, so a burst of clients (parallel hooks) could be refused
  (`ECONNREFUSED`, seen on macOS); it is now 32.
- POSIX: `pid_alive` no longer counts a zombie (exited, not yet reaped) as a running agent.
- The package metadata said 0.1.0 while this changelog said 0.1.1: `pyproject.toml`, `__version__`,
  `uv.lock`, README and SECURITY now say 0.2.0, and a test keeps them equal.
- `Index.from_dict` on something that is not a mapping raises `IndexValidationError` (it raised
  `TypeError`); the agent client raises `ProtocolError` for an empty or non-JSON reply (it raised
  `IndexError` / `ValueError`). Both found by the new fuzz tests; neither was reachable with a
  well-behaved agent.
- Tests: Windows SDDL alias (`LA`) normalised like the product does; short runtime roots on POSIX;
  hooks inherit the test state root; macOS NFD/precomposition case.

### Added

- **Several repositories.** A per-user registry of repositories (`repos.json`: absolute canonical
  paths and dates only, strict reading, atomic locked writes, `.bak` before a damaged file is
  replaced); `init` registers and `uninstall` forgets; `nbp-git-safe registry list|add|remove|prune`.
- `status|unlock|lock|seal|doctor --all`: one block per repository, a failure never stops the others,
  an aggregate exit code. `unlock --all` runs each distinct `keyCommand` once (the `unlock()` flow takes
  an optional key source; the key still goes only to an agent it just started, over the authenticated
  channel, and the group's buffer is zeroed). `seal --all` never unlocks; `--push` pushes the vault
  branch without force where `autoPush` and an `origin` exist and treats an unreachable origin as
  non-fatal.
- **Windows tray** (`nbp-git-safe tray`, no new dependency, `ctypes` only): a status circle (green,
  yellow, red, gray), a per-repository menu (unlock, lock, seal now, open folder, auto-unlock) and
  global commands, balloons for expiring keys, unsealed files and failures, and a periodic seal (and
  push, if configured) of the unlocked repositories. One instance per session, `tray.json`
  configuration (`tray --config`), a name-free rotating log, `unlockAtLogin` (off by default).
  `nbp-git-safe autostart install|remove|status` manages the per-user `Run` value.
- Layers for other platforms: `fleet.py` (pure model), `fleetops.py`, `traycontroller.py` (the brain a
  front end drives) and `docs/TRAY.md`. macOS and Linux front ends are welcome as forks or pull requests.
- `THREAT_MODEL.md` section 8 for the new surface.
- Tests: the registry (hostile entries, damaged files, concurrent writers in threads and processes),
  the pure model with case tables and an injected clock, the controller with fake operations, real git
  integration (one key command per distinct `keyCommand`, `--all` past a broken repository, `seal --all`
  never unlocking, push rules, leak scans of every file the tray writes), fixed-seed fuzzing of the
  registry and tray-configuration parsers, the Windows `Run` value in a throw-away key, and a smoke test
  of the real window and message loop (skipped without a desktop).
- Package: PyPI classifiers, keywords and project URLs; an explicit sdist file list (no internal
  plan, no upstream test suite, no CI files, no lockfile); `scripts/check_package.py` and a CI job
  `package` that builds the wheel and sdist, checks them and runs the entry points from a clean
  environment.
- Tests: fixed-seed fuzzing of the index validator, the blob and index decoders, the `.nbp-safe`
  reading against `git check-ignore`, and the agent handshake and framing; the README quickstart and
  every documented command are executed or parsed by a test; the purge test runs the commands the
  tool prints and asserts reachability instead of file existence.
- **Registered key id** (`nbp-safe.keyId`, public, local config only) and `nbp-git-safe key-id
  [--accept <id>]`; `Config.key_id`; `keyid.py` and `keypin.py`; doctor findings for a missing id, a
  relative `keyCommand` path and an agent holding another key.
- **`unlock-batch`** (internal) and `unlockchild.py`: the tray's unlock in a short-lived child process;
  `TrayController(unlock_runner=...)`.
- `notifications = "full" | "minimal"` in `tray.json`; `autostart install --allow-writable`;
  `winsec.write_exposure`; `gitutil.kill_tree`, `GitTimeoutError`, `network_env`; a push lane in the
  tray controller; `check_error` in the tray model.
- Tests for every finding of the fifth review (each fails on the previous commit): the key-id and
  working-directory rules with real repositories and a real child, a local socket that accepts and never
  answers (the push is stopped and the connection closes), a stand-in `git` whose grandchild keeps the
  pipes open, the push lane and the failed-deep-check state in the controller, a real `icacls` grant for
  the autostart check, and the OS-level lock with a killed holder.

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
