<!-- SPDX-License-Identifier: MIT -->
# Roadmap

What is left to do and what could come next. Status as of the `0.1.1` work (see
`docs/MAINTAINER-NOTES.md` for the current repository state and how to resume).

Legend: **[ ]** open, **[~]** partly done, **[x]** done.

## 1. Before announcing 0.1.1

- [ ] **Independent re-review of the delta since the last completed review.** Three adversarial reviews
      are done (see `docs/MAINTAINER-NOTES.md`). A fourth review (POSIX code, agent trust design,
      packaging, docs fidelity) was started and **never finished**, and everything after commit `b4123b1`
      (typed errors in index/agent-reply parsing, package metadata, fuzz tests, docs-as-tests) has had no
      security review at all.
- [ ] **Release `0.1.1` properly.** The local-only tag that existed during development pointed at a commit
      whose package metadata still said `0.1.0`; it was deleted. Create the tag on the final commit, push
      it **by name** (`git push origin v0.1.1`, never `--tags`: the history carries the upstream project's
      tags), and write GitHub release notes from `CHANGELOG.md`.
- [ ] Decide on **PyPI**. The package metadata, sdist contents and a CI `package` job are prepared, nothing
      is published. Prefer GitHub Actions trusted publishing (OIDC) over a long-lived token.

## 1b. Several repositories and the tray (branch `ci-tray`, awaiting security review)

- [x] Per-user registry of repositories and the `registry` commands; `init` and `uninstall` keep it.
- [x] `status|unlock|lock|seal|doctor --all`; `unlock --all` runs one `keyCommand` per distinct
      argv; `seal --all [--push]` never unlocks.
- [x] Windows autostart (`autostart install|remove|status`, per-user `Run` value).
- [x] Windows tray (`nbp-git-safe tray`): icon colours, menu, balloons, periodic seal and push,
      `tray.json`, rotating name-free log. Architecture and extension points: `docs/TRAY.md`.
- [ ] **Independent security review** of this branch (registry parser, `unlock --all`, tray, autostart).
- [ ] Hardening option: run the tray's unlock in a short-lived child process (`nbp-git-safe unlock`)
      so the key never enters the long-lived tray process (see `THREAT_MODEL.md` section 8).
- [ ] Not verified on real hardware: high-DPI and high-contrast themes, the password-manager prompt
      raised from the tray, non-interactive sessions, Windows 10.
- [ ] Elevated agent versus a non-elevated tray (same open item as the hooks, section 2).

### Other platforms

**Front ends for macOS (a menu-bar item) and Linux (a tray through StatusNotifier/AppIndicator) are
welcome, by fork or pull request.** Everything except the window is already neutral and tested on
Linux and macOS in CI: the registry, the `--all` commands, the model (`fleet.py`) and the controller
(`traycontroller.py`). A port is the thin layer described in section 7 of
[docs/TRAY.md](docs/TRAY.md); contribution notes are in [CONTRIBUTING.md](CONTRIBUTING.md).

## 2. Known gaps (backlog, in rough priority order)

Security and robustness:

- [ ] **POSIX code paths only exercised by CI**, never reviewed line by line by a human on Linux/macOS:
      `SO_PEERCRED` / `LOCAL_PEERCRED` / `getpeereid`, `RLIMIT_CORE`, `start_new_session`, the socket
      directory under `/tmp/nbp-<euid>` (squatting by another real local user is only simulated with loose
      modes and symlinks), `pid_alive` (`/proc/<pid>/stat` parsing with process names containing spaces or
      parentheses; `ps` missing; pid reuse).
- [ ] **A receive can block forever on a partial frame** (POSIX, `recv_bytes` after `poll`); the 16 listener
      slots can be occupied by another process of the same user (denial of service only).
- [ ] **Hook stderr can show file names/paths** (a few messages include them). Replace by counts where no
      existing test depends on the text.
- [ ] **Materialised files do not keep the original permission bits** (POSIX umask applies; on Windows they
      inherit the folder ACL).
- [ ] **Nested repositories and submodules** inside the protected set are skipped without a warning.
      Also unhandled: HFS+ ignorable code points in `.git`-like names (defence in depth only, the index is
      authenticated).
- [ ] **Elevated agent vs non-elevated hooks (Windows).** The hook cannot inspect the elevated agent process
      and degrades to "path check only" with a warning. Side effect: an unelevated `unlock` starts a second
      agent while the elevated one keeps the key until its TTL (`lock` cannot reach it). Needs a design
      decision (document only, or a cross-integrity-level handshake).
- [ ] **The git-config-hooks shim fallback** (git older than 2.54) is tested by simulating an old version,
      never against a real old git.
- [ ] **Durability:** `fsync` is done for `open` and the verified-state file; the vault build relies on git's
      own durability. Review power-loss behaviour.
- [ ] **Pattern-version memory** is capped at 64 independent versions per repository (the 65th stops the
      hooks with instructions); consider compaction that provably keeps every protection.
- [ ] Python cannot reliably wipe key material from memory; key may reach pagefile/hibernation/crash
      dumps. Document mitigations per OS (and consider `mlock`/`VirtualLock` best effort).

Testing and CI:

- [ ] Real second-user tests (Windows pipe DACL and POSIX socket directory) on a CI runner or VM.
- [ ] Python 3.14 in the matrix when the dependency pins allow.
- [ ] The Windows job takes ~30 minutes; evaluate test isolation for `pytest-xdist` (agents, pipes, temp
      state) before enabling it, and keep the result documented in `CONTRIBUTING.md`.
- [ ] One macOS flake was seen once (purge test, object still present after prune); the test was rewritten to
      assert reachability instead of file existence. Watch for a recurrence.
- [ ] Mutation testing (e.g. `mutmut`) for `crypto.py`, `guard.py`, `protect.py`; coverage-guided fuzzing
      (Atheris/Hypothesis) beyond the fixed-seed fuzz tests that exist now.
- [ ] Bump the pinned GitHub Actions SHAs periodically (same 7-day cooldown as dependencies).

Documentation:

- [ ] A short "how it works" diagram and a worked example with screenshots.
- [ ] Per-OS install notes (`uv tool`, `pipx`, Windows Store Python, macOS Homebrew Python).
- [ ] Shell completions and a man page generated from the CLI.

## 3. Ideas for later (not committed to)

Key management:

- **More key sources** as documented presets for `keyCommand`: 1Password CLI (exists as an example), Bitwarden,
  `pass`, `secret-tool` (libsecret), macOS Keychain (`security`), Windows Credential Manager / DPAPI,
  FIDO2 `hmac-secret` and TPM sealing.
- **Key backup/recovery helpers**: printable recovery sheet, optional Shamir split (documented trade-offs).
- **Multiple maintainers**: wrap the master key per recipient (public-key wrapping) so access can be added and
  revoked without re-encrypting every file, and rotation does not require everyone to share one secret.
  This is a format change (v2) and needs its own threat model.
- **Rotation UX**: re-encrypt into a fresh ref with one command, verify, then swap; a guided
  "old ref retirement" checklist.

Format and scale:

- **Streaming AEAD for large files** (chunked STREAM construction) instead of one-shot AES-SIV with a
  64 MiB cap; optional content-defined chunking so big, slowly changing files deduplicate in history.
- **Partial open** (materialise only some paths) and `open --dry-run`.
- **Vault history compaction** that keeps the verifiable chain (seq/prev) while dropping old blobs.
- **Metadata minimisation**: configurable padding strategies, commit-time jitter, optional fixed-size
  decoy entries.

Automation and ecosystem:

- `nbp-git-safe verify`: an offline integrity checker that needs **no key** (path allow-list, magic bytes,
  chain structure) so a CI job or server-side `pre-receive` hook can reject plaintext or malformed vaults.
- A GitHub Action that fails a pull request when a protected path appears in clear on the main branch
  (late detection for clients that skip local hooks).
- Optional file watcher inside the agent for "seal on change" without commits.
- Packages for Homebrew, Scoop/winget and AUR; signed releases (Sigstore) and an SBOM; reproducible builds.
- Behaviour notes for GUI clients (GitHub Desktop and IDEs may bundle a git that ignores config hooks).
- Translations of the README.

## 4. Non-goals

- Network features, telemetry, or any LLM/AI component at runtime. The tool must stay deterministic code.
- Hiding the *existence* or *size* of the vault from the remote (only names, contents and structure are hidden;
  see `THREAT_MODEL.md`).
- Protecting a machine that is already compromised while the agent is unlocked.
