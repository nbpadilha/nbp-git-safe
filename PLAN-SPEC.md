# nbp-git-safe — implementation spec (source of truth for all phases)

Owner: Nikolas Padilha (github.com/nbpadilha). License: MIT. 100% deterministic code: **no LLM, no network calls, no telemetry** at runtime or in tests.
Language/docs: English (README gets a short PT-BR section). Nothing school-specific in code, docs, tests or examples (use placeholders and fake data).

## Goal
Version sensitive files in a Git repo, encrypted, with **latest version + full history inside the same GitHub repo** (no tarballs/snapshots), **file names/paths hidden** from the remote, key **never written to disk**, and an experience that is almost invisible: the user keeps generating/editing files at their normal paths; commit/push just work.

## Non-negotiable rules
1. **Key never on disk.** Lives only in RAM of a local agent process (ssh-agent style). It reaches the agent from a configurable command (`keyCommand`, JSON argv, run WITHOUT a shell, e.g. `["op","document","get","<ITEM_ID>","--vault","<VAULT_ID>"]`) whose stdout is base64 of 64 bytes, read via pipe. Never print/log the key. Agent expires by TTL (default 8h) or `lock`.
2. **Fail closed everywhere.** No agent / wrong key_id / auth failure / bad index → non-zero exit, nothing written, never plaintext.
3. Never `git push --force` (except `purge`/`rotate` with typed confirmation), never suggest `--no-verify`. The tool never pushes on its own unless the user opted in.
4. Pinned dependency versions (`==`), release at least 7 days old, `uv.lock` committed. Runtime dependency: `cryptography` only.
5. SPDX `MIT` header per source file. Third-party attribution in NOTICE / THIRD_PARTY.md.
6. **Clean-room for GPL/MPL projects (git-crypt, git-remote-gcrypt, sops):** ideas only, never read or copy their source while implementing. MIT code (transcrypt, git-secret) may be adapted with attribution.

## Architecture (decided): orphan branch `nbp-safe` built with git plumbing, no worktree
- Plain files stay at their **real paths** in the working tree, hidden from the main branch by a managed block in `.git/info/exclude` (markers `# >>> nbp-git-safe managed >>>` / `# <<< nbp-git-safe managed <<<`). Optional managed block in versioned `.gitignore` (generic patterns only).
- Branch `refs/heads/nbp-safe` (orphan) contains ONLY: `.gitattributes` (`* -text -diff -merge`), fixed generic `README.md`, `nbp-safe/index` (encrypted), `store/<32 hex>` (encrypted blobs). Built without touching working tree/index of main:
  1. ciphertext → `git hash-object -w --stdin --no-filters`
  2. `GIT_INDEX_FILE=.git/nbp-safe/index.tmp git update-index --add --cacheinfo 100644,<sha>,store/<id>` ; `git write-tree` ; `git commit-tree -p <parent>`
  3. `git update-ref refs/heads/nbp-safe <new> <old>` (compare-and-swap)
- Plain text and real names **never enter the git object database**. This is a testable invariant.
- Sealing is triggered by hooks (`post-commit`, `pre-push` seals before checking) and by `nbp-git-safe seal`. Locked agent → do not seal, warn, never write plaintext.
- Hooks via git config hooks (`hook.<name>.command` + `.event`, git ≥ 2.54; verify the exact minimum version) so they run alongside existing hooks without touching hook files; fallback: transcrypt-style shim installed only if no hook exists (hash-compare, never overwrite foreign hooks). `doctor` checks.

## Config
- `.nbp-safe` (versioned, repo root): `.gitignore` syntax (`#`, `!`, `/`, `**`), consumed literally by `git ls-files -z -c -i -X .nbp-safe` and by the exclude block. Patterns should be generic (lint warns on name-like patterns).
- `.git/info/nbp-safe` (local, unversioned): extra patterns. Protected set = versioned OR local; a local negation never unprotects a versioned pattern. pre-commit uses the union of `.nbp-safe` from HEAD, index and working tree; removing a pattern and committing the file in the same commit is blocked (override only `NBP_SAFE_ALLOW_UNPROTECT=1`).
- `.nbp-safe.config` (versioned, git-config format, read with `git config -f`): harmless options only (`vault.ref`, `pad.bucket`, `onMissing`, `commit.timeGranularity`).
- `.git/config [nbp-safe]` (local): `keyCommand` (JSON argv), `autoUnlock` (default false), `autoPush` (default false), `ttl`. **Nothing that executes a command may come from a versioned file** (RCE risk).
- Precedence: flag > env `NBP_SAFE_*` > `.git/config` > `.nbp-safe.config` > defaults.

## Crypto format (FORMAT.md must document it)
- Master key: 64 random bytes. HKDF-SHA256 with distinct `info` → `k_blob` (64), `k_index` (64), `k_mac` (32), key_id = first 8 bytes of HKDF(master, "nbp-git-safe/v1/key-id").
- Blob: `magic = b"\x00NBPSAFE"` (8) + version `0x01` + key_id (8) + `AESSIV(k_blob).encrypt(frame, [header, file_id])`; `frame = u64_be(len) || data || zero pad to multiple of pad.bucket (default 4096)`. `file_id` in AD binds blob↔id. One-shot in memory: refuse files > 64 MiB.
- Use `cryptography.hazmat.primitives.ciphers.aead.AESSIV` — **no custom crypto construction**. Add RFC 5297 test vectors.
- Index: canonical JSON, encrypted with `k_index`, AD = `header || "index"`, padded. Content `{v, key_id, entries:{id:{path(POSIX,NFC), mode, size, mac, created, updated}}}`. Validate on open: relative path, no `..`, no `.git` component, must match the protected set (a malicious index cannot write outside), reject case collisions and Windows reserved names.
- File ids: 128-bit random, hex name = `store/<id>`. Never derived from the path.
- Move detection: `mac` = HMAC-SHA256(k_mac, content). A vanished path + a new path with identical mac (unambiguous) → move, keep id. Moved+edited → remove+new (documented); `nbp-git-safe mv` handles explicit moves. Stat cache in `.git/nbp-safe/statcache` keyed by HMAC of path (the `.git` dir must not contain names or content).
- Removal: `onMissing=keep` default (warn only); `remove`/`ask` options; `rm <path>` explicit.
- Vault commit message fixed: `nbp-safe: seal`; timestamps rounded to the hour (configurable).

## Key agent
- `multiprocessing.connection` with `authkey=None` and our own **mutual HMAC-SHA256 handshake** (`hmac.compare_digest`); only `send_bytes`/`recv_bytes(maxlength)` — **never `recv()`** (unpickle). The stdlib challenge uses HMAC-MD5 and `==`.
- Windows: AF_PIPE `\\.\pipe\nbp-git-safe-<random>` (hardening later: DACL via ctypes + reject remote clients); POSIX: AF_UNIX in a 0700 dir, `RLIMIT_CORE=0`.
- `agent.json` in `.git/nbp-safe/`: address, authkey, pid, expiry. **Never the encryption key.**
- Ops: hello, status, enc_blob, dec_blob, enc_index, dec_index, mac, key_id, lock. Key never leaves the agent.
- `unlock` runs `keyCommand` in the CLI process (foreground, so interactive prompts like Windows Hello appear), 120 s timeout, validates base64→64 bytes, sends to agent over the authenticated channel. Agent starts detached (`DETACHED_PROCESS|CREATE_NEW_PROCESS_GROUP`, pythonw on Windows; `start_new_session` on POSIX). Absolute TTL + optional idle timeout. Orphan `agent.json` detected and removed.
- Hooks never prompt by default; locked → clear error "run `nbp-git-safe unlock`".

## Guard on the main branch (defence in depth)
1. managed exclude block; 2. pre-commit by path (`git ls-files -c -i -X`); 3. pre-commit by content (if agent open: compare mac of staged blobs against index macs — catches renamed copies); 4. pre-push repeats 2–3 for each pushed ref range and validates `nbp-safe` (allowed paths only, magic on every `store/*`, known hash for `.gitattributes`/README); 5. optional `.gitignore` block. `--no-verify` still leaves the exclude block (`add -A` safe; `add -f` + `--no-verify` leaks — documented limit).

## CLI (daily use should need almost none)
`init [--generate-key]` (prints the key ONLY to stdout once, tells user to pipe it to a password manager), `unlock`, `lock`, `status`, `seal`, `open`, `ls`, `log <path>`, `diff <path>` (difflib in memory, no temp files), `mv`, `rm`, `sync`, `push` (no force), `rotate`, `purge` (typed confirmation), `doctor`, `uninstall`, `hook <event>`.
`open` materializes real names from the vault into the working tree and never overwrites diverging local plaintext (writes `*.nbp-theirs`, also excluded). Plain writes via `path.nbp-tmp` + `os.replace` (`*.nbp-tmp` excluded).

## Multi-machine
Clone → `uv tool install nbp-git-safe==X` → `nbp-git-safe init` (detects `origin/nbp-safe`, creates local branch, hooks, exclude) → `unlock` → `open`. post-merge/post-checkout run `open` automatically if the agent is unlocked. Without the key the user only sees opaque `store/<hex>`. `sync`: fetch + 3-way merge by index entries (merge commit with two parents); same-id conflict → second id `.conflict-<short>`; never force. Rotation: new key + new ref (`nbp-safe-<year>`) with current state re-encrypted; old ref deleted only with typed confirmation.

## Test strategy (all fake data, no network)
- Unit: RFC 5297 vectors; round-trip/padding/AD (swapping ids fails); index parser (+fuzz in phase 7); path validation; index merge.
- Integration with real git in tmp dirs (isolate with `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` like transcrypt's `tests/_test_helper.bash`): init, seal, push to local `--bare` remote, clone, open; new/changed/moved/moved+edited/removed; divergent sync; rotate; `core.autocrlf=true`; names with accents and spaces.
- **Leak tests (gate for every phase ≥1):** fake data carries random canaries in content AND file names (`CANARY_N_<rand>`). After every scenario scan the bare remote (`git cat-file --batch-all-objects --batch`: blobs/trees/commits/tags; `for-each-ref`; `packed-refs`; commit messages) and the whole local `.git` (objects, `agent.json`, statcache, info/) and OS temp for the canaries, also base64/UTF-16/hex encoded. Zero hits. The harness must be proven by planting a canary on purpose.
- Failure: agent killed mid-seal (ref unchanged), wrong key (key_id), tampered blob/index/tree, `keyCommand` timeout/invalid/non-zero, disk full on `open`.
- Coexistence: pre-existing hook in hooks dir, husky-style `core.hooksPath`, pre-commit framework, git without config-hooks (shim fallback), `--no-verify` (prove the exclude still protects `add -A`).
- Matrix in CI: Windows (PowerShell + Git Bash), Ubuntu, macOS × Python 3.11/3.12/3.13. Pytest for everything (BATS only optional smoke).

## Repository layout
```
LICENSE (MIT: transcrypt copyrights + ours)  NOTICE  THIRD_PARTY.md  README.md  SECURITY.md  THREAT_MODEL.md  CHANGELOG.md
docs/FORMAT.md   pyproject.toml   uv.lock
src/nbp_git_safe/{cli,config,crypto,agent,vault,index,guard,hooks,gitutil}.py
tests/{unit,integration,leak}/    .github/workflows/ci.yml  (no secrets; actions pinned by SHA; `uv sync --frozen`; license check)
```
Deps: `cryptography` exact-pinned (release > 7 days), `[tool.uv] exclude-newer = "<absolute date>"`; dev: pytest, ruff.

## Phases (one at a time; acceptance criteria are mandatory)
- **0 Fork:** full (non-shallow) `git clone` of https://github.com/elasticdog/transcrypt into this folder, keep upstream history, tag `upstream-base`, NO remote created, NOTICE, our copyright line added to LICENSE (original lines intact). Acceptance: `git log` shows upstream history; LICENSE original intact; upstream BATS suite runs green here if bats is available (otherwise report).
- **1 Crypto + leak harness (highest risk):** `crypto.py`, `docs/FORMAT.md`, leak-test harness, pyproject/uv skeleton; remove the transcrypt script in an explicit commit (keep `tests/_test_helper.bash` ideas ported to pytest fixtures). Acceptance: RFC vectors pass; 100% branch coverage in `crypto`; harness detects a deliberately planted canary.
- **2 Agent** (Windows first). Acceptance: unlock/lock/status/TTL on Windows (and Linux if available); mutual handshake; test proving the key is absent from disk and from `agent.json`; fail closed.
- **3 Vault by plumbing:** seal/open/status/ls/log/mv/rm, index, CAS. Acceptance: full cycle + leak scan green; no worktree; autocrlf tested.
- **4 Main-branch guard:** init, managed exclude, hooks (config + fallback), pre-commit/pre-push (path + content + vault validation), doctor. Acceptance: coexistence matrix green; `add -A` and `add -f` blocked; leak green.
- **5 Multi-machine:** sync/merge, push without force, clone flow, rotate, purge with typed confirmation. Acceptance: two diverged clones converge with no force; remote never gets a non-fast-forward without explicit confirmation.
- **6 Automation/UX:** post-commit/merge/checkout, opt-in `autoPush`, optional watcher, docs. Acceptance: "edit → commit → push" without extra commands in the happy path.
- **7 Hardening/release:** Windows pipe DACL via ctypes, fuzz, external review, 0.1 release, SECURITY/THREAT_MODEL complete.

## Threat model summary (THREAT_MODEL.md must state)
Protects: contents and names on GitHub/forks/clones without the key; local object DB (no plaintext/names); tampering (AES-SIV per blob, AD binds id, authenticated index). Does NOT protect: number/size(mitigated by padding)/timing of changes, equality of contents, branch name; compromised key = entire history (rotate via new ref, no retroactive protection); compromised PC with agent unlocked; plaintext at rest in the working tree (indexers/AV/cloud sync — `doctor` warns); `git stash -a`/`add -f` plaintext; Python cannot reliably wipe memory; LGPD/GDPR erasure needs history rewrite (typed confirmation) and may need GitHub support.

## Experience requirement (owner)
"My experience must stay the same": after setup the owner keeps running the same scripts that write reports at the same paths, then `git add/commit/push` as usual; the vault is sealed automatically; nothing extra in the common path.
