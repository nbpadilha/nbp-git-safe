# Threat model

Status: pre-release, **not audited by any third party**. This document says what nbp-git-safe is
meant to protect, against whom, and where it stops. If something here contradicts the code, the
code is wrong or this file is: please report it ([SECURITY.md](SECURITY.md)).

## 1. What is protected

| Asset | Where it lives | Protection |
|---|---|---|
| Contents of protected files | `store/<id>` blobs on the vault branch | AES-SIV (256-bit key pair), key bound to file id, padded to size buckets |
| File names and paths | inside the encrypted index only | the index is AES-SIV encrypted; ids are random, never derived from names |
| Master key (64 bytes) | the password manager; the memory of the agent process | never written to disk by this tool; handed over by a pipe |
| Integrity of the vault | blobs, index, tree | authenticated encryption; index entries carry content MACs; the vault tree shape is validated |
| The main branch | ordinary commits | guard hooks keep protected files and their content out of it |

## 2. Adversaries considered

1. **A reader of the Git remote** (the hosting provider, anyone with read access, a fork, a leaked
   backup of the remote) who does not have the key.
2. **A writer on the remote** (a collaborator, a compromised token, a malicious host) who tries to
   tamper with the vault: corrupt, swap, roll back, or plant data.
3. **A reader of the local object database** (`.git`) without the key and without a running agent:
   a stolen disk image of a locked machine, a backup of the repository folder.
4. **A careless operator**: forgetting a hook, running `git add -f`, committing while locked.
5. **Another local user** of the same machine trying to talk to the agent.

Out of scope: an attacker who controls the machine while the agent is unlocked (section 4), a
compromised password manager, a malicious `keyCommand`, a malicious git or Python installation, and
attacks on the `cryptography` library itself.

## 3. What it protects against

* **Content and names against adversary 1.** Without the key the remote shows opaque `store/<hex>`
  names, one encrypted index, a fixed generic README, fixed commit messages, a fixed identity and
  timestamps rounded to the hour.
* **Tampering by adversary 2.** A modified blob fails AES-SIV authentication; a blob copied to
  another id fails (the id is authenticated data); a modified or swapped index fails; a tree with
  extra entries, a non-regular mode, a wrong `.gitattributes` / README or a blob without the
  magic header is rejected by `open`, `status` and the push guard. An index cannot place a file
  outside the protected set or outside the repository (relative paths only, no `..`, no `.git`
  component, no Windows reserved names, case-collision checks).
* **Rollback and replacement.** The clone remembers the remote vault tip it last saw; a tip that is
  an ancestor of it (rollback) or unrelated (replaced history) is reported and refused unless you
  pass `--accept-remote-rewrite`. Every index also carries an authenticated, strictly increasing
  `seq` and the digest of its parent's index (`docs/FORMAT.md` section 6), and the clone remembers
  the newest tip it verified per vault ref (`.git/nbp-safe/vault-seq.json`: commit ids and numbers
  only): a fast-forward commit that replays an older encrypted index (which needs no key) fails the
  chain check and is never opened. Which vault ref a clone trusts is a **local** decision
  (`nbp-safe.vaultRef` in `.git/config`, the flag or the environment): a `vault.ref` in the
  versioned `.nbp-safe.config` is ignored (and reported), so a commit cannot redirect the clone to
  another ref that holds an old, authentic vault commit and so has no record to be compared with.
  A vault ref this clone has never verified (a fresh clone, a ref you chose, a lost record) is
  adopted only with `--confirm-first-adopt` after the error showed its key id, `seq` and tip.
  A `vault-seq.json` that exists but cannot be read is an error (`open`, `sync`, `seal` and the
  push guard stop and say so; `doctor` reports a problem), never an empty record.
* **Pattern removal and negation upstream.** A collaborator who removes a pattern from `.nbp-safe`
  or defeats it with a `!` negation (even from a web UI, where no hook runs) does not unprotect
  anything here: the clone keeps every distinct *version* of `.nbp-safe` it has seen and evaluates
  each as a source of the union, so a negation of a newer version never cancels what an older
  version protects, while a negation inside the version it is written in keeps working. The guard
  also blocks any path of the vault index, `post-merge`/`post-checkout`/`doctor` warn loudly when
  the current version weakens an earlier one, and only `unprotect <pattern>` or
  `unprotect --accept-current` (typed confirmation, durable) forgets (`docs/GUARD.md`). The
  protection lives in this clone's memory: a clone that never saw the protecting version (a fresh
  clone of an already-weakened `.nbp-safe`) has nothing to remember. `.nbp-safe` and
  `.nbp-safe.config` are never protected paths (their content is still compared with the protected
  content), so a broad pattern pushed from the remote cannot lock the repair of the file.
  The file is read exactly as git reads it (one CR, BOM, trailing spaces; a CR-padded line is a
  different pattern, so it cannot make an older version look "equal" and be pruned), a link,
  special file or oversized `.nbp-safe` is refused unread, an unreadable memory stops the hooks
  (fail closed), and the memory is capped at 64 independent versions (`unprotect --accept-current`
  to start over): nothing is dropped silently.
* **Hostile working tree.** `git` and `keyCommand` are resolved to absolute paths outside the
  current directory and outside the repository tree (`PATH` entries inside the repository, such as
  a `node_modules/.bin` or a `bin/` of the project, are skipped; when nothing else is found the
  bare name is used and the system search applies), and children get
  `NoDefaultCurrentDirectoryInExePath=1`; the auxiliary git that matches patterns runs with an
  environment without the repository-binding variables and without the variables that inject
  configuration or programs (`GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_COUNT`/`KEY_*`/`VALUE_*`,
  `GIT_EXTERNAL_DIFF`, `GIT_PAGER`, `GIT_ASKPASS`, `SSH_ASKPASS`, `GIT_SSH*`, `GIT_EDITOR`,
  `GIT_TRACE*`; `GIT_CONFIG_GLOBAL`/`SYSTEM` stay, they are how the user's own config is chosen),
  while the calls about the user's repository keep the user's environment, which fetch and push
  need; `open` writes through random, exclusively created temporary files and re-checks links and
  junctions before every write; a versioned `.nbp-safe.config` can only raise `pad.bucket` /
  `commit.timeGranularity` to their floors and cannot set `onMissing` or `vault.ref`.
* **The local object database (adversary 3).** Plain content and real names are never written to
  `.git/objects` by this tool (the invariant is enforced by leak tests on every scenario). The
  stat cache is keyed by an HMAC of the path and holds sizes, times and content MACs only.
  The agent's `agent.json` (outside the repository, see "Local channel") holds the pipe address, the
  PID, the expiry and a public nonce, never the encryption key.
* **Operator mistakes (adversary 4).** A managed block in `.git/info/exclude` keeps `git add -A`
  away from protected files; `pre-commit` blocks protected paths and, with the agent unlocked,
  renamed or copied content; `pre-push` repeats the checks over every commit being pushed and
  validates the vault branch. `doctor` reports tracked protected files, a missing guard, a stash
  that holds protected files and cloud-synced folders. Failure is closed: an unexpected error in a
  hook blocks the commit.
* **Local channel (adversary 5).** The agent speaks only over a named pipe or a 0700 Unix socket,
  requires a mutual HMAC-SHA256 handshake before any request, uses length-limited `send_bytes` /
  `recv_bytes` only (never unpickling), and never returns the key. What makes it hard to hijack
  (design in `docs/FORMAT.md` section 11):
  * `agent.json` is not a trust anchor. It lives outside the repository, in a per-user directory
    (`%LOCALAPPDATA%` on Windows; `~/.cache/nbp-git-safe-<uid>` elsewhere, found through the
    password database, not through `$HOME` or `$XDG_RUNTIME_DIR`, so that a hook started by a GUI
    with another environment still finds the agent; `NBP_SAFE_RUNTIME_DIR` overrides it) that the
    tool creates and re-verifies on every use (owner, no link/junction, DACL or mode); in a
    directory that fails the check nothing
    is read, written or deleted. A planted file therefore cannot make the program delete anything
    (the only paths ever removed are `agent.json` and a socket at an exactly computed place), nor
    can it point the client at an arbitrary pipe.
  * POSIX sockets live in a short, separately verified directory (`/tmp/nbp-<uid>`, 0700, owned by
    the user, not a link; `docs/FORMAT.md` section 11) because `sun_path` is ~104 bytes. Squatting
    that name in the shared `/tmp` (another user creating it first, or loosening it) makes the
    check fail and the agent refuse to start: a denial of service, closed. It never leaks anything:
    the secret and the state are not in that directory, and the client trusts a socket only after
    the mutual handshake, the pid named in `agent.json` and the peer's uid.
  * The connection key is not stored: it is `HMAC(agent.secret, nonce)`; an impostor that merely
    writes an `agent.json` of its own cannot complete the handshake, so it receives neither
    plaintext (`seal`) nor the master key. `unlock` hands the key only to an agent it started
    itself (credentials over the child's stdin pipe, reported pid checked), never to one found
    through a file.
  * Before sending a byte the client checks the pid and user of the process that serves the
    connection (`GetNamedPipeServerProcessId`, `SO_PEERCRED`); the Windows pipe has a DACL for the
    current user only, rejects remote clients, claims its name with `FILE_FLAG_FIRST_PIPE_INSTANCE`
    and is opened by clients at `SECURITY_IDENTIFICATION`. The pipe DACL and the state-directory
    ACL are compared by SID after resolving the SDDL aliases (`SY`, `BA`, `LA`, `CO`, `OW`), so
    the built-in Administrator is not refused for being printed as `LA`. Windows hides the token
    of an elevated process from a non-elevated one (and the reverse): when the agent's process
    cannot be inspected, the hook does not treat it as an impostor and does not give it anything;
    it degrades to the path check and says "agent unavailable" with the elevation hint (run git
    and `unlock` at the same level).
  * The agent process runs `python -I` (no `PYTHON*` variables, no current directory or user site on
    `sys.path`) with an explicit minimal environment, so a package planted in the temp or the
    working directory is never imported into the process that holds the key.
  * Limit: a process running as YOU can read `agent.secret`, read the agent's memory and the
    plaintext working tree. None of this defends against that (adversary "compromised machine with
    an unlocked agent", section 4).

## 4. What it does NOT protect against

* **Metadata.** The remote learns that a vault exists, its branch name, the number of files, their
  approximate sizes (bucketed, 4 KiB by default; the order of magnitude of large files is visible),
  when each seal happens (timestamps are rounded to the hour but the push time is visible to the
  host), which blobs changed between commits, and whether a file was modified at all.
* **Equality of contents over time.** Encryption is deterministic per (key, id, content): the same
  file with unchanged content keeps the same blob. Two different files with equal content get
  different blobs (different ids).
* **A compromised key.** Whoever has the master key can decrypt the **entire history** of that
  vault. `rotate` protects what is written afterwards; it cannot protect what an attacker already
  copied. Deleting the old branch from the remote does not recall copies.
* **A compromised machine with an unlocked agent.** Anything that can run as your user can talk to
  the agent for as long as it is unlocked and can read the plaintext working tree anyway.
  Python cannot reliably wipe memory; keys live in ordinary objects for the agent's lifetime, and
  can reach swap or a crash dump.
* **Plaintext at rest in the working tree.** Protected files are plain files at their real paths:
  indexers, antivirus, backup tools, cloud-sync clients and editors' recovery files can copy them.
  `doctor` warns about well-known cloud-synced folders (a heuristic).
* **Bypassing the guard.** `git commit --no-verify` skips `pre-commit`. `git add -f` writes the
  content into `.git/objects` immediately, before any hook runs; a blocked commit leaves an
  unreachable blob until `git prune`. `git add -f` plus `--no-verify` produces a local commit with
  the protected file (the push guard then blocks the push, but a local history that was never
  pushed keeps the data until rewritten). `git stash -a` / `-u` can capture protected files.
  Clients that do not run hooks (some GUIs, libgit2-based tools) skip layers 2 to 4.
* **First adoption of a vault (trust on first use).** A clone that has never verified a vault ref
  cannot know which tip is the newest: an older commit of the real history, pushed by someone with
  write access as the vault branch, verifies under the key and looks like a valid vault. The
  confirmation (`--confirm-first-adopt`) shows the key id, the `seq` and the tip so that the owner
  can compare them with a machine that already has the vault; it cannot decide for the owner. After
  the first adoption the chain and the recorded tip detect any older tip. A clone whose
  `vault-seq.json` is lost starts again at this point.
* **A locked agent.** With the agent locked the content check cannot run: a renamed copy of a
  protected file can pass `pre-commit` (the path check still runs).
* **History that existed before adoption.** The tool protects what it manages from now on. Files
  that were committed to the main branch earlier stay in that history, and unreachable objects
  already present in `.git/objects` (old stashes, abandoned commits) are not touched. Review and
  clean the repository (history rewrite, `git gc --prune=now`) before relying on it.
* **Names in versioned configuration.** `.nbp-safe` is versioned on the main branch, and the
  managed `.git/info/exclude` block contains the same patterns: whatever you write there is visible
  to the remote. Keep the patterns generic (`*.csv`, `reports/`); personal names belong in
  `.git/info/nbp-safe`, which is local. `init` and `pre-commit` print a lint warning for patterns
  that look like names or e-mail addresses.
* **Erasure obligations (LGPD/GDPR and similar).** Removing data really means rewriting vault
  history (`purge`, typed confirmation), a forced push that only you can run, pruning every clone,
  and possibly a request to the Git host to drop caches and forks.
* **Availability.** Losing the key makes the vault unreadable; there is no recovery. A remote
  can refuse or delete data; the local clones are the backup.
* **Denial of service by a writer on the remote** (for example pushing a huge or malformed vault):
  such a vault is rejected, but it still costs time and bandwidth.
* **Timing and side channels** of the implementation, and anything in the OS (swap, hibernation
  files, crash dumps).

## 5. Known gaps and planned work

* The POSIX side of the agent hardening (peer-credential checks with `SO_PEERCRED` / macOS
  `LOCAL_PEERCRED`, the 0700 directory checks) is implemented but has so far only been exercised
  on Windows 11; it needs a run on Linux and macOS.
* An external review of the format and the agent. Fuzzing of the index and blob parsers.
* Blobs are whole files held in memory (limit 64 MiB each); no streaming and no delta compression.
* No post-quantum consideration: AES-256-based, symmetric.

## 6. Operational advice that follows from the model

1. Keep the key only in a password manager; use item **UUIDs** in `keyCommand`; never put a key in
   a file, an environment variable of a long-lived shell, or shell history.
2. Use a short TTL on shared or travel machines, and `nbp-git-safe lock` when you leave.
3. Run `nbp-git-safe doctor` after setup and after upgrading git.
4. Keep protected folders out of cloud-sync clients and indexers.
5. Treat a lost laptop with an unlocked agent as a key compromise: rotate.
6. Before adopting an existing repository, check its history and object database for the data you
   are about to protect.
7. Do not commit with `--no-verify`; never `git add -f` a protected file.

## 7. What the end-to-end rehearsal taught

The tool was exercised on a real repository's generated reports and backups (dozens of files, tens
of MiB, a mix of CSV, JSON, logs and HTML) with a throw-away key, a local bare remote and a second
clone playing "another machine". A leak scan then searched the remote and the local `.git` for
thousands of canaries built from the real file names, name fragments, e-mail addresses,
identifiers and content lines, in UTF-8, UTF-16, base64 and hex. The data itself is not part of
this repository. What came out of it:

* **Zero canaries** in any object, ref, commit message or file of the remote, and none in the vault
  objects of any clone. The only hits were identifiers that already existed in the repository's
  own versioned code, in the main branch's `.git/index`, and in the generic patterns of
  `.git/info/exclude` (see "Names in versioned configuration" above).
* **A pre-existing unreachable blob** with plaintext from the repository's earlier life was
  inherited by the clone. The tool neither created nor can see it: see "History that existed before
  adoption".
* **Scale.** The first `seal` wrote one git process per file (`hash-object -w`), about 40 ms each
  on Windows, which made 5,000 files take almost four minutes. Blobs are now written in one
  `git fast-import` batch with the ids verified afterwards (about five times faster; 5,000 files
  in under a minute, and `git commit` with hooks about 6 seconds, on the rehearsal machine). Some
  per-file cost remains: one agent round trip per file for the path-keyed stat cache.
* **Moves and deletions do not propagate as deletions.** On another clone the old path of a moved
  file stays, and a file deleted locally on one machine reappears on another (`onMissing=keep`).
  The tool never deletes plaintext on its own; remove such files by hand or with `rm <path>`.
* **`log <path>` follows the blob.** A pure move changes only the index, so the log of a moved
  file shows the history of its content, not a row for the move.
* **Live files.** A file that another process appends to during a seal is sealed as of the moment
  it was read; the next seal picks up the rest.
* **Fail-closed paths behaved as designed** with a killed agent, an expired TTL, a locked agent
  (seal refuses, commits of code still work, a hint is printed) and a remote that moved ahead
  (the push is rejected; `sync` merges; both versions of a file edited on two machines are kept).
