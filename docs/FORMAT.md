# nbp-git-safe on-disk format, version 1

Normative description of what `src/nbp_git_safe/crypto.py` produces and accepts. All integers are
big-endian. "||" is byte concatenation. No cryptographic construction is invented here: only
AES-SIV (RFC 5297), HKDF-SHA256 (RFC 5869) and HMAC-SHA256 (RFC 2104) from the `cryptography`
package are used.

## 1. Master key

* 64 random bytes (`os.urandom`), generated once by `init --generate-key`.
* Textual form (what `keyCommand` must print and what the agent accepts): standard base64 (RFC 4648
  section 4 alphabet, with padding), exactly 88 characters, decoding to exactly 64 bytes. The parser
  is strict: a single trailing `\n` or `\r\n` is tolerated; any other whitespace, other alphabet
  (e.g. URL-safe), missing/extra padding, non-canonical trailing bits, or a length other than 64
  decoded bytes is rejected. Inputs longer than 1024 characters are rejected before decoding.
* The master key is never written to disk. Only the derived keys below exist in memory, and the
  master key itself is not retained after derivation.

## 2. Key derivation

HKDF with SHA-256, `salt = None` (RFC 5869: a string of HashLen zero bytes), input keying material
= the 64-byte master key. Each derived value uses its own `info` string and a single Expand call:

| Name      | `info` (ASCII)             | Length | Used for                                   |
|-----------|----------------------------|--------|--------------------------------------------|
| `k_blob`  | `nbp-git-safe/v1/blob`     | 64     | AES-256-SIV key for file blobs             |
| `k_index` | `nbp-git-safe/v1/index`    | 64     | AES-256-SIV key for the index              |
| `k_mac`   | `nbp-git-safe/v1/mac`      | 32     | HMAC-SHA256 key for content MACs           |
| `key_id`  | `nbp-git-safe/v1/key-id`   | 8      | public identifier of the key (see below)   |

`key_id` is the HKDF output for the `key-id` info, requested at length 8 (equivalently, the first
8 bytes of a longer output, since HKDF-Expand is prefix-consistent). It is stored in clear in every
blob header so a wrong key is detected before any decryption. It reveals nothing about the master
key beyond a 64-bit one-way fingerprint.

Keys are domain-separated: a blob cannot be opened as an index or vice versa (different keys and
different associated data).

## 3. Header (17 bytes)

| Offset | Length | Value                                                 |
|--------|--------|-------------------------------------------------------|
| 0      | 8      | magic `00 4E 42 50 53 41 46 45` (`\x00NBPSAFE`)       |
| 8      | 1      | format version, `0x01`                                |
| 9      | 8      | `key_id`                                              |

The header is authenticated (it is part of the associated data) even though it is stored in clear.

## 4. Frame and padding

Plaintext is wrapped in a frame before encryption:

```
frame = u64_be(len(data)) || data || 0x00 * pad
```

`pad` is the smallest value >= 0 such that `len(frame)` is a multiple of `pad.bucket` (default
4096, configurable between 1 and 1 MiB). So an empty file still produces one full bucket (the 8-byte
length prefix is padded to 4096 bytes). Padding hides exact sizes behind the bucket granularity; it
does not hide the order of magnitude of large files.

On decryption (after authentication succeeds) the frame is rejected as malformed if it is shorter
than 8 bytes, if the length prefix exceeds the remaining bytes, or if any padding byte is non-zero.
Decryption does not require knowing the bucket: any zero padding is accepted, because the frame is
authenticated end to end.

Limit: one-shot, in memory. Plaintext larger than 64 MiB (67,108,864 bytes) is refused on
encryption (and on MAC computation); blobs larger than 64 MiB plus the fixed overhead and the
maximum bucket are refused on decryption without being processed.

## 5. File blob (`store/<file_id>`)

```
blob = header || AES-SIV-256(k_blob).encrypt(frame, AD = [header, file_id_raw])
```

* `file_id`: 128 random bits (`os.urandom(16)`), never derived from the path. Its textual form is
  32 lowercase hexadecimal characters (the name of the object under `store/`); `file_id_raw` is the
  16 decoded bytes. Uppercase, short, long or non-hex ids are rejected.
* AES-SIV takes the associated data as a *vector of two components*: `header` (17 bytes) and
  `file_id_raw` (16 bytes), in this order (RFC 5297 section 2.4: each component is processed
  separately by S2V, so component boundaries are unambiguous).
* The AES-SIV output is `SIV (16 bytes) || ciphertext (len(frame))`, so
  `len(blob) = 17 + 16 + len(frame)`.
* Because the id is in the associated data, a blob copied to another `store/<id>` fails
  authentication. Because AES-SIV is deterministic, equal (key, id, plaintext, bucket) yields an
  identical blob; and since the id is random per file, equal contents in different files do not
  produce equal blobs.

Decryption order: validate length (>= 17 + 16 + 8), magic and version; compare `key_id` with the
key's `key_id` in constant time (`hmac.compare_digest`); only then decrypt/authenticate; then
validate the frame. Failure at any step is a typed error with a fixed message and nothing is
returned.

## 6. Index (`nbp-safe/index`)

```
index_blob = header || AES-SIV-256(k_index).encrypt(frame, AD = [header || "index"])
```

* The associated data is a *single* component: the 17 header bytes concatenated with the 5 ASCII
  bytes `index`.
* The plaintext is canonical JSON of a JSON object: UTF-8, keys sorted, separators `,` and `:` with
  no whitespace, non-ASCII characters left unescaped, `NaN`/`Infinity` forbidden. It is wrapped in
  the same frame/padding as blobs.
* On open, the parser rejects non-objects, invalid UTF-8/JSON, duplicate object keys and
  non-finite numbers. Structural validation of the content (path rules, protected-set membership,
  case collisions, reserved names) belongs to the index module (phase 3) and is applied on top of
  this layer.
* Logical content: `{v: 2, key_id, entries: {file_id: {path, mode, size, mac, created, updated}},
  seq, prev}` where `path` is a POSIX-style NFC relative path.
* **Chain.** `seq` is an integer (1 to 2^53) and `prev` is `""` or the SHA-256 (hex) of the canonical
  JSON of the FIRST parent's index. A root commit has `prev == ""`; every other commit has `seq`
  strictly greater than the `seq` of every parent and `prev` equal to the first parent's digest (a
  merge: `seq = max(parents) + 1`). Both are inside the authenticated index, so only the key
  holder can write them. A commit that replays an older tree on top of a newer parent has a
  `seq` that does not increase and is refused. Version 1 (no `seq`/`prev`) was never published
  and is not accepted. Purge keeps each `seq` and recomputes `prev` along the rewritten chain;
  rotate starts a new lineage (`seq` 1).
* **Local verification state** (`.git/nbp-safe/vault-seq.json`, commit ids and numbers only):
  the newest vault tip whose chain this clone verified, per vault ref. `open`, `sync`, the
  hooks, `doctor` and the vault `pre-push` verify the chain (incrementally from that tip) and
  refuse a tip that is behind it or does not descend from it, unless the history is adopted on
  purpose (`purge`, `--accept-remote-rewrite`). A ref with no entry is never adopted silently: the
  chain is verified from the root and the tip is adopted only with `--confirm-first-adopt`, after
  the error showed the key id, the `seq` and the tip (trust on first use, see `THREAT_MODEL.md`). A
  file that exists but cannot be parsed is an error, not an empty record.
* **Pattern memory** (`.git/nbp-safe/pattern-versions/<id>`, `pattern-forgotten.json`): one file per
  distinct version of `.nbp-safe` the clone has seen (the meaningful pattern lines, `<id>` = first 32
  hex digits of their SHA-256), and the patterns / versions `unprotect` forgot. See `GUARD.md`.

## 7. Content MAC

`mac = HMAC-SHA256(k_mac, content)` (32 bytes) over the *plaintext* file content, stored in the
(encrypted) index. Used for move detection and for comparing staged content with protected content
without decrypting blobs. Verification uses `hmac.compare_digest`.

## 8. Error handling guarantees

* All errors derive from `NbpCryptoError`; messages are fixed strings and never contain key
  material, plaintext, ciphertext, file ids or names.
* Underlying exceptions are not chained (`raise ... from None` / raised outside the handler) so
  tracebacks cannot expose parsed content.
* `KeySet` objects have a redacted `repr`/`str` (only `key_id`), cannot be pickled or copied, and
  have no `__dict__`.
* Python cannot reliably wipe memory; derived keys live in ordinary `bytes` objects for the life of
  the agent process.

## 9. Test vectors

`tests/unit/test_rfc5297.py` checks `AESSIV` against RFC 5297 Appendix A.1 (deterministic) and A.2
(nonce-based) vectors, proving the primitive. `tests/unit/test_crypto.py` pins the HKDF `key_id`
derivation and the content MAC against independent HMAC-based computations.

## 10. Vault branch (`refs/heads/nbp-safe`)

An orphan branch built only with git plumbing (`hash-object -w --stdin --no-filters`,
`update-index --cacheinfo` on a private `GIT_INDEX_FILE`, `write-tree`, `commit-tree`,
`update-ref <ref> <new> <old>` as compare-and-swap). No worktree, and neither the index nor the
working tree of the main branch is touched. The tree contains exactly:

| Path             | Content                                                              |
|------------------|----------------------------------------------------------------------|
| `.gitattributes` | `* -text -diff -merge\n`                                             |
| `README.md`      | fixed generic text                                                   |
| `nbp-safe/index` | the encrypted index (section 6)                                      |
| `store/<id>`     | one encrypted blob per file (section 5), `<id>` = 32 lowercase hex   |

Anything else in the tree, a non-regular mode, a different `.gitattributes`/`README.md` hash, a
missing index, or an index entry without a `store/<id>` blob is rejected by `open`.

Commits use the fixed message `nbp-safe: seal`, the fixed identity `nbp-safe
<nbp-safe@localhost.invalid>` for author and committer, and timestamps rounded down to
`commit.timeGranularity` (default one hour), always `+0000`. Because AES-SIV is deterministic, sealing
unchanged content produces the same tree and no commit is created.

Index content validated on `open` (before anything is written): `v == 2`; `seq` and `prev` as in section 6 and the chain verified; `key_id` equals the
agent's key; every file id is 32 lowercase hex; every entry has exactly `path, mode, size, mac,
created, updated`; `mode` is `100644` or `100755`; `path` is NFC, relative, `/`-separated, has no
empty/`.`/`..` component, no control characters or `<>:"|?*\`, no component ending in a dot or
space, no `.git`/`git~N` component, no Windows reserved device name (with or without extension), no
`.gitattributes`/`.gitignore`/`.gitmodules`/`.nbp-safe`/`.nbp-safe.config` name at any depth and
no `*.nbp-tmp`/`*.nbp-theirs` suffix; paths must not collide case-insensitively nor be both a file
and a directory; every path must match the protected set and must not be tracked on the main
branch. Each decrypted blob must match its entry's `size` and `mac`.

## 11. Agent transport (state directory, `agent.json`, handshake, messages)

**State directory.** Everything the agent needs to be found lives OUTSIDE the repository, in a
per-user directory computed by the program (never read from a file):
`%LOCALAPPDATA%/nbp-git-safe/<repo hash>` on Windows, `~/.cache/nbp-git-safe-<uid>/<repo hash>` on
POSIX (the home directory comes from the password database, not from `$HOME`, and
`$XDG_RUNTIME_DIR` is deliberately not used: it exists in a login session and not in a hook started
by a GUI or cron, which would otherwise look for the agent in another place; the absolute path in
`NBP_SAFE_RUNTIME_DIR` overrides the base), where `<repo hash>` is the first 24 hex digits of
SHA-256 of the canonical path of `<git-common-dir>/nbp-safe`. The directory and its parent are
created by the tool (Windows: protected DACL, full control for the current user, SYSTEM and
Administrators only; POSIX: mode 0700) and **re-verified on every use**: not a link or junction,
owned by the current user (Windows: or Administrators), and no access for anybody else (Windows:
no allow entry for another account; POSIX: no group/other bits). If the check fails nothing is read
from it, written to it or deleted from it, and the agent counts as not running.

Files in it: `agent.secret` (32 random bytes, created once with `O_EXCL`, mode 0600), `agent.json`,
`unlock.lock`. On POSIX the socket does **not** live here (see "Socket directory" below).

`agent.json`: `{v: 2, address, family, nonce (hex, 32 bytes), pid, started, expires_at,
idle_timeout}`. It contains **no secret** and never the encryption key. The connection `authkey` is
derived, not stored: `authkey = HMAC-SHA256(agent.secret, "nbp-git-safe/agent/authkey/v2" || nonce)`.
`address` must be exactly what the program would have made: a pipe `\\.\pipe\nbp-git-safe-<24 hex>` on
Windows, a socket that is a direct child of the socket directory on POSIX (`<12 hex>-<12 hex>.sock`,
at most 100 bytes in all); anything else makes the file "corrupted". The only paths the program ever deletes are `agent.json` and a socket that passed
that check; the content of a file never decides what else is removed.

**Socket directory (POSIX).** `sun_path` holds 104 bytes on macOS and 108 on Linux, far less than
the state directory path, so sockets sit in a separate short directory: `/tmp/nbp-<euid>` by
default (fixed, deliberately independent of `$TMPDIR`, which is `/var/folders/...` on macOS and
differs between processes, and of `$XDG_RUNTIME_DIR`, absent in cron or GUI-started hooks), or
`<state root>/s` when the state root is overridden with `NBP_SAFE_RUNTIME_DIR`. Socket names are
`<first 12 hex of the repository hash>-<12 random hex>.sock`; the full path must be at most 100
bytes, otherwise the agent refuses to start with a clear message (use a shorter
`NBP_SAFE_RUNTIME_DIR`). The directory is created 0700 and, like the state directory, re-verified on
every use: a plain directory (not a link), owned by the current user, no group/other bits.
It holds **sockets only**; `agent.secret`, `agent.json` and the lock stay in the private state
directory. If somebody else created `/tmp/nbp-<uid>` first (squatting), or its mode is loose, the
check fails and the agent does not start: a denial of service that fails closed. Nothing secret is
ever placed there, and a socket in a directory another user controls would still need the
`agent.secret`-derived handshake (and the peer-uid and pid checks) to be trusted.

**Who starts the agent.** The process that runs `unlock` generates the address, the nonce and the
`authkey` and hands them to the new agent over the agent's own **stdin pipe** (one JSON line); the
agent answers `READY <pid>` on its stdout pipe. The pid must be the process just started (on
Windows a venv launcher stub re-executes the interpreter, so a direct child of it is accepted). The
agent runs with `python -I` (isolated: no `PYTHON*` variables, no user site, no current directory
on `sys.path`), working directory = the state directory and an explicit minimal environment. The
master key is delivered only to an agent started this way: an agent that is merely *found* through
`agent.json` is used for ordinary requests (after the checks below) but never receives the key; a
locked or unauthenticated one is replaced by a new agent.

**Transport.** Windows: a named pipe created by the tool with `CreateNamedPipeW` (ctypes):
DACL granting the current user only, `PIPE_REJECT_REMOTE_CLIENTS`, and
`FILE_FLAG_FIRST_PIPE_INSTANCE` so the name cannot be squatted; clients connect at
`SECURITY_IDENTIFICATION` (the server cannot impersonate them). POSIX: an `AF_UNIX` socket in the
0700 socket directory (mode 0600, listen backlog 32), the peer's uid is checked on accept and (Linux `SO_PEERCRED`, macOS
`LOCAL_PEERCRED`) by the client. Before sending a single byte the client checks that the process
serving the connection is the pid in `agent.json` (Windows `GetNamedPipeServerProcessId`, POSIX
peer credentials) and belongs to the current user. `multiprocessing.connection` is used with
`authkey=None` and only `send_bytes`/`recv_bytes(maxlength)` (never `recv`, which unpickles).

Mutual handshake (HMAC-SHA256 keyed with `authkey`, `hmac.compare_digest`):

1. client -> `"NBPAGENT\x01" || cnonce(32)`
2. server -> `snonce(32) || HMAC(authkey, "nbp-git-safe/agent/v1/server" || cnonce || snonce)`
3. client verifies, then -> `HMAC(authkey, "nbp-git-safe/agent/v1/client" || cnonce || snonce)`
4. server verifies, then -> `"OK"`

Handshake messages are limited to 128 bytes and must arrive within 5 s. Requests are
`u8 proto(1) || u8 op || args` with `args` = length-prefixed (`u32`) parts, at most
`MAX_BLOB_SIZE + 1 MiB` per message; replies are `u8 proto || u8 status || body` where an error body
is a short fixed code. Operations: `hello`, `status`, `load_key` (once), `enc_blob`, `dec_blob`,
`enc_index`, `dec_index`, `mac`, `key_id`, `lock`.

## 12. Merge, rotation and purge commits

* **sync** merge commit: fixed message `nbp-safe: sync`, two parents (local tip first), same fixed
  identity and rounded timestamp as a seal. Its tree starts from the local tree; entries adopted from
  the other side bring their blob (same id) or are re-encrypted under a new id (conflict copies).
  Conflict-copy paths are `<dir>/<stem>.conflict-<8 hex>.<ext>` or `<path>.conflict-<8 hex>`
  (`-2`, `-3` if taken), always inside the protected set.
* **rotate** commit: fixed message `nbp-safe: rotate`, no parent, on a new branch `nbp-safe-<suffix>`.
  New key, new `key_id`, fresh file ids, MACs recomputed, same paths/modes/sizes/timestamps.
* **purge** rewrites every commit of the branch (same fixed messages, original timestamps, parents
  mapped); index and tree lose the purged ids.
* Local state, none of it secret and none of it containing names or content:
  `.git/nbp-safe/remote-seen.json` (`{"refs": {ref: commit id}}`), `purged.json`
  (`{ref: tip before the last purge}`), `autopush.json` (refspecs added by `init --auto-push`).
