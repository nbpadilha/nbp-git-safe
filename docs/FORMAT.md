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
* Planned logical content: `{v, key_id, entries: {file_id: {path, mode, size, mac, created,
  updated}}}` where `path` is a POSIX-style NFC relative path.

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

Index content validated on `open` (before anything is written): `v == 1`; `key_id` equals the
agent's key; every file id is 32 lowercase hex; every entry has exactly `path, mode, size, mac,
created, updated`; `mode` is `100644` or `100755`; `path` is NFC, relative, `/`-separated, has no
empty/`.`/`..` component, no control characters or `<>:"|?*\`, no component ending in a dot or
space, no `.git`/`git~N` component, no Windows reserved device name (with or without extension), no
`.gitattributes`/`.gitignore`/`.gitmodules`/`.nbp-safe`/`.nbp-safe.config` name at any depth and
no `*.nbp-tmp`/`*.nbp-theirs` suffix; paths must not collide case-insensitively nor be both a file
and a directory; every path must match the protected set and must not be tracked on the main
branch. Each decrypted blob must match its entry's `size` and `mac`.

## 11. Agent transport (`agent.json`, handshake, messages)

`<git-common-dir>/nbp-safe/agent.json`: `{v, address, family, authkey (hex, 32 bytes), pid,
started, expires_at, idle_timeout}`. It never contains the encryption key. The agent listens on a
named pipe `\.\pipe\nbp-git-safe-<random>` (Windows) or an `AF_UNIX` socket in a private 0700
directory (POSIX); `multiprocessing.connection` is used with `authkey=None` and only
`send_bytes`/`recv_bytes(maxlength)` (never `recv`, which unpickles).

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
