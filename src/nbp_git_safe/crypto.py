# SPDX-License-Identifier: MIT
"""Cryptographic core of nbp-git-safe.

Implements the format documented in ``docs/FORMAT.md``. No custom cryptographic
construction is used: only ``AESSIV``, ``HKDF`` and ``HMAC`` from
``cryptography.hazmat.primitives``.

Security properties of this module's API:

* Errors are typed and carry fixed messages. They never contain key material,
  plaintext, ciphertext or file names.
* ``KeySet`` never exposes the master key (it is not even retained) and refuses
  to be pickled, copied or printed with its secret fields.
* Everything is one-shot in memory; inputs above ``MAX_DATA_SIZE`` are refused.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
import struct
from collections.abc import Callable
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as crypto_hmac
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"\x00NBPSAFE"
VERSION = 1
KEY_ID_LEN = 8
HEADER_LEN = len(MAGIC) + 1 + KEY_ID_LEN  # 17
TAG_LEN = 16  # AES-SIV synthetic IV / tag
FRAME_LEN_BYTES = 8
MASTER_KEY_LEN = 64
FILE_ID_BYTES = 16
DEFAULT_BUCKET = 4096
MAX_BUCKET = 1 << 20
MAX_DATA_SIZE = 64 * 1024 * 1024  # 64 MiB
MAX_BLOB_SIZE = HEADER_LEN + TAG_LEN + FRAME_LEN_BYTES + MAX_DATA_SIZE + MAX_BUCKET
MAX_KEY_TEXT_LEN = 1024

INFO_BLOB = b"nbp-git-safe/v1/blob"
INFO_INDEX = b"nbp-git-safe/v1/index"
INFO_MAC = b"nbp-git-safe/v1/mac"
INFO_KEY_ID = b"nbp-git-safe/v1/key-id"
INDEX_AD_SUFFIX = b"index"


class NbpCryptoError(Exception):
    """Base class. Messages are fixed strings and never contain secrets or data."""


class InvalidKeyError(NbpCryptoError):
    """Master key is malformed (bad base64 or not exactly 64 bytes)."""


class InvalidArgumentError(NbpCryptoError):
    """A caller-supplied argument (file id, bucket, type) is invalid."""


class SizeLimitError(NbpCryptoError):
    """Input exceeds the 64 MiB one-shot limit."""


class BlobFormatError(NbpCryptoError):
    """Bad magic, unsupported version, truncated blob or malformed frame."""


class KeyIdMismatchError(NbpCryptoError):
    """The blob was written with a different key (key_id differs)."""


class AuthenticationError(NbpCryptoError):
    """Authentication failed: wrong key, wrong file id, or tampered data."""


class IndexFormatError(NbpCryptoError):
    """Decrypted index is not valid canonical-compatible JSON object."""


def _check_size(n: int) -> None:
    if n > MAX_DATA_SIZE:
        raise SizeLimitError("input exceeds the 64 MiB limit")


def _check_bucket(bucket: int) -> None:
    if isinstance(bucket, bool) or not isinstance(bucket, int) or not 1 <= bucket <= MAX_BUCKET:
        raise InvalidArgumentError("invalid padding bucket")


def _check_bytes(value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise InvalidArgumentError("expected a bytes-like object")
    return bytes(value)


def new_file_id() -> str:
    """Return a fresh random 128-bit file id as 32 lowercase hex characters."""
    return os.urandom(FILE_ID_BYTES).hex()


def _file_id_bytes(file_id: str) -> bytes:
    """Validate a file id (32 lowercase hex chars) and return its 16 raw bytes."""
    if not isinstance(file_id, str) or len(file_id) != FILE_ID_BYTES * 2:
        raise InvalidArgumentError("invalid file id")
    if file_id != file_id.lower():
        raise InvalidArgumentError("invalid file id")
    try:
        raw = bytes.fromhex(file_id)
    except ValueError:
        raw = b""
    if len(raw) != FILE_ID_BYTES:
        raise InvalidArgumentError("invalid file id")
    return raw


# --------------------------------------------------------------------------- keys


def generate_key() -> bytes:
    """Generate a fresh 64-byte master key from the OS CSPRNG."""
    return os.urandom(MASTER_KEY_LEN)


def encode_key(master: bytes) -> str:
    """Serialize a master key as standard base64 (88 characters, no newline)."""
    raw = _check_bytes(master)
    if len(raw) != MASTER_KEY_LEN:
        raise InvalidKeyError("master key must be exactly 64 bytes")
    return base64.b64encode(raw).decode("ascii")


def decode_key(text: str | bytes) -> bytes:
    """Strictly parse a base64 master key: exactly 64 bytes, canonical encoding.

    A single trailing ``\\n`` or ``\\r\\n`` (as emitted by command-line tools) is
    tolerated; any other whitespace, alphabet violation or non-canonical padding
    is rejected.
    """
    if isinstance(text, str):
        try:
            data = text.encode("ascii")
        except UnicodeEncodeError:
            raise InvalidKeyError("master key is not valid base64") from None
    elif isinstance(text, (bytes, bytearray)):
        data = bytes(text)
    else:
        raise InvalidKeyError("master key is not valid base64")
    if len(data) > MAX_KEY_TEXT_LEN:
        raise InvalidKeyError("master key is not valid base64")
    if data.endswith(b"\r\n"):
        data = data[:-2]
    elif data.endswith(b"\n"):
        data = data[:-1]
    try:
        raw = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        raise InvalidKeyError("master key is not valid base64") from None
    if base64.b64encode(raw) != data:
        raise InvalidKeyError("master key is not valid base64")
    if len(raw) != MASTER_KEY_LEN:
        raise InvalidKeyError("master key must be exactly 64 bytes")
    return raw


def _hkdf(master: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(master)


class KeySet:
    """Keys derived from the master key. The master key itself is not retained."""

    __slots__ = ("_k_blob", "_k_index", "_k_mac", "_key_id")

    def __init__(self, master: bytes) -> None:
        raw = _check_bytes(master)
        if len(raw) != MASTER_KEY_LEN:
            raise InvalidKeyError("master key must be exactly 64 bytes")
        self._k_blob = _hkdf(raw, INFO_BLOB, 64)
        self._k_index = _hkdf(raw, INFO_INDEX, 64)
        self._k_mac = _hkdf(raw, INFO_MAC, 32)
        self._key_id = _hkdf(raw, INFO_KEY_ID, KEY_ID_LEN)

    @classmethod
    def from_base64(cls, text: str | bytes) -> KeySet:
        return cls(decode_key(text))

    @property
    def key_id(self) -> bytes:
        """8-byte public key identifier (stored in every blob header)."""
        return self._key_id

    def __repr__(self) -> str:
        return f"<KeySet key_id={self._key_id.hex()}>"

    __str__ = __repr__

    def __reduce__(self) -> Any:
        raise TypeError("KeySet cannot be pickled or copied")

    def __getstate__(self) -> Any:
        raise TypeError("KeySet cannot be pickled or copied")

    # -- internal accessors used by the module-level functions only
    def _blob_cipher(self) -> AESSIV:
        return AESSIV(self._k_blob)

    def _index_cipher(self) -> AESSIV:
        return AESSIV(self._k_index)

    def _mac_key(self) -> bytes:
        return self._k_mac


# ------------------------------------------------------------------- frame/header


def _header(keys: KeySet) -> bytes:
    return MAGIC + bytes([VERSION]) + keys.key_id


def _pad_frame(data: bytes, bucket: int) -> bytes:
    total = FRAME_LEN_BYTES + len(data)
    padded = -(-total // bucket) * bucket
    return struct.pack(">Q", len(data)) + data + b"\x00" * (padded - total)


def _unpad_frame(frame: bytes) -> bytes:
    if len(frame) < FRAME_LEN_BYTES:
        raise BlobFormatError("malformed frame")
    (n,) = struct.unpack(">Q", frame[:FRAME_LEN_BYTES])
    if n > len(frame) - FRAME_LEN_BYTES:
        raise BlobFormatError("malformed frame")
    end = FRAME_LEN_BYTES + n
    if any(frame[end:]):
        raise BlobFormatError("malformed frame")
    return frame[FRAME_LEN_BYTES:end]


def parse_header(blob: bytes) -> bytes:
    """Validate magic/version of a blob and return its 8-byte key_id (no key needed)."""
    raw = _check_bytes(blob)
    if len(raw) < HEADER_LEN + TAG_LEN + FRAME_LEN_BYTES:
        raise BlobFormatError("truncated blob")
    if raw[: len(MAGIC)] != MAGIC:
        raise BlobFormatError("bad magic")
    if raw[len(MAGIC)] != VERSION:
        raise BlobFormatError("unsupported version")
    return raw[len(MAGIC) + 1 : HEADER_LEN]


def _seal(cipher: AESSIV, header: bytes, ad: list[bytes], data: bytes, bucket: int) -> bytes:
    _check_bucket(bucket)
    _check_size(len(data))
    return header + cipher.encrypt(_pad_frame(data, bucket), ad)


def _open(
    cipher: AESSIV, keys: KeySet, blob: bytes, make_ad: Callable[[bytes], list[bytes]]
) -> bytes:
    raw = _check_bytes(blob)
    if len(raw) > MAX_BLOB_SIZE:
        raise SizeLimitError("input exceeds the 64 MiB limit")
    key_id = parse_header(raw)
    if not hmac.compare_digest(key_id, keys.key_id):
        raise KeyIdMismatchError("blob was written with a different key")
    header = raw[:HEADER_LEN]
    ok = True
    frame = b""
    try:
        frame = cipher.decrypt(raw[HEADER_LEN:], make_ad(header))
    except InvalidTag:
        ok = False
    if not ok:
        raise AuthenticationError("authentication failed")
    return _unpad_frame(frame)


# ------------------------------------------------------------------------- blobs


def encrypt_blob(keys: KeySet, file_id: str, data: bytes, bucket: int = DEFAULT_BUCKET) -> bytes:
    """Encrypt ``data`` for ``store/<file_id>``. Deterministic for equal inputs."""
    fid = _file_id_bytes(file_id)
    plain = _check_bytes(data)
    return _seal(keys._blob_cipher(), _header(keys), [_header(keys), fid], plain, bucket)


def decrypt_blob(keys: KeySet, file_id: str, blob: bytes) -> bytes:
    """Decrypt a blob; fails closed on any mismatch (key, id, tampering)."""
    fid = _file_id_bytes(file_id)
    return _open(keys._blob_cipher(), keys, blob, lambda header: [header, fid])


# ------------------------------------------------------------------------- index


def canonical_json(obj: object) -> bytes:
    """Canonical JSON: sorted keys, no whitespace, UTF-8, no NaN/Infinity."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _reject_constant(_name: str) -> Any:
    raise ValueError("non-finite number")


def encrypt_index(keys: KeySet, index: dict[str, Any], bucket: int = DEFAULT_BUCKET) -> bytes:
    """Encrypt the index (AD = header || "index") with the index key."""
    if not isinstance(index, dict):
        raise InvalidArgumentError("index must be a JSON object")
    try:
        payload = canonical_json(index)
    except (TypeError, ValueError):
        payload = None
    if payload is None:
        raise InvalidArgumentError("index is not serializable")
    header = _header(keys)
    return _seal(keys._index_cipher(), header, [header + INDEX_AD_SUFFIX], payload, bucket)


def decrypt_index(keys: KeySet, blob: bytes) -> dict[str, Any]:
    """Decrypt and parse the index. Structural validation lives in the index module."""
    plain = _open(keys._index_cipher(), keys, blob, lambda header: [header + INDEX_AD_SUFFIX])
    return _parse_index(plain)


def _parse_index(plain: bytes) -> dict[str, Any]:
    result: Any = None
    try:
        result = json.loads(
            plain.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (ValueError, RecursionError):  # includes UnicodeDecodeError, JSONDecodeError
        result = None
    if not isinstance(result, dict):
        raise IndexFormatError("index is not a valid JSON object")
    return result


# --------------------------------------------------------------------------- MAC


def content_mac(keys: KeySet, data: bytes) -> bytes:
    """HMAC-SHA256(k_mac, data): used for move detection and content comparison."""
    plain = _check_bytes(data)
    _check_size(len(plain))
    h = crypto_hmac.HMAC(keys._mac_key(), hashes.SHA256())
    h.update(plain)
    return h.finalize()


def verify_mac(keys: KeySet, data: bytes, mac: bytes) -> bool:
    """Constant-time comparison of ``mac`` against the HMAC of ``data``."""
    return hmac.compare_digest(content_mac(keys, data), _check_bytes(mac))
