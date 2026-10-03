# SPDX-License-Identifier: MIT
"""Deterministic fuzzing of the blob/index decoders and of the key parser (fixed seeds).

Every mutation of a valid ciphertext (one flipped byte, truncation, extension, swapped header)
must end in a typed ``NbpCryptoError``: never a silent success with other content, never a
crash with any other exception type.
"""

from __future__ import annotations

import base64
import random
from typing import Any

import pytest

from nbp_git_safe import crypto

SEED = 20261004
MASTER = bytes(range(64))
OTHER = bytes(range(1, 65))
FID = "0123456789abcdef0123456789abcdef"
FID2 = "fedcba9876543210fedcba9876543210"
BUCKET = 64  # small buckets keep the blobs short and the loops fast


@pytest.fixture(scope="module")
def keys() -> crypto.KeySet:
    return crypto.KeySet(MASTER)


def mutations(rng: random.Random, blob: bytes, count: int) -> list[bytes]:
    out: list[bytes] = []
    for _ in range(count):
        kind = rng.randrange(7)
        if kind == 0:  # flip one bit
            i = rng.randrange(len(blob))
            out.append(blob[:i] + bytes([blob[i] ^ (1 << rng.randrange(8))]) + blob[i + 1 :])
        elif kind == 1:  # replace one byte
            i = rng.randrange(len(blob))
            out.append(blob[:i] + bytes([(blob[i] + rng.randint(1, 255)) % 256]) + blob[i + 1 :])
        elif kind == 2:  # truncate
            out.append(blob[: rng.randrange(len(blob))])
        elif kind == 3:  # extend
            out.append(blob + rng.randbytes(rng.randint(1, 80)))
        elif kind == 4:  # delete a slice
            i = rng.randrange(len(blob))
            out.append(blob[:i] + blob[i + rng.randint(1, 8) :])
        elif kind == 5:  # duplicate a slice
            i = rng.randrange(len(blob))
            out.append(blob[:i] + blob[i : i + 8] + blob[i:])
        else:  # swap two bytes that differ
            i, j = rng.randrange(len(blob)), rng.randrange(len(blob))
            if blob[i] == blob[j]:
                j = (i + 1) % len(blob)
                if blob[i] == blob[j]:
                    continue
            swapped = bytearray(blob)
            swapped[i], swapped[j] = swapped[j], swapped[i]
            out.append(bytes(swapped))
    return [m for m in out if m != blob]


def test_fuzz_blob_mutations_always_raise_a_typed_error(keys: crypto.KeySet) -> None:
    rng = random.Random(SEED)  # noqa: S311 - a fixed seed, not a secret
    for size in (0, 1, 5, 100, 4000):
        data = rng.randbytes(size)
        blob = crypto.encrypt_blob(keys, FID, data, BUCKET)
        for bad in mutations(rng, blob, 300):
            with pytest.raises(crypto.NbpCryptoError):
                crypto.decrypt_blob(keys, FID, bad)
        assert crypto.decrypt_blob(keys, FID, blob) == data


def test_fuzz_index_mutations_always_raise_a_typed_error(keys: crypto.KeySet) -> None:
    rng = random.Random(SEED + 1)  # noqa: S311
    doc = {"v": 2, "key_id": keys.key_id.hex(), "entries": {}, "seq": 1, "prev": ""}
    blob = crypto.encrypt_index(keys, doc, BUCKET)
    for bad in mutations(rng, blob, 1500):
        with pytest.raises(crypto.NbpCryptoError):
            crypto.decrypt_index(keys, bad)
    assert crypto.decrypt_index(keys, blob) == doc


def test_fuzz_arbitrary_bytes_are_never_accepted(keys: crypto.KeySet) -> None:
    rng = random.Random(SEED + 2)  # noqa: S311
    header = crypto.MAGIC + bytes([crypto.VERSION]) + keys.key_id
    for _ in range(1500):
        kind = rng.randrange(4)
        if kind == 0:
            blob = rng.randbytes(rng.randint(0, 200))
        elif kind == 1:  # right magic/version/key id, random body
            blob = header + rng.randbytes(rng.randint(0, 200))
        elif kind == 2:  # right magic, random rest
            blob = crypto.MAGIC + rng.randbytes(rng.randint(0, 200))
        else:  # a valid header of ANOTHER key
            blob = crypto.MAGIC + bytes([crypto.VERSION]) + rng.randbytes(8) + rng.randbytes(60)
        for decoder in (
            lambda b: crypto.decrypt_blob(keys, FID, b),
            lambda b: crypto.decrypt_index(keys, b),
            crypto.parse_header,
        ):
            try:
                decoder(blob)
            except crypto.NbpCryptoError:
                continue
            assert decoder is crypto.parse_header  # only the (unauthenticated) header parse passes


def test_fuzz_cross_use_is_rejected(keys: crypto.KeySet) -> None:
    """A blob is bound to its file id, its key and its kind (blob vs index)."""
    rng = random.Random(SEED + 3)  # noqa: S311
    other = crypto.KeySet(OTHER)
    for _ in range(40):
        data = rng.randbytes(rng.randint(0, 300))
        blob = crypto.encrypt_blob(keys, FID, data, BUCKET)
        with pytest.raises(crypto.AuthenticationError):
            crypto.decrypt_blob(keys, FID2, blob)  # another id
        with pytest.raises(crypto.KeyIdMismatchError):
            crypto.decrypt_blob(other, FID, blob)  # another key
        with pytest.raises(crypto.NbpCryptoError):
            crypto.decrypt_index(keys, blob)  # a blob is not an index
        index_blob = crypto.encrypt_index(keys, {"k": data.hex()}, BUCKET)
        with pytest.raises(crypto.NbpCryptoError):
            crypto.decrypt_blob(keys, FID, index_blob)  # an index is not a blob


def test_fuzz_bad_arguments_raise_typed_errors(keys: crypto.KeySet) -> None:
    weird: list[Any] = [None, 0, 1.5, "", "x", [], {}, (), object(), True]
    ids = [*weird, FID.upper(), FID[:-1], FID + "0", "g" * 32, "é" * 32, b"0" * 32]
    for fid in ids:
        with pytest.raises(crypto.NbpCryptoError):
            crypto.encrypt_blob(keys, fid, b"x", BUCKET)
        with pytest.raises(crypto.NbpCryptoError):
            crypto.decrypt_blob(keys, fid, b"x" * 100)
    for data in weird:
        with pytest.raises(crypto.NbpCryptoError):
            crypto.encrypt_blob(keys, FID, data, BUCKET)
        with pytest.raises(crypto.NbpCryptoError):
            crypto.decrypt_blob(keys, FID, data)
        with pytest.raises(crypto.NbpCryptoError):
            crypto.content_mac(keys, data)
    for bucket in (0, -1, (1 << 20) + 1, 1 << 21, 1.5, None, "4096", True, False):
        with pytest.raises(crypto.InvalidArgumentError):
            crypto.encrypt_blob(keys, FID, b"x", bucket)  # type: ignore[arg-type]
    for index in (None, [], "x", 5, {"a": float("nan")}, {"a": object()}, {1, 2}):
        with pytest.raises(crypto.NbpCryptoError):
            crypto.encrypt_index(keys, index, BUCKET)  # type: ignore[arg-type]


def test_fuzz_key_text_accepts_only_canonical_base64_of_64_bytes() -> None:
    rng = random.Random(SEED + 5)  # noqa: S311
    good = base64.b64encode(MASTER).decode()
    cases: list[Any] = [good, good + "\n", good + "\r\n", good.encode(), bytearray(good, "ascii")]
    bad_cases: list[Any] = [
        None,
        5,
        [],
        good + "\n\n",
        " " + good,
        good + " ",
        good[:-1],
        good + "A",
    ]
    for _ in range(1500):
        raw = rng.randbytes(rng.randint(0, 90))
        text = base64.b64encode(raw).decode()
        mutated = list(good)
        for _ in range(rng.randint(1, 3)):
            mutated[rng.randrange(len(mutated))] = rng.choice("AZaz09+/=-_ \né*")
        bad_cases += [text, "".join(mutated), good.replace("=", ""), good[: rng.randint(0, 88)]]
    for text in cases:
        assert crypto.decode_key(text) == MASTER
    for text in bad_cases:
        try:
            raw = crypto.decode_key(text)
        except crypto.InvalidKeyError:
            continue
        assert len(raw) == 64  # only a canonical encoding of exactly 64 bytes passes
        assert base64.b64encode(raw).decode() == (
            text.decode() if isinstance(text, bytes) else text
        ).rstrip("\r\n")
    with pytest.raises(crypto.InvalidKeyError):
        crypto.decode_key(good * 20)  # longer than MAX_KEY_TEXT_LEN
