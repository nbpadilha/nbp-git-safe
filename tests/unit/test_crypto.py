# SPDX-License-Identifier: MIT
"""Unit tests for ``nbp_git_safe.crypto`` (fake data only)."""

from __future__ import annotations

import base64
import copy
import pickle
import secrets
import struct

import pytest

from nbp_git_safe import crypto
from nbp_git_safe.crypto import (
    HEADER_LEN,
    KeySet,
    decrypt_blob,
    decrypt_index,
    encrypt_blob,
    encrypt_index,
    new_file_id,
)

MASTER_A = bytes(range(64))
MASTER_B = bytes(range(1, 65))
FID = "00112233445566778899aabbccddeeff"
FID2 = "ffeeddccbbaa99887766554433221100"


@pytest.fixture(scope="module")
def keys() -> KeySet:
    return KeySet(MASTER_A)


@pytest.fixture(scope="module")
def other_keys() -> KeySet:
    return KeySet(MASTER_B)


# ------------------------------------------------------------------ key derivation


def test_key_id_is_8_bytes_and_stable(keys: KeySet) -> None:
    assert len(keys.key_id) == 8
    assert KeySet(MASTER_A).key_id == keys.key_id
    assert KeySet(MASTER_B).key_id != keys.key_id


def test_derived_keys_are_distinct_and_have_documented_lengths(keys: KeySet) -> None:
    blob, index, mac = keys._k_blob, keys._k_index, keys._k_mac
    assert (len(blob), len(index), len(mac)) == (64, 64, 32)
    assert len({blob, index, mac[:32], MASTER_A}) == 4
    assert keys.key_id not in {blob, index, mac}


def test_key_id_matches_independent_hkdf_computation(keys: KeySet) -> None:
    # Independent HKDF-SHA256 (RFC 5869, empty salt) to pin the documented derivation.
    import hashlib
    import hmac

    prk = hmac.new(b"\x00" * 32, MASTER_A, hashlib.sha256).digest()
    okm = hmac.new(prk, b"nbp-git-safe/v1/key-id" + b"\x01", hashlib.sha256).digest()
    assert keys.key_id == okm[:8]


@pytest.mark.parametrize("bad", [b"", b"x" * 63, b"x" * 65, bytearray(10)])
def test_keyset_rejects_wrong_length(bad: bytes) -> None:
    with pytest.raises(crypto.InvalidKeyError):
        KeySet(bad)


@pytest.mark.parametrize("bad", ["a" * 64, 123, None])
def test_keyset_rejects_non_bytes(bad: object) -> None:
    with pytest.raises(crypto.InvalidArgumentError):
        KeySet(bad)  # type: ignore[arg-type]


def test_keyset_accepts_bytearray_and_memoryview() -> None:
    assert KeySet(bytearray(MASTER_A)).key_id == KeySet(memoryview(MASTER_A)).key_id


def test_keyset_repr_str_do_not_leak_key_material(keys: KeySet) -> None:
    for text in (repr(keys), str(keys), f"{keys}", f"{[keys]}"):
        assert keys.key_id.hex() in text
        assert MASTER_A.hex() not in text
        assert keys._k_blob.hex() not in text
        assert keys._k_index.hex() not in text
        assert keys._k_mac.hex() not in text
        assert base64.b64encode(MASTER_A).decode() not in text
        assert base64.b64encode(keys._k_blob).decode() not in text


def test_keyset_cannot_be_pickled_or_copied(keys: KeySet) -> None:
    with pytest.raises(TypeError):
        pickle.dumps(keys)
    with pytest.raises(TypeError):
        copy.copy(keys)
    with pytest.raises(TypeError):
        copy.deepcopy(keys)
    with pytest.raises(TypeError):
        keys.__getstate__()


def test_keyset_has_no_instance_dict_and_no_master_attribute(keys: KeySet) -> None:
    assert not hasattr(keys, "__dict__")
    assert not hasattr(keys, "master")
    with pytest.raises(AttributeError):
        keys.extra = 1  # type: ignore[attr-defined]


# --------------------------------------------------------------- key serialization


def test_generate_key_is_64_random_bytes() -> None:
    a, b = crypto.generate_key(), crypto.generate_key()
    assert len(a) == len(b) == 64
    assert a != b


def test_key_roundtrip_via_base64() -> None:
    key = crypto.generate_key()
    text = crypto.encode_key(key)
    assert len(text) == 88
    assert crypto.decode_key(text) == key
    assert crypto.decode_key(text.encode()) == key
    assert crypto.decode_key(bytearray(text.encode())) == key
    assert KeySet.from_base64(text).key_id == KeySet(key).key_id


def test_decode_key_tolerates_one_trailing_newline_only() -> None:
    text = crypto.encode_key(MASTER_A)
    assert crypto.decode_key(text + "\n") == MASTER_A
    assert crypto.decode_key(text + "\r\n") == MASTER_A
    for bad in (text + "\n\n", text + " ", " " + text, text + "\r", text[:44] + "\n" + text[44:]):
        with pytest.raises(crypto.InvalidKeyError):
            crypto.decode_key(bad)


def test_encode_key_rejects_wrong_length_and_type() -> None:
    with pytest.raises(crypto.InvalidKeyError):
        crypto.encode_key(b"short")
    with pytest.raises(crypto.InvalidArgumentError):
        crypto.encode_key("not bytes")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "!" * 88,
        "not base64 at all",
        base64.b64encode(b"x" * 63).decode(),
        base64.b64encode(b"x" * 65).decode(),
        base64.b64encode(b"x" * 32).decode(),
        "é" * 88,  # non-ASCII text
        "A" * 2000,  # over the text cap
        base64.urlsafe_b64encode(b"\xfb\xff" * 32).decode(),  # URL-safe alphabet
        base64.b64encode(MASTER_A).decode()[:-1],  # truncated, bad padding
        123,
        None,
    ],
)
def test_decode_key_rejects_invalid_input(bad: object) -> None:
    with pytest.raises(crypto.InvalidKeyError):
        crypto.decode_key(bad)  # type: ignore[arg-type]


def test_decode_key_rejects_non_canonical_padding_bits() -> None:
    text = crypto.encode_key(MASTER_A)
    assert text.endswith("==")
    # Same 64 bytes, but trailing unused bits set: decodes leniently, must be rejected.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last = alphabet.index(text[-3])
    tampered = text[:-3] + alphabet[last ^ 1] + "=="
    assert base64.b64decode(tampered, validate=True) == MASTER_A
    with pytest.raises(crypto.InvalidKeyError):
        crypto.decode_key(tampered)


def test_key_errors_never_contain_the_input() -> None:
    secret = base64.b64encode(b"S" * 30).decode()
    with pytest.raises(crypto.InvalidKeyError) as exc:
        crypto.decode_key(secret)
    assert secret not in str(exc.value)
    assert secret not in repr(exc.value)
    assert exc.value.__cause__ is None


# ------------------------------------------------------------------------- file ids


def test_new_file_id_shape_and_uniqueness() -> None:
    ids = {new_file_id() for _ in range(50)}
    assert len(ids) == 50
    assert all(len(i) == 32 and i == i.lower() and int(i, 16) >= 0 for i in ids)


@pytest.mark.parametrize(
    "bad", ["", "abc", FID.upper(), FID + "0", FID[:-1] + "g", " " + FID[1:], 1234, None]
)
def test_invalid_file_ids_rejected(keys: KeySet, bad: object) -> None:
    with pytest.raises(crypto.InvalidArgumentError):
        encrypt_blob(keys, bad, b"x")  # type: ignore[arg-type]
    blob = encrypt_blob(keys, FID, b"x")
    with pytest.raises(crypto.InvalidArgumentError):
        decrypt_blob(keys, bad, blob)  # type: ignore[arg-type]


def test_non_hex_file_id_of_right_length_rejected(keys: KeySet) -> None:
    with pytest.raises(crypto.InvalidArgumentError):
        encrypt_blob(keys, "z" * 32, b"x")
    # length 32 but non-ASCII digits that str.fromhex would not accept
    with pytest.raises(crypto.InvalidArgumentError):
        encrypt_blob(keys, "0660" * 32, b"x")


# ------------------------------------------------------------------------- blobs


@pytest.mark.parametrize("size", [0, 1, 4, 5, 4087, 4088, 4089, 4095, 4096, 4097, 20000])
def test_blob_roundtrip_and_padding(keys: KeySet, size: int) -> None:
    data = secrets.token_bytes(size)
    blob = encrypt_blob(keys, FID, data)
    assert blob[:8] == b"\x00NBPSAFE"
    assert blob[8] == 1
    assert blob[9:17] == keys.key_id
    body = len(blob) - HEADER_LEN - 16  # minus header and SIV tag = padded frame
    assert body % 4096 == 0
    assert body == -(-(8 + size) // 4096) * 4096
    assert decrypt_blob(keys, FID, blob) == data


@pytest.mark.parametrize("bucket", [1, 64, 100, 4096, 65536])
def test_custom_bucket(keys: KeySet, bucket: int) -> None:
    data = b"x" * 200
    blob = encrypt_blob(keys, FID, data, bucket=bucket)
    frame_len = len(blob) - HEADER_LEN - 16
    assert frame_len % bucket == 0
    assert frame_len == -(-208 // bucket) * bucket
    assert decrypt_blob(keys, FID, blob) == data


@pytest.mark.parametrize("bad", [0, -1, (1 << 20) + 1, 4096.0, "4096", None, True])
def test_invalid_bucket_rejected(keys: KeySet, bad: object) -> None:
    with pytest.raises(crypto.InvalidArgumentError):
        encrypt_blob(keys, FID, b"x", bucket=bad)  # type: ignore[arg-type]
    with pytest.raises(crypto.InvalidArgumentError):
        encrypt_index(keys, {}, bucket=bad)  # type: ignore[arg-type]


def test_blob_is_deterministic(keys: KeySet) -> None:
    assert encrypt_blob(keys, FID, b"same") == encrypt_blob(keys, FID, b"same")
    assert encrypt_blob(keys, FID, b"same") != encrypt_blob(keys, FID, b"diff")


def test_same_content_different_id_differs(keys: KeySet) -> None:
    assert encrypt_blob(keys, FID, b"same") != encrypt_blob(keys, FID2, b"same")


def test_swapping_file_id_fails(keys: KeySet) -> None:
    blob = encrypt_blob(keys, FID, b"payload")
    with pytest.raises(crypto.AuthenticationError):
        decrypt_blob(keys, FID2, blob)


def test_bytes_like_inputs_accepted(keys: KeySet) -> None:
    blob = encrypt_blob(keys, FID, bytearray(b"abc"))
    assert decrypt_blob(keys, FID, memoryview(blob)) == b"abc"


def test_non_bytes_inputs_rejected(keys: KeySet) -> None:
    with pytest.raises(crypto.InvalidArgumentError):
        encrypt_blob(keys, FID, "text")  # type: ignore[arg-type]
    with pytest.raises(crypto.InvalidArgumentError):
        decrypt_blob(keys, FID, "text")  # type: ignore[arg-type]


def test_every_single_byte_tamper_fails(keys: KeySet) -> None:
    blob = encrypt_blob(keys, FID, b"top secret payload", bucket=64)
    for i in range(len(blob)):
        for flip in (0x01, 0x80):
            bad = bytearray(blob)
            bad[i] ^= flip
            with pytest.raises(crypto.NbpCryptoError):
                decrypt_blob(keys, FID, bytes(bad))


def test_tamper_classification(keys: KeySet) -> None:
    blob = bytearray(encrypt_blob(keys, FID, b"data", bucket=64))
    magic = bytearray(blob)
    magic[0] ^= 1
    with pytest.raises(crypto.BlobFormatError, match="magic"):
        decrypt_blob(keys, FID, bytes(magic))
    version = bytearray(blob)
    version[8] = 2
    with pytest.raises(crypto.BlobFormatError, match="version"):
        decrypt_blob(keys, FID, bytes(version))
    key_id = bytearray(blob)
    key_id[12] ^= 1
    with pytest.raises(crypto.KeyIdMismatchError):
        decrypt_blob(keys, FID, bytes(key_id))
    body = bytearray(blob)
    body[-1] ^= 1
    with pytest.raises(crypto.AuthenticationError):
        decrypt_blob(keys, FID, bytes(body))


def test_truncated_and_appended_blobs_fail(keys: KeySet) -> None:
    blob = encrypt_blob(keys, FID, b"data", bucket=64)
    for n in (0, 1, 8, 17, 40):
        with pytest.raises(crypto.BlobFormatError, match="truncated"):
            decrypt_blob(keys, FID, blob[:n])
    for bad in (blob[:-1], blob + b"\x00", blob[:HEADER_LEN] + blob[HEADER_LEN + 1 :]):
        with pytest.raises(crypto.NbpCryptoError):
            decrypt_blob(keys, FID, bad)


def test_wrong_key_id_fails_before_decryption(keys: KeySet, other_keys: KeySet) -> None:
    blob = encrypt_blob(keys, FID, b"data")
    with pytest.raises(crypto.KeyIdMismatchError):
        decrypt_blob(other_keys, FID, blob)


def test_forged_header_with_other_key_id_still_fails_auth(keys: KeySet, other_keys: KeySet) -> None:
    # Re-label a blob with the other key's id: key_id check passes, authentication must fail.
    blob = encrypt_blob(keys, FID, b"data")
    forged = blob[:9] + other_keys.key_id + blob[HEADER_LEN:]
    with pytest.raises(crypto.AuthenticationError):
        decrypt_blob(other_keys, FID, forged)


def test_encrypt_refuses_over_64_mib(keys: KeySet) -> None:
    big = bytes(crypto.MAX_DATA_SIZE + 1)
    with pytest.raises(crypto.SizeLimitError):
        encrypt_blob(keys, FID, big)
    with pytest.raises(crypto.SizeLimitError):
        crypto.content_mac(keys, big)


def test_decrypt_refuses_oversized_blob(keys: KeySet) -> None:
    with pytest.raises(crypto.SizeLimitError):
        decrypt_blob(keys, FID, bytes(crypto.MAX_BLOB_SIZE + 1))


def test_exactly_64_mib_is_accepted(keys: KeySet) -> None:
    data = bytes(crypto.MAX_DATA_SIZE)
    blob = encrypt_blob(keys, FID, data)
    assert decrypt_blob(keys, FID, blob) == data


# ------------------------------------------------------------ frame post-auth checks


def _seal_frame(keys: KeySet, frame: bytes) -> bytes:
    """Authenticated blob around an arbitrary (possibly malformed) frame."""
    header = crypto._header(keys)
    return header + keys._blob_cipher().encrypt(frame, [header, bytes.fromhex(FID)])


def test_malformed_frames_rejected_even_when_authentic(keys: KeySet) -> None:
    cases = {
        "min size, length beyond frame": struct.pack(">Q", 1),
        "length beyond frame": struct.pack(">Q", 100) + b"x" * 10,
        "huge length": struct.pack(">Q", (1 << 64) - 1) + b"x" * 10,
        "non-zero padding": struct.pack(">Q", 1) + b"a" + b"\x00\x01",
    }
    for name, frame in cases.items():
        with pytest.raises(crypto.BlobFormatError, match="frame"):
            decrypt_blob(keys, FID, _seal_frame(keys, frame))
        assert name


def test_exact_frame_without_padding_is_valid(keys: KeySet) -> None:
    frame = struct.pack(">Q", 3) + b"abc"
    assert decrypt_blob(keys, FID, _seal_frame(keys, frame)) == b"abc"


# ----------------------------------------------------------------------- parse_header


def test_parse_header_returns_key_id(keys: KeySet) -> None:
    assert crypto.parse_header(encrypt_blob(keys, FID, b"x")) == keys.key_id
    assert crypto.parse_header(encrypt_index(keys, {})) == keys.key_id


def test_parse_header_rejects_garbage() -> None:
    with pytest.raises(crypto.BlobFormatError):
        crypto.parse_header(b"not a blob at all, definitely not, no magic here....")
    with pytest.raises(crypto.BlobFormatError):
        crypto.parse_header(b"")


# ------------------------------------------------------------------------------ index


INDEX = {
    "v": 1,
    "key_id": "aa" * 8,
    "entries": {FID: {"path": "docs/a b.txt", "mode": 33188, "size": 3, "mac": "00" * 32}},
}


def test_index_roundtrip(keys: KeySet) -> None:
    blob = encrypt_index(keys, INDEX)
    assert crypto.parse_header(blob) == keys.key_id
    assert decrypt_index(keys, blob) == INDEX


def test_index_is_canonical_and_deterministic(keys: KeySet) -> None:
    a = {"b": 1, "a": {"y": 2, "x": [1, 2]}}
    b = {"a": {"x": [1, 2], "y": 2}, "b": 1}
    assert encrypt_index(keys, a) == encrypt_index(keys, b)
    assert crypto.canonical_json(a) == b'{"a":{"x":[1,2],"y":2},"b":1}'
    assert crypto.canonical_json({"k": "é"}) == '{"k":"é"}'.encode()


def test_index_padding(keys: KeySet) -> None:
    blob = encrypt_index(keys, {})
    assert (len(blob) - HEADER_LEN - 16) % 4096 == 0
    big = encrypt_index(keys, {"x": "y" * 5000})
    assert (len(big) - HEADER_LEN - 16) % 4096 == 0
    assert len(big) > len(blob)


def test_index_and_blob_are_not_interchangeable(keys: KeySet) -> None:
    index_blob = encrypt_index(keys, {})
    with pytest.raises(crypto.AuthenticationError):
        decrypt_blob(keys, FID, index_blob)
    plain_blob = encrypt_blob(keys, FID, b"{}")
    with pytest.raises(crypto.AuthenticationError):
        decrypt_index(keys, plain_blob)


def test_index_wrong_key_and_tamper(keys: KeySet, other_keys: KeySet) -> None:
    blob = encrypt_index(keys, INDEX)
    with pytest.raises(crypto.KeyIdMismatchError):
        decrypt_index(other_keys, blob)
    small = encrypt_index(keys, {"a": 1}, bucket=64)
    for i in range(len(small)):
        bad = bytearray(small)
        bad[i] ^= 0x01
        with pytest.raises(crypto.NbpCryptoError):
            decrypt_index(keys, bytes(bad))


def test_index_must_be_a_dict_and_serializable(keys: KeySet) -> None:
    for bad in ([1], "x", None, 5):
        with pytest.raises(crypto.InvalidArgumentError):
            encrypt_index(keys, bad)  # type: ignore[arg-type]
    for bad in ({"x": object()}, {"x": float("nan")}, {1: 1, "a": 2}, {"x": b"bytes"}):
        with pytest.raises(crypto.InvalidArgumentError):
            encrypt_index(keys, bad)  # type: ignore[arg-type]


def _seal_index_payload(keys: KeySet, payload: bytes) -> bytes:
    header = crypto._header(keys)
    return crypto._seal(
        keys._index_cipher(), header, [header + crypto.INDEX_AD_SUFFIX], payload, 4096
    )


@pytest.mark.parametrize(
    "payload",
    [
        b"[1,2,3]",
        b'"string"',
        b"123",
        b"null",
        b"{not json",
        b"\xff\xfe\x00",
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b"",
    ],
)
def test_authentic_but_invalid_index_payload_rejected(keys: KeySet, payload: bytes) -> None:
    with pytest.raises(crypto.IndexFormatError) as exc:
        decrypt_index(keys, _seal_index_payload(keys, payload))
    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None


def test_deeply_nested_index_payload_rejected(keys: KeySet) -> None:
    with pytest.raises(crypto.IndexFormatError):
        decrypt_index(keys, _seal_index_payload(keys, b"[" * 200000))


def test_unpad_frame_rejects_frames_shorter_than_length_prefix() -> None:
    # Unreachable through decrypt_* (header/size checks come first); guard tested directly.
    with pytest.raises(crypto.BlobFormatError, match="frame"):
        crypto._unpad_frame(bytes(7))


def test_index_error_message_has_no_content(keys: KeySet) -> None:
    secret = b'{"leak-me": 1, "leak-me": 2}'
    with pytest.raises(crypto.IndexFormatError) as exc:
        decrypt_index(keys, _seal_index_payload(keys, secret))
    assert "leak-me" not in str(exc.value)
    assert "leak-me" not in repr(exc.value)


# -------------------------------------------------------------------------------- MAC


def test_content_mac_properties(keys: KeySet, other_keys: KeySet) -> None:
    m = crypto.content_mac(keys, b"data")
    assert len(m) == 32
    assert m == crypto.content_mac(keys, b"data")
    assert m != crypto.content_mac(keys, b"datb")
    assert m != crypto.content_mac(other_keys, b"data")
    assert crypto.content_mac(keys, bytearray(b"data")) == m


def test_content_mac_matches_independent_hmac(keys: KeySet) -> None:
    import hashlib
    import hmac

    assert (
        crypto.content_mac(keys, b"abc") == hmac.new(keys._k_mac, b"abc", hashlib.sha256).digest()
    )


def test_verify_mac(keys: KeySet) -> None:
    m = crypto.content_mac(keys, b"data")
    assert crypto.verify_mac(keys, b"data", m) is True
    assert crypto.verify_mac(keys, b"other", m) is False
    assert crypto.verify_mac(keys, b"data", m[:-1]) is False
    with pytest.raises(crypto.InvalidArgumentError):
        crypto.verify_mac(keys, b"data", "hex")  # type: ignore[arg-type]


# ------------------------------------------------------------------- error hygiene


def test_errors_have_fixed_messages_and_no_chained_context(keys: KeySet) -> None:
    blob = encrypt_blob(keys, FID, b"PLAINTEXT-MARKER")
    with pytest.raises(crypto.AuthenticationError) as exc:
        decrypt_blob(keys, FID2, blob)
    text = str(exc.value) + repr(exc.value)
    assert "PLAINTEXT-MARKER" not in text
    assert MASTER_A.hex() not in text
    assert exc.value.__cause__ is None
    assert exc.value.__context__ is None
