# SPDX-License-Identifier: MIT
"""RFC 5297 (AES-SIV) Appendix A test vectors against ``cryptography``'s ``AESSIV``.

These prove the primitive that ``nbp_git_safe.crypto`` relies on behaves per the RFC.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESSIV


def _h(text: str) -> bytes:
    return bytes.fromhex(text.replace(" ", "").replace("\n", ""))


# A.1. Deterministic Authenticated Encryption Example
A1_KEY = _h("fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0 f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff")
A1_AD = _h("10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627")
A1_PLAIN = _h("11223344 55667788 99aabbcc ddee")
A1_OUT = _h("85632d07 c6e8f37f 950acd32 0a2ecc93 40c02b96 90c4dc04 daef7f6a fe5c")

# A.2. Nonce-Based Authenticated Encryption Example (the nonce is the last AD component)
A2_KEY = _h("7f7e7d7c 7b7a7978 77767574 73727170 40414243 44454647 48494a4b 4c4d4e4f")
A2_AD1 = _h(
    "00112233 44556677 8899aabb ccddeeff deaddada deaddada ffeeddcc bbaa9988 77665544 33221100"
)
A2_AD2 = _h("10203040 50607080 90a0")
A2_NONCE = _h("09f91102 9d74e35b d84156c5 635688c0")
A2_PLAIN = _h(
    "74686973 20697320 736f6d65 20706c61 696e7465 78742074 6f20656e 63727970 74207573 696e6720"
    "5349562d 414553"
)
A2_OUT = _h(
    "7bdb6e3b 432667eb 06f4d14b ff2fbd0f cb900f2f ddbe4043 26601965 c889bf17 dba77ceb 094fa663"
    "b7a3f748 ba8af829 ea64ad54 4a272e9c 485b62a3 fd5c0d"
)


def test_rfc5297_a1_encrypt() -> None:
    assert AESSIV(A1_KEY).encrypt(A1_PLAIN, [A1_AD]) == A1_OUT


def test_rfc5297_a1_decrypt() -> None:
    assert AESSIV(A1_KEY).decrypt(A1_OUT, [A1_AD]) == A1_PLAIN


def test_rfc5297_a2_encrypt() -> None:
    assert AESSIV(A2_KEY).encrypt(A2_PLAIN, [A2_AD1, A2_AD2, A2_NONCE]) == A2_OUT


def test_rfc5297_a2_decrypt() -> None:
    assert AESSIV(A2_KEY).decrypt(A2_OUT, [A2_AD1, A2_AD2, A2_NONCE]) == A2_PLAIN


@pytest.mark.parametrize(
    ("key", "ad", "out"),
    [(A1_KEY, [A1_AD], A1_OUT), (A2_KEY, [A2_AD1, A2_AD2, A2_NONCE], A2_OUT)],
)
def test_rfc5297_wrong_associated_data_fails(key: bytes, ad: list[bytes], out: bytes) -> None:
    from cryptography.exceptions import InvalidTag

    with pytest.raises(InvalidTag):
        AESSIV(key).decrypt(out, [*ad, b"extra"])
