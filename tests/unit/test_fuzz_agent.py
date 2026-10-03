# SPDX-License-Identifier: MIT
"""Deterministic fuzzing of the agent's handshake and framing with malformed messages (fixed
seed). The agent (a real ``AgentServer`` in a thread) must neither hang nor die, must never answer
a request before authentication, and must keep serving legitimate clients afterwards."""

from __future__ import annotations

import contextlib
import random
import struct
from collections.abc import Iterator
from functools import partial
from multiprocessing.connection import Client
from pathlib import Path

import pytest

from nbp_git_safe import agent, crypto
from tests.helpers import ThreadAgent

SEED = 20261006
KEY = bytes(range(64))
FID = "0123456789abcdef0123456789abcdef"


@pytest.fixture
def served(tmp_path: Path) -> Iterator[ThreadAgent]:
    ta = ThreadAgent(tmp_path / "state", KEY)
    yield ta
    ta.stop()


def still_healthy(ta: ThreadAgent) -> None:
    with ta.client() as client:
        assert client.hello() == agent.PROTO
        status = client.status()
        assert status["locked"] is False
        assert client.key_id() == crypto.KeySet(KEY).key_id
        blob = client.enc_blob(FID, b"payload", 64)
        assert client.dec_blob(FID, blob) == b"payload"


def garbage_first_messages(rng: random.Random) -> list[bytes]:
    magic, n = agent.HS_MAGIC, agent.NONCE_LEN
    out = [
        b"",
        b"\x00",
        magic,  # no nonce
        magic + b"\x00" * (n - 1),
        magic + b"\x00" * (n + 1),
        magic[:-1] + b"\x02" + b"\x00" * n,  # other version
        b"\x80\x04\x95\x00",  # pickle-looking
        b"GET / HTTP/1.1\r\n\r\n",
        b"\xff" * agent.HS_MAX,  # exactly the limit
        b"\xff" * (agent.HS_MAX + 1),  # one over the limit
        b"x" * 100000,
    ]
    for _ in range(40):
        out.append(rng.randbytes(rng.randint(0, 200)))
        out.append(magic + rng.randbytes(rng.randint(0, 80)))
    return out


def test_fuzz_handshake_garbage_never_wedges_or_kills_the_agent(served: ThreadAgent) -> None:
    rng = random.Random(SEED)  # noqa: S311 - a fixed seed, not a secret
    for message in garbage_first_messages(rng):
        raw = Client(served.info.address, served.info.family, authkey=None)
        try:
            with contextlib.suppress(OSError, ValueError):
                raw.send_bytes(message)
            # the server hangs up (EOF/OSError) or, never, answers with something other than a
            # handshake reply: it must not send an operation reply to an unauthenticated peer
            with contextlib.suppress(EOFError, OSError):
                if raw.poll(2.0):
                    reply = raw.recv_bytes(1 << 16)
                    assert not reply.startswith(bytes([agent.PROTO, agent.STATUS_OK]))
        finally:
            with contextlib.suppress(OSError):
                raw.close()
    still_healthy(served)


def test_fuzz_half_finished_and_wrong_handshakes(served: ThreadAgent) -> None:
    """Valid first message, then a wrong / truncated / oversized proof, then a hang-up."""
    rng = random.Random(SEED + 1)  # noqa: S311
    for _ in range(40):
        raw = Client(served.info.address, served.info.family, authkey=None)
        try:
            raw.send_bytes(agent.HS_MAGIC + rng.randbytes(agent.NONCE_LEN))
            if not raw.poll(3.0):
                pytest.fail("the agent did not answer a well-formed hello")
            reply = raw.recv_bytes(agent.HS_MAX)
            assert len(reply) == agent.NONCE_LEN + 32
            raw.send_bytes(rng.choice([b"", rng.randbytes(32), rng.randbytes(33), b"\xff" * 300]))
            with contextlib.suppress(EOFError, OSError):
                assert not raw.poll(1.0) or raw.recv_bytes(64) != agent.HS_OK
        except (EOFError, OSError):
            pass
        finally:
            with contextlib.suppress(OSError):
                raw.close()
    still_healthy(served)


@pytest.fixture
def authed(served: ThreadAgent) -> Iterator[agent.AgentClient]:
    with served.client() as client:
        yield client


def fuzz_bodies(rng: random.Random) -> Iterator[bytes]:
    """Request bodies of every shape: random, truncated length prefixes, absurd lengths."""
    for _ in range(60):
        yield rng.randbytes(rng.randint(0, 64))
    huge = struct.pack(">I", 0xFFFFFFFF)
    yield huge
    yield huge + b"abc"
    yield agent.pack_args(b"", b"", b"")
    yield agent.pack_args(FID.encode(), struct.pack(">I", 0xFFFFFFFF), b"data")  # bucket too big
    yield agent.pack_args(FID.encode(), struct.pack(">I", 0), b"data")
    yield agent.pack_args(FID.encode(), b"\x00", b"data")  # bucket of the wrong size
    yield agent.pack_args(b"\xff\xfe", b"x")  # file id that is not ASCII
    yield agent.pack_args(struct.pack(">I", 64), b"[1, 2, 3]")  # JSON that is not an object
    yield agent.pack_args(struct.pack(">I", 64), b'{"a": NaN}')
    yield agent.pack_args(struct.pack(">I", 64), b"\xff\xfe\x00")
    yield agent.pack_args(b"short")
    yield agent.pack_args(b"x" * 300)


def test_fuzz_authenticated_malformed_requests_get_typed_replies(
    served: ThreadAgent, authed: agent.AgentClient
) -> None:
    rng = random.Random(SEED + 2)  # noqa: S311
    ops = [op for name, op in vars(agent).items() if name.startswith("OP_")]
    ops.remove(agent.OP_LOCK)  # a valid lock is a valid request: it legitimately stops the agent
    ops += [0, 11, 99, 255]
    conn = authed._conn
    sent = 0
    for op in ops:
        for body in fuzz_bodies(rng):
            conn.send_bytes(bytes([agent.PROTO, op]) + body)
            assert conn.poll(10.0), "the agent stopped answering"
            reply = conn.recv_bytes(agent.MAX_MESSAGE)
            assert reply[0] == agent.PROTO and reply[1] in (agent.STATUS_OK, agent.STATUS_ERR)
            if reply[1] == agent.STATUS_ERR:
                code = reply[2:].decode("ascii")  # codes are plain ASCII words, never data
                assert code.isidentifier() and len(code) < 32
            sent += 1
    # wrong protocol bytes and degenerate frames, same connection
    for first in (0, 2, 255):
        conn.send_bytes(bytes([first, agent.OP_HELLO]))
        assert conn.recv_bytes(agent.MAX_MESSAGE)[1] == agent.STATUS_ERR
    for tiny in (b"", b"\x01"):
        conn.send_bytes(tiny)
        assert conn.recv_bytes(agent.MAX_MESSAGE)[1] == agent.STATUS_ERR
    assert sent > 500
    assert authed.hello() == agent.PROTO  # the very same connection still works
    still_healthy(served)


def test_fuzz_requests_before_authentication_are_never_served(served: ThreadAgent) -> None:
    rng = random.Random(SEED + 3)  # noqa: S311
    for _ in range(60):
        raw = Client(served.info.address, served.info.family, authkey=None)
        try:
            op = rng.choice([agent.OP_STATUS, agent.OP_KEY_ID, agent.OP_DEC_INDEX, agent.OP_LOCK])
            with contextlib.suppress(OSError, ValueError):
                raw.send_bytes(bytes([agent.PROTO, op]) + rng.randbytes(rng.randint(0, 40)))
            with contextlib.suppress(EOFError, OSError):
                if raw.poll(1.0):
                    assert not raw.recv_bytes(1 << 16).startswith(
                        bytes([agent.PROTO, agent.STATUS_OK])
                    )
        finally:
            with contextlib.suppress(OSError):
                raw.close()
    still_healthy(served)  # in particular, an unauthenticated OP_LOCK did not stop it


def test_fuzz_client_side_rejects_malformed_replies() -> None:
    """The client of a (fake, hostile) agent: replies of every shape are typed errors."""

    class Fake:
        def __init__(self, reply: bytes) -> None:
            self.reply = reply

        def send_bytes(self, _data: bytes) -> None:
            pass

        def poll(self, _timeout: float) -> bool:
            return True

        def recv_bytes(self, _maxlength: int) -> bytes:
            return self.reply

        def close(self) -> None:
            pass

    rng = random.Random(SEED + 4)  # noqa: S311
    replies = [b"", b"\x01", b"\x02\x00x", b"\x01\x07", bytes([agent.PROTO, agent.STATUS_ERR])]
    replies += [rng.randbytes(rng.randint(0, 50)) for _ in range(200)]
    replies += [bytes([agent.PROTO, agent.STATUS_ERR]) + rng.randbytes(8) for _ in range(100)]
    info = None  # the info object is not used by the call path under test
    for reply in replies:
        client = agent.AgentClient(Fake(reply), info)  # type: ignore[arg-type]
        for call in (client.hello, client.status, partial(client.dec_index, b"x")):
            with contextlib.suppress(agent.AgentError, crypto.NbpCryptoError):
                call()  # any other exception type fails the test
