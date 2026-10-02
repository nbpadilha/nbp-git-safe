# SPDX-License-Identifier: MIT
"""Key agent: holds the derived keys in RAM only and serves crypto operations.

Transport: ``multiprocessing.connection`` with ``authkey=None`` (so the stdlib challenge, which
uses HMAC-MD5 and ``==``, is NOT used) plus our own mutual HMAC-SHA256 handshake compared with
``hmac.compare_digest``. Only ``send_bytes`` / ``recv_bytes(maxlength=...)`` are used: ``recv()``
(which unpickles) is never called. Windows uses an ``AF_PIPE`` named pipe, POSIX an ``AF_UNIX``
socket inside a private (0700) directory.

``agent.json`` (in ``<git-common-dir>/nbp-safe/``) stores the address, the connection ``authkey``,
the pid and the expiry. It never stores the encryption key, which is delivered once, over the
authenticated channel, by ``unlock`` and then lives only in this process.
"""

from __future__ import annotations

import contextlib
import ctypes
import hashlib
import hmac
import json
import os
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from multiprocessing.connection import Client, Connection, Listener
from pathlib import Path
from typing import Any

from nbp_git_safe import crypto

PROTO = 1
AGENT_JSON = "agent.json"
UNLOCK_LOCK = "unlock.lock"
AUTHKEY_LEN = 32
NONCE_LEN = 32
HS_MAGIC = b"NBPAGENT\x01"
HS_OK = b"OK"
HS_MAX = 128
HS_TIMEOUT = 5.0
CONN_IDLE_TIMEOUT = 30.0  # an authenticated client that stays silent this long is dropped
REQUEST_TIMEOUT = 300.0
MAX_MESSAGE = crypto.MAX_BLOB_SIZE + (1 << 20)
MAX_CONNECTIONS = 16
KEY_WAIT = 30.0  # a freshly spawned agent exits if no key arrives within this time
START_TIMEOUT = 20.0

# operations
OP_HELLO = 1
OP_LOAD_KEY = 2
OP_ENC_BLOB = 3
OP_DEC_BLOB = 4
OP_ENC_INDEX = 5
OP_DEC_INDEX = 6
OP_MAC = 7
OP_KEY_ID = 8
OP_LOCK = 9
OP_STATUS = 10
_OPS_WITHOUT_KEY = {OP_HELLO, OP_LOAD_KEY, OP_LOCK, OP_STATUS}
_OPS_NO_ACTIVITY = {OP_HELLO, OP_STATUS}

STATUS_OK = 0
STATUS_ERR = 1


class AgentError(Exception):
    """Base class for agent problems. Messages are fixed strings (no key, data or names)."""


class HandshakeError(AgentError):
    """The peer failed the mutual authentication (or spoke another protocol)."""


class ProtocolError(AgentError):
    """Malformed, oversized or unknown message."""


class AgentNotRunningError(AgentError):
    """No live agent for this repository (not started, expired or locked)."""


class AgentLockedError(AgentError):
    """The agent is running but holds no key."""


class AgentExpiredError(AgentError):
    """The agent's TTL elapsed."""


# error codes on the wire -> exception raised by the client
_CRYPTO_CODES: dict[str, type[crypto.NbpCryptoError]] = {
    "key_id": crypto.KeyIdMismatchError,
    "auth": crypto.AuthenticationError,
    "format": crypto.BlobFormatError,
    "index": crypto.IndexFormatError,
    "size": crypto.SizeLimitError,
    "arg": crypto.InvalidArgumentError,
    "key": crypto.InvalidKeyError,
}
_CRYPTO_MESSAGES = {
    "key_id": "blob was written with a different key",
    "auth": "authentication failed",
    "format": "malformed blob",
    "index": "index is not a valid JSON object",
    "size": "input exceeds the 64 MiB limit",
    "arg": "invalid argument",
    "key": "master key is invalid",
}
_CODE_FOR_CLASS = {cls: code for code, cls in _CRYPTO_CODES.items()}


# --------------------------------------------------------------------- process helpers


def pid_alive(pid: int) -> bool:
    """Is ``pid`` a live process? (Never use ``os.kill(pid, 0)`` on Windows: it terminates.)"""
    if pid <= 0:
        return False
    if sys.platform == "win32":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel32.OpenProcess(0x1000, 0, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return ctypes.get_last_error() == 5  # ACCESS_DENIED: exists but not ours
        try:
            code = ctypes.c_uint32()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


# ------------------------------------------------------------------------------- state


@dataclass(frozen=True)
class AgentInfo:
    """Contents of ``agent.json``. The authkey is redacted from ``repr``."""

    address: str
    family: str
    authkey: bytes = field(repr=False)
    pid: int
    started: float
    expires_at: float
    idle_timeout: float | None

    def to_json(self) -> bytes:
        return json.dumps(
            {
                "v": PROTO,
                "address": self.address,
                "family": self.family,
                "authkey": self.authkey.hex(),
                "pid": self.pid,
                "started": self.started,
                "expires_at": self.expires_at,
                "idle_timeout": self.idle_timeout,
            },
            sort_keys=True,
        ).encode("ascii")

    @classmethod
    def from_json(cls, raw: bytes) -> AgentInfo:
        try:
            data = json.loads(raw.decode("utf-8"))
            authkey = bytes.fromhex(data["authkey"])
            info = cls(
                address=str(data["address"]),
                family=str(data["family"]),
                authkey=authkey,
                pid=int(data["pid"]),
                started=float(data["started"]),
                expires_at=float(data["expires_at"]),
                idle_timeout=None if data["idle_timeout"] is None else float(data["idle_timeout"]),
            )
        except (ValueError, KeyError, TypeError, AttributeError):
            raise AgentError("agent.json is corrupted") from None
        if data.get("v") != PROTO or len(authkey) != AUTHKEY_LEN or info.family not in _FAMILIES:
            raise AgentError("agent.json is corrupted")
        return info

    def __repr__(self) -> str:
        return (
            f"AgentInfo(address={self.address!r}, pid={self.pid}, "
            f"expires_at={self.expires_at}, authkey=<redacted>)"
        )


_FAMILIES = ("AF_PIPE", "AF_UNIX")


def agent_json_path(state_dir: Path) -> Path:
    return Path(state_dir) / AGENT_JSON


def read_agent_info(state_dir: Path) -> AgentInfo | None:
    path = agent_json_path(state_dir)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    return AgentInfo.from_json(raw)


def write_agent_info(state_dir: Path, info: AgentInfo) -> None:
    """Atomically write ``agent.json`` (mode 0600 where the OS supports it)."""
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    tmp = state_dir / f"{AGENT_JSON}.{secrets.token_hex(4)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(info.to_json())
    os.replace(tmp, agent_json_path(state_dir))


def remove_agent_info(state_dir: Path) -> None:
    with contextlib.suppress(FileNotFoundError):
        agent_json_path(state_dir).unlink()


def cleanup_orphan(state_dir: Path) -> bool:
    """Remove a stale ``agent.json`` (unreadable, dead pid or expired). True if removed."""
    try:
        info = read_agent_info(state_dir)
    except AgentError:
        remove_agent_info(state_dir)
        return True
    if info is None:
        return False
    if not pid_alive(info.pid) or time.time() >= info.expires_at:
        remove_agent_info(state_dir)
        if info.family == "AF_UNIX":
            with contextlib.suppress(OSError):
                shutil.rmtree(Path(info.address).parent)
        return True
    return False


# -------------------------------------------------------------------------- wire format


def pack_args(*parts: bytes) -> bytes:
    return b"".join(struct.pack(">I", len(p)) + p for p in parts)


def unpack_args(data: bytes, count: int) -> list[bytes]:
    """Split exactly ``count`` length-prefixed parts; anything else is a protocol error."""
    parts: list[bytes] = []
    pos = 0
    for _ in range(count):
        if pos + 4 > len(data):
            raise ProtocolError("malformed message")
        (n,) = struct.unpack(">I", data[pos : pos + 4])
        pos += 4
        if pos + n > len(data):
            raise ProtocolError("malformed message")
        parts.append(data[pos : pos + n])
        pos += n
    if pos != len(data):
        raise ProtocolError("malformed message")
    return parts


def _proof(authkey: bytes, label: bytes, cnonce: bytes, snonce: bytes) -> bytes:
    return hmac.new(
        authkey, b"nbp-git-safe/agent/v1/" + label + cnonce + snonce, hashlib.sha256
    ).digest()


def _recv_limited(conn: Connection, maxlength: int, timeout: float) -> bytes:
    """Receive one message of at most ``maxlength`` bytes within ``timeout`` seconds."""
    try:
        if not conn.poll(timeout):
            raise HandshakeError("peer did not answer in time")
        return conn.recv_bytes(maxlength)
    except (EOFError, OSError):
        raise HandshakeError("connection closed during handshake") from None


def client_handshake(conn: Connection, authkey: bytes, timeout: float = HS_TIMEOUT) -> None:
    """Authenticate the server first, then ourselves (mutual HMAC-SHA256)."""
    cnonce = os.urandom(NONCE_LEN)
    try:
        conn.send_bytes(HS_MAGIC + cnonce)
    except (OSError, ValueError):
        raise HandshakeError("connection closed during handshake") from None
    msg = _recv_limited(conn, HS_MAX, timeout)
    if len(msg) != NONCE_LEN + 32:
        raise HandshakeError("agent failed authentication")
    snonce, proof = msg[:NONCE_LEN], msg[NONCE_LEN:]
    if not hmac.compare_digest(proof, _proof(authkey, b"server", cnonce, snonce)):
        raise HandshakeError("agent failed authentication")
    try:
        conn.send_bytes(_proof(authkey, b"client", cnonce, snonce))
    except (OSError, ValueError):
        raise HandshakeError("connection closed during handshake") from None
    ack = _recv_limited(conn, HS_MAX, timeout)
    if not hmac.compare_digest(ack, HS_OK):
        raise HandshakeError("agent rejected authentication")


def server_handshake(conn: Connection, authkey: bytes, timeout: float = HS_TIMEOUT) -> None:
    msg = _recv_limited(conn, HS_MAX, timeout)
    if len(msg) != len(HS_MAGIC) + NONCE_LEN or not msg.startswith(HS_MAGIC):
        raise HandshakeError("unsupported handshake")
    cnonce = msg[len(HS_MAGIC) :]
    snonce = os.urandom(NONCE_LEN)
    try:
        conn.send_bytes(snonce + _proof(authkey, b"server", cnonce, snonce))
    except (OSError, ValueError):
        raise HandshakeError("connection closed during handshake") from None
    answer = _recv_limited(conn, HS_MAX, timeout)
    if not hmac.compare_digest(answer, _proof(authkey, b"client", cnonce, snonce)):
        raise HandshakeError("client failed authentication")
    try:
        conn.send_bytes(HS_OK)
    except (OSError, ValueError):
        raise HandshakeError("connection closed during handshake") from None


# ------------------------------------------------------------------------------ server


class AgentServer:
    """The agent. ``exit_func`` is ``os._exit`` in the real process; tests inject a stub."""

    def __init__(
        self,
        state_dir: Path,
        ttl: float,
        idle_timeout: float | None = None,
        *,
        exit_func: Callable[[int], Any] = os._exit,
        key_wait: float = KEY_WAIT,
    ) -> None:
        self.state_dir = Path(state_dir)
        self.ttl = float(ttl)
        self.idle_timeout = idle_timeout
        self._exit = exit_func
        self._key_wait = key_wait
        self._keys: crypto.KeySet | None = None
        self._authkey = os.urandom(AUTHKEY_LEN)
        self._lock = threading.Lock()
        self._stopping = threading.Event()
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self._listener: Listener | None = None
        self._unix_dir: Path | None = None
        self._started = 0.0
        self._expires_at = 0.0
        self._last_activity = 0.0
        self.info: AgentInfo | None = None

    # -- lifecycle
    def start(self) -> AgentInfo:
        if sys.platform == "win32":
            family = "AF_PIPE"
            address = rf"\\.\pipe\nbp-git-safe-{secrets.token_hex(12)}"
        else:
            family = "AF_UNIX"
            self._unix_dir = Path(tempfile.mkdtemp(prefix="nbp-safe-"))  # mkdtemp is 0700
            address = str(self._unix_dir / "agent.sock")
        self._listener = Listener(address, family, authkey=None)
        now = time.time()
        self._started = self._last_activity = now
        self._expires_at = now + self.ttl
        self.info = AgentInfo(
            address=address,
            family=family,
            authkey=self._authkey,
            pid=os.getpid(),
            started=now,
            expires_at=self._expires_at,
            idle_timeout=self.idle_timeout,
        )
        write_agent_info(self.state_dir, self.info)
        threading.Thread(target=self._watchdog, name="nbp-watchdog", daemon=True).start()
        return self.info

    def serve_forever(self) -> None:
        assert self._listener is not None
        while not self._stopping.is_set():
            try:
                conn = self._listener.accept()
            except (OSError, EOFError):
                if self._stopping.is_set():
                    return
                time.sleep(0.05)
                continue
            if self._stopping.is_set():
                with contextlib.suppress(OSError):
                    conn.close()
                return
            if not self._slots.acquire(blocking=False):
                with contextlib.suppress(OSError):
                    conn.close()
                continue
            threading.Thread(target=self._serve_conn, args=(conn,), daemon=True).start()

    def shutdown(self, reason: str = "") -> None:
        if self._stopping.is_set():
            return
        self._stopping.set()
        self._keys = None
        remove_agent_info(self.state_dir)
        if self._unix_dir is not None:
            shutil.rmtree(self._unix_dir, ignore_errors=True)
        if self._exit is not os._exit:
            self._wake()  # thread mode (tests): unblock accept()
        self._exit(0)

    def _wake(self) -> None:
        """Unblock ``accept`` (used by thread-mode shutdown in tests)."""
        if self.info is None:
            return
        with contextlib.suppress(Exception):
            Client(self.info.address, self.info.family, authkey=None).close()

    def _watchdog(self) -> None:
        while not self._stopping.wait(0.05):
            now = time.time()
            if now >= self._expires_at:
                self.shutdown("ttl")
            elif self.idle_timeout is not None and now - self._last_activity >= self.idle_timeout:
                self.shutdown("idle")
            elif self._keys is None and now - self._started >= self._key_wait:
                self.shutdown("no key")

    # -- connection handling
    def _serve_conn(self, conn: Connection) -> None:
        try:
            server_handshake(conn, self._authkey)
            deadline_idle = time.monotonic()
            while not self._stopping.is_set():
                if not conn.poll(0.5):
                    if time.monotonic() - deadline_idle > CONN_IDLE_TIMEOUT:
                        return
                    continue
                deadline_idle = time.monotonic()
                data = conn.recv_bytes(MAX_MESSAGE)  # OSError if larger: connection dropped
                status, body, then_lock = self._dispatch(data)
                conn.send_bytes(bytes([PROTO, status]) + body)
                if then_lock:
                    with contextlib.suppress(EOFError, OSError):
                        conn.poll(2.0)  # let the client read the reply before we exit
                    self.shutdown("lock")
                    return
        except (HandshakeError, EOFError, OSError, ValueError):
            return
        finally:
            with contextlib.suppress(OSError):
                conn.close()
            self._slots.release()

    def _error(self, code: str) -> tuple[int, bytes, bool]:
        return STATUS_ERR, code.encode("ascii"), False

    def _dispatch(self, data: bytes) -> tuple[int, bytes, bool]:
        if len(data) < 2 or data[0] != PROTO:
            return self._error("bad_request")
        op, body = data[1], data[2:]
        if time.time() >= self._expires_at:
            return self._error("expired")
        with self._lock:
            if op not in _OPS_NO_ACTIVITY:
                self._last_activity = time.time()
            try:
                return self._handle(op, body)
            except ProtocolError:
                return self._error("bad_request")
            except crypto.NbpCryptoError as exc:
                return self._error(_CODE_FOR_CLASS.get(type(exc), "internal"))
            except Exception:
                return self._error("internal")

    def _handle(self, op: int, body: bytes) -> tuple[int, bytes, bool]:
        if op not in _OPS_WITHOUT_KEY and self._keys is None:
            return self._error("locked")
        keys = self._keys
        if op == OP_HELLO:
            return STATUS_OK, struct.pack(">B", PROTO), False
        if op == OP_STATUS:
            return STATUS_OK, self._status_json(), False
        if op == OP_LOCK:
            return STATUS_OK, b"", True
        if op == OP_LOAD_KEY:
            if self._keys is not None:
                return self._error("already_loaded")
            (raw,) = unpack_args(body, 1)
            self._keys = crypto.KeySet(raw)
            return STATUS_OK, self._keys.key_id, False
        assert keys is not None
        if op == OP_KEY_ID:
            return STATUS_OK, keys.key_id, False
        if op == OP_MAC:
            (data,) = unpack_args(body, 1)
            return STATUS_OK, crypto.content_mac(keys, data), False
        if op == OP_ENC_BLOB:
            file_id, bucket, data = unpack_args(body, 3)
            blob = crypto.encrypt_blob(
                keys, file_id.decode("ascii", "replace"), data, _bucket(bucket)
            )
            return STATUS_OK, blob, False
        if op == OP_DEC_BLOB:
            file_id, blob = unpack_args(body, 2)
            return (
                STATUS_OK,
                crypto.decrypt_blob(keys, file_id.decode("ascii", "replace"), blob),
                False,
            )
        if op == OP_ENC_INDEX:
            bucket, payload = unpack_args(body, 2)
            index = _json_object(payload)
            return STATUS_OK, crypto.encrypt_index(keys, index, _bucket(bucket)), False
        if op == OP_DEC_INDEX:
            (blob,) = unpack_args(body, 1)
            return STATUS_OK, crypto.canonical_json(crypto.decrypt_index(keys, blob)), False
        return self._error("unknown_op")

    def _status_json(self) -> bytes:
        keys = self._keys
        return json.dumps(
            {
                "proto": PROTO,
                "locked": keys is None,
                "key_id": keys.key_id.hex() if keys is not None else None,
                "pid": os.getpid(),
                "started": self._started,
                "expires_at": self._expires_at,
                "idle_timeout": self.idle_timeout,
            }
        ).encode("ascii")


def _bucket(raw: bytes) -> int:
    if len(raw) != 4:
        raise ProtocolError("malformed message")
    return int(struct.unpack(">I", raw)[0])


def _json_object(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"))
    except ValueError:
        raise ProtocolError("malformed message") from None
    if not isinstance(value, dict):
        raise ProtocolError("malformed message")
    return value


# ------------------------------------------------------------------------------ client


class AgentClient:
    """Authenticated connection to the agent. Holds no key material."""

    def __init__(self, conn: Connection, info: AgentInfo) -> None:
        self._conn = conn
        self.info = info

    @classmethod
    def connect(cls, state_dir: Path) -> AgentClient:
        """Connect to the live agent of ``state_dir`` or raise ``AgentNotRunningError``."""
        try:
            info = read_agent_info(state_dir)
        except AgentError:
            remove_agent_info(state_dir)
            raise AgentNotRunningError("agent state was corrupted and has been removed") from None
        if info is None:
            raise AgentNotRunningError("key agent is not running (run `nbp-git-safe unlock`)")
        if not pid_alive(info.pid) or time.time() >= info.expires_at:
            cleanup_orphan(state_dir)
            raise AgentNotRunningError("key agent is not running (run `nbp-git-safe unlock`)")
        return cls.connect_info(info)

    @classmethod
    def connect_info(cls, info: AgentInfo) -> AgentClient:
        try:
            conn = Client(info.address, info.family, authkey=None)
        except (OSError, EOFError):
            raise AgentNotRunningError("key agent is not reachable") from None
        try:
            client_handshake(conn, info.authkey)
        except BaseException:
            with contextlib.suppress(OSError):
                conn.close()
            raise
        return cls(conn, info)

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self._conn.close()

    def __enter__(self) -> AgentClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _call(self, op: int, body: bytes = b"", timeout: float = REQUEST_TIMEOUT) -> bytes:
        try:
            self._conn.send_bytes(bytes([PROTO, op]) + body)
            if not self._conn.poll(timeout):
                raise AgentError("key agent did not answer in time")
            reply = self._conn.recv_bytes(MAX_MESSAGE)
        except (EOFError, OSError, ValueError):
            raise AgentNotRunningError("connection to the key agent was lost") from None
        if len(reply) < 2 or reply[0] != PROTO:
            raise ProtocolError("malformed reply from the key agent")
        if reply[1] == STATUS_OK:
            return reply[2:]
        code = reply[2:].decode("ascii", "replace")
        if code == "locked":
            raise AgentLockedError("key agent holds no key (run `nbp-git-safe unlock`)")
        if code == "expired":
            raise AgentExpiredError("key agent TTL elapsed (run `nbp-git-safe unlock`)")
        if code in _CRYPTO_CODES:
            raise _CRYPTO_CODES[code](_CRYPTO_MESSAGES[code])
        raise AgentError("key agent refused the request")

    # -- operations
    def hello(self) -> int:
        return self._call(OP_HELLO)[0]

    def status(self) -> dict[str, Any]:
        value = json.loads(self._call(OP_STATUS).decode("ascii"))
        assert isinstance(value, dict)
        return value

    def load_key(self, master: bytes) -> bytes:
        """Deliver the master key (once) over the authenticated channel; returns the key_id."""
        return self._call(OP_LOAD_KEY, pack_args(master))

    def key_id(self) -> bytes:
        return self._call(OP_KEY_ID)

    def mac(self, data: bytes) -> bytes:
        return self._call(OP_MAC, pack_args(data))

    def enc_blob(self, file_id: str, data: bytes, bucket: int = crypto.DEFAULT_BUCKET) -> bytes:
        return self._call(
            OP_ENC_BLOB, pack_args(file_id.encode("ascii", "replace"), _pack_u32(bucket), data)
        )

    def dec_blob(self, file_id: str, blob: bytes) -> bytes:
        return self._call(OP_DEC_BLOB, pack_args(file_id.encode("ascii", "replace"), blob))

    def enc_index(self, index: dict[str, Any], bucket: int = crypto.DEFAULT_BUCKET) -> bytes:
        payload = crypto.canonical_json(index)
        return self._call(OP_ENC_INDEX, pack_args(_pack_u32(bucket), payload))

    def dec_index(self, blob: bytes) -> dict[str, Any]:
        value = json.loads(self._call(OP_DEC_INDEX, pack_args(blob)).decode("utf-8"))
        assert isinstance(value, dict)
        return value

    def lock(self) -> None:
        with contextlib.suppress(AgentNotRunningError):
            self._call(OP_LOCK, timeout=10.0)


def _pack_u32(value: int) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << 32:
        raise crypto.InvalidArgumentError("invalid padding bucket")
    return struct.pack(">I", value)


# -------------------------------------------------------------------- spawn / unlock


def _agent_environment() -> dict[str, str]:
    """Environment for the agent process: ``NBP_SAFE_*`` variables are not inherited."""
    return {k: v for k, v in os.environ.items() if not k.startswith("NBP_SAFE_")}


def _agent_executable() -> str:
    exe = Path(sys.executable)
    if sys.platform == "win32":
        pythonw = exe.with_name("pythonw.exe")
        if pythonw.is_file():
            return str(pythonw)
    return str(exe)


def spawn_agent(state_dir: Path, ttl: float, idle_timeout: float | None) -> AgentInfo:
    """Start the agent detached and wait until it publishes ``agent.json``."""
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    argv = [_agent_executable(), "-m", "nbp_git_safe.agent", "--state-dir", str(state_dir)]
    argv += ["--ttl", repr(float(ttl))]
    if idle_timeout is not None:
        argv += ["--idle", repr(float(idle_timeout))]
    kwargs: dict[str, Any] = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = (
            subprocess.DETACHED_PROCESS  # type: ignore[attr-defined]
            | subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
        )
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell, no secrets
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        cwd=tempfile.gettempdir(),
        env=_agent_environment(),
        **kwargs,
    )
    deadline = time.monotonic() + START_TIMEOUT
    while time.monotonic() < deadline:
        try:
            info = read_agent_info(state_dir)
        except AgentError:
            info = None
        if info is not None and info.pid != 0 and pid_alive(info.pid):
            return info
        if proc.poll() is not None and info is None:
            break
        time.sleep(0.05)
    raise AgentError("key agent failed to start")


@contextlib.contextmanager
def unlock_guard(state_dir: Path) -> Any:
    """Serialize concurrent ``unlock`` calls with an exclusive lock file (stale after 3 min)."""
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    path = state_dir / UNLOCK_LOCK
    for _ in range(2):
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            try:
                age = time.time() - path.stat().st_mtime
            except FileNotFoundError:
                continue
            if age > 180:
                with contextlib.suppress(FileNotFoundError):
                    path.unlink()
                continue
            raise AgentError("another unlock is in progress") from None
        os.close(fd)
        break
    else:  # pragma: no cover - lost the race twice
        raise AgentError("another unlock is in progress")
    try:
        yield
    finally:
        with contextlib.suppress(FileNotFoundError):
            path.unlink()


def deliver_key(
    state_dir: Path,
    master: bytes,
    ttl: float,
    idle_timeout: float | None,
    spawn: Callable[[Path, float, float | None], AgentInfo] = spawn_agent,
) -> dict[str, Any]:
    """Start an agent, hand it the master key over the authenticated channel, return its status.

    On any failure after the spawn the agent is told to lock (and its file removed), so a
    half-initialised agent never stays around."""
    info = spawn(state_dir, ttl, idle_timeout)
    try:
        with AgentClient.connect_info(info) as client:
            client.load_key(master)
            return client.status()
    except BaseException:
        with contextlib.suppress(Exception), AgentClient.connect_info(info) as client:
            client.lock()
        raise


# ----------------------------------------------------------------------- entry point


def _harden_process() -> None:
    if sys.platform != "win32":
        import resource

        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def main(argv: list[str] | None = None, exit_func: Callable[[int], Any] = os._exit) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="nbp_git_safe.agent")
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--ttl", type=float, required=True)
    parser.add_argument("--idle", type=float, default=None)
    args = parser.parse_args(argv)
    _harden_process()
    state_dir = Path(args.state_dir)
    try:
        existing = read_agent_info(state_dir)
    except AgentError:
        existing = None
    if existing is not None and existing.pid != os.getpid() and pid_alive(existing.pid):
        return 3
    server = AgentServer(state_dir, args.ttl, args.idle, exit_func=exit_func)
    server.start()
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
