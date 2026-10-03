# SPDX-License-Identifier: MIT
"""Key agent: holds the derived keys in RAM only and serves crypto operations.

Transport: ``multiprocessing.connection`` with ``authkey=None`` (so the stdlib challenge, which
uses HMAC-MD5 and ``==``, is NOT used) plus our own mutual HMAC-SHA256 handshake compared with
``hmac.compare_digest``. Only ``send_bytes`` / ``recv_bytes(maxlength=...)`` are used: ``recv()``
(which unpickles) is never called. Windows uses an ``AF_PIPE`` named pipe created by us with a
current-user-only DACL and remote clients rejected (``winsec``); POSIX an ``AF_UNIX`` socket
inside a private (0700) directory, with the peer's uid checked.

Trust (``docs/FORMAT.md`` section 11): ``agent.json`` is NOT a trust anchor. The agent's state
lives OUTSIDE the repository, in a per-user directory this module creates and re-verifies on every
use (``%LOCALAPPDATA%\\nbp-git-safe\\<repo hash>`` or ``~/.cache/nbp-git-safe-<uid>/<repo hash>``,
see ``compute_runtime_root``; owner and ACL/mode checked, no links). The connection ``authkey``
is never stored: it is ``HMAC(agent.secret, nonce)`` where ``agent.secret`` is a random file in
that directory and the nonce is public (in ``agent.json``). A process that merely plants an
``agent.json`` cannot answer the handshake, so it never receives the master key (``unlock`` only
ever delivers it to an agent this very process started and authenticated) nor plaintext. The
client also checks, before anything is sent, that the process serving the pipe/socket is the one
``agent.json`` names and that it belongs to the current user.

``agent.json`` is never used to decide what to delete: the only paths removed are ``agent.json``
itself and, on POSIX, a socket that is a direct child of the verified socket directory
(``<12 hex>-<12 hex>.sock``, see ``socket_dir``).
"""

from __future__ import annotations

import contextlib
import ctypes
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import stat
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from multiprocessing.connection import Client, Connection, Listener
from pathlib import Path
from typing import Any

from nbp_git_safe import crypto, winsec

PROTO = 1
STATE_VERSION = 2  # agent.json layout (v1 stored the authkey and lived inside .git)
AGENT_JSON = "agent.json"
SECRET_FILE = "agent.secret"  # noqa: S105 - a file name, not a secret
UNLOCK_LOCK = "unlock.lock"
RUNTIME_NAME = "nbp-git-safe"
SECRET_LEN = 32
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
HANDOFF_MAX = 4096  # bytes of the credentials line the CLI sends to a new agent
_PIPE_RE = re.compile(r"\\\\\.\\pipe\\nbp-git-safe-[0-9a-f]{24}")
_SOCK_RE = re.compile(r"[0-9a-f]{12}-[0-9a-f]{12}\.sock")
# ``sun_path`` is 104 bytes on macOS and 108 on Linux (including the NUL): stay well under both.
MAX_SOCKET_PATH = 100
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_BINARY = getattr(os, "O_BINARY", 0)

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


class ProcessInspectionError(HandshakeError):
    """The process that serves the connection cannot be inspected from this one. On Windows that
    is what an agent running ELEVATED looks like to a non-elevated hook (or the reverse): the
    process token is not readable. Nothing is sent to it; the callers degrade to the path check
    and tell the user why."""


ELEVATION_MESSAGE = (
    "the agent's process cannot be inspected from this one; it probably runs at another "
    "elevation level (elevated while this process is not, or the reverse): nothing is sent to it, "
    "only the path check runs. Run git and `nbp-git-safe unlock` from the same kind of terminal"
)


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
    return not _is_zombie(pid)


def _is_zombie(pid: int) -> bool:
    """A process that has exited but was not reaped by its parent still answers ``kill(pid, 0)``;
    it holds no key and serves nothing, so it is not "alive" (an orphan whose reaper is slow, or a
    container whose init never reaps, must not look like a running agent)."""
    try:
        if sys.platform.startswith("linux"):
            with open(f"/proc/{pid}/stat", "rb") as handle:
                raw = handle.read()
            state = raw[raw.rfind(b")") + 1 :].split()[0]
            return state in (b"Z", b"X")
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["/bin/ps", "-o", "stat=", "-p", str(pid)],
            capture_output=True,
            check=False,
            timeout=5,
        )
        return proc.stdout.strip().startswith(b"Z")
    except (OSError, IndexError, subprocess.SubprocessError):
        return False


# ------------------------------------------------------------------------------- state


class InsecureStateError(AgentError):
    """The agent's state directory (or its secret) is not under the exclusive control of the
    current user. Nothing is read from it, written to it or deleted from it."""


_root_override: list[Path] = []


def set_runtime_root(root: Path) -> None:
    """Fix the base directory for this process. Used by a freshly started agent, whose environment
    is deliberately empty: the starter passes the root it resolved on the command line."""
    _root_override[:] = [Path(root)]


def clear_runtime_root() -> None:
    _root_override.clear()


def runtime_root() -> Path:
    """Per-user base directory of all agent state (outside any repository)."""
    if _root_override:
        return _root_override[0]
    if sys.platform == "win32":
        return compute_runtime_root(sys.platform, os.environ, uid=None, home=Path.home())
    return compute_runtime_root(
        sys.platform, os.environ, uid=os.geteuid(), home=_account_home() or Path.home()
    )


RUNTIME_DIR_ENV = "NBP_SAFE_RUNTIME_DIR"


def compute_runtime_root(
    platform: str, env: Mapping[str, str], *, uid: int | None, home: Path
) -> Path:
    """The per-user base directory of all agent state, as a pure function of its inputs.

    Windows: ``%LOCALAPPDATA%`` plus ``nbp-git-safe``. Elsewhere
    ``<home>/.cache/nbp-git-safe-<uid>``, and deliberately NOT ``$XDG_RUNTIME_DIR`` (present in a
    login session, absent in a hook started by a GUI, cron or another shell: the same repository
    would get two state roots and the hook would not find the agent) nor ``$HOME`` (the caller
    passes the account's home from the password database). ``NBP_SAFE_RUNTIME_DIR`` (an absolute
    path) overrides it explicitly."""
    override = env.get(RUNTIME_DIR_ENV)
    if override and os.path.isabs(override):
        return Path(override)
    if platform == "win32":
        base = env.get("LOCALAPPDATA")
        root = Path(base) if base and os.path.isabs(base) else home / "AppData" / "Local"
        return root / RUNTIME_NAME
    return home / ".cache" / f"{RUNTIME_NAME}-{uid}"


def _account_home() -> Path | None:
    """The home directory of the current account from the password database (not ``$HOME``)."""
    try:
        import pwd

        return Path(pwd.getpwuid(os.geteuid()).pw_dir)
    except (ImportError, KeyError, OSError):  # no pwd on Windows; no entry in a minimal container
        return None


def repo_key(state_dir: Path | str) -> str:
    """Stable name of a repository's state directory: a hash of its canonical path. Computed by
    this program from the repository location, never read from a file."""
    canonical = os.path.normcase(os.path.realpath(state_dir))
    return hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()[:24]


def runtime_path(state_dir: Path | str) -> Path:
    """Where the agent of the repository whose ``.git/nbp-safe`` is ``state_dir`` keeps its files
    (pure computation: nothing is touched)."""
    return runtime_root() / repo_key(state_dir)


def _dir_problem(path: Path) -> str | None:
    """Why ``path`` is not a private directory of the current user, or ``None``."""
    if sys.platform == "win32":
        return winsec.private_dir_problem(path)
    try:
        st = os.lstat(path)
    except OSError:
        return "cannot be inspected"
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return "is not a plain directory"
    if st.st_uid != os.geteuid():
        return "is owned by another user"
    if st.st_mode & 0o077:
        return "is accessible to other users"
    return None


def _make_private(path: Path) -> None:
    if sys.platform == "win32":
        winsec.create_private_dir(path)
    else:
        with contextlib.suppress(FileExistsError):
            os.mkdir(path, 0o700)


def private_dir(state_dir: Path | str, *, create: bool) -> Path | None:
    """The verified state directory of a repository. With ``create=False`` an absent directory
    gives ``None``. Raises ``InsecureStateError`` for anything that is not private to the user."""
    root, rdir = runtime_root(), runtime_path(state_dir)
    for level in (root, rdir):
        if not os.path.lexists(level):
            if not create:
                return None
            if level is root:
                level.parent.mkdir(parents=True, exist_ok=True)
            _make_private(level)
        problem = _dir_problem(level)
        if problem:
            raise InsecureStateError(f"the key agent's state directory is not private: {problem}")
    return rdir


def _default_posix_root() -> Path:
    return compute_runtime_root(
        sys.platform, {}, uid=os.geteuid(), home=_account_home() or Path.home()
    )


def socket_dir() -> Path:
    """Where the POSIX agent sockets live. A socket path is limited to ~104 bytes, so it cannot
    sit under the (long) state root: the default is the short, fixed ``/tmp/nbp-<uid>`` (not
    ``$TMPDIR``, which is ``/var/folders/...`` on macOS and differs between processes; not
    ``$XDG_RUNTIME_DIR``, absent in cron/GUI-started hooks). When the state root is overridden
    (``NBP_SAFE_RUNTIME_DIR``, tests) it is ``<root>/s``. Pure computation."""
    root = runtime_root()
    if root == _default_posix_root():
        return Path(f"/tmp/nbp-{os.geteuid()}")  # noqa: S108 - verified 0700, owned, no links
    return root / "s"


def private_socket_dir(*, create: bool) -> Path | None:
    """The verified socket directory (owner, mode 0700, not a link), created when asked. It holds
    sockets only: the secret and the state stay in the private state directory. If another user
    got there first (``/tmp`` squatting) this raises ``InsecureStateError``: the agent cannot
    start (denial of service, closed), and nothing secret is ever placed there."""
    if sys.platform == "win32":
        return None
    sdir = socket_dir()
    root = runtime_root()
    if sdir.parent == root and os.path.lexists(root):
        problem = _dir_problem(root)  # <root>/s: the root is judged like everywhere else
        if problem:
            raise InsecureStateError(f"the key agent's state directory is not private: {problem}")
    if not os.path.lexists(sdir):
        if not create:
            return None
        if sdir.parent == root and not os.path.lexists(root):
            root.parent.mkdir(parents=True, exist_ok=True)
            _make_private(root)
        _make_private(sdir)
    problem = _dir_problem(sdir)
    if problem:
        raise InsecureStateError(f"the key agent's socket directory is not private: {problem}")
    return sdir


def agent_json_path(state_dir: Path | str) -> Path:
    return runtime_path(state_dir) / AGENT_JSON


SHARING_RETRY_WINDOW = 3.0  # seconds a sharing violation is waited out before it is an error
SHARING_RETRY_STEP = 0.005


def _retry_sharing(operation: Callable[[], Any]) -> Any:
    """Run a file operation on ``agent.json``, waiting out Windows sharing violations.

    ``agent.json`` is replaced atomically (``os.replace``) and polled by other processes. On
    Windows an ``open``/``replace``/``unlink`` that collides with another process's open or
    rename of the same name fails with ``PermissionError`` (EACCES) instead of blocking; that is
    transient by nature. Measured on Windows 11: a reader racing a replacing writer got it on
    ~10% of the attempts and the writer on most of them. The wait is bounded; after the window
    the error is raised as it is."""
    deadline = time.monotonic() + SHARING_RETRY_WINDOW
    while True:
        try:
            return operation()
        except PermissionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(SHARING_RETRY_STEP)


def load_secret(rdir: Path, *, create: bool) -> bytes | None:
    """The per-repository secret the connection authkeys are derived from (random, 32 bytes,
    created once with ``O_EXCL`` inside the private directory). ``None`` if absent and not
    ``create``. A file that is not a regular file is refused; a short or garbled one is replaced
    when ``create`` (agents started with the old one become unreachable, which is safe)."""
    path = rdir / SECRET_FILE
    deadline = time.monotonic() + 2.0
    while True:
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            if not create:
                return None
            try:
                fd = os.open(
                    path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _BINARY, 0o600
                )
            except FileExistsError:
                continue
            with os.fdopen(fd, "wb") as handle:
                handle.write(os.urandom(SECRET_LEN))
            continue
        if not stat.S_ISREG(st.st_mode):
            raise InsecureStateError("the key agent's secret is not a regular file")
        if st.st_size == SECRET_LEN:
            data = _retry_sharing(path.read_bytes)
            if len(data) == SECRET_LEN:
                return bytes(data)
        if time.monotonic() >= deadline:
            if not create:
                raise AgentError("the key agent's secret is corrupted")
            with contextlib.suppress(FileNotFoundError):
                _retry_sharing(path.unlink)
            deadline = time.monotonic() + 2.0
            continue
        time.sleep(0.01)


def derive_authkey(secret: bytes, nonce: bytes) -> bytes:
    return hmac.new(secret, b"nbp-git-safe/agent/authkey/v2" + nonce, hashlib.sha256).digest()


@dataclass(frozen=True)
class Endpoint:
    """Where a new agent listens and how it is authenticated. Made by the process that starts the
    agent and handed over on a private pipe; it is never read back from ``agent.json``."""

    address: str
    family: str
    nonce: bytes = field(repr=False)
    authkey: bytes = field(repr=False)

    def to_handoff(self) -> bytes:
        return (
            json.dumps(
                {
                    "v": STATE_VERSION,
                    "address": self.address,
                    "family": self.family,
                    "nonce": self.nonce.hex(),
                    "authkey": self.authkey.hex(),
                },
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )

    @classmethod
    def from_handoff(cls, raw: bytes, sdir: Path | None) -> Endpoint:
        try:
            data = json.loads(raw.decode("utf-8"))
            ep = cls(
                address=str(data["address"]),
                family=str(data["family"]),
                nonce=bytes.fromhex(data["nonce"]),
                authkey=bytes.fromhex(data["authkey"]),
            )
        except (ValueError, KeyError, TypeError, AttributeError):
            raise AgentError("invalid agent hand-off") from None
        if (
            data.get("v") != STATE_VERSION
            or len(ep.nonce) != NONCE_LEN
            or len(ep.authkey) != AUTHKEY_LEN
        ):
            raise AgentError("invalid agent hand-off")
        check_endpoint(ep.address, ep.family, sdir)
        return ep


def check_endpoint(address: str, family: str, sdir: Path | None) -> None:
    """The address must be exactly what this program would have made: the platform's own family,
    a pipe name of our shape, or a socket that is a direct child of the socket directory ``sdir``
    and short enough for ``sun_path``."""
    if sys.platform == "win32":
        ok = family == "AF_PIPE" and _PIPE_RE.fullmatch(address) is not None
    else:
        ok = (
            family == "AF_UNIX"
            and os.path.isabs(address)
            and len(address.encode("utf-8", "surrogateescape")) <= MAX_SOCKET_PATH
            and os.path.dirname(address) == str(sdir)
            and _SOCK_RE.fullmatch(os.path.basename(address)) is not None
        )
    if not ok:
        raise AgentError("agent endpoint is not valid")


def new_endpoint(state_dir: Path | str) -> Endpoint:
    """Fresh nonce, address and derived authkey for a new agent of this repository."""
    rdir = private_dir(state_dir, create=True)
    assert rdir is not None
    secret = load_secret(rdir, create=True)
    assert secret is not None
    nonce = os.urandom(NONCE_LEN)
    if sys.platform == "win32":
        address, family = rf"\\.\pipe\nbp-git-safe-{secrets.token_hex(12)}", "AF_PIPE"
    else:
        sdir = private_socket_dir(create=True)
        assert sdir is not None
        address = str(sdir / f"{repo_key(state_dir)[:12]}-{secrets.token_hex(6)}.sock")
        family = "AF_UNIX"
        if len(address.encode("utf-8", "surrogateescape")) > MAX_SOCKET_PATH:
            raise AgentError(
                "the agent socket path would be too long for AF_UNIX; "
                "use a shorter NBP_SAFE_RUNTIME_DIR"
            )
    return Endpoint(address, family, nonce, derive_authkey(secret, nonce))


@dataclass(frozen=True)
class AgentInfo:
    """What a client needs to reach an agent. ``agent.json`` holds everything but the authkey,
    which is derived (``derive_authkey``) and never written; it is redacted from ``repr``."""

    address: str
    family: str
    authkey: bytes = field(repr=False)
    pid: int
    started: float
    expires_at: float
    idle_timeout: float | None
    nonce: bytes = field(default=b"", repr=False)

    def to_json(self) -> bytes:
        return json.dumps(
            {
                "v": STATE_VERSION,
                "address": self.address,
                "family": self.family,
                "nonce": self.nonce.hex(),
                "pid": self.pid,
                "started": self.started,
                "expires_at": self.expires_at,
                "idle_timeout": self.idle_timeout,
            },
            sort_keys=True,
        ).encode("ascii")

    @classmethod
    def from_json(cls, raw: bytes, secret: bytes) -> AgentInfo:
        try:
            data = json.loads(raw.decode("utf-8"))
            nonce = bytes.fromhex(data["nonce"])
            info = cls(
                address=str(data["address"]),
                family=str(data["family"]),
                authkey=derive_authkey(secret, nonce),
                pid=int(data["pid"]),
                started=float(data["started"]),
                expires_at=float(data["expires_at"]),
                idle_timeout=None if data["idle_timeout"] is None else float(data["idle_timeout"]),
                nonce=nonce,
            )
        except (ValueError, KeyError, TypeError, AttributeError):
            raise AgentError("agent.json is corrupted") from None
        finite = all(math.isfinite(v) for v in (info.started, info.expires_at))
        if data.get("v") != STATE_VERSION or len(nonce) != NONCE_LEN or not finite or info.pid <= 0:
            raise AgentError("agent.json is corrupted")
        return info

    def __repr__(self) -> str:
        return (
            f"AgentInfo(address={self.address!r}, pid={self.pid}, "
            f"expires_at={self.expires_at}, authkey=<redacted>)"
        )


def read_agent_info(state_dir: Path | str) -> AgentInfo | None:
    """The agent recorded for a repository, with its authkey derived. ``None``: no state at all.
    Raises ``InsecureStateError`` (nothing is trusted), or ``AgentError`` for a file that is
    unreadable, malformed or points anywhere but where this program would have put an agent."""
    rdir = private_dir(state_dir, create=False)
    if rdir is None:
        return None
    try:
        raw = _retry_sharing((rdir / AGENT_JSON).read_bytes)
    except FileNotFoundError:
        return None
    secret = load_secret(rdir, create=False)
    if secret is None:
        raise AgentError("agent.json is corrupted")
    info = AgentInfo.from_json(raw, secret)
    try:
        check_endpoint(info.address, info.family, None if sys.platform == "win32" else socket_dir())
    except AgentError:
        raise AgentError("agent.json is corrupted") from None
    return info


def write_agent_info(state_dir: Path | str, info: AgentInfo) -> None:
    """Atomically write ``agent.json`` (mode 0600 where the OS supports it)."""
    rdir = private_dir(state_dir, create=True)
    assert rdir is not None
    tmp = rdir / f"{AGENT_JSON}.{secrets.token_hex(4)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(info.to_json())
        handle.flush()
        os.fsync(handle.fileno())
    try:
        _retry_sharing(lambda: os.replace(tmp, rdir / AGENT_JSON))
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise


def remove_agent_info(state_dir: Path | str) -> None:
    """Delete ``agent.json`` (a path this program computes). Nothing is removed from a directory
    that fails the privacy check."""
    try:
        rdir = private_dir(state_dir, create=False)
    except InsecureStateError:
        return
    if rdir is None:
        return
    with contextlib.suppress(FileNotFoundError):
        _retry_sharing((rdir / AGENT_JSON).unlink)


def _remove_socket(address: str) -> None:
    """Unlink a POSIX socket that ``check_endpoint`` accepted (and only that)."""
    if sys.platform == "win32":
        return
    with contextlib.suppress(AgentError, OSError):
        check_endpoint(address, "AF_UNIX", socket_dir())
        if stat.S_ISSOCK(os.lstat(address).st_mode):
            os.unlink(address)


def cleanup_orphan(state_dir: Path | str) -> bool:
    """Remove a stale ``agent.json`` (unreadable, dead pid or expired). True if removed. The
    content of the file never decides what else is deleted."""
    try:
        info = read_agent_info(state_dir)
    except InsecureStateError:
        return False
    except AgentError:
        remove_agent_info(state_dir)
        return True
    if info is None:
        return False
    if not pid_alive(info.pid) or time.time() >= info.expires_at:
        remove_agent_info(state_dir)
        _remove_socket(info.address)
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


# ------------------------------------------------------------------ listener and peer checks


def _peer_ids(conn: Connection) -> tuple[int | None, int | None]:
    """``(pid, uid)`` of the other end of a POSIX ``AF_UNIX`` connection; ``None`` for a value
    the platform does not report."""
    import socket

    sock = socket.socket(fileno=os.dup(conn.fileno()))
    try:
        if sys.platform.startswith("linux"):
            raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            pid, uid, _gid = struct.unpack("3i", raw)
            return int(pid), int(uid)
        if sys.platform == "darwin":  # LOCAL_PEERCRED (xucred: version, uid, ...) / LOCAL_PEERPID
            level, peercred, peerpid = 0, 0x001, 0x002
            cred = sock.getsockopt(level, peercred, 76)
            uid = struct.unpack_from("=I", cred, 4)[0]
            pid = struct.unpack("i", sock.getsockopt(level, peerpid, 4))[0]
            return int(pid), int(uid)
        return None, None
    finally:
        sock.close()


class _UnixListener:
    """``AF_UNIX`` listener that drops connections from other users (the 0700 directory is the
    first barrier, the peer uid the second)."""

    def __init__(self, address: str) -> None:
        # The stdlib default backlog is 1: on macOS a burst of clients (parallel git hooks) is then
        # refused (ECONNREFUSED) while the agent is busy accepting; allow a real queue.
        self._listener = Listener(address, "AF_UNIX", backlog=2 * MAX_CONNECTIONS, authkey=None)
        with contextlib.suppress(OSError):
            os.chmod(address, 0o600)

    def accept(self) -> Connection | None:
        conn = self._listener.accept()
        try:
            _pid, uid = _peer_ids(conn)
        except OSError:
            uid = None
        if uid is not None and uid != os.geteuid():
            with contextlib.suppress(OSError):
                conn.close()
            return None
        return conn

    def close(self) -> None:
        self._listener.close()


def open_listener(address: str, family: str) -> Any:
    if sys.platform == "win32":
        return winsec.HardenedPipeListener(address)
    return _UnixListener(address)


def connect_raw(address: str, family: str) -> Connection:
    """Open a connection without authenticating it (the caller verifies the server first)."""
    if sys.platform == "win32":
        return winsec.connect_pipe(address)
    return Client(address, family, authkey=None)


def _verify_windows(conn: Connection, info: AgentInfo) -> None:
    pid = winsec.pipe_server_pid(conn._handle)  # type: ignore[attr-defined]
    if pid != info.pid:
        raise HandshakeError("agent process is not the expected one")
    owner = winsec.process_owner_sid(pid)
    if owner is None:  # the token cannot be read: another elevation level, not "an impostor"
        raise ProcessInspectionError(ELEVATION_MESSAGE)
    if owner != winsec.current_user_sid():
        raise HandshakeError("agent process is not the expected one")


def verify_server(conn: Connection, info: AgentInfo) -> None:
    """Before any byte is sent: the process serving this connection must be the one the state
    names and must belong to the current user."""
    try:
        if sys.platform == "win32":
            _verify_windows(conn, info)
        else:
            pid_, uid = _peer_ids(conn)
            if (uid is not None and uid != os.geteuid()) or (pid_ is not None and pid_ != info.pid):
                raise HandshakeError("agent process is not the expected one")
    except OSError:
        raise HandshakeError("agent process could not be identified") from None


# ------------------------------------------------------------------------------ server


class AgentServer:
    """The agent. ``exit_func`` is ``os._exit`` in the real process; tests inject a stub.

    ``endpoint`` is what the process that started the agent handed over (address and authkey);
    without it (thread mode in tests) the server makes its own, exactly as ``new_endpoint``."""

    def __init__(
        self,
        state_dir: Path,
        ttl: float,
        idle_timeout: float | None = None,
        *,
        exit_func: Callable[[int], Any] = os._exit,
        key_wait: float = KEY_WAIT,
        endpoint: Endpoint | None = None,
    ) -> None:
        self.state_dir = Path(state_dir)
        self.ttl = float(ttl)
        self.idle_timeout = idle_timeout
        self._exit = exit_func
        self._key_wait = key_wait
        self._endpoint = endpoint
        self._keys: crypto.KeySet | None = None
        self._authkey = b""
        self._lock = threading.Lock()
        self._stopping = threading.Event()
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self._listener: Any = None
        self._started = 0.0
        self._expires_at = 0.0
        self._last_activity = 0.0
        self.info: AgentInfo | None = None

    # -- lifecycle
    def start(self) -> AgentInfo:
        endpoint = self._endpoint or new_endpoint(self.state_dir)
        rdir = private_dir(self.state_dir, create=True)
        assert rdir is not None
        check_endpoint(
            endpoint.address, endpoint.family, None if sys.platform == "win32" else socket_dir()
        )
        self._authkey = endpoint.authkey
        self._listener = open_listener(endpoint.address, endpoint.family)
        now = time.time()
        self._started = self._last_activity = now
        self._expires_at = now + self.ttl
        self.info = AgentInfo(
            address=endpoint.address,
            family=endpoint.family,
            authkey=endpoint.authkey,
            pid=os.getpid(),
            started=now,
            expires_at=self._expires_at,
            idle_timeout=self.idle_timeout,
            nonce=endpoint.nonce,
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
            if conn is None:  # a peer of another user, already hung up on
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
        try:
            # the key is already gone; a stuck file must never keep the process alive
            with contextlib.suppress(OSError, AgentError):
                self._remove_own_info()
            if self.info is not None:
                _remove_socket(self.info.address)
        finally:
            if self._exit is not os._exit:
                self._wake()  # thread mode (tests): unblock accept()
            self._exit(0)

    def _remove_own_info(self) -> None:
        """Remove ``agent.json`` only while it still describes THIS agent: a replacement agent
        started right after a ``lock`` must not lose its record to us."""
        if self.info is None:
            return
        rdir = private_dir(self.state_dir, create=False)
        if rdir is None:
            return
        try:
            current = _retry_sharing((rdir / AGENT_JSON).read_bytes)
        except FileNotFoundError:
            return
        if current == self.info.to_json():
            remove_agent_info(self.state_dir)

    def _wake(self) -> None:
        """Unblock ``accept`` (used by thread-mode shutdown in tests)."""
        if self.info is None:
            return
        with contextlib.suppress(Exception):
            connect_raw(self.info.address, self.info.family).close()

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
        gone = "key agent is not running (run `nbp-git-safe unlock`)"
        try:
            info = read_agent_info(state_dir)
        except InsecureStateError as exc:
            raise AgentNotRunningError(str(exc)) from None
        except AgentError:
            remove_agent_info(state_dir)
            raise AgentNotRunningError("agent state was corrupted and has been removed") from None
        if info is None:
            raise AgentNotRunningError(gone)
        if not pid_alive(info.pid) or time.time() >= info.expires_at:
            cleanup_orphan(state_dir)
            raise AgentNotRunningError(gone)
        return cls.connect_info(info)

    @classmethod
    def connect_info(cls, info: AgentInfo) -> AgentClient:
        try:
            conn = connect_raw(info.address, info.family)
        except (OSError, EOFError):
            raise AgentNotRunningError("key agent is not reachable") from None
        try:
            verify_server(conn, info)  # who is serving this? decided before anything is sent
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
        reply = self._call(OP_HELLO)
        if not reply:
            raise ProtocolError("malformed reply from the key agent")
        return reply[0]

    @staticmethod
    def _json_object(body: bytes, encoding: str) -> dict[str, Any]:
        try:
            value = json.loads(body.decode(encoding))
        except (ValueError, RecursionError):
            raise ProtocolError("malformed reply from the key agent") from None
        if not isinstance(value, dict):
            raise ProtocolError("malformed reply from the key agent")
        return value

    def status(self) -> dict[str, Any]:
        return self._json_object(self._call(OP_STATUS), "ascii")

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
        return self._json_object(self._call(OP_DEC_INDEX, pack_args(blob)), "utf-8")

    def lock(self) -> None:
        with contextlib.suppress(AgentNotRunningError):
            self._call(OP_LOCK, timeout=10.0)


def _pack_u32(value: int) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << 32:
        raise crypto.InvalidArgumentError("invalid padding bucket")
    return struct.pack(">I", value)


# -------------------------------------------------------------------- spawn / unlock


def _agent_environment() -> dict[str, str]:
    """The agent's whole environment: nothing is inherited (no ``PYTHON*``, no ``NBP_SAFE_*``, no
    ``PATH`` of the caller). Windows needs ``SYSTEMROOT`` (sockets); everything else is explicit."""
    if sys.platform == "win32":
        root = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or r"C:\Windows"
        return {"SYSTEMROOT": root, "WINDIR": root, "PATH": str(Path(root) / "System32")}
    return {"PATH": "/usr/bin:/bin"}


def _agent_executable() -> str:
    exe = Path(sys.executable)
    if sys.platform == "win32":
        pythonw = exe.with_name("pythonw.exe")
        if pythonw.is_file():
            return str(pythonw)
    return str(exe)


def _agent_argv(state_dir: Path, ttl: float, idle_timeout: float | None) -> list[str]:
    """``-I``: isolated mode (no ``PYTHON*`` variables, no user site, and neither the current
    directory nor the script directory on ``sys.path``), so nothing planted next to the caller can
    be imported into the process that holds the key."""
    argv = [_agent_executable(), "-I", "-m", "nbp_git_safe.agent", "--state-dir", str(state_dir)]
    argv += ["--runtime-root", str(runtime_root()), "--ttl", repr(float(ttl))]
    if idle_timeout is not None:
        argv += ["--idle", repr(float(idle_timeout))]
    return argv


def _read_ready(proc: subprocess.Popen[bytes], timeout: float) -> int:
    """The agent's ``READY <pid>`` line, read from the private pipe only this process holds."""
    assert proc.stdout is not None
    box: list[bytes] = []
    reader = threading.Thread(target=lambda: box.append(proc.stdout.readline()), daemon=True)  # type: ignore[union-attr]
    reader.start()
    reader.join(timeout)
    match = re.fullmatch(rb"READY (\d{1,10})\r?\n?", box[0]) if box else None
    if match is None:
        raise AgentError("key agent failed to start")
    return int(match.group(1))


def _is_our_child(pid: int, proc: subprocess.Popen[bytes]) -> bool:
    """Is ``pid`` the process we started, or (Windows venv launchers re-exec the interpreter) a
    direct child of it?"""
    if pid == proc.pid:
        return True
    return sys.platform == "win32" and winsec.parent_pid(pid) == proc.pid


def _kill_quietly(proc: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(Exception):
        proc.kill()
    with contextlib.suppress(Exception):
        proc.wait(5)


def spawn_agent(state_dir: Path, ttl: float, idle_timeout: float | None) -> AgentInfo:
    """Start a NEW agent, detached, and return what is needed to reach it.

    The authkey and the address are generated here and sent to the child over its stdin pipe (never
    through a file another process could have written); the child answers ``READY <pid>`` on its
    stdout pipe. The pid it reports must be the process started here (or its direct child, for a
    launcher stub), and the connection that follows is checked against that pid."""
    state_dir = Path(state_dir)
    endpoint = new_endpoint(state_dir)  # creates and verifies the private state directory
    rdir = runtime_path(state_dir)
    kwargs: dict[str, Any] = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = (
            subprocess.DETACHED_PROCESS  # type: ignore[attr-defined]
            | subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
        )
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        _agent_argv(state_dir, ttl, idle_timeout),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        cwd=rdir,
        env=_agent_environment(),
        **kwargs,
    )
    try:
        assert proc.stdin is not None
        proc.stdin.write(endpoint.to_handoff())
        proc.stdin.close()
        pid = _read_ready(proc, START_TIMEOUT)
        if not _is_our_child(pid, proc) or not pid_alive(pid):
            raise AgentError("key agent failed to start")
    except BaseException:
        _kill_quietly(proc)
        raise
    finally:
        if proc.stdout is not None:
            proc.stdout.close()
    now = time.time()
    return AgentInfo(
        endpoint.address,
        endpoint.family,
        endpoint.authkey,
        pid,
        now,
        now + float(ttl),
        idle_timeout,
        endpoint.nonce,
    )


@contextlib.contextmanager
def unlock_guard(state_dir: Path) -> Any:
    """Serialize concurrent ``unlock`` calls with an exclusive lock file (stale after 3 min)."""
    rdir = private_dir(state_dir, create=True)
    assert rdir is not None
    path = rdir / UNLOCK_LOCK
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

    The key goes only to the agent ``spawn`` just started (its address and authkey are the ones
    this process generated, and the connection is checked against its pid): never to an agent
    that was merely found through a file. On any failure after the spawn the agent is told to lock
    (and its file removed), so a half-initialised agent never stays around."""
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


def _read_handoff(fd: int = 0) -> bytes:
    """One line (at most ``HANDOFF_MAX`` bytes) from the pipe the starter wrote."""
    data = b""
    while b"\n" not in data and len(data) < HANDOFF_MAX:
        chunk = os.read(fd, HANDOFF_MAX - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _announce_ready(fd: int = 1) -> None:
    with contextlib.suppress(OSError):
        os.write(fd, b"READY %d\n" % os.getpid())


def main(
    argv: list[str] | None = None,
    exit_func: Callable[[int], Any] = os._exit,
    endpoint: Endpoint | None = None,
) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="nbp_git_safe.agent")
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--runtime-root", default=None)
    parser.add_argument("--ttl", type=float, required=True)
    parser.add_argument("--idle", type=float, default=None)
    args = parser.parse_args(argv)
    _harden_process()
    if args.runtime_root is not None:
        set_runtime_root(Path(args.runtime_root))
    state_dir = Path(args.state_dir)
    try:
        if endpoint is None:
            rdir = private_dir(state_dir, create=True)
            assert rdir is not None
            endpoint = Endpoint.from_handoff(
                _read_handoff(),
                None if sys.platform == "win32" else private_socket_dir(create=True),
            )
        server = AgentServer(state_dir, args.ttl, args.idle, exit_func=exit_func, endpoint=endpoint)
        server.start()
    except (AgentError, OSError):
        return 2
    _announce_ready()
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
