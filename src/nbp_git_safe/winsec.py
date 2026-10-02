# SPDX-License-Identifier: MIT
"""Windows security helpers (ctypes only, no dependency): the current user's SID, private
directories, a hardened named-pipe listener and process identity checks.

Used by the key agent so that its state directory and its pipe are reachable by the current user
alone. Importing this module on another platform is harmless; calling anything raises
``RuntimeError``.

* Directories are created with a protected DACL: full control for the current user, SYSTEM and
  Administrators only. ``private_dir_problem`` re-checks owner and DACL on every use, so a
  directory somebody else created, or whose ACL was loosened, is refused.
* The pipe is created with ``CreateNamedPipeW`` (``multiprocessing`` cannot pass a security
  descriptor): DACL for the current user only, ``PIPE_REJECT_REMOTE_CLIENTS``, and
  ``FILE_FLAG_FIRST_PIPE_INSTANCE`` on the first instance so that nobody else can squat the name.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import re
import stat
import sys
import time
from ctypes import wintypes
from typing import Any

IS_WINDOWS = sys.platform == "win32"
if IS_WINDOWS:
    from multiprocessing.connection import PipeConnection, PipeListener

PIPE_ACCESS_DUPLEX = 0x00000003
FILE_FLAG_OVERLAPPED = 0x40000000
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
PIPE_TYPE_MESSAGE = 0x00000004
PIPE_READMODE_MESSAGE = 0x00000002
PIPE_WAIT = 0x00000000
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
PIPE_MODE = PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS
PIPE_UNLIMITED_INSTANCES = 255
NMPWAIT_WAIT_FOREVER = 0xFFFFFFFF
BUFSIZE = 8192

SECURITY_SQOS_PRESENT = 0x00100000
SECURITY_IDENTIFICATION = 0x00010000  # the server may identify us but never impersonate us

_REPARSE = 0x400
_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_SE_FILE_OBJECT = 1
_SE_KERNEL_OBJECT = 6
_OWNER_INFO = 0x1
_DACL_INFO = 0x4
_PROCESS_QUERY_LIMITED = 0x1000
_ERROR_ALREADY_EXISTS = 183
_ADMINS = "S-1-5-32-544"
_SYSTEM = "S-1-5-18"
_CREATOR = "S-1-3-0"
_OWNER_RIGHTS = "S-1-3-4"
_ALIASES = {"SY": _SYSTEM, "BA": _ADMINS, "CO": _CREATOR, "OW": _OWNER_RIGHTS}
_DOMAIN_SID = re.compile(r"^(S-1-5-21-\d+-\d+-\d+)-(\d+)$")
_LOCAL_ADMIN_RID = "500"
_ACE_RE = re.compile(r"\(([^()]*)\)")
_ALLOW_TYPES = {"A", "OA", "XA", "ZA"}

_PTR = ctypes.c_void_p


class _SecurityAttributes(ctypes.Structure):
    _fields_ = (
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", _PTR),
        ("bInheritHandle", wintypes.BOOL),
    )


def _require_windows() -> None:
    if not IS_WINDOWS:
        raise RuntimeError("winsec is Windows-only")


_libs: dict[str, Any] = {}


def _dll(name: str) -> Any:
    _require_windows()
    lib = _libs.get(name)
    if lib is not None:
        return lib
    lib = ctypes.WinDLL(name, use_last_error=True)
    if name == "kernel32":
        lib.GetCurrentProcess.restype = _PTR
        lib.OpenProcess.restype = _PTR
        lib.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        lib.CloseHandle.argtypes = [_PTR]
        lib.LocalFree.argtypes = [_PTR]
        lib.LocalFree.restype = _PTR
        lib.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(_SecurityAttributes)]
        lib.CreateNamedPipeW.restype = _PTR
        lib.CreateNamedPipeW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(_SecurityAttributes),
        ]
        lib.GetNamedPipeServerProcessId.argtypes = [_PTR, ctypes.POINTER(wintypes.DWORD)]
    elif name == "advapi32":
        lib.OpenProcessToken.argtypes = [_PTR, wintypes.DWORD, ctypes.POINTER(_PTR)]
        lib.GetTokenInformation.argtypes = [
            _PTR,
            wintypes.DWORD,
            _PTR,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        lib.ConvertSidToStringSidW.argtypes = [_PTR, ctypes.POINTER(wintypes.LPWSTR)]
        lib.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            ctypes.POINTER(_PTR),
            _PTR,
        ]
        lib.GetNamedSecurityInfoW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(_PTR),
            _PTR,
            ctypes.POINTER(_PTR),
            _PTR,
            ctypes.POINTER(_PTR),
        ]
        lib.GetNamedSecurityInfoW.restype = wintypes.DWORD
        lib.GetSecurityInfo.argtypes = [
            _PTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(_PTR),
            _PTR,
            ctypes.POINTER(_PTR),
            _PTR,
            ctypes.POINTER(_PTR),
        ]
        lib.GetSecurityInfo.restype = wintypes.DWORD
        lib.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
            _PTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.LPWSTR),
            _PTR,
        ]
    _libs[name] = lib
    return lib


def _sid_to_string(psid: int) -> str:
    out = wintypes.LPWSTR()
    if not _dll("advapi32").ConvertSidToStringSidW(psid, ctypes.byref(out)):
        raise OSError("ConvertSidToStringSid failed")
    try:
        return str(out.value)
    finally:
        _dll("kernel32").LocalFree(ctypes.cast(out, _PTR))


def _token_user_sid(token: int) -> str:
    advapi = _dll("advapi32")
    size = wintypes.DWORD(0)
    advapi.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(size))
    buf = ctypes.create_string_buffer(size.value)
    if not advapi.GetTokenInformation(token, _TOKEN_USER, buf, size, ctypes.byref(size)):
        raise OSError("GetTokenInformation failed")
    psid = ctypes.cast(buf, ctypes.POINTER(_PTR))[0]
    return _sid_to_string(psid)


_cached_sid: list[str] = []


def current_user_sid() -> str:
    """SID string of the user running this process (for example ``S-1-5-21-...``)."""
    if _cached_sid:
        return _cached_sid[0]
    kernel, advapi = _dll("kernel32"), _dll("advapi32")
    token = _PTR()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
        raise OSError("OpenProcessToken failed")
    try:
        sid = _token_user_sid(token.value or 0)
    finally:
        kernel.CloseHandle(token)
    _cached_sid.append(sid)
    return sid


class _SecurityDescriptor:
    """A security descriptor built from SDDL; freed on close."""

    def __init__(self, sddl: str) -> None:
        self.pointer = _PTR()
        ok = _dll("advapi32").ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(self.pointer), None
        )
        if not ok:
            raise OSError("could not build a security descriptor")
        self.attributes = _SecurityAttributes(
            ctypes.sizeof(_SecurityAttributes), self.pointer, False
        )

    def close(self) -> None:
        if self.pointer:
            _dll("kernel32").LocalFree(self.pointer)
            self.pointer = _PTR()


def _private_dir_sddl() -> str:
    me = current_user_sid()
    return f"D:P(A;OICI;FA;;;{me})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"


def pipe_sddl() -> str:
    """DACL of the agent pipe: full access for the current user and nobody else."""
    return f"D:P(A;;GA;;;{current_user_sid()})"


def create_private_dir(path: str | os.PathLike[str]) -> None:
    """Create ``path`` (one level) with a protected DACL. A directory that already exists is not
    touched here: ``private_dir_problem`` decides whether it is acceptable."""
    descriptor = _SecurityDescriptor(_private_dir_sddl())
    try:
        ok = _dll("kernel32").CreateDirectoryW(os.fspath(path), ctypes.byref(descriptor.attributes))
        if not ok and ctypes.get_last_error() != _ERROR_ALREADY_EXISTS:
            raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
    finally:
        descriptor.close()


def _local_admin_sid(me: str) -> str | None:
    """SID of this machine's built-in Administrator: the current user's own domain prefix and the
    well-known relative id 500 (the alias ``LA`` in SDDL)."""
    match = _DOMAIN_SID.match(me.upper())
    return f"{match.group(1)}-{_LOCAL_ADMIN_RID}" if match else None


def _resolve_trustee(trustee: str, me: str) -> str:
    """The SID an SDDL trustee stands for: aliases (``SY``, ``BA``, ``LA``, ``CO``, ``OW``) are
    resolved, an SID is normalised to upper case; anything else is returned as it is (and so is
    "another account")."""
    text = trustee.strip().upper()
    if text == "LA":
        return _local_admin_sid(me) or "LA"
    return _ALIASES.get(text, text)


def _dacl_problem(dacl_sddl: str, me: str) -> str | None:
    """Does the DACL grant access to anyone but the current user, SYSTEM, Administrators (and the
    built-in Administrator account, a member of them), CREATOR OWNER and OWNER RIGHTS? Every
    trustee is compared by SID after the SDDL aliases are resolved, so the current user is
    accepted whichever way it is printed (``S-1-5-21-...-500`` and ``LA`` are the same account)."""
    me_sid = me.upper()
    allowed = {me_sid, _SYSTEM, _ADMINS, _CREATOR, _OWNER_RIGHTS}
    local_admin = _local_admin_sid(me_sid)
    if local_admin:
        allowed.add(local_admin)
    for match in _ACE_RE.finditer(dacl_sddl):
        fields = match.group(1).split(";")
        if len(fields) < 6:
            return "unrecognised ACL entry"
        kind, trustee = fields[0], fields[5]
        if kind not in _ALLOW_TYPES:
            continue
        if _resolve_trustee(trustee, me_sid) not in allowed:
            return "the ACL grants access to another account"
    return None


def private_dir_problem(path: str | os.PathLike[str]) -> str | None:
    """Why ``path`` is not a directory only the current user controls, or ``None`` if it is:
    a link or junction, not a directory, owner not the current user (or Administrators), no DACL,
    or any allow entry for an account other than the user, SYSTEM and Administrators."""
    try:
        st = os.lstat(path)
    except OSError:
        return "cannot be inspected"
    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & _REPARSE:
        return "is a link or junction"
    if not stat.S_ISDIR(st.st_mode):
        return "is not a directory"
    advapi, kernel = _dll("advapi32"), _dll("kernel32")
    owner, dacl, descriptor = _PTR(), _PTR(), _PTR()
    code = advapi.GetNamedSecurityInfoW(
        os.fspath(path),
        _SE_FILE_OBJECT,
        _OWNER_INFO | _DACL_INFO,
        ctypes.byref(owner),
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if code != 0:
        return "its security information cannot be read"
    try:
        me = current_user_sid()
        if not owner or _sid_to_string(owner.value or 0) not in (me, _ADMINS):
            return "is owned by another account"
        if not dacl:
            return "has no access control list (open to everyone)"
        text = wintypes.LPWSTR()
        ok = advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor, 1, _DACL_INFO, ctypes.byref(text), None
        )
        if not ok:
            return "its access control list cannot be read"
        try:
            return _dacl_problem(str(text.value), me)
        finally:
            kernel.LocalFree(ctypes.cast(text, _PTR))
    finally:
        kernel.LocalFree(descriptor)


def pipe_dacl_sddl(handle: int) -> str:
    """DACL (SDDL) of a pipe handle; used by tests to prove the hardening."""
    advapi, kernel = _dll("advapi32"), _dll("kernel32")
    dacl, descriptor = _PTR(), _PTR()
    code = advapi.GetSecurityInfo(
        handle,
        _SE_KERNEL_OBJECT,
        _DACL_INFO,
        None,
        None,
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if code != 0:
        raise OSError(f"GetSecurityInfo failed ({code})")
    try:
        text = wintypes.LPWSTR()
        ok = advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor, 1, _DACL_INFO, ctypes.byref(text), None
        )
        if not ok:
            raise OSError("cannot render the DACL")
        try:
            return str(text.value)
        finally:
            kernel.LocalFree(ctypes.cast(text, _PTR))
    finally:
        kernel.LocalFree(descriptor)


# ------------------------------------------------------------------------------ the pipe


def _invalid_handle() -> int:
    return int(ctypes.c_void_p(-1).value or 0)


def create_pipe_instance(name: str, *, first: bool) -> int:
    """One instance of the agent pipe (overlapped, message mode, current-user DACL, remote clients
    rejected). The first instance also claims the name exclusively."""
    flags = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED
    if first:
        flags |= FILE_FLAG_FIRST_PIPE_INSTANCE
    descriptor = _SecurityDescriptor(pipe_sddl())
    try:
        handle = _dll("kernel32").CreateNamedPipeW(
            name,
            flags,
            PIPE_MODE,
            PIPE_UNLIMITED_INSTANCES,
            BUFSIZE,
            BUFSIZE,
            NMPWAIT_WAIT_FOREVER,
            ctypes.byref(descriptor.attributes),
        )
        if handle is None or int(handle) == _invalid_handle():
            raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
        return int(handle)
    finally:
        descriptor.close()


if IS_WINDOWS:

    class HardenedPipeListener(PipeListener):  # type: ignore[misc]
        """``multiprocessing``'s ``PipeListener`` with our pipe instances (same interface)."""

        def _new_handle(self, first: bool = False) -> int:
            return create_pipe_instance(self._address, first=first)


def connect_pipe(address: str, timeout: float = 5.0) -> Any:
    """Open a client connection to a pipe. The access level is ``SECURITY_IDENTIFICATION``: a
    server we reach by mistake can learn who we are but cannot act as us."""
    import _winapi  # type: ignore[import-not-found]

    _require_windows()
    deadline = time.monotonic() + timeout
    while True:
        try:
            handle = _winapi.CreateFile(
                address,
                _winapi.GENERIC_READ | _winapi.GENERIC_WRITE,
                0,
                _winapi.NULL,
                _winapi.OPEN_EXISTING,
                _winapi.FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                _winapi.NULL,
            )
            break
        except OSError as exc:
            busy = getattr(exc, "winerror", None) in (
                _winapi.ERROR_SEM_TIMEOUT,
                _winapi.ERROR_PIPE_BUSY,
            )
            if not busy or time.monotonic() >= deadline:
                raise
            time.sleep(0.01)
    try:
        _winapi.SetNamedPipeHandleState(handle, _winapi.PIPE_READMODE_MESSAGE, None, None)
    except BaseException:
        with contextlib.suppress(OSError):
            _winapi.CloseHandle(handle)
        raise
    return PipeConnection(handle)


def pipe_server_pid(handle: int) -> int:
    """Process id of the server end of a pipe handle we hold as a client."""
    pid = wintypes.DWORD(0)
    if not _dll("kernel32").GetNamedPipeServerProcessId(handle, ctypes.byref(pid)):
        raise OSError("GetNamedPipeServerProcessId failed")
    return int(pid.value)


# ------------------------------------------------------------------------ process identity


def process_owner_sid(pid: int) -> str | None:
    """SID of the user a process runs as, or ``None`` when that cannot be read (for example a
    process of another user: access denied)."""
    kernel, advapi = _dll("kernel32"), _dll("advapi32")
    process = kernel.OpenProcess(_PROCESS_QUERY_LIMITED, False, pid)
    if not process:
        return None
    try:
        token = _PTR()
        if not advapi.OpenProcessToken(process, _TOKEN_QUERY, ctypes.byref(token)):
            return None
        try:
            return _token_user_sid(token.value or 0)
        except OSError:
            return None
        finally:
            kernel.CloseHandle(token)
    finally:
        kernel.CloseHandle(process)


def is_current_user_process(pid: int) -> bool:
    return process_owner_sid(pid) == current_user_sid()


class _ProcessBasicInformation(ctypes.Structure):
    _fields_ = (
        ("Reserved1", _PTR),
        ("PebBaseAddress", _PTR),
        ("Reserved2_0", _PTR),
        ("Reserved2_1", _PTR),
        ("UniqueProcessId", _PTR),
        ("InheritedFromUniqueProcessId", _PTR),
    )


def parent_pid(pid: int) -> int | None:
    """Parent process id (as recorded at creation), or ``None`` if it cannot be read."""
    kernel = _dll("kernel32")
    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtQueryInformationProcess.argtypes = [
        _PTR,
        wintypes.ULONG,
        _PTR,
        wintypes.ULONG,
        ctypes.POINTER(wintypes.ULONG),
    ]
    ntdll.NtQueryInformationProcess.restype = ctypes.c_long
    process = kernel.OpenProcess(_PROCESS_QUERY_LIMITED, False, pid)
    if not process:
        return None
    try:
        info = _ProcessBasicInformation()
        returned = wintypes.ULONG(0)
        status = ntdll.NtQueryInformationProcess(
            process, 0, ctypes.byref(info), ctypes.sizeof(info), ctypes.byref(returned)
        )
        if status != 0:
            return None
        return int(info.InheritedFromUniqueProcessId or 0)
    finally:
        kernel.CloseHandle(process)
