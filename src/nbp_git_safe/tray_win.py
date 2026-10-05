# SPDX-License-Identifier: MIT
"""Windows notification-area front end (``nbp-git-safe tray``), ``ctypes`` only: no dependency.

A thin layer over ``traycontroller`` (which holds every decision): a hidden top-level window that
owns the notification icon, ``Shell_NotifyIconW`` for the icon, tooltip and balloons,
``TrackPopupMenu`` for the menu, ``WM_TIMER`` to drive the controller, and icons drawn in memory
(``fleet.render_icon_bgra`` + ``CreateIconIndirect``; no image file). One instance per user
session (a named mutex). Worker threads never touch a window: they post ``WM_WAKE``.

The structures, constants and the pure helpers load on any platform (so they can be tested
anywhere); every call into Windows goes through ``_api()``, which raises elsewhere.
"""

from __future__ import annotations

import contextlib
import ctypes
import hashlib
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from nbp_git_safe import agent, autostart, fleet, gitutil, trayconfig, traycontroller
from nbp_git_safe.traylog import LOG_NAME, TrayLog

# window messages and flags (winuser.h, shellapi.h)
WM_NULL = 0x0000
WM_DESTROY = 0x0002
WM_TIMER = 0x0113
WM_LBUTTONUP = 0x0202
WM_RBUTTONUP = 0x0205
WM_CONTEXTMENU = 0x007B
WM_APP = 0x8000
WM_TRAY = WM_APP + 1  # callback of the notification icon
WM_WAKE = WM_APP + 2  # a worker thread says "something changed"
TIMER_ID = 1
TIMER_MS = 5000
NIM_ADD, NIM_MODIFY, NIM_DELETE = 0, 1, 2
NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_INFO = 0x1, 0x2, 0x4, 0x10
NIIF_INFO, NIIF_WARNING, NIIF_ERROR = 0x1, 0x2, 0x3
MF_STRING, MF_GRAYED, MF_CHECKED, MF_POPUP, MF_SEPARATOR = 0x0, 0x1, 0x8, 0x10, 0x800
TPM_RIGHTBUTTON, TPM_NONOTIFY, TPM_RETURNCMD = 0x2, 0x80, 0x100
SM_CXSMICON = 49
ERROR_ALREADY_EXISTS = 183
ICON_ID = 1
MENU_LABEL_MAX = 90
FIRST_MENU_ID = 1000

LRESULT = ctypes.c_ssize_t
HANDLE = ctypes.c_void_p


class wt:
    """The few Win32 type names used here, spelled with ``ctypes`` primitives. ``ctypes.wintypes``
    is not imported so that this module loads on every platform."""

    DWORD = ctypes.c_uint32
    UINT = ctypes.c_uint32
    WORD = ctypes.c_uint16
    ATOM = ctypes.c_uint16
    BOOL = ctypes.c_int
    WCHAR = ctypes.c_wchar
    LPCWSTR = ctypes.c_wchar_p
    WPARAM = ctypes.c_size_t  # UINT_PTR
    LPARAM = ctypes.c_ssize_t  # LONG_PTR

    class POINT(ctypes.Structure):
        _fields_ = (("x", ctypes.c_long), ("y", ctypes.c_long))

    class MSG(ctypes.Structure):
        _fields_ = (
            ("hwnd", ctypes.c_void_p),
            ("message", ctypes.c_uint32),
            ("wParam", ctypes.c_size_t),
            ("lParam", ctypes.c_ssize_t),
            ("time", ctypes.c_uint32),
            ("pt", ctypes.c_long * 2),
        )


class GUID(ctypes.Structure):
    _fields_ = (
        ("Data1", wt.DWORD),
        ("Data2", wt.WORD),
        ("Data3", wt.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    )


class NOTIFYICONDATAW(ctypes.Structure):
    """The Vista-and-later layout of ``NOTIFYICONDATAW``."""

    _fields_ = (
        ("cbSize", wt.DWORD),
        ("hWnd", HANDLE),
        ("uID", wt.UINT),
        ("uFlags", wt.UINT),
        ("uCallbackMessage", wt.UINT),
        ("hIcon", HANDLE),
        ("szTip", wt.WCHAR * 128),
        ("dwState", wt.DWORD),
        ("dwStateMask", wt.DWORD),
        ("szInfo", wt.WCHAR * 256),
        ("uTimeout", wt.UINT),  # a union with uVersion
        ("szInfoTitle", wt.WCHAR * 64),
        ("dwInfoFlags", wt.DWORD),
        ("guidItem", GUID),
        ("hBalloonIcon", HANDLE),
    )


class WNDCLASSEXW(ctypes.Structure):
    _fields_ = (
        ("cbSize", wt.UINT),
        ("style", wt.UINT),
        ("lpfnWndProc", HANDLE),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", HANDLE),
        ("hIcon", HANDLE),
        ("hCursor", HANDLE),
        ("hbrBackground", HANDLE),
        ("lpszMenuName", wt.LPCWSTR),
        ("lpszClassName", wt.LPCWSTR),
        ("hIconSm", HANDLE),
    )


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = (
        ("biSize", wt.DWORD),
        ("biWidth", ctypes.c_long),
        ("biHeight", ctypes.c_long),
        ("biPlanes", wt.WORD),
        ("biBitCount", wt.WORD),
        ("biCompression", wt.DWORD),
        ("biSizeImage", wt.DWORD),
        ("biXPelsPerMeter", ctypes.c_long),
        ("biYPelsPerMeter", ctypes.c_long),
        ("biClrUsed", wt.DWORD),
        ("biClrImportant", wt.DWORD),
    )


class ICONINFO(ctypes.Structure):
    _fields_ = (
        ("fIcon", wt.BOOL),
        ("xHotspot", wt.DWORD),
        ("yHotspot", wt.DWORD),
        ("hbmMask", HANDLE),
        ("hbmColor", HANDLE),
    )


# ------------------------------------------------------------------- pure helpers (any platform)


def menu_label(text: str) -> str:
    """A menu string: ``&`` doubled (a folder name must not become an accelerator), control
    characters dropped, long text shortened."""
    clean = "".join(ch for ch in text if ch.isprintable()).replace("&", "&&")
    return clean if len(clean) <= MENU_LABEL_MAX else clean[: MENU_LABEL_MAX - 3] + "..."


def fit(text: str, limit: int) -> str:
    """``text`` cut to ``limit`` UTF-16 code units minus the terminator (a fixed ``szInfo``...)."""
    return text if len(text) < limit else text[: limit - 1]


def mutex_name(sid: str) -> str:
    """Per-user, per-session name of the single-instance mutex."""
    return "Local\\nbp-git-safe-tray-" + hashlib.sha256(sid.encode()).hexdigest()[:16]


def flatten_menu(
    items: tuple[fleet.MenuItem, ...], first_id: int = FIRST_MENU_ID
) -> dict[int, str]:
    """``{numeric menu id: command id}`` for every actionable item of the tree, numbered in
    drawing order (``TrackPopupMenu`` returns the number; the command id stays a string)."""
    mapping: dict[int, str] = {}

    def walk(level: tuple[fleet.MenuItem, ...]) -> None:
        for item in level:
            if item.children:
                walk(item.children)
            elif item.id and not item.separator:
                mapping[first_id + len(mapping)] = item.id

    walk(items)
    return mapping


# ------------------------------------------------------------------------------- Windows calls

_apis: list[Any] = []


class _Api:
    def __init__(self) -> None:
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)  # type: ignore[attr-defined]
        self.gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)  # type: ignore[attr-defined]
        self.shell32 = ctypes.WinDLL("shell32", use_last_error=True)  # type: ignore[attr-defined]
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        self.WNDPROC = ctypes.WINFUNCTYPE(  # type: ignore[attr-defined]
            LRESULT, HANDLE, wt.UINT, wt.WPARAM, wt.LPARAM
        )
        self._declare()

    def _declare(self) -> None:
        u, g, s, k = self.user32, self.gdi32, self.shell32, self.kernel32
        u.RegisterClassExW.argtypes = [ctypes.POINTER(WNDCLASSEXW)]
        u.RegisterClassExW.restype = wt.ATOM
        u.UnregisterClassW.argtypes = [wt.LPCWSTR, HANDLE]
        u.CreateWindowExW.argtypes = [
            wt.DWORD,
            wt.LPCWSTR,
            wt.LPCWSTR,
            wt.DWORD,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            HANDLE,
            HANDLE,
            HANDLE,
            HANDLE,
        ]
        u.CreateWindowExW.restype = HANDLE
        u.DefWindowProcW.argtypes = [HANDLE, wt.UINT, wt.WPARAM, wt.LPARAM]
        u.DefWindowProcW.restype = LRESULT
        u.DestroyWindow.argtypes = [HANDLE]
        u.PostMessageW.argtypes = [HANDLE, wt.UINT, wt.WPARAM, wt.LPARAM]
        u.PostQuitMessage.argtypes = [ctypes.c_int]
        u.GetMessageW.argtypes = [
            ctypes.POINTER(wt.MSG),
            HANDLE,
            wt.UINT,
            wt.UINT,
        ]
        u.PeekMessageW.argtypes = [
            ctypes.POINTER(wt.MSG),
            HANDLE,
            wt.UINT,
            wt.UINT,
            wt.UINT,
        ]
        u.TranslateMessage.argtypes = [ctypes.POINTER(wt.MSG)]
        u.DispatchMessageW.argtypes = [ctypes.POINTER(wt.MSG)]
        u.DispatchMessageW.restype = LRESULT
        u.SetTimer.argtypes = [HANDLE, ctypes.c_size_t, wt.UINT, HANDLE]
        u.SetTimer.restype = ctypes.c_size_t
        u.KillTimer.argtypes = [HANDLE, ctypes.c_size_t]
        u.CreatePopupMenu.restype = HANDLE
        u.AppendMenuW.argtypes = [HANDLE, wt.UINT, ctypes.c_size_t, wt.LPCWSTR]
        u.TrackPopupMenu.argtypes = [
            HANDLE,
            wt.UINT,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            HANDLE,
            HANDLE,
        ]
        u.DestroyMenu.argtypes = [HANDLE]
        u.GetMenuItemCount.argtypes = [HANDLE]
        u.GetCursorPos.argtypes = [ctypes.POINTER(wt.POINT)]
        u.SetForegroundWindow.argtypes = [HANDLE]
        u.RegisterWindowMessageW.argtypes = [wt.LPCWSTR]
        u.GetSystemMetrics.argtypes = [ctypes.c_int]
        u.GetDC.argtypes = [HANDLE]
        u.GetDC.restype = HANDLE
        u.ReleaseDC.argtypes = [HANDLE, HANDLE]
        u.CreateIconIndirect.argtypes = [ctypes.POINTER(ICONINFO)]
        u.CreateIconIndirect.restype = HANDLE
        u.DestroyIcon.argtypes = [HANDLE]
        g.CreateDIBSection.argtypes = [
            HANDLE,
            ctypes.c_void_p,
            wt.UINT,
            ctypes.POINTER(ctypes.c_void_p),
            HANDLE,
            wt.DWORD,
        ]
        g.CreateDIBSection.restype = HANDLE
        g.CreateBitmap.argtypes = [
            ctypes.c_int,
            ctypes.c_int,
            wt.UINT,
            wt.UINT,
            ctypes.c_void_p,
        ]
        g.CreateBitmap.restype = HANDLE
        g.DeleteObject.argtypes = [HANDLE]
        s.Shell_NotifyIconW.argtypes = [wt.DWORD, ctypes.POINTER(NOTIFYICONDATAW)]
        k.CreateMutexW.argtypes = [HANDLE, wt.BOOL, wt.LPCWSTR]
        k.CreateMutexW.restype = HANDLE
        k.CloseHandle.argtypes = [HANDLE]
        k.GetModuleHandleW.argtypes = [wt.LPCWSTR]
        k.GetModuleHandleW.restype = HANDLE


def _api() -> _Api:
    if sys.platform != "win32":
        raise RuntimeError("the Windows tray runs on Windows only")
    if not _apis:
        _apis.append(_Api())
    return _apis[0]  # type: ignore[no-any-return]


def acquire_single_instance(name: str) -> int | None:
    """Create the named mutex. Returns its handle, or ``None`` when another instance holds it."""
    api = _api()
    handle = api.kernel32.CreateMutexW(None, False, name)
    if not handle:
        return None
    if ctypes.get_last_error() == ERROR_ALREADY_EXISTS:  # type: ignore[attr-defined]
        api.kernel32.CloseHandle(handle)
        return None
    return int(handle)


def make_icon(bgra: bytes, size: int) -> int:
    """An ``HICON`` from a top-down BGRA bitmap (the colour bitmap carries the alpha)."""
    api = _api()
    header = BITMAPINFOHEADER()
    header.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    header.biWidth, header.biHeight = size, -size  # negative: top-down
    header.biPlanes, header.biBitCount, header.biCompression = 1, 32, 0
    bits = ctypes.c_void_p()
    hdc = api.user32.GetDC(None)
    color = api.gdi32.CreateDIBSection(hdc, ctypes.byref(header), 0, ctypes.byref(bits), None, 0)
    api.user32.ReleaseDC(None, hdc)
    if not color or not bits.value:
        raise OSError("could not create the icon bitmap")
    ctypes.memmove(bits, bgra, len(bgra))
    stride = ((size + 15) // 16) * 2  # a 1-bpp mask row is a multiple of 16 bits
    zeros = (ctypes.c_ubyte * (stride * size))()
    mask = api.gdi32.CreateBitmap(size, size, 1, 1, zeros)
    info = ICONINFO(True, 0, 0, mask, color)
    icon = api.user32.CreateIconIndirect(ctypes.byref(info))
    api.gdi32.DeleteObject(color)
    api.gdi32.DeleteObject(mask)
    if not icon:
        raise OSError("could not create the icon")
    return int(icon)


def small_icon_size() -> int:
    return max(16, _api().user32.GetSystemMetrics(SM_CXSMICON))


class TrayApp:
    """The window, the icon and the menu. ``create`` then ``run`` (or ``pump`` in a test)."""

    CLASS_NAME = "NbpGitSafeTray"

    def __init__(self, controller: traycontroller.TrayController) -> None:
        self.controller = controller
        self.hwnd: int | None = None
        self._icons: dict[fleet.Color, int] = {}
        self._shown: tuple[fleet.Color, str] | None = None
        self._taskbar_created = 0
        self._wndproc: Any = None
        self._class_registered = False
        self.quitting = False
        self.icon_added = False

    # ------------------------------------------------------------------ creation

    def create(self) -> bool:
        """Register the class, create the hidden window and add the icon. ``False`` when there is
        no desktop to put an icon on (a service session): nothing is left behind."""
        api = _api()
        u = api.user32
        self._wndproc = api.WNDPROC(self._on_message)
        module = api.kernel32.GetModuleHandleW(None)
        cls = WNDCLASSEXW()
        cls.cbSize = ctypes.sizeof(WNDCLASSEXW)
        cls.lpfnWndProc = ctypes.cast(self._wndproc, ctypes.c_void_p).value
        cls.hInstance = module
        cls.lpszClassName = self.CLASS_NAME
        if not u.RegisterClassExW(ctypes.byref(cls)):
            return False
        self._class_registered = True
        self._taskbar_created = u.RegisterWindowMessageW("TaskbarCreated")
        self.hwnd = u.CreateWindowExW(
            0, self.CLASS_NAME, "nbp-git-safe", 0, 0, 0, 0, 0, None, None, module, None
        )
        if not self.hwnd:
            self.destroy()
            return False
        size = small_icon_size()
        for color in fleet.Color:
            self._icons[color] = make_icon(fleet.render_icon_bgra(color, size), size)
        u.SetTimer(self.hwnd, TIMER_ID, TIMER_MS, None)
        if not self._add_icon(self.controller.view()):
            self.destroy()
            return False
        return True

    def destroy(self) -> None:
        api = _api()
        if self.hwnd:
            with contextlib.suppress(Exception):
                api.user32.KillTimer(self.hwnd, TIMER_ID)
            if self.icon_added:
                self._notify(NIM_DELETE, NIF_MESSAGE, None, "")
                self.icon_added = False
            api.user32.DestroyWindow(self.hwnd)
            self.hwnd = None
        for icon in self._icons.values():
            api.user32.DestroyIcon(icon)
        self._icons.clear()
        if self._class_registered:
            api.user32.UnregisterClassW(self.CLASS_NAME, api.kernel32.GetModuleHandleW(None))
            self._class_registered = False

    # ------------------------------------------------------------------ icon and balloons

    def _data(self, flags: int, icon: int | None, tip: str) -> NOTIFYICONDATAW:
        data = NOTIFYICONDATAW()
        data.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        data.hWnd = self.hwnd
        data.uID = ICON_ID
        data.uFlags = flags
        data.uCallbackMessage = WM_TRAY
        data.hIcon = icon
        data.szTip = fit(tip, 128)
        return data

    def _notify(self, message: int, flags: int, icon: int | None, tip: str) -> bool:
        return bool(
            _api().shell32.Shell_NotifyIconW(message, ctypes.byref(self._data(flags, icon, tip)))
        )

    def _add_icon(self, view: traycontroller.View) -> bool:
        ok = self._notify(
            NIM_ADD,
            NIF_MESSAGE | NIF_ICON | NIF_TIP,
            self._icons[view.color],
            view.tooltip,
        )
        self.icon_added = ok
        self._shown = (view.color, view.tooltip) if ok else None
        return ok

    def apply_view(self, view: traycontroller.View) -> None:
        """Update the icon and the tooltip when (and only when) they changed."""
        if not self.icon_added or self._shown == (view.color, view.tooltip):
            return
        flags = NIF_ICON | NIF_TIP
        if self._notify(NIM_MODIFY, flags, self._icons[view.color], view.tooltip):
            self._shown = (view.color, view.tooltip)

    def balloon(self, notice: fleet.Notice) -> None:
        if not self.icon_added:
            return
        data = self._data(NIF_INFO, None, "")
        data.szInfoTitle = fit(notice.title, 64)
        data.szInfo = fit(notice.text, 256)
        data.dwInfoFlags = {"error": NIIF_ERROR, "warning": NIIF_WARNING}.get(
            notice.level, NIIF_INFO
        )
        _api().shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(data))

    def sync(self) -> None:
        """Pull the controller's view: icon, tooltip and any balloons that are due."""
        view = self.controller.view()
        self.apply_view(view)
        for notice in self.controller.drain_notices():
            self.balloon(notice)

    # ------------------------------------------------------------------ menu

    def build_menu(self, items: tuple[fleet.MenuItem, ...]) -> tuple[int, dict[int, str]]:
        """A popup menu for ``items`` and ``{menu id: command id}``. The caller destroys it."""
        u = _api().user32
        mapping = flatten_menu(items)
        ids = {command: number for number, command in mapping.items()}

        def fill(handle: int, level: tuple[fleet.MenuItem, ...]) -> None:
            for item in level:
                if item.separator:
                    u.AppendMenuW(handle, MF_SEPARATOR, 0, None)
                    continue
                flags = (
                    MF_STRING
                    | (0 if item.enabled else MF_GRAYED)
                    | (MF_CHECKED if item.checked else 0)
                )
                if item.children:
                    sub = u.CreatePopupMenu()
                    fill(sub, item.children)
                    u.AppendMenuW(handle, flags | MF_POPUP, sub, menu_label(item.label))
                else:
                    u.AppendMenuW(handle, flags, ids.get(item.id, 0), menu_label(item.label))

        root = u.CreatePopupMenu()
        fill(root, items)
        return int(root), mapping

    def show_menu(self) -> None:
        api = _api()
        u = api.user32
        self.controller.tick()
        view = self.controller.view()
        root, mapping = self.build_menu(view.menu)
        point = wt.POINT()
        u.GetCursorPos(ctypes.byref(point))
        u.SetForegroundWindow(self.hwnd)  # or the menu will not close when you click elsewhere
        chosen = u.TrackPopupMenu(
            root,
            TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
            point.x,
            point.y,
            0,
            self.hwnd,
            None,
        )
        u.PostMessageW(self.hwnd, WM_NULL, 0, 0)
        u.DestroyMenu(root)
        command = mapping.get(chosen)
        if command is not None and self.controller.command(command).quit:
            self.quitting = True
            u.DestroyWindow(self.hwnd)

    # ------------------------------------------------------------------ messages

    def _on_message(self, hwnd: int, message: int, wparam: int, lparam: int) -> int:
        u = _api().user32
        try:
            if message == WM_TIMER and wparam == TIMER_ID:
                self.controller.tick()
                self.sync()
                return 0
            if message == WM_WAKE:
                self.sync()
                return 0
            if message == WM_TRAY:
                if lparam in (WM_RBUTTONUP, WM_LBUTTONUP, WM_CONTEXTMENU):
                    self.show_menu()
                return 0
            if self._taskbar_created and message == self._taskbar_created:
                self.icon_added = False  # Explorer restarted: the icon must be added again
                self._add_icon(self.controller.view())
                return 0
            if message == WM_DESTROY:
                if self.icon_added:
                    self._notify(NIM_DELETE, NIF_MESSAGE, None, "")
                    self.icon_added = False
                u.PostQuitMessage(0)
                return 0
        except Exception:  # a callback must never raise into Windows
            self.controller.report("window", None, "unexpected")
            return 0
        return int(u.DefWindowProcW(hwnd, message, wparam, lparam))

    def wake(self) -> None:
        """Thread-safe: ask the UI thread to redraw."""
        if self.hwnd:
            _api().user32.PostMessageW(self.hwnd, WM_WAKE, 0, 0)

    def pump(self) -> int:
        """Handle the messages waiting now (a test's way to run the loop). Returns how many."""
        u = _api().user32
        msg = wt.MSG()
        count = 0
        while u.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):  # PM_REMOVE
            u.TranslateMessage(ctypes.byref(msg))
            u.DispatchMessageW(ctypes.byref(msg))
            count += 1
        return count

    def run_loop(self) -> None:
        u = _api().user32
        msg = wt.MSG()
        while u.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            u.TranslateMessage(ctypes.byref(msg))
            u.DispatchMessageW(ctypes.byref(msg))


# ---------------------------------------------------------------------------------- entry point


def _open_folder(path: Path) -> None:
    os.startfile(path)  # type: ignore[attr-defined]  # noqa: S606 - opens Explorer on a folder


def _open_config() -> None:
    root = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or r"C:\Windows"
    subprocess.Popen(  # noqa: S603 - fixed program, the path of our own file
        [str(Path(root) / "System32" / "notepad.exe"), str(trayconfig.config_path())],
        creationflags=gitutil.CREATE_NO_WINDOW,
    )


def _autostart_get() -> bool | None:
    return autostart.status().installed


def _autostart_set(on: bool) -> None:
    if on:
        autostart.install()
    else:
        autostart.remove()


def _ensure_std_streams() -> None:
    """``pythonw`` has no console: ``sys.stdout`` and ``sys.stderr`` are ``None``."""
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "w", encoding="ascii"))  # noqa: SIM115


def _make_log() -> TrayLog:
    try:
        base = agent.private_root(create=True)
    except (agent.InsecureStateError, OSError):
        return TrayLog(None)
    return TrayLog(base / LOG_NAME if base else None)


def run() -> int:
    """``nbp-git-safe tray``: returns when the user chooses Quit."""
    from nbp_git_safe import winsec

    _ensure_std_streams()
    gitutil.hide_child_windows()
    with contextlib.suppress(Exception):  # sharper icons and menus on scaled displays
        _api().user32.SetProcessDPIAware()
    handle = acquire_single_instance(mutex_name(winsec.current_user_sid()))
    if handle is None:
        sys.stderr.write("nbp-git-safe: the tray is already running\n")
        return 0
    app: TrayApp | None = None

    def wake() -> None:
        if app is not None:
            app.wake()

    controller = traycontroller.TrayController(
        log=_make_log(),
        autostart_get=_autostart_get,
        autostart_set=_autostart_set,
        open_folder=_open_folder,
        open_config=_open_config,
        wake=wake,
    )
    app = TrayApp(controller)
    if not app.create():
        sys.stderr.write("nbp-git-safe: could not create the notification icon\n")
        _api().kernel32.CloseHandle(handle)
        return 1
    controller.start()
    app.wake()
    try:
        app.run_loop()
    finally:
        with contextlib.suppress(Exception):
            app.destroy()
        _api().kernel32.CloseHandle(handle)
    return 0
