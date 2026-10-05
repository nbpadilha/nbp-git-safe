# SPDX-License-Identifier: MIT
"""The Windows front end. The pure helpers run everywhere; the smoke tests need a Windows session
with a desktop and a notification area and are skipped without one (a CI service session). They
add a real notification icon for a moment and remove it; nothing is shown that was not asked."""

from __future__ import annotations

import ctypes
import struct
import sys
import threading
from collections.abc import Iterator

import pytest

from nbp_git_safe import fleet, registry, tray_win, traycontroller
from nbp_git_safe.fleet import MenuItem

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="the tray is Windows only")


# --------------------------------------------------------------------------- any platform


def test_menu_labels_are_safe_for_a_menu() -> None:
    assert tray_win.menu_label("a&b") == "a&&b"  # a folder name must not become an accelerator
    assert tray_win.menu_label("tab\tand\nnewline") == "tabandnewline"
    long = tray_win.menu_label("x" * 500)
    assert len(long) == tray_win.MENU_LABEL_MAX and long.endswith("...")
    assert tray_win.menu_label("ünï©ode ok") == "ünï©ode ok"


def test_fit_leaves_room_for_the_terminator() -> None:
    assert tray_win.fit("abc", 128) == "abc"
    assert len(tray_win.fit("x" * 500, 128)) == 127
    assert len(tray_win.fit("y" * 128, 128)) == 127


def test_mutex_name_is_per_user_and_stable() -> None:
    one = tray_win.mutex_name("S-1-5-21-1-2-3-1001")
    assert one == tray_win.mutex_name("S-1-5-21-1-2-3-1001")
    assert one != tray_win.mutex_name("S-1-5-21-1-2-3-1002")
    assert one.startswith("Local\\nbp-git-safe-tray-") and "S-1-5" not in one


def test_flatten_menu_numbers_actionable_items_in_drawing_order() -> None:
    menu = (
        MenuItem(label="info", enabled=False),
        MenuItem(label="repo", children=(MenuItem("a:1", "one"), MenuItem("a:2", "two"))),
        fleet.SEPARATOR,
        MenuItem("b:1", "three"),
    )
    assert tray_win.flatten_menu(menu) == {1000: "a:1", 1001: "a:2", 1002: "b:1"}
    assert tray_win.flatten_menu(menu, 5) == {5: "a:1", 6: "a:2", 7: "b:1"}


def test_the_real_menu_flattens_to_parseable_unique_commands() -> None:
    state = fleet.RepoState("a" * 24, 1, "r", "/r", fleet.UNLOCKED, 10_000.0)
    menu = fleet.build_menu([state], 0.0, fleet.MenuSettings(autostart=True))
    mapping = tray_win.flatten_menu(menu)
    assert len(set(mapping.values())) == len(mapping)
    assert all(fleet.parse_command(c) is not None for c in mapping.values())


def test_the_module_loads_on_every_platform_and_refuses_calls_elsewhere() -> None:
    if sys.platform == "win32":
        pytest.skip("this is the non-Windows contract")
    with pytest.raises(RuntimeError, match="Windows only"):
        tray_win.acquire_single_instance("x")


@windows_only
@pytest.mark.skipif(struct.calcsize("P") != 8, reason="sizes below are the 64-bit ones")
def test_structure_sizes_match_the_windows_headers() -> None:
    assert ctypes.sizeof(tray_win.NOTIFYICONDATAW) == 976
    assert ctypes.sizeof(tray_win.WNDCLASSEXW) == 80
    assert ctypes.sizeof(tray_win.ICONINFO) == 32
    assert ctypes.sizeof(tray_win.BITMAPINFOHEADER) == 40
    assert tray_win.NOTIFYICONDATAW.szTip.size == 256  # 128 UTF-16 units


# ------------------------------------------------------------------------ Windows session


def quiet_controller(wake=lambda: None) -> traycontroller.TrayController:  # type: ignore[no-untyped-def]
    return traycontroller.TrayController(
        load_registry=lambda: registry.Loaded(),
        work_worker=traycontroller.InlineWorker(),
        unlock_worker=traycontroller.InlineWorker(),
        wake=wake,
    )


@pytest.fixture
def app() -> Iterator[tray_win.TrayApp]:
    if sys.platform != "win32":
        pytest.skip("the tray is Windows only")
    controller = quiet_controller()
    instance = tray_win.TrayApp(controller)
    if not instance.create():
        instance.destroy()
        pytest.skip("no desktop or notification area in this session")
    yield instance
    instance.destroy()


@windows_only
def test_single_instance_mutex() -> None:
    name = tray_win.mutex_name("S-1-5-test-" + "x" * 8)
    first = tray_win.acquire_single_instance(name)
    assert first
    try:
        assert tray_win.acquire_single_instance(name) is None  # the second instance would leave
    finally:
        tray_win._api().kernel32.CloseHandle(first)
    again = tray_win.acquire_single_instance(name)  # released: free again
    assert again
    tray_win._api().kernel32.CloseHandle(again)


@windows_only
def test_icons_are_created_for_all_four_colours(app: tray_win.TrayApp) -> None:
    assert set(app._icons) == set(fleet.Color)
    assert all(handle for handle in app._icons.values())
    assert len(set(app._icons.values())) == 4
    assert app.icon_added


@windows_only
def test_icon_tooltip_and_balloon_updates_do_not_raise(app: tray_win.TrayApp) -> None:
    view = app.controller.view()
    assert view.color == fleet.Color.GRAY
    green = traycontroller.View(fleet.Color.GREEN, "nbp-git-safe: 1 unlocked", view.menu, ())
    app.apply_view(green)
    assert app._shown == (fleet.Color.GREEN, "nbp-git-safe: 1 unlocked")
    app.apply_view(green)  # unchanged: nothing sent
    for level in ("info", "warning", "error"):
        app.balloon(fleet.Notice("Title " + "t" * 100, "Text " + "x" * 400, level))
    app.sync()
    assert app.pump() >= 0


@windows_only
def test_the_menu_is_built_as_a_native_menu(app: tray_win.TrayApp) -> None:
    state = fleet.RepoState("b" * 24, 1, "my&repo", "C:\\r", fleet.LOCKED)
    items = fleet.build_menu([state], 0.0, fleet.MenuSettings(autostart=False))
    handle, mapping = app.build_menu(items)
    try:
        api = tray_win._api()
        assert api.user32.GetMenuItemCount(handle) == len(items)
        assert len(mapping) == len(fleet.menu_ids(items))
    finally:
        api.user32.DestroyMenu(handle)


@windows_only
def test_the_message_loop_runs_wakes_and_quits_cleanly() -> None:
    """The whole lifecycle in a helper thread (a window belongs to the thread that made it):
    create, wake, timer, close, loop ends, icon removed."""
    ready = threading.Event()
    done = threading.Event()
    box: dict[str, object] = {}

    def run() -> None:
        controller = quiet_controller(wake=lambda: box["app"].wake())  # type: ignore[attr-defined]
        instance = tray_win.TrayApp(controller)
        box["app"] = instance
        if not instance.create():
            box["skip"] = True
            ready.set()
            instance.destroy()
            return
        ready.set()
        instance.run_loop()
        box["icon_after_loop"] = instance.icon_added
        instance.destroy()
        done.set()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert ready.wait(20)
    if box.get("skip"):
        thread.join(5)
        pytest.skip("no desktop or notification area in this session")
    app = box["app"]
    api = tray_win._api()
    assert api.user32.PostMessageW(app.hwnd, tray_win.WM_WAKE, 0, 0)  # type: ignore[attr-defined]
    assert api.user32.PostMessageW(app.hwnd, tray_win.WM_TIMER, tray_win.TIMER_ID, 0)  # type: ignore[attr-defined]
    assert api.user32.PostMessageW(app.hwnd, 0x0010, 0, 0)  # type: ignore[attr-defined]  # WM_CLOSE
    assert done.wait(20), "the message loop did not end"
    thread.join(5)
    assert box["icon_after_loop"] is False  # WM_DESTROY removed the icon
