# SPDX-License-Identifier: MIT
"""The pure model of several repositories: colours, tooltip, menu, commands, schedule, notices,
icon bitmap. No disk, no process, no window; the clock is a number."""

from __future__ import annotations

from dataclasses import replace

import pytest

from nbp_git_safe import fleet
from nbp_git_safe.fleet import (
    ERROR,
    LOCKED,
    MISSING,
    UNLOCKED,
    Color,
    MenuItem,
    MenuSettings,
    RepoState,
)

NOW = 1_000_000.0
HOUR = 3600.0


def state(
    status: str = UNLOCKED,
    *,
    key: str = "a" * 24,
    name: str = "repo",
    left: float | None = 5 * HOUR,
    **kw: object,
) -> RepoState:
    expires = NOW + left if (status == UNLOCKED and left is not None) else None
    return RepoState(
        key=key,
        index=1,
        name=name,
        path=f"/x/{name}",
        status=status,
        expires_at=expires,
        **kw,  # type: ignore[arg-type]
    )


def keyed(n: int, **kw: object) -> RepoState:
    kw.setdefault("name", f"r{n}")
    return state(key=f"{n:024x}", **kw)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- colour table

COLOR_CASES = [
    ("none", [], Color.GRAY),
    ("one unlocked", [state()], Color.GREEN),
    ("all unlocked", [keyed(1), keyed(2)], Color.GREEN),
    ("one locked", [keyed(1), keyed(2, status=LOCKED)], Color.YELLOW),
    ("all locked", [keyed(1, status=LOCKED)], Color.YELLOW),
    ("less than an hour left", [keyed(1, left=HOUR - 1)], Color.YELLOW),
    ("exactly an hour left is fine", [keyed(1, left=HOUR)], Color.GREEN),
    ("folder missing", [keyed(1), keyed(2, status=MISSING)], Color.YELLOW),
    ("broken repository", [keyed(1, status=ERROR)], Color.RED),
    ("doctor problem", [keyed(1, problems=2)], Color.RED),
    ("doctor clean", [keyed(1, problems=0)], Color.GREEN),
    ("doctor not run yet", [keyed(1, problems=None)], Color.GREEN),
    ("vault diverged", [keyed(1, divergent=True)], Color.RED),
    ("pending, young", [keyed(1, pending=3, pending_since=NOW - 60)], Color.GREEN),
    ("pending, old", [keyed(1, pending=3, pending_since=NOW - 1800)], Color.RED),
    ("pending counted but no time", [keyed(1, pending=3)], Color.GREEN),
    ("old time but nothing pending", [keyed(1, pending=0, pending_since=NOW - 9999)], Color.GREEN),
    ("red beats yellow", [keyed(1, status=LOCKED), keyed(2, problems=1)], Color.RED),
    ("locked with a problem is red", [keyed(1, status=LOCKED, problems=1)], Color.RED),
    ("unlocked without expiry known", [keyed(1, left=None)], Color.GREEN),
    (
        "operation error alone is not red",
        [keyed(1, error="key-command", status=LOCKED)],
        Color.YELLOW,
    ),
]


@pytest.mark.parametrize(
    ("label", "states", "expected"), COLOR_CASES, ids=[c[0] for c in COLOR_CASES]
)
def test_icon_colour_rules(label: str, states: list[RepoState], expected: Color) -> None:
    assert fleet.aggregate_color(states, NOW) == expected


def test_colour_thresholds_are_parameters() -> None:
    assert fleet.aggregate_color([keyed(1, left=2 * HOUR)], NOW, low=3 * HOUR) == Color.YELLOW
    old = keyed(1, pending=1, pending_since=NOW - 100)
    assert fleet.aggregate_color([old], NOW, pending_grace=50) == Color.RED
    assert fleet.aggregate_color([old], NOW, pending_grace=500) == Color.GREEN


def test_remaining_is_never_negative_and_only_for_unlocked() -> None:
    assert state(left=-5).remaining(NOW) == 0.0
    assert state(LOCKED).remaining(NOW) is None


# ------------------------------------------------------------------------------ text

REMAINING_CASES = [
    (-5, "<1m"),
    (0, "<1m"),
    (59, "<1m"),
    (60, "1m"),
    (45 * 60, "45m"),
    (3599, "59m"),
    (3600, "1h 00m"),
    (5 * 3600 + 12 * 60, "5h 12m"),
    (23 * 3600 + 59 * 60, "23h 59m"),
    (24 * 3600, "1d 0h"),
    (2 * 86400 + 3 * 3600 + 59 * 60, "2d 3h"),
]


@pytest.mark.parametrize(("seconds", "text"), REMAINING_CASES)
def test_format_remaining(seconds: float, text: str) -> None:
    assert fleet.format_remaining(seconds) == text


def test_tooltip_summaries() -> None:
    assert "no repositories" in fleet.tooltip([], NOW)
    text = fleet.tooltip([keyed(1), keyed(2, status=LOCKED), keyed(3, left=1500)], NOW)
    assert text == "nbp-git-safe: 2 unlocked, 1 locked; next expiry 25m"
    sick = fleet.tooltip([keyed(1, problems=1), keyed(2, status=ERROR)], NOW)
    assert "1 unlocked" in sick and "1 unavailable" in sick and "2 need attention" in sick


def test_tooltip_fits_the_windows_limit() -> None:
    many = [keyed(i, problems=1, left=60 * i) for i in range(1, 400)]
    assert len(fleet.tooltip(many, NOW)) <= fleet.TOOLTIP_MAX


# ------------------------------------------------------------------------------ menu


def find(items: tuple[MenuItem, ...], command_id: str) -> MenuItem:
    for item in items:
        if item.id == command_id:
            return item
        for child in item.children:
            if child.id == command_id:
                return child
    raise AssertionError(command_id)


def test_empty_menu_explains_itself_and_has_the_global_items() -> None:
    menu = fleet.build_menu([], NOW)
    assert menu[0].label == "No repositories registered" and not menu[0].enabled
    ids = fleet.menu_ids(menu)
    assert {"all:unlock", "all:lock", "all:seal", "app:quit", "set:toggle-push"} <= set(ids)
    assert "app:autostart" not in ids  # not supported unless the front end says so


def test_row_labels_and_repo_submenu() -> None:
    a, b = keyed(1, name="alpha"), keyed(2, name="beta", status=LOCKED, auto_unlock=True)
    menu = fleet.build_menu([a, b], NOW)
    assert menu[0].label == "alpha: unlocked, 5h 00m left"
    assert menu[1].label == "beta: locked"
    sub_a = {c.id.split(":")[2]: c for c in menu[0].children}
    sub_b = {c.id.split(":")[2]: c for c in menu[1].children}
    assert not sub_a["unlock"].enabled and sub_a["lock"].enabled and sub_a["seal"].enabled
    assert sub_b["unlock"].enabled and not sub_b["lock"].enabled and not sub_b["seal"].enabled
    assert sub_b["toggle-autounlock"].checked and not sub_a["toggle-autounlock"].checked
    assert sub_a["open-folder"].enabled


def test_missing_and_error_rows() -> None:
    gone = keyed(1, status=MISSING)
    broken = keyed(2, status=ERROR, name="odd")
    menu = fleet.build_menu([gone, broken], NOW)
    assert menu[0].label == "r1: folder not found" and menu[1].label == "odd: error"
    sub = {c.id.split(":")[2]: c for c in menu[0].children}
    assert not sub["open-folder"].enabled and not sub["unlock"].enabled
    sub = {c.id.split(":")[2]: c for c in menu[1].children}
    assert not sub["unlock"].enabled  # a broken repository cannot be unlocked from the menu


def test_busy_repositories_cannot_start_another_operation() -> None:
    busy = keyed(1, busy="sealing")
    menu = fleet.build_menu([busy], NOW)
    assert menu[0].label.endswith("(sealing...)")
    assert all(
        not c.enabled for c in menu[0].children if c.id.split(":")[2] in ("unlock", "lock", "seal")
    )
    assert not find(menu, "all:unlock").enabled


def test_label_shows_pending_problems_divergence_and_last_error() -> None:
    row = fleet.row_label(
        keyed(1, pending=2, problems=1, divergent=True, error="push-offline"), "r1", NOW
    )
    assert (
        row
        == "r1: unlocked, 5h 00m left, 2 unsealed, 1 problem(s), vault diverged, last: push-offline"
    )


def test_duplicate_folder_names_get_numbers() -> None:
    names = fleet.display_names([keyed(1, name="app"), keyed(2, name="app"), keyed(3, name="x")])
    assert names == ["app", "app (2)", "x"]


def test_settings_menu_reflects_the_configuration() -> None:
    settings = MenuSettings(
        seal_minutes=45, seal_push=True, unlock_at_login=True, autostart=True, config_error="bad"
    )
    menu = fleet.build_menu([], NOW, settings)
    assert "Configuration problem" in menu[0].label and not menu[0].enabled
    submenu = next(i for i in menu if i.label == "Settings").children
    intervals = {c.id: c for c in submenu if c.id.startswith("set:seal-interval")}
    assert list(intervals) == [f"set:seal-interval:{n}" for n in (5, 15, 30, 45, 60)]
    assert [i for i, c in intervals.items() if c.checked] == ["set:seal-interval:45"]
    assert find(submenu, "set:toggle-push").checked
    assert find(submenu, "set:toggle-unlock-at-login").checked
    assert find(menu, "app:autostart").checked
    off = fleet.build_menu([], NOW, MenuSettings(autostart=False))
    assert not find(off, "app:autostart").checked


def test_every_menu_id_parses_and_ids_are_unique() -> None:
    states = [keyed(1), keyed(2, status=LOCKED)]
    ids = fleet.menu_ids(fleet.build_menu(states, NOW, MenuSettings(autostart=False)))
    assert len(ids) == len(set(ids))
    for command_id in ids:
        assert fleet.parse_command(command_id) is not None, command_id


COMMANDS = [
    ("repo:" + "a" * 24 + ":unlock", fleet.Command("repo", "unlock", "a" * 24)),
    (
        "repo:" + "0" * 24 + ":toggle-autounlock",
        fleet.Command("repo", "toggle-autounlock", "0" * 24),
    ),
    ("all:seal", fleet.Command("all", "seal")),
    ("set:seal-interval:30", fleet.Command("set", "seal-interval", value="30")),
    ("set:toggle-push", fleet.Command("set", "toggle-push")),
    ("app:quit", fleet.Command("app", "quit")),
]
BAD_COMMANDS = [
    "",
    "repo",
    "repo:short:unlock",
    "repo:" + "A" * 24 + ":unlock",  # upper case is not a key we make
    "repo:" + "g" * 24 + ":unlock",
    "repo:" + "a" * 24 + ":format-disk",
    "repo:" + "a" * 24 + ":unlock:extra",
    "all:format",
    "all:",
    "set:seal-interval",
    "set:seal-interval:abc",
    "set:seal-interval:-5",
    "set:nope",
    "app:quit:now",
    "run:calc.exe",
    "../../etc/passwd",
    "all:seal\n",
]


@pytest.mark.parametrize(("text", "expected"), COMMANDS)
def test_parse_command(text: str, expected: fleet.Command) -> None:
    assert fleet.parse_command(text) == expected


@pytest.mark.parametrize("text", BAD_COMMANDS)
def test_parse_command_rejects_everything_else(text: str) -> None:
    assert fleet.parse_command(text) is None


# ---------------------------------------------------------------------------- schedule


def test_schedule_runs_jobs_at_their_interval() -> None:
    s = fleet.Schedule({"refresh": 30, "seal": 900}, 0.0)
    assert s.due(0.0) == [] and s.due(29.9) == []
    assert s.due(30.0) == ["refresh"]
    assert s.due(31.0) == []  # running: never started twice
    s.done("refresh", 31.0)
    assert s.due(60.9) == [] and s.due(61.0) == ["refresh"]
    s.done("refresh", 61.5)
    assert s.due(900.0) == ["refresh", "seal"]
    assert s.running("seal")


def test_schedule_immediately_flag_and_trigger() -> None:
    s = fleet.Schedule({"a": 10, "b": 10}, 100.0, immediately=["b"])
    assert s.due(100.0) == ["b"]
    assert s.trigger("a") is True
    assert s.trigger("a") is False and s.trigger("b") is False  # both running
    s.done("a", 105.0)
    assert s.due(114.9) == [] and s.due(115.0) == ["a"]


def test_schedule_has_no_catch_up_burst_after_a_long_sleep() -> None:
    s = fleet.Schedule({"seal": 900}, 0.0)
    assert s.due(900.0) == ["seal"]
    s.done("seal", 900.0)
    # the laptop slept for ten hours: one run now, not forty
    assert s.due(900.0 + 36000) == ["seal"]
    s.done("seal", 900.0 + 36000)
    assert s.due(900.0 + 36000 + 1) == []


def test_schedule_survives_a_clock_that_goes_back() -> None:
    s = fleet.Schedule({"seal": 900}, 10_000.0)
    # the clock jumped back a day: the job must not wait a day
    assert s.due(10_000.0 - 86_400) == []
    assert s.due(10_000.0 - 86_400 + 900) == ["seal"]


def test_schedule_interval_change_and_validation() -> None:
    s = fleet.Schedule({"seal": 3600}, 0.0)
    s.set_interval("seal", 60, 10.0)
    assert s.due(69.9) == [] and s.due(70.0) == ["seal"]
    with pytest.raises(ValueError):
        fleet.Schedule({"x": 0}, 0.0)
    with pytest.raises(ValueError):
        s.set_interval("seal", -1, 0.0)


def test_schedule_interval_change_while_running_applies_after_done() -> None:
    s = fleet.Schedule({"seal": 100}, 0.0)
    assert s.due(100.0) == ["seal"]
    s.set_interval("seal", 5, 101.0)
    s.done("seal", 102.0)
    assert s.due(106.9) == [] and s.due(107.0) == ["seal"]


# ---------------------------------------------------------------------------- notices


def notices(tracker: fleet.NoticeTracker, states: list[RepoState], now: float = NOW):
    return tracker.update(states, now, warn_expiry_minutes=30, warn_pending_minutes=30)


def test_expiry_notice_fires_once_per_unlock() -> None:
    t = fleet.NoticeTracker()
    assert notices(t, [keyed(1, left=2 * HOUR)]) == []
    close = keyed(1, left=29 * 60)
    first = notices(t, [close])
    assert len(first) == 1 and first[0].level == "warning" and "r1" in first[0].text
    assert notices(t, [close], NOW + 60) == []  # same unlock: not again
    # unlocked again (a new expiry): warned again when it gets close
    later = NOW + 9 * HOUR
    renewed = replace(keyed(1), expires_at=later + 20 * 60)
    assert len(notices(t, [renewed], later)) == 1


def test_expiry_notice_is_off_with_zero_and_ignores_locked() -> None:
    t = fleet.NoticeTracker()
    near = keyed(1, left=60)
    assert t.update([near], NOW, warn_expiry_minutes=0, warn_pending_minutes=0) == []
    assert notices(t, [keyed(2, status=LOCKED)]) == []


def test_pending_notice_once_per_episode() -> None:
    t = fleet.NoticeTracker()
    young = keyed(1, pending=2, pending_since=NOW - 600)
    assert notices(t, [young]) == []
    old = keyed(1, pending=2, pending_since=NOW - 31 * 60)
    got = notices(t, [old])
    assert len(got) == 1 and "2 protected file(s)" in got[0].text and "31m" in got[0].text
    assert notices(t, [old]) == []
    cleared = keyed(1, pending=0)
    assert notices(t, [cleared]) == []
    again = keyed(1, pending=1, pending_since=NOW + 100)
    assert len(notices(t, [again], NOW + 100 + 40 * 60)) == 1  # a new episode


def test_error_notice_once_per_code_and_resets() -> None:
    t = fleet.NoticeTracker()
    bad = keyed(1, error="key-command", status=LOCKED)
    got = notices(t, [bad])
    assert len(got) == 1 and got[0].level == "error"
    assert notices(t, [bad]) == []
    assert len(notices(t, [keyed(1, error="push-offline", status=LOCKED)])) == 1
    assert notices(t, [keyed(1, status=LOCKED)]) == []
    assert len(notices(t, [bad])) == 1  # failing again after a success is news


def test_tracker_forgets_repositories_that_left() -> None:
    t = fleet.NoticeTracker()
    notices(t, [keyed(1, left=60, error="x")])
    notices(t, [])
    assert t._expiry == set() and t._pending == set() and t._errors == {}


# ----------------------------------------------------------------------------- icon


@pytest.mark.parametrize("color", list(Color))
def test_icon_bitmap_has_the_expected_colour_and_transparent_corners(color: Color) -> None:
    size = 32
    pixels = fleet.render_icon_bgra(color, size)
    assert len(pixels) == size * size * 4
    r, g, b = fleet.ICON_RGB[color]

    def px(x: int, y: int) -> tuple[int, int, int, int]:
        at = (y * size + x) * 4
        return pixels[at + 2], pixels[at + 1], pixels[at], pixels[at + 3]

    assert px(size // 2, size // 2) == (r, g, b, 255)  # the middle is the pure colour
    assert px(0, 0)[3] == 0 and px(size - 1, size - 1)[3] == 0 and px(0, size - 1)[3] == 0
    rim_r, rim_g, rim_b, rim_a = px(size // 2, 2)
    assert rim_a == 255 and (rim_r, rim_g, rim_b) == (r * 3 // 4, g * 3 // 4, b * 3 // 4)
    opaque = sum(1 for i in range(3, len(pixels), 4) if pixels[i] == 255)
    assert 0.5 * size * size < opaque < size * size  # a disc, not a square


def test_the_four_colours_are_distinct_and_deterministic() -> None:
    bitmaps = {c: fleet.render_icon_bgra(c, 16) for c in Color}
    assert len(set(bitmaps.values())) == 4
    assert bitmaps[Color.RED] == fleet.render_icon_bgra(Color.RED, 16)
    with pytest.raises(ValueError):
        fleet.render_icon_bgra(Color.RED, 4)
