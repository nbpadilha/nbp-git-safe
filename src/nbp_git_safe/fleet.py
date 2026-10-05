# SPDX-License-Identifier: MIT
"""Pure model of several repositories, for the tray and for any other front end.

Nothing here touches the disk, a process, the network or a window; the clock is always a
parameter. It is the layer a macOS or Linux front end reuses unchanged (see ``docs/TRAY.md``):

* ``RepoState``: what is known about one repository at one moment.
* ``aggregate_color`` / ``tooltip``: the icon colour and the short summary.
* ``build_menu`` / ``parse_command``: the menu as data (``MenuItem``) and the strict parser of the
  command ids it carries, so a front end only draws the tree and sends back the id that was chosen.
* ``Schedule``: periodic jobs with an injectable clock (no catch-up burst after a sleep).
* ``NoticeTracker``: which balloon notices are due, each one only once.
* ``render_icon_bgra``: the status circle as a BGRA bitmap, drawn in memory.
"""

from __future__ import annotations

import math
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

LOCKED, UNLOCKED, MISSING, ERROR = "locked", "unlocked", "missing", "error"
LOW_REMAINING = 3600.0  # an unlocked agent with less than this left makes the icon yellow
DEFAULT_PENDING_GRACE = 1800.0
TOOLTIP_MAX = 127  # Windows: 128 UTF-16 units including the terminator


class Color(StrEnum):
    GREEN = "green"
    YELLOW = "yellow"
    RED = "red"
    GRAY = "gray"


@dataclass(frozen=True)
class RepoState:
    """One registered repository. ``key`` is the agent's own repository key (stable, 24 hex);
    ``index`` the 1-based position in the registry (the only thing the log may name)."""

    key: str
    index: int
    name: str  # short folder name
    path: str
    status: str  # UNLOCKED, LOCKED, MISSING or ERROR
    expires_at: float | None = None
    auto_unlock: bool = False
    problems: int | None = None  # findings at level "problem" of the last doctor run
    divergent: bool = False  # the vault diverged from origin, or went back, or was replaced
    pending: int = 0  # protected files not sealed yet
    pending_since: float | None = None
    busy: str = ""  # an operation in progress ("unlocking", "sealing", ...)
    error: str = ""  # short code of the last failed operation ("" when none)

    def remaining(self, now: float) -> float | None:
        if self.status != UNLOCKED or self.expires_at is None:
            return None
        return max(0.0, self.expires_at - now)


def pending_too_long(state: RepoState, now: float, grace: float) -> bool:
    return (
        state.pending > 0
        and state.pending_since is not None
        and (now - state.pending_since >= grace)
    )


def needs_attention(state: RepoState, now: float, grace: float = DEFAULT_PENDING_GRACE) -> bool:
    """The red conditions: a broken repository, a doctor problem, a divergent vault, or protected
    files that stayed unsealed for longer than ``grace`` seconds."""
    return (
        state.status == ERROR
        or bool(state.problems)
        or state.divergent
        or pending_too_long(state, now, grace)
    )


def aggregate_color(
    states: Sequence[RepoState],
    now: float,
    *,
    low: float = LOW_REMAINING,
    pending_grace: float = DEFAULT_PENDING_GRACE,
) -> Color:
    """Gray: nothing registered. Red: any repository needs attention. Yellow: any is locked,
    missing, or unlocked with less than ``low`` seconds left. Green: all unlocked and healthy."""
    if not states:
        return Color.GRAY
    if any(needs_attention(s, now, pending_grace) for s in states):
        return Color.RED
    for state in states:
        if state.status in (LOCKED, MISSING):
            return Color.YELLOW
        remaining = state.remaining(now)
        if remaining is not None and remaining < low:
            return Color.YELLOW
    return Color.GREEN


def format_remaining(seconds: float) -> str:
    """``2d 3h``, ``5h 12m``, ``45m`` or ``<1m`` (never negative)."""
    total = max(0, int(seconds))
    if total < 60:
        return "<1m"
    minutes = total // 60
    if minutes < 60:
        return f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {minutes:02d}m"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h"


def tooltip(
    states: Sequence[RepoState], now: float, *, pending_grace: float = DEFAULT_PENDING_GRACE
) -> str:
    if not states:
        return "nbp-git-safe: no repositories registered"
    unlocked = [s for s in states if s.status == UNLOCKED]
    locked = sum(1 for s in states if s.status == LOCKED)
    parts = []
    if unlocked:
        parts.append(f"{len(unlocked)} unlocked")
    if locked:
        parts.append(f"{locked} locked")
    other = len(states) - len(unlocked) - locked
    if other:
        parts.append(f"{other} unavailable")
    text = "nbp-git-safe: " + ", ".join(parts)
    attention = sum(1 for s in states if needs_attention(s, now, pending_grace))
    if attention:
        text += f"; {attention} need attention"
    soonest = [r for s in unlocked if (r := s.remaining(now)) is not None]
    if soonest:
        text += f"; next expiry {format_remaining(min(soonest))}"
    return text if len(text) <= TOOLTIP_MAX else text[: TOOLTIP_MAX - 3] + "..."


# ---------------------------------------------------------------------------------- menu


@dataclass(frozen=True)
class MenuItem:
    id: str = ""
    label: str = ""
    enabled: bool = True
    checked: bool = False
    separator: bool = False
    children: tuple[MenuItem, ...] = ()


SEPARATOR = MenuItem(separator=True)


@dataclass(frozen=True)
class Command:
    """A parsed command id. ``scope``: ``repo`` (``key`` set), ``all``, ``set`` or ``app``."""

    scope: str
    action: str
    key: str = ""
    value: str = ""


REPO_ACTIONS = ("unlock", "lock", "seal", "open-folder", "toggle-autounlock")
ALL_ACTIONS = ("unlock", "lock", "seal")
SET_ACTIONS = ("seal-interval", "toggle-push", "toggle-unlock-at-login", "edit-config")
APP_ACTIONS = ("autostart", "quit")
_KEY_CHARS = frozenset("0123456789abcdef")


def parse_command(command_id: str) -> Command | None:
    """Strict parser of the ids ``build_menu`` produces; anything else is ``None``."""
    parts = command_id.split(":")
    if parts[0] == "repo" and len(parts) == 3:
        _, key, action = parts
        if len(key) == 24 and set(key) <= _KEY_CHARS and action in REPO_ACTIONS:
            return Command("repo", action, key)
    elif parts[0] == "all" and len(parts) == 2 and parts[1] in ALL_ACTIONS:
        return Command("all", parts[1])
    elif parts[0] == "set" and len(parts) in (2, 3) and parts[1] in SET_ACTIONS:
        value = parts[2] if len(parts) == 3 else ""
        if parts[1] == "seal-interval" and not (value.isascii() and value.isdigit()):
            return None
        return Command("set", parts[1], value=value)
    elif parts[0] == "app" and len(parts) == 2 and parts[1] in APP_ACTIONS:
        return Command("app", parts[1])
    return None


def display_names(states: Sequence[RepoState]) -> list[str]:
    """Folder names, with ``(2)``, ``(3)`` ... added to repeated ones so each row is distinct."""
    counts: dict[str, int] = {}
    names = []
    for state in states:
        counts[state.name] = counts.get(state.name, 0) + 1
        names.append(
            state.name if counts[state.name] == 1 else f"{state.name} ({counts[state.name]})"
        )
    return names


def row_label(state: RepoState, name: str, now: float) -> str:
    if state.status == UNLOCKED:
        remaining = state.remaining(now)
        text = "unlocked" + (
            f", {format_remaining(remaining)} left" if remaining is not None else ""
        )
    elif state.status == LOCKED:
        text = "locked"
    elif state.status == MISSING:
        text = "folder not found"
    else:
        text = "error"
    if state.pending:
        text += f", {state.pending} unsealed"
    if state.problems:
        text += f", {state.problems} problem(s)"
    if state.divergent:
        text += ", vault diverged"
    if state.error:
        text += f", last: {state.error}"
    if state.busy:
        text += f" ({state.busy}...)"
    return f"{name}: {text}"


@dataclass(frozen=True)
class MenuSettings:
    seal_minutes: int = 15
    seal_push: bool = False
    unlock_at_login: bool = False
    autostart: bool | None = None  # None: not supported on this platform
    autostart_label: str = "Start with Windows"
    config_error: str = ""


def _repo_submenu(state: RepoState) -> tuple[MenuItem, ...]:
    idle = not state.busy
    unlocked = state.status == UNLOCKED
    usable = state.status in (UNLOCKED, LOCKED)
    key = state.key
    return (
        MenuItem(f"repo:{key}:unlock", "Unlock", idle and usable and not unlocked),
        MenuItem(f"repo:{key}:lock", "Lock", idle and unlocked),
        MenuItem(f"repo:{key}:seal", "Seal now", idle and unlocked),
        MenuItem(f"repo:{key}:open-folder", "Open folder", state.status != MISSING),
        MenuItem(f"repo:{key}:toggle-autounlock", "Auto-unlock", usable, checked=state.auto_unlock),
    )


def build_menu(
    states: Sequence[RepoState],
    now: float,
    settings: MenuSettings = MenuSettings(),  # noqa: B008 - frozen, shared on purpose
    *,
    seal_choices: Collection[int] = (5, 15, 30, 60),
) -> tuple[MenuItem, ...]:
    items: list[MenuItem] = []
    if settings.config_error:
        items += [MenuItem("", "Configuration problem: defaults in use", False), SEPARATOR]
    if not states:
        items.append(MenuItem("", "No repositories registered", False))
    for state, name in zip(states, display_names(states), strict=True):
        items.append(MenuItem(label=row_label(state, name, now), children=_repo_submenu(state)))
    any_idle = any(not s.busy for s in states)
    items += [
        SEPARATOR,
        MenuItem("all:unlock", "Unlock all", any_idle),
        MenuItem("all:lock", "Lock all", any_idle),
        MenuItem("all:seal", "Seal all now", any_idle),
        SEPARATOR,
    ]
    choices = sorted(set(seal_choices) | {settings.seal_minutes})
    settings_menu = (
        *(
            MenuItem(
                f"set:seal-interval:{n}", f"Seal every {n} min", checked=n == settings.seal_minutes
            )
            for n in choices
        ),
        SEPARATOR,
        MenuItem("set:toggle-push", "Push when sealing", checked=settings.seal_push),
        MenuItem("set:toggle-unlock-at-login", "Unlock at login", checked=settings.unlock_at_login),
        MenuItem("set:edit-config", "Open configuration file"),
    )
    items.append(MenuItem(label="Settings", children=settings_menu))
    if settings.autostart is not None:
        items.append(
            MenuItem("app:autostart", settings.autostart_label, checked=settings.autostart)
        )
    items += [SEPARATOR, MenuItem("app:quit", "Quit")]
    return tuple(items)


def menu_ids(items: Sequence[MenuItem]) -> list[str]:
    """Every command id of a menu tree (a helper for front ends and tests)."""
    found: list[str] = []
    for item in items:
        if item.id:
            found.append(item.id)
        found += menu_ids(item.children)
    return found


# ------------------------------------------------------------------------------ schedule


class Schedule:
    """Periodic jobs driven by a clock the caller supplies.

    ``due(now)`` returns the names that should start now (in the order they were declared) and
    marks them running; ``done(name, now)`` schedules the next run ``interval`` seconds after the
    END of this one, so a long run, a laptop sleep or a clock that jumped never causes a burst of
    catch-up runs. A job still running is never started twice."""

    def __init__(
        self, intervals: Mapping[str, float], now: float, *, immediately: Collection[str] = ()
    ) -> None:
        for name, seconds in intervals.items():
            if seconds <= 0:
                raise ValueError(f"interval of {name} must be positive")
        self._intervals = dict(intervals)
        self._next = {n: (now if n in immediately else now + s) for n, s in intervals.items()}
        self._running: set[str] = set()

    def set_interval(self, name: str, seconds: float, now: float) -> None:
        if seconds <= 0:
            raise ValueError("interval must be positive")
        self._intervals[name] = seconds
        if name not in self._running:
            self._next[name] = min(self._next[name], now + seconds)

    def due(self, now: float) -> list[str]:
        out = []
        for name in self._intervals:
            # a clock that went backwards must not postpone a job for longer than its interval
            if name not in self._running and self._next[name] > now + self._intervals[name]:
                self._next[name] = now + self._intervals[name]
            if name not in self._running and now >= self._next[name]:
                self._running.add(name)
                out.append(name)
        return out

    def trigger(self, name: str) -> bool:
        """Start ``name`` out of turn (a menu command). False when it is already running."""
        if name in self._running:
            return False
        self._running.add(name)
        return True

    def done(self, name: str, now: float) -> None:
        self._running.discard(name)
        self._next[name] = now + self._intervals[name]

    def running(self, name: str) -> bool:
        return name in self._running


# ------------------------------------------------------------------------------- notices


@dataclass(frozen=True)
class Notice:
    title: str
    text: str
    level: str = "info"  # info, warning or error


class NoticeTracker:
    """Which balloon notices are due. Each condition produces one notice per occurrence: an expiry
    warning once per unlock, an unsealed-files warning once per episode, an error once per code."""

    def __init__(self) -> None:
        self._expiry: set[tuple[str, float]] = set()
        self._pending: set[tuple[str, float]] = set()
        self._errors: dict[str, str] = {}

    def update(
        self,
        states: Sequence[RepoState],
        now: float,
        *,
        warn_expiry_minutes: int,
        warn_pending_minutes: int,
    ) -> list[Notice]:
        notices: list[Notice] = []
        names = dict(zip((s.key for s in states), display_names(states), strict=True))
        live = set(names)
        for state in states:
            name = names[state.key]
            remaining = state.remaining(now)
            if (
                warn_expiry_minutes
                and remaining is not None
                and remaining > 0
                and remaining <= warn_expiry_minutes * 60
                and state.expires_at is not None
                and (state.key, state.expires_at) not in self._expiry
            ):
                self._expiry.add((state.key, state.expires_at))
                notices.append(
                    Notice(
                        "Key about to expire",
                        f"{name}: locks in {format_remaining(remaining)}",
                        "warning",
                    )
                )
            if (
                warn_pending_minutes
                and state.pending_since is not None
                and state.pending > 0
                and now - state.pending_since >= warn_pending_minutes * 60
                and (state.key, state.pending_since) not in self._pending
            ):
                self._pending.add((state.key, state.pending_since))
                notices.append(
                    Notice(
                        "Files not sealed",
                        f"{name}: {state.pending} protected file(s) not sealed for "
                        f"{format_remaining(now - state.pending_since)}",
                        "warning",
                    )
                )
            if state.error and self._errors.get(state.key) != state.error:
                self._errors[state.key] = state.error
                notices.append(Notice("Operation failed", f"{name}: {state.error}", "error"))
            elif not state.error:
                self._errors.pop(state.key, None)
        # forget repositories that left the registry (keys never accumulate)
        self._expiry = {k for k in self._expiry if k[0] in live}
        self._pending = {k for k in self._pending if k[0] in live}
        self._errors = {k: v for k, v in self._errors.items() if k in live}
        return notices


# ---------------------------------------------------------------------------------- icon

ICON_RGB: dict[Color, tuple[int, int, int]] = {
    Color.GREEN: (46, 160, 67),
    Color.YELLOW: (219, 171, 9),
    Color.RED: (207, 34, 46),
    Color.GRAY: (140, 140, 140),
}


def render_icon_bgra(color: Color, size: int = 32) -> bytes:
    """A filled circle in ``color`` with a darker rim and soft edges, as top-down BGRA bytes
    (``size * size * 4``). Pure arithmetic: no image file, no graphics library."""
    if size < 8:
        raise ValueError("an icon needs at least 8 pixels")
    red, green, blue = ICON_RGB[color]
    rim = (red * 3 // 4, green * 3 // 4, blue * 3 // 4)
    centre = (size - 1) / 2
    radius = size * 0.46
    rim_width = max(1.0, size / 12)
    out = bytearray(size * size * 4)
    for y in range(size):
        for x in range(size):
            distance = math.hypot(x - centre, y - centre)
            coverage = min(1.0, max(0.0, radius + 0.5 - distance))
            if coverage <= 0.0:
                continue
            r, g, b = rim if distance > radius - rim_width else (red, green, blue)
            at = (y * size + x) * 4
            out[at : at + 4] = bytes((b, g, r, round(255 * coverage)))
    return bytes(out)
