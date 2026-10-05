# SPDX-License-Identifier: MIT
"""The tray controller with fake operations, an injected clock and inline or manual workers: no
window, no git, no agent. What the real operations do is covered by the integration tests."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from nbp_git_safe import fleet, fleetops, registry, trayconfig
from nbp_git_safe.config import Config
from nbp_git_safe.fleet import Color
from nbp_git_safe.fleetops import AgentView, DeepCheck, Outcome, RepoHandle
from nbp_git_safe.traycontroller import CommandResult, InlineWorker, TrayController
from nbp_git_safe.traylog import TrayLog

T0 = 1_700_000_000.0


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class ManualWorker:
    """Collects jobs; ``run_all`` runs them (so a test can look at the state in between)."""

    def __init__(self) -> None:
        self.jobs: list[Callable[[], None]] = []

    def submit(self, job: Callable[[], None]) -> None:
        self.jobs.append(job)

    def run_all(self) -> None:
        while self.jobs:
            self.jobs.pop(0)()


@dataclass
class FakeOps:
    """Stands in for the ``fleetops`` module."""

    agents: dict[str, AgentView] = field(default_factory=dict)
    configs: dict[str, Config] = field(default_factory=dict)
    broken: dict[str, str] = field(default_factory=dict)  # path -> HandleError code
    deep: dict[str, DeepCheck] = field(default_factory=dict)
    calls: list[tuple[str, Any]] = field(default_factory=list)
    unlock_outcome: str = "ok"
    seal_kind: str = "ok"
    seal_code: str = "sealed"
    boom: set[str] = field(default_factory=set)
    clock: Clock = field(default_factory=Clock)
    ttl: float = 8 * 3600

    # the module-level helpers the controller also uses
    HandleError = fleetops.HandleError

    def open_handle(self, path: str, index: int, flags: object = None) -> RepoHandle:
        self.calls.append(("open", path))
        if path in self.broken:
            raise fleetops.HandleError(self.broken[path], "x")
        name = fleetops.short_name(path)
        key = f"{abs(hash(('k', path))):024x}"[-24:]
        cfg = self.configs.get(path, Config())
        return RepoHandle(index, Path(path), name, None, None, cfg, key)  # type: ignore[arg-type]

    def read_agent(self, handle: RepoHandle) -> AgentView:
        self.calls.append(("read", handle.index))
        return self.agents.get(str(handle.path), AgentView("locked"))

    def unlock_all(
        self, handles: Sequence[RepoHandle], on_outcome: Callable[[Outcome], None] | None = None
    ) -> list[Outcome]:
        self.calls.append(("unlock", tuple(h.name for h in handles)))
        if "unlock" in self.boom:
            raise RuntimeError("secret detail that must not be logged")
        out = []
        for h in handles:
            if self.unlock_outcome == "ok":
                self.agents[str(h.path)] = AgentView("unlocked", self.clock.now + self.ttl, "kid")
                o = Outcome(h.index, h.name, "ok", "unlocked", "unlocked")
            else:
                o = Outcome(h.index, h.name, "failed", "no", "key-command")
            out.append(o)
            if on_outcome:
                on_outcome(o)
        return out

    def lock_one(self, handle: RepoHandle) -> Outcome:
        self.calls.append(("lock", handle.name))
        self.agents[str(handle.path)] = AgentView("locked")
        return Outcome(handle.index, handle.name, "ok", "locked", "locked")

    def seal_one(self, handle: RepoHandle, *, push: bool = False) -> Outcome:
        self.calls.append(("seal", handle.name, push))
        if "seal" in self.boom:
            raise RuntimeError("secret detail that must not be logged")
        return Outcome(
            handle.index, handle.name, self.seal_kind, "m", self.seal_code, {"sealed": 2}
        )

    def deep_check(self, handle: RepoHandle) -> DeepCheck:
        self.calls.append(("deep", handle.name))
        if "deep" in self.boom:
            raise RuntimeError("boom")
        return self.deep.get(str(handle.path), DeepCheck(0, False, None))

    def set_auto_unlock(self, handle: RepoHandle, enabled: bool) -> None:
        self.calls.append(("autounlock", handle.name, enabled))
        self.configs[str(handle.path)] = Config(auto_unlock=enabled)

    def classify(self, exc: BaseException) -> tuple[str, str]:  # pragma: no cover - not used
        return fleetops.classify(exc)

    short_name = staticmethod(fleetops.short_name)

    def count(self, kind: str) -> int:
        return sum(1 for c in self.calls if c[0] == kind)


class Rig:
    """A controller wired to fakes. ``paths`` is the registry content."""

    def __init__(self, tmp_path: Path, *paths: str, config: trayconfig.TrayConfig | None = None):
        self.clock = Clock()
        self.ops = FakeOps(clock=self.clock)
        self.paths = [str(tmp_path / p) for p in paths]
        for p in self.paths:
            Path(p).mkdir(exist_ok=True)
        self.config = config or trayconfig.TrayConfig()
        self.config_error: str | None = None
        self.config_saved: list[dict[str, object]] = []
        self.wakes = 0
        self.opened: list[Path] = []
        self.autostart_state: bool | None = None
        self.log_path = tmp_path / "tray.log"
        self.unlock_worker: Any = InlineWorker()
        self.work_worker: Any = InlineWorker()
        self.build()

    def build(self) -> TrayController:
        def update(**changes: object) -> trayconfig.TrayConfig:
            if "boom" in changes:
                raise trayconfig.TrayConfigError("nope")
            self.config_saved.append(dict(changes))
            merged = {**vars(self.config), **changes}
            self.config = trayconfig.validate(merged)
            return self.config

        self.controller = TrayController(
            clock=self.clock,
            load_registry=lambda: registry.Loaded(
                entries=[registry.Entry(p, 1) for p in self.paths]
            ),
            load_config=lambda: (self.config, self.config_error),
            update_config=update,
            ops=self.ops,
            log=TrayLog(self.log_path),
            unlock_worker=self.unlock_worker,
            work_worker=self.work_worker,
            autostart_get=lambda: self.autostart_state,
            autostart_set=self._set_autostart,
            open_folder=self.opened.append,
            open_config=lambda: self.opened.append(Path("config")),
            wake=self._wake,
        )
        return self.controller

    def _set_autostart(self, on: bool) -> None:
        self.autostart_state = on

    def _wake(self) -> None:
        self.wakes += 1

    def tick(self, seconds: float = 0.0) -> None:
        self.clock.advance(seconds)
        self.controller.tick()

    def keys(self) -> list[str]:
        return [s.key for s in self.controller.view().states]

    def cmd(self, action: str, index: int | None = None) -> CommandResult:
        if index is None:
            return self.controller.command(action)
        return self.controller.command(f"repo:{self.keys()[index]}:{action}")

    def color(self) -> Color:
        return self.controller.view().color

    def states(self) -> dict[str, fleet.RepoState]:
        return {s.name: s for s in self.controller.view().states}


# -------------------------------------------------------------------------------- tests


def test_starts_gray_with_no_repositories_then_reflects_the_registry(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.controller.start()
    assert rig.color() == Color.GRAY and "no repositories" in rig.controller.view().tooltip
    rig.paths = [str(tmp_path / "a"), str(tmp_path / "b")]
    for p in rig.paths:
        Path(p).mkdir()
    rig.tick(31)  # the refresh job is due immediately and then every 30 s
    assert rig.color() == Color.YELLOW  # both locked
    assert set(rig.states()) == {"a", "b"}
    assert rig.states()["a"].status == fleet.LOCKED


def test_colours_follow_unlock_lock_and_expiry(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a", "b")
    rig.tick()
    assert rig.color() == Color.YELLOW
    rig.controller.command("all:unlock")
    assert rig.color() == Color.GREEN
    assert rig.ops.calls.count(("unlock", ("a", "b"))) == 1
    rig.cmd("lock", 0)
    assert rig.color() == Color.YELLOW and rig.states()["a"].status == fleet.LOCKED
    rig.controller.command("all:unlock")
    rig.clock.advance(8 * 3600 - 1800)  # 30 minutes left on both
    rig.tick(31)
    assert rig.color() == Color.YELLOW  # less than an hour: yellow


def test_a_single_repository_unlock_names_only_that_repository(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a", "b")
    rig.tick()
    rig.cmd("unlock", 1)
    assert ("unlock", ("b",)) in rig.ops.calls
    assert rig.states()["b"].status == fleet.UNLOCKED and rig.states()["a"].status == fleet.LOCKED


def test_unlock_failure_sets_a_code_and_one_balloon(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a")
    rig.ops.unlock_outcome = "fail"
    rig.tick()
    rig.cmd("unlock", 0)
    assert rig.states()["a"].error == "key-command"
    first = rig.controller.drain_notices()
    assert [n.level for n in first] == ["error"] and "key-command" in first[0].text
    rig.cmd("unlock", 0)
    assert rig.controller.drain_notices() == []  # the same failure is not shouted twice
    rig.ops.unlock_outcome = "ok"
    rig.cmd("unlock", 0)
    assert rig.states()["a"].error == ""


def test_an_unlock_already_in_progress_is_not_started_twice(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a")
    manual = ManualWorker()
    rig.controller._unlock_worker = manual
    rig.tick()
    rig.cmd("unlock", 0)
    rig.cmd("unlock", 0)
    rig.controller.command("all:unlock")
    assert len(manual.jobs) == 1
    assert rig.states()["a"].busy == "unlocking"
    assert "(unlocking...)" in rig.controller.view().menu[0].label
    manual.run_all()
    assert rig.states()["a"].busy == "" and rig.states()["a"].status == fleet.UNLOCKED
    assert rig.ops.count("unlock") == 1


def test_nothing_blocks_while_an_unlock_waits(tmp_path: Path) -> None:
    """The unlock lane is separate: ticks and views work while it is occupied."""
    rig = Rig(tmp_path, "a")
    rig.controller._unlock_worker = ManualWorker()
    rig.tick()
    rig.cmd("unlock", 0)
    rig.tick(31)  # refresh jobs keep running on the other lane
    assert rig.controller.view().states[0].busy == "unlocking"
    assert rig.ops.count("read") >= 2


# ------------------------------------------------------------------------------- sealing


def test_periodic_seal_runs_only_for_unlocked_repositories(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a", "b")
    rig.tick()
    rig.cmd("unlock", 0)
    assert rig.ops.count("seal") == 0
    rig.tick(15 * 60)
    seals = [c for c in rig.ops.calls if c[0] == "seal"]
    assert seals == [("seal", "a", False)]  # b is locked and is never unlocked by the seal
    assert ("unlock", ("b",)) not in rig.ops.calls
    rig.tick(15 * 60)
    assert rig.ops.count("seal") == 2


def test_seal_interval_and_push_come_from_the_configuration(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a", config=trayconfig.TrayConfig(sealIntervalMinutes=5, sealPush=True))
    rig.tick()
    rig.cmd("unlock", 0)
    rig.tick(4 * 60 + 59)
    assert rig.ops.count("seal") == 0
    rig.tick(1)
    assert ("seal", "a", True) in rig.ops.calls


def test_seal_failure_is_recorded_and_notified_once(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a")
    rig.tick()
    rig.cmd("unlock", 0)
    rig.ops.seal_kind, rig.ops.seal_code = "failed", "vault"
    rig.tick(15 * 60)
    assert rig.states()["a"].error == "vault"
    assert [n.level for n in rig.controller.drain_notices()] == ["error"]
    rig.tick(15 * 60)
    assert rig.controller.drain_notices() == []
    rig.ops.seal_kind, rig.ops.seal_code = "ok", "sealed"
    rig.tick(15 * 60)
    assert rig.states()["a"].error == ""


def test_a_push_that_could_not_reach_origin_is_a_warning_code_not_a_failure(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a", config=trayconfig.TrayConfig(sealPush=True))
    rig.tick()
    rig.cmd("unlock", 0)
    rig.ops.seal_kind, rig.ops.seal_code = "warn", "push-offline"
    rig.tick(15 * 60)
    assert rig.states()["a"].error == "push-offline"
    assert rig.color() == Color.GREEN  # offline is not a red condition


def test_a_manual_seal_marks_busy_and_clears_pending(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a")
    rig.tick()
    rig.cmd("unlock", 0)
    rig.ops.deep[rig.paths[0]] = DeepCheck(0, False, 4)
    rig.tick(10 * 60)  # the deep job runs
    assert rig.states()["a"].pending == 4 and rig.states()["a"].pending_since == rig.clock.now
    manual = ManualWorker()
    rig.controller._work_worker = manual
    rig.cmd("seal", 0)
    assert rig.states()["a"].busy == "sealing"
    manual.run_all()
    assert rig.states()["a"].pending == 0 and rig.states()["a"].busy == ""


def test_pending_files_turn_the_icon_red_and_warn_after_the_grace(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a", config=trayconfig.TrayConfig(sealIntervalMinutes=1440))
    rig.tick()
    rig.cmd("unlock", 0)
    rig.ops.deep[rig.paths[0]] = DeepCheck(0, False, 3)
    rig.tick(600)
    assert rig.color() == Color.GREEN and rig.controller.drain_notices() == []
    rig.tick(30 * 60)
    assert rig.color() == Color.RED
    notes = rig.controller.drain_notices()
    assert any("not sealed" in n.text for n in notes)
    rig.tick(60)
    assert not any("not sealed" in n.text for n in rig.controller.drain_notices())


def test_doctor_problems_and_divergence_turn_the_icon_red(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a", "b")
    rig.tick()
    rig.controller.command("all:unlock")
    rig.ops.deep[rig.paths[0]] = DeepCheck(2, False, 0)
    rig.tick(600)
    assert rig.color() == Color.RED and rig.states()["a"].problems == 2
    rig.ops.deep[rig.paths[0]] = DeepCheck(0, False, 0)
    rig.ops.deep[rig.paths[1]] = DeepCheck(0, True, 0)
    rig.tick(600)
    assert rig.color() == Color.RED and rig.states()["b"].divergent
    rig.ops.deep[rig.paths[1]] = DeepCheck(0, False, 0)
    rig.tick(600)
    assert rig.color() == Color.GREEN


def test_expiry_warning_balloon_once_per_unlock(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a")
    rig.ops.ttl = 45 * 60
    rig.tick()
    rig.cmd("unlock", 0)
    assert rig.controller.drain_notices() == []
    rig.tick(16 * 60)
    got = rig.controller.drain_notices()
    assert len(got) == 1 and "locks in" in got[0].text and got[0].level == "warning"
    rig.tick(30)
    assert rig.controller.drain_notices() == []


# ------------------------------------------------------------------- unavailable repositories


def test_missing_and_broken_repositories(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "good", "gone", "odd")
    rig.ops.broken[rig.paths[1]] = "missing"
    rig.ops.broken[rig.paths[2]] = "config"
    rig.tick()
    states = rig.states()
    assert states["gone"].status == fleet.MISSING and states["odd"].status == fleet.ERROR
    assert rig.color() == Color.RED  # the broken one decides
    rig.ops.broken.pop(rig.paths[2])
    rig.tick(10 * 60)  # a deep refresh reopens what could not be opened
    assert rig.states()["odd"].status == fleet.LOCKED
    assert rig.color() == Color.YELLOW


def test_a_broken_repository_is_not_retried_on_every_refresh(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "odd")
    rig.ops.broken[rig.paths[0]] = "config"
    rig.tick()
    opens = rig.ops.count("open")
    for _ in range(5):
        rig.tick(31)
    assert rig.ops.count("open") == opens


def test_a_missing_folder_that_returns_is_picked_up(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a")
    rig.ops.broken[rig.paths[0]] = "missing"
    rig.tick()
    assert rig.states()["a"].status == fleet.MISSING
    rig.ops.broken.clear()
    rig.tick(31)
    assert rig.states()["a"].status == fleet.LOCKED


def test_a_folder_that_vanishes_after_it_was_opened_becomes_missing(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a")
    rig.tick()
    assert rig.states()["a"].status == fleet.LOCKED
    Path(rig.paths[0]).rmdir()
    rig.tick(31)
    assert rig.states()["a"].status == fleet.MISSING and rig.color() == Color.YELLOW
    Path(rig.paths[0]).mkdir()
    rig.tick(31)
    assert rig.states()["a"].status == fleet.LOCKED


def test_refresh_reads_agents_without_reopening_repositories(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a", "b", "c")
    rig.tick()
    opens = rig.ops.count("open")
    for _ in range(4):
        rig.tick(31)
    assert rig.ops.count("open") == opens == 3  # config read once; later cycles only read agents
    assert rig.ops.count("read") >= 15


def test_entries_leaving_the_registry_disappear(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a", "b")
    rig.tick()
    rig.cmd("unlock", 0)
    rig.paths.pop(0)
    rig.tick(31)
    assert set(rig.states()) == {"b"}
    rig.controller.command("repo:" + "f" * 24 + ":unlock")  # a stale menu id is ignored
    assert rig.ops.count("unlock") == 1


def test_worktree_entries_of_one_repository_are_listed_once(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "main", "linked")
    original = rig.ops.open_handle

    def same_repo(path: str, index: int, flags: object = None) -> RepoHandle:
        handle = original(path, index)
        return RepoHandle(handle.index, handle.path, handle.name, None, None, handle.cfg, "e" * 24)  # type: ignore[arg-type]

    rig.ops.open_handle = same_repo  # type: ignore[method-assign]
    rig.tick()
    assert list(rig.states()) == ["main"]
    opens = rig.ops.count("open")
    rig.tick(31)
    assert rig.ops.count("open") == opens  # the duplicate is remembered, not reopened


# ----------------------------------------------------------------- settings and other commands


def test_settings_commands_write_the_configuration_and_reschedule(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a")
    rig.tick()
    rig.controller.command("set:seal-interval:5")
    assert rig.config_saved[-1] == {"sealIntervalMinutes": 5}
    rig.controller.command("set:toggle-push")
    rig.controller.command("set:toggle-unlock-at-login")
    assert rig.config.sealPush is True and rig.config.unlockAtLogin is True
    rig.controller.command("set:toggle-push")
    assert rig.config.sealPush is False
    view = rig.controller.view()
    settings = next(i for i in view.menu if i.label == "Settings").children
    checked = {c.id for c in settings if c.checked}
    assert checked == {"set:seal-interval:5", "set:toggle-unlock-at-login"}
    rig.cmd("unlock", 0)
    rig.tick(5 * 60)
    assert rig.ops.count("seal") == 1  # the new interval applies at once


def test_a_bad_setting_is_reported_not_raised(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    result = rig.controller.command("set:seal-interval:99999")
    assert "between" in result.message
    assert rig.controller.command("set:seal-interval:abc").message == "unknown command"


def test_configuration_errors_show_in_the_menu_and_defaults_apply(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.config_error = "sealIntervalMinutes: must be between 1 and 1440"
    rig.build()
    menu = rig.controller.view().menu
    assert "Configuration problem" in menu[0].label


def test_config_changes_made_in_the_file_are_picked_up(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a")
    rig.tick()
    rig.cmd("unlock", 0)
    rig.config = trayconfig.TrayConfig(sealIntervalMinutes=2)
    rig.tick(60)  # the config job runs every minute
    rig.tick(2 * 60)
    assert rig.ops.count("seal") >= 1


def test_open_folder_edit_config_and_autostart(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a")
    rig.autostart_state = False
    rig.tick()
    rig.cmd("open-folder", 0)
    assert rig.opened == [Path(rig.paths[0])]
    rig.controller.command("set:edit-config")
    assert rig.opened[-1] == Path("config")
    assert rig.autostart_state is False
    rig.controller.command("app:autostart")
    assert rig.autostart_state is True
    assert next(i for i in rig.controller.view().menu if i.id == "app:autostart").checked
    rig.controller.command("app:autostart")
    assert rig.autostart_state is False


def test_autostart_is_absent_when_unsupported(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.tick()
    assert "app:autostart" not in fleet.menu_ids(rig.controller.view().menu)
    rig.controller.command("app:autostart")  # does nothing


def test_toggle_auto_unlock_changes_the_repository_configuration(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a")
    rig.tick()
    rig.cmd("toggle-autounlock", 0)
    assert ("autounlock", "a", True) in rig.ops.calls
    assert rig.states()["a"].auto_unlock is True
    rig.cmd("toggle-autounlock", 0)
    assert rig.states()["a"].auto_unlock is False


def test_quit_and_unknown_commands(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a")
    rig.tick()
    assert rig.controller.command("app:quit").quit is True
    for bad in ("", "nonsense", "repo:zz:unlock", "all:format-disk", "../x"):
        result = rig.controller.command(bad)
        assert result.quit is False and result.message == "unknown command"
    assert rig.ops.count("unlock") == 0


# ------------------------------------------------------------------------ start and failures


def test_unlock_at_login_unlocks_everything_once(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a", "b", config=trayconfig.TrayConfig(unlockAtLogin=True))
    rig.controller.start()
    assert rig.ops.calls.count(("unlock", ("a", "b"))) == 1
    rig.tick()
    rig.tick(31)
    assert rig.ops.count("unlock") == 1
    assert rig.color() == Color.GREEN


def test_unlock_at_login_is_off_by_default(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a")
    rig.controller.start()
    rig.tick()
    assert rig.ops.count("unlock") == 0


@pytest.mark.parametrize("job", ["unlock", "seal", "deep"])
def test_an_exception_in_a_job_becomes_a_log_line_not_a_crash(tmp_path: Path, job: str) -> None:
    rig = Rig(tmp_path, "a")
    rig.tick()
    rig.ops.boom.add(job)
    rig.cmd("unlock", 0)
    rig.tick(15 * 60)
    rig.tick(10 * 60)
    rig.controller.view()
    text = rig.log_path.read_text(encoding="ascii")
    assert "error" in text and "secret detail" not in text


def test_log_has_codes_and_counts_only(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "customer-report-folder")
    rig.tick()
    rig.cmd("unlock", 0)
    rig.tick(15 * 60)
    text = rig.log_path.read_text(encoding="ascii")
    assert "customer" not in text and str(tmp_path) not in text
    assert "repo=1" in text and "seal" in text and "unlock" in text


def test_the_controller_never_holds_a_key(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a")
    rig.tick()
    rig.cmd("unlock", 0)
    for name, value in vars(rig.controller).items():
        assert not isinstance(value, bytes | bytearray), name


def test_wake_is_called_when_state_changes(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a")
    rig.tick()
    assert rig.wakes > 0
    before = rig.wakes
    rig.cmd("unlock", 0)
    assert rig.wakes > before
