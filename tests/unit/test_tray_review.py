# SPDX-License-Identifier: MIT
"""Tray controller behaviour found wrong by the security review: a push that hangs must not stop
the state from updating (own lane), a health check that raised must not leave the icon green, and
a configuration changed a moment ago must apply to the next unlock and push (no fake of git or of a
window: the same rig as ``test_traycontroller``)."""

from __future__ import annotations

from pathlib import Path

from nbp_git_safe import trayconfig
from nbp_git_safe.config import Config
from nbp_git_safe.fleet import Color
from nbp_git_safe.fleetops import AgentView
from tests.unit.test_traycontroller import ManualWorker, Rig


def push_rig(tmp_path: Path) -> tuple[Rig, ManualWorker]:
    rig = Rig(tmp_path, "a", config=trayconfig.TrayConfig(sealPush=True))
    lane = ManualWorker()
    rig.controller._push_worker = lane
    rig.tick()
    rig.cmd("unlock", 0)
    return rig, lane


def test_a_push_that_never_returns_does_not_stop_refresh_or_the_next_seal(tmp_path: Path) -> None:
    rig, lane = push_rig(tmp_path)
    rig.tick(15 * 60)  # the periodic seal runs; its push is queued on the push lane, not run
    assert rig.ops.count("seal") == 1 and rig.ops.count("push") == 0
    assert len(lane.jobs) == 1
    # the push is "hung" (its job never runs): everything else carries on
    rig.ops.agents[rig.paths[0]] = AgentView("locked")  # the agent went away meanwhile
    rig.tick(30)  # the refresh job
    assert rig.states()["a"].status == "locked"
    assert rig.color() == Color.YELLOW
    rig.ops.agents[rig.paths[0]] = AgentView("unlocked", rig.clock.now + 8 * 3600, "kid")
    rig.tick(15 * 60)  # the next periodic seal still runs, and does not queue a second push
    assert rig.ops.count("seal") == 2 and len(lane.jobs) == 1
    lane.run_all()
    assert rig.ops.count("push") == 1


def test_a_push_timeout_is_a_short_code_and_a_discreet_balloon(tmp_path: Path) -> None:
    rig, lane = push_rig(tmp_path)
    rig.ops.push_kind, rig.ops.push_code = "warn", "push-timeout"
    rig.tick(15 * 60)
    lane.run_all()
    assert rig.states()["a"].error == "push-timeout"
    assert rig.color() == Color.GREEN  # an unreachable origin is not a red condition
    notices = rig.controller.drain_notices()
    assert [(n.title, n.level) for n in notices] == [("Push did not complete", "warning")]
    rig.tick(15 * 60)
    lane.run_all()
    assert rig.controller.drain_notices() == []  # once per code, not once per cycle
    rig.ops.push_kind, rig.ops.push_code = "ok", "pushed"
    rig.tick(15 * 60)
    lane.run_all()
    assert rig.states()["a"].error == ""


def test_a_push_that_raises_is_logged_and_the_lane_goes_on(tmp_path: Path) -> None:
    rig, lane = push_rig(tmp_path)
    rig.ops.boom.add("push")
    rig.tick(15 * 60)
    lane.run_all()
    assert rig.states()["a"].error == "unexpected"
    assert "secret detail" not in rig.log_path.read_text(encoding="ascii")
    rig.ops.boom.clear()
    rig.tick(15 * 60)
    lane.run_all()
    assert rig.ops.count("push") >= 1  # the lane and the dedupe set were not left stuck


def test_a_failed_health_check_turns_the_icon_red_until_it_runs_again(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a")
    rig.tick()
    rig.cmd("unlock", 0)
    assert rig.color() == Color.GREEN
    rig.ops.boom.add("deep")
    rig.tick(10 * 60)  # the health check raises
    state = rig.states()["a"]
    assert state.check_error == "unexpected" and state.error == "unexpected"
    assert rig.color() == Color.RED  # not a clean bill of health
    assert [n.level for n in rig.controller.drain_notices()] == ["error"]
    rig.ops.boom.clear()
    rig.tick(10 * 60)
    state = rig.states()["a"]
    assert state.check_error == "" and state.error == "" and rig.color() == Color.GREEN


def test_the_configuration_is_read_again_right_before_unlock_and_push(tmp_path: Path) -> None:
    rig, lane = push_rig(tmp_path)
    rig.cmd("lock", 0)
    path = rig.paths[0]
    rig.ops.configs[path] = Config(key_command=("changed", "a", "moment", "ago"), auto_push=True)
    rig.cmd("unlock", 0)
    last_unlock = [cfg for what, cfg in rig.ops.seen_cfgs if what == "unlock"][-1]
    assert last_unlock.key_command == ("changed", "a", "moment", "ago")  # not the old one
    rig.ops.configs[path] = Config(auto_push=True, ttl=123)
    rig.tick(15 * 60)
    lane.run_all()
    pushed_with = [cfg for what, cfg in rig.ops.seen_cfgs if what == "push"][-1]
    assert pushed_with.ttl == 123


def test_a_repository_that_cannot_be_reopened_for_the_unlock_reports_it(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "a")
    rig.tick()
    rig.ops.broken[rig.paths[0]] = "config"  # its configuration became invalid a moment ago
    rig.cmd("unlock", 0)
    assert rig.ops.count("unlock") == 1  # the job ran with nothing to unlock ...
    assert ("unlock", ()) in rig.ops.calls
    assert rig.states()["a"].error == "config"  # ... and the reason is shown


def test_the_unlock_runner_given_to_the_controller_replaces_the_in_process_unlock(
    tmp_path: Path,
) -> None:
    """The Windows tray passes the runner that unlocks in a short-lived child process (the key
    never enters the tray); the controller must call it, not its own operations' ``unlock_all``."""
    from nbp_git_safe.fleetops import Outcome

    rig = Rig(tmp_path, "a")
    rig.tick()
    asked: list[list[str]] = []

    def runner(handles: list[object], on_outcome: object = None) -> list[Outcome]:
        asked.append([h.name for h in handles])  # type: ignore[attr-defined]
        outcome = Outcome(1, "a", "failed", "no", "key-command")
        on_outcome(outcome)  # type: ignore[operator]
        return [outcome]

    rig.controller._unlock_runner = runner  # type: ignore[assignment]
    rig.cmd("unlock", 0)
    assert asked == [["a"]] and rig.ops.count("unlock") == 0
    assert rig.states()["a"].error == "key-command"  # the outcome reached the state as usual


def test_minimal_notifications_name_no_folder(tmp_path: Path) -> None:
    """Windows keeps a history of notifications: with ``notifications=minimal`` a balloon says
    ``repository 1`` (the registry position, as the log does), never the folder's name."""
    rig = Rig(tmp_path, "customer-folder", config=trayconfig.TrayConfig(notifications="minimal"))
    rig.tick()
    rig.ops.unlock_outcome = "failed"
    rig.cmd("unlock", 0)
    notices = rig.controller.drain_notices()
    assert notices and all("customer-folder" not in n.text for n in notices)
    assert any(n.text.startswith("repository 1: ") for n in notices)


def test_full_notifications_keep_the_folder_name(tmp_path: Path) -> None:
    rig = Rig(tmp_path, "customer-folder")
    rig.tick()
    rig.ops.unlock_outcome = "failed"
    rig.cmd("unlock", 0)
    assert any("customer-folder: key-command" in n.text for n in rig.controller.drain_notices())
