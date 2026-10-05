# SPDX-License-Identifier: MIT
"""The tray controller on real repositories with real agents (no window): the one-prompt rule, the
periodic seal, the locks, and the leak gate over every file the tray writes (registry, tray
configuration, log, state) and every ``.git``."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from nbp_git_safe import agent, trayconfig, unlock
from nbp_git_safe.fleet import Color
from nbp_git_safe.traycontroller import InlineWorker, TrayController
from nbp_git_safe.traylog import LOG_NAME, TrayLog
from tests import helpers
from tests.integration.fleetkit import (
    MakeRepo,
    assert_key_nowhere,
    repo_named,
    runs,
    wait_gone,
)
from tests.leak.harness import LeakScanner, assert_no_leaks


@pytest.fixture
def keylog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "key-runs.txt"
    monkeypatch.setenv("NBP_SAFE_TEST_KEY_LOG", str(path))
    return path


class Now:
    """A wall clock the test can move (the agents' expiry is real time: only the controller's
    schedule moves with it)."""

    def __init__(self) -> None:
        self.offset = 0.0

    def __call__(self) -> float:
        return time.time() + self.offset


def real_controller(clock: Now) -> TrayController:
    base = agent.private_root(create=True)
    assert base is not None
    return TrayController(
        clock=clock,
        log=TrayLog(base / LOG_NAME),
        unlock_worker=InlineWorker(),
        work_worker=InlineWorker(),
    )


def test_unlock_seal_lock_through_the_controller(
    make_repo: MakeRepo, keylog: Path, master_key: bytes
) -> None:
    a, b = repo_named(make_repo, "a"), repo_named(make_repo, "b")
    for repo in (a, b):
        repo.set_config("nbp-safe.ttl", "2h")  # a key with under an hour left makes the icon yellow
        helpers.populate(repo)
    trayconfig.save(trayconfig.TrayConfig(sealIntervalMinutes=1, sealPush=False))
    clock = Now()
    controller = real_controller(clock)
    controller.start()
    controller.tick()
    view = controller.view()
    assert view.color == Color.YELLOW and [s.name for s in view.states] == ["a", "b"]

    controller.command("all:unlock")
    assert runs(keylog) == ["ok"]  # one prompt for two repositories
    assert controller.view().color == Color.GREEN
    pids = [agent.read_agent_info(r.state_dir).pid for r in (a, b)]  # type: ignore[union-attr]

    # files written by "a script" sit unsealed until the periodic seal runs
    assert a.sh("for-each-ref", "refs/heads/nbp-safe").strip() == ""
    clock.offset += 61
    controller.tick()
    for repo in (a, b):
        assert repo.sh("rev-parse", "--verify", "refs/heads/nbp-safe").strip()
    assert controller.view().color == Color.GREEN
    assert all(s.error == "" for s in controller.view().states)

    key = controller.view().states[0].key
    controller.command(f"repo:{key}:lock")
    states = {s.name: s for s in controller.view().states}
    assert states["a"].status == "locked" and states["b"].status == "unlocked"
    assert controller.view().color == Color.YELLOW
    clock.offset += 61
    controller.tick()  # "a" is locked: the periodic seal must not unlock it
    assert runs(keylog) == ["ok"]
    assert unlock.current_status(a.state_dir) is None

    controller.command("all:lock")
    assert controller.view().color == Color.YELLOW
    assert all(wait_gone(pid) for pid in pids)

    log = (agent.runtime_root() / LOG_NAME).read_text(encoding="ascii")
    for name in ("a", "b"):
        for canary in (a if name == "a" else b).canaries:
            assert canary not in log
    assert str(tmp_names(a, b)[0]) not in log
    assert_key_nowhere(master_key, [a, b], log)
    scanner = LeakScanner(a.canaries + b.canaries)
    assert_no_leaks(scanner.scan_dir(agent.runtime_root()))


def tmp_names(*repos: helpers.NbpRepo) -> list[Path]:
    return [r.path for r in repos]


def test_a_repository_that_disappears_never_stops_the_others(
    make_repo: MakeRepo, keylog: Path
) -> None:
    keep, doomed = repo_named(make_repo, "keep"), repo_named(make_repo, "doomed")
    clock = Now()
    controller = real_controller(clock)
    controller.tick()
    assert len(controller.view().states) == 2
    # the folder is moved away behind the tray's back
    import shutil

    agent_state = doomed.state_dir
    shutil.rmtree(doomed.path)
    clock.offset += 31
    controller.tick()
    states = {s.name: s for s in controller.view().states}
    assert states["doomed"].status == "missing" and states["keep"].status == "locked"
    controller.command("all:unlock")
    assert controller.view().states[0].status == "unlocked"
    assert unlock.current_status(agent_state) is None  # nothing started for the missing one
    controller.command("all:lock")
    assert unlock.current_status(keep.state_dir) is None
