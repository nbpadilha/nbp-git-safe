# SPDX-License-Identifier: MIT
"""Several repositories at once, with real git in temporary directories: the registry commands,
``status|unlock|lock|seal|doctor --all`` and the one-prompt-per-key rule of ``unlock --all``.

Keys are throw-away test keys; the test key command writes one line per run (arguments only) to a
file, which is how "run once per distinct keyCommand" is counted. No real data, nothing outside the
isolated runtime root."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from nbp_git_safe import agent, crypto, registry, unlock
from nbp_git_safe.cli import main
from tests import helpers
from tests.helpers import NbpRepo
from tests.leak.harness import LeakScanner, assert_no_leaks

MakeRepo = Callable[..., object]


def run(*argv: str) -> helpers.CliResult:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(argv))
    return helpers.CliResult(code, out.getvalue(), err.getvalue())


@pytest.fixture
def keylog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "key-runs.txt"
    monkeypatch.setenv("NBP_SAFE_TEST_KEY_LOG", str(path))
    return path


def runs(log: Path) -> list[str]:
    return log.read_text(encoding="ascii").splitlines() if log.exists() else []


def repo_named(make_repo: MakeRepo, name: str, *extra: str, mode: str = "ok") -> NbpRepo:
    """A repository whose keyCommand is the test command with ``extra`` arguments (so repositories
    with the same ``extra`` share an identical argv)."""
    repo = make_repo(name)
    assert isinstance(repo, NbpRepo)
    repo.set_config(
        "nbp-safe.keyCommand", json.dumps([sys.executable, str(helpers.KEYCMD), mode, *extra])
    )
    registry.add(repo.path)
    return repo


def key_needles(master: bytes) -> dict[str, bytes]:
    text = crypto.encode_key(master)
    return {
        "key-base64": text.encode(),
        "key-raw": master,
        "key-hex": master.hex().encode(),
        "key-first-half-raw": master[:32],
    }


def assert_key_nowhere(master: bytes, repos: list[NbpRepo], *texts: str) -> None:
    scanner = LeakScanner([], raw_needles=key_needles(master))
    hits = scanner.scan_dir(agent.runtime_root())
    for repo in repos:
        hits += scanner.scan_git_dir(repo.path / ".git")
    for text in texts:
        hits += scanner.scan_bytes(text.encode("utf-8", "replace"), "command output")
    assert_no_leaks(hits)


def wait_gone(pid: int, seconds: float = 10.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not agent.pid_alive(pid):
            return True
        time.sleep(0.05)
    return False


# ------------------------------------------------------------------------------ registry


def test_init_registers_and_uninstall_unregisters(make_repo: MakeRepo) -> None:
    repo = make_repo("one")
    assert isinstance(repo, NbpRepo)
    first = repo.cli("init")
    assert first.code == 0 and "added to the per-user registry" in first.err
    assert [e.path for e in registry.load().entries] == [registry.canonical(repo.path)]
    assert "added to the per-user registry" not in repo.cli("init").err  # idempotent
    assert len(registry.load().entries) == 1
    assert repo.cli("uninstall", "--yes").code == 0
    assert registry.load().entries == []


def test_init_still_works_when_the_registry_is_broken(make_repo: MakeRepo) -> None:
    repo = make_repo("one")
    assert isinstance(repo, NbpRepo)
    registry.add(repo.path.parent)  # creates the (private) directory
    (agent.runtime_root() / registry.REGISTRY_NAME).write_bytes(b"{ broken")
    result = repo.cli("init")
    assert result.code == 0
    assert [e.path for e in registry.load().entries] == [registry.canonical(repo.path)]
    assert (agent.runtime_root() / "repos.json.bak").read_bytes() == b"{ broken"


def test_registry_commands(make_repo: MakeRepo, tmp_path: Path) -> None:
    repo = make_repo("kept")
    assert isinstance(repo, NbpRepo)
    plain = tmp_path / "plain"
    plain.mkdir()
    gone = tmp_path / "gone"
    gone.mkdir()
    assert run("registry", "list").out.strip() == "no repositories registered"
    assert repo.cli("registry", "add").code == 0
    assert "already registered" in repo.cli("registry", "add").out
    registry.add(plain)
    registry.add(gone)
    gone.rmdir()
    listing = run("registry", "list").out
    assert listing.count("\n") == 3 and "[1]" in listing and str(repo.path) in listing
    pruned = run("registry", "prune")
    assert pruned.code == 0 and "2 entries removed" in pruned.out
    assert [e.path for e in registry.load().entries] == [registry.canonical(repo.path)]
    assert run("-C", str(plain), "registry", "add").code == 1  # not a repository
    assert repo.cli("registry", "remove").out.strip() == "removed"
    assert repo.cli("registry", "remove").out.strip() == "was not registered"
    assert run("registry").code == 2


def test_all_flag_needs_a_registry_and_refuses_dash_c(make_repo: MakeRepo, tmp_path: Path) -> None:
    for command in ("status", "unlock", "lock", "seal", "doctor"):
        result = run(command, "--all")
        assert result.code == 0 and "no repositories registered" in result.out, command
    clash = run("-C", str(tmp_path), "status", "--all")
    assert clash.code == 2 and "cannot be combined with -C" in clash.err
    single = run("-C", str(tmp_path), "seal", "--push")
    assert single.code == 2 and "--push goes with --all" in single.err


# --------------------------------------------------------------------------- unlock --all


def test_unlock_all_runs_one_identical_key_command_once(
    make_repo: MakeRepo, keylog: Path, master_key: bytes
) -> None:
    a, b = repo_named(make_repo, "a"), repo_named(make_repo, "b")
    result = run("unlock", "--all")
    assert result.code == 0, result.out + result.err
    assert runs(keylog) == ["ok"]  # ONE run for the two repositories
    assert "2 repositories: 2 ok" in result.out and result.out.count("unlocked (key") == 2
    for repo in (a, b):
        status = unlock.current_status(repo.state_dir)
        assert status is not None and status["locked"] is False
    again = run("unlock", "--all")
    assert again.code == 0 and again.out.count("already unlocked") == 2
    assert runs(keylog) == ["ok"]  # nothing to unlock: the command did not run at all
    status_all = run("status", "--all")
    assert status_all.code == 0 and status_all.out.count("agent: unlocked") == 2
    pids = [agent.read_agent_info(r.state_dir).pid for r in (a, b)]  # type: ignore[union-attr]
    locked = run("lock", "--all")
    assert locked.code == 0 and locked.out.count("locked") >= 2
    assert all(wait_gone(pid) for pid in pids)  # no agent left behind
    assert all(unlock.current_status(r.state_dir) is None for r in (a, b))
    assert_key_nowhere(master_key, [a, b], result.out, result.err, again.out, status_all.out)


def test_unlock_all_runs_one_command_per_distinct_keycommand(
    make_repo: MakeRepo, keylog: Path
) -> None:
    repos = [
        repo_named(make_repo, "a"),
        repo_named(make_repo, "b", "other"),
        repo_named(make_repo, "c"),
        repo_named(make_repo, "d", "other"),
        repo_named(make_repo, "e", "third"),
    ]
    result = run("unlock", "--all")
    assert result.code == 0, result.out + result.err
    assert sorted(runs(keylog)) == ["ok", "ok other", "ok third"]  # one per group, not per repo
    assert "5 repositories: 5 ok" in result.out
    assert all((unlock.current_status(r.state_dir) or {}).get("locked") is False for r in repos)
    run("lock", "--all")


def test_a_failing_command_fails_its_group_only_and_is_asked_once(
    make_repo: MakeRepo, keylog: Path
) -> None:
    bad1 = repo_named(make_repo, "bad1", mode="exit1")
    bad2 = repo_named(make_repo, "bad2", mode="exit1")
    good = repo_named(make_repo, "good")
    result = run("unlock", "--all")
    assert result.code == 1
    assert sorted(runs(keylog)) == ["exit1", "ok"]  # the failed command was not repeated
    assert result.out.count("FAILED") == 2 and "exit code 1" in result.out
    assert "1 ok, 2 failed" in result.out
    assert unlock.current_status(bad1.state_dir) is None
    assert unlock.current_status(bad2.state_dir) is None
    assert (unlock.current_status(good.state_dir) or {}).get("locked") is False
    run("lock", "--all")


def test_a_repository_without_a_key_command_fails_alone(make_repo: MakeRepo, keylog: Path) -> None:
    keyless = repo_named(make_repo, "keyless")
    keyless.sh("config", "--local", "--unset", "nbp-safe.keyCommand")
    other = repo_named(make_repo, "other")
    result = run("unlock", "--all")
    assert result.code == 1 and "no keyCommand configured" in result.out
    assert runs(keylog) == ["ok"]
    assert (unlock.current_status(other.state_dir) or {}).get("locked") is False
    run("lock", "--all")


def test_unlock_all_honours_each_repositorys_own_ttl(make_repo: MakeRepo, keylog: Path) -> None:
    short, long = repo_named(make_repo, "short"), repo_named(make_repo, "long")
    short.set_config("nbp-safe.ttl", "10m")
    long.set_config("nbp-safe.ttl", "2h")
    assert run("unlock", "--all").code == 0
    left = {
        r.path.name: (unlock.current_status(r.state_dir) or {})["expires_at"] - time.time()
        for r in (short, long)
    }
    assert 500 < left["short"] <= 600 and 7000 < left["long"] <= 7200
    run("lock", "--all")


# ---------------------------------------------------------- one broken repository in the middle


def three_with_a_hole(make_repo: MakeRepo, tmp_path: Path) -> tuple[NbpRepo, NbpRepo, list[Path]]:
    first = repo_named(make_repo, "first")
    gone = tmp_path / "vanished"
    gone.mkdir()
    registry.add(gone)
    gone.rmdir()  # in the registry, not on disk
    plain = tmp_path / "not-a-repo"
    plain.mkdir()
    registry.add(plain)
    last = repo_named(make_repo, "last")
    return first, last, [gone, plain]


@pytest.mark.parametrize("command", ["status", "lock", "doctor", "seal"])
def test_commands_continue_past_a_broken_repository(
    make_repo: MakeRepo, tmp_path: Path, command: str
) -> None:
    first, last, _holes = three_with_a_hole(make_repo, tmp_path)
    agents = [first.unlock_in_thread(), last.unlock_in_thread()]
    try:
        result = run(command, "--all")
        lines = result.out.splitlines()
        assert any(line.startswith("[1] first") for line in lines)
        assert any(line.startswith("[4] last") for line in lines)  # reached after the failures
        assert "[2] vanished: warning: the folder does not exist" in result.out
        assert "[3] not-a-repo: FAILED" in result.out
        assert result.code == 1  # one repository could not be opened
        assert "4 repositories" in lines[-1]
    finally:
        for ta in agents:
            ta.stop()


def test_status_all_exit_code_three_when_something_is_only_locked(make_repo: MakeRepo) -> None:
    repo_named(make_repo, "locked-one")
    result = run("status", "--all")
    assert result.code == 3 and "agent: locked" in result.out


def test_doctor_all_reports_problems_with_exit_code_one(make_repo: MakeRepo) -> None:
    repo = repo_named(make_repo, "needs-init")
    result = run("doctor", "--all")
    assert result.code == 1 and "[PROBLEM]" in result.out
    assert repo.cli("init").code == 0
    ok = run("doctor", "--all")
    assert "[PROBLEM]" not in ok.out


def test_worktrees_of_one_repository_are_listed_once(make_repo: MakeRepo, tmp_path: Path) -> None:
    repo = repo_named(make_repo, "main-tree")
    repo.sh("commit", "--allow-empty", "-q", "-m", "base")
    linked = tmp_path / "linked-tree"
    repo.sh("worktree", "add", "-q", str(linked), "-b", "side")
    registry.add(linked)
    result = run("status", "--all")
    assert "1 repository:" in result.out.splitlines()[-1]


# ------------------------------------------------------------------------------- seal --all


def test_seal_all_seals_unlocked_and_never_unlocks_a_locked_one(
    make_repo: MakeRepo, keylog: Path
) -> None:
    open_repo = repo_named(make_repo, "open")
    shut = repo_named(make_repo, "shut")
    for repo in (open_repo, shut):
        helpers.populate(repo)
    thread_agent = open_repo.unlock_in_thread()
    try:
        result = run("seal", "--all")
        assert result.code == 0, result.out + result.err
        assert "[1] open: sealed:" in result.out
        assert "[2] shut: locked" in result.out
        assert runs(keylog) == []  # no key command: sealing never unlocks
        assert unlock.current_status(shut.state_dir) is None
        assert open_repo.sh("rev-parse", "--verify", "refs/heads/nbp-safe").strip()
        assert shut.raw("rev-parse", "--verify", "refs/heads/nbp-safe").returncode != 0
        assert "1 ok, 1 skipped" in result.out
        again = run("seal", "--all")
        assert "nothing to seal" in again.out and again.code == 0
        # the output names no protected file
        for canary in open_repo.canaries:
            assert canary not in result.out + result.err
        open_repo.assert_no_leak()
    finally:
        thread_agent.stop()


def test_seal_all_push_pushes_only_where_autopush_and_origin_exist(
    make_repo: MakeRepo, tmp_path: Path
) -> None:
    pushed = repo_named(make_repo, "pushed")
    no_remote = repo_named(make_repo, "no-remote")
    no_flag = repo_named(make_repo, "no-flag")
    offline = repo_named(make_repo, "offline")
    git = pushed.git
    bare = git.init(tmp_path / "origin.git", bare=True)
    bare_flag = git.init(tmp_path / "origin-flag.git", bare=True)
    pushed.sh("remote", "add", "origin", str(bare))
    no_flag.sh("remote", "add", "origin", str(bare_flag))
    offline.sh("remote", "add", "origin", str(tmp_path / "does-not-exist.git"))
    for repo in (pushed, no_remote, offline):
        repo.set_config("nbp-safe.autoPush", "true")
    repos = [pushed, no_remote, no_flag, offline]
    for repo in repos:
        helpers.populate(repo)
    agents = [r.unlock_in_thread() for r in repos]
    try:
        plain = run("seal", "--all")
        assert plain.code == 0
        assert git.run("for-each-ref", "refs/heads", cwd=bare).strip() == ""  # no --push: no push
        result = run("seal", "--all", "--push")
        assert result.code == 0, result.out + result.err  # an unreachable origin is not fatal
        refs = git.run("for-each-ref", "--format=%(refname)", cwd=bare).split()
        assert refs == ["refs/heads/nbp-safe"]  # only the vault branch, never main
        assert git.run("for-each-ref", cwd=bare_flag).strip() == ""
        assert "pushed @" in result.out and "(no force)" in result.out
        assert "push: no origin remote" in result.out
        assert "push: autoPush is not set" in result.out
        assert "could not reach origin" in result.out
        pushed.assert_no_leak(bare)
        for repo in repos:
            for canary in repo.canaries:
                assert canary not in result.out
    finally:
        for ta in agents:
            ta.stop()


def test_a_rejected_push_is_an_error_and_is_never_forced(
    make_repo: MakeRepo, tmp_path: Path
) -> None:
    mine = repo_named(make_repo, "mine")
    bare = mine.git.init(tmp_path / "origin.git", bare=True)
    mine.sh("remote", "add", "origin", str(bare))
    mine.set_config("nbp-safe.autoPush", "true")
    helpers.populate(mine)
    # someone else put an unrelated vault branch on origin
    other = repo_named(make_repo, "other")
    helpers.populate(other)
    ta_other = other.unlock_in_thread()
    ta_mine = mine.unlock_in_thread()
    try:
        assert other.cli("seal").code == 0
        other.sh("push", "-q", str(bare), "refs/heads/nbp-safe:refs/heads/nbp-safe")
        before = mine.git.run("rev-parse", "refs/heads/nbp-safe", cwd=bare).strip()
        result = run("seal", "--all", "--push")
        assert result.code == 1 and "push: origin has vault commits" in result.out
        assert mine.git.run("rev-parse", "refs/heads/nbp-safe", cwd=bare).strip() == before
    finally:
        ta_mine.stop()
        ta_other.stop()
