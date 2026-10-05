# SPDX-License-Identifier: MIT
"""Parts of ``fleetops`` that need no repository: error classification, the group key, grouping by
keyCommand and the handle errors."""

from __future__ import annotations

from pathlib import Path

import pytest

from nbp_git_safe import agent, crypto, fleetops, unlock, vault
from nbp_git_safe import index as index_mod
from nbp_git_safe.config import Config, ConfigError
from nbp_git_safe.fleetops import GroupKey, RepoHandle
from nbp_git_safe.gitutil import GitError

CASES = [
    (unlock.KeyCommandError("keyCommand failed (exit code 1)"), "key-command"),
    (agent.ProcessInspectionError("x"), "other-elevation"),
    (agent.HandshakeError("x"), "agent-auth"),
    (agent.AgentNotRunningError("x"), "locked"),
    (agent.AgentLockedError("x"), "locked"),
    (agent.AgentExpiredError("x"), "locked"),
    (agent.AgentError("x"), "agent"),
    (ConfigError("ttl: bad"), "config"),
    (vault.VaultError("x"), "vault"),
    (crypto.AuthenticationError("x"), "vault"),
    (index_mod.IndexValidationError("x"), "vault"),
    (GitError("git failed"), "git"),
    (PermissionError(13, "Access denied"), "io"),
    (RuntimeError("path C:\\secret\\name.csv and a key"), "unexpected"),
]


@pytest.mark.parametrize(("exc", "code"), CASES, ids=[c[1] + str(i) for i, c in enumerate(CASES)])
def test_classify(exc: BaseException, code: str) -> None:
    got, message = fleetops.classify(exc)
    assert got == code
    if code == "unexpected":  # an unknown exception is reduced to its class name
        assert message == "unexpected error (RuntimeError)" and "secret" not in message


def test_handles_report_short_codes(tmp_path: Path) -> None:
    with pytest.raises(fleetops.HandleError) as missing:
        fleetops.open_handle(tmp_path / "nope", 1)
    assert missing.value.code == "missing"
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(fleetops.HandleError) as not_repo:
        fleetops.open_handle(plain, 2)
    assert not_repo.value.code == "not-a-repo"


def test_short_name() -> None:
    assert fleetops.short_name("/a/b/proj") == "proj"
    assert fleetops.short_name("/a/b/proj/") == "proj"
    assert fleetops.short_name("C:\\work\\proj\\") == "proj"
    assert fleetops.short_name("/") == "/"


def handle(n: int, command: tuple[str, ...] | None, timeout: float = 120.0) -> RepoHandle:
    cfg = Config(key_command=command, key_command_timeout=timeout)
    return RepoHandle(n, Path(f"/r{n}"), f"r{n}", None, None, cfg, f"{n:024x}")  # type: ignore[arg-type]


def test_grouping_is_by_identical_argv_in_order_of_first_appearance() -> None:
    a, b = ("op", "read", "x"), ("op", "read", "y")
    groups = fleetops.group_by_key_command(
        [handle(1, a), handle(2, b), handle(3, a), handle(4, None), handle(5, ("op", "read", "x"))]
    )
    assert [[h.index for h in g] for g in groups] == [[1, 3, 5], [2], [4]]
    # near misses are different groups: extra argument, other case, other order
    near = fleetops.group_by_key_command(
        [
            handle(1, ("a", "b")),
            handle(2, ("a", "b", "")),
            handle(3, ("A", "b")),
            handle(4, ("b", "a")),
        ]
    )
    assert len(near) == 4


def test_group_key_runs_once_caches_failure_and_wipes() -> None:
    calls: list[int] = []

    def produce() -> bytes:
        calls.append(1)
        return bytes(range(64))

    source = GroupKey(produce)
    assert source.get() == bytes(range(64)) == source.get()
    assert len(calls) == 1 and source.runs == 1
    buffer = source._buffer
    assert buffer is not None
    source.wipe()
    assert bytes(buffer) == b"\x00" * 64  # the buffer it owned is zeroed
    with pytest.raises(unlock.KeyCommandError, match="wiped"):
        source.get()
    assert "redacted" in repr(source) and "\\x" not in repr(source)


def test_group_key_failure_is_remembered_not_retried() -> None:
    calls: list[int] = []

    def produce() -> bytes:
        calls.append(1)
        raise unlock.KeyCommandError("keyCommand timed out after 120 s")

    source = GroupKey(produce)
    for _ in range(3):
        with pytest.raises(unlock.KeyCommandError, match="timed out"):
            source.get()
    assert len(calls) == 1  # a refused prompt is not asked again for the next repository
    source.wipe()


def test_unlock_all_with_no_handles_does_nothing() -> None:
    assert fleetops.unlock_all([]) == []


def test_unlock_all_uses_the_injected_runner_once_per_group(tmp_path: Path) -> None:
    """The runner is called once per distinct argv even when ``unlock`` itself fails afterwards."""
    seen: list[tuple[str, ...]] = []

    def runner(argv: tuple[str, ...], timeout: float) -> bytes:
        seen.append(tuple(argv))
        return bytes(64)

    handles = [
        RepoHandle(
            i,
            tmp_path / f"r{i}",
            f"r{i}",
            type("R", (), {"state_dir": tmp_path / f"state{i}"})(),  # type: ignore[arg-type]
            None,  # type: ignore[arg-type]
            Config(key_command=("k", "1" if i < 3 else "2")),
            f"{i:024x}",
        )
        for i in range(1, 5)
    ]

    def failing_spawn(state_dir: Path, ttl: float, idle: float | None) -> agent.AgentInfo:
        raise agent.AgentError("key agent failed to start")

    outcomes = fleetops.unlock_all(handles, key_runner=runner, spawn=failing_spawn)  # type: ignore[arg-type]
    assert [o.kind for o in outcomes] == ["failed"] * 4
    assert seen == [("k", "1"), ("k", "2")]
    assert all(o.code == "agent" for o in outcomes)
