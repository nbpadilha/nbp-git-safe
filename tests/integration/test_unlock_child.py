# SPDX-License-Identifier: MIT
"""The tray's unlock runs in a short-lived child process, so the key never enters the long-lived
tray (review finding B8: the tray was documented as holding no key while ``unlock --all`` made a
buffer and an immutable copy of it per repository inside it). Real child, real agents, throw-away
keys; plus the strict reading of what a misbehaving child may print."""

from __future__ import annotations

import io
import json
import os
import sys
import time
from pathlib import Path

import pytest

from nbp_git_safe import agent, crypto, fleetops, unlock, unlockchild
from tests import helpers
from tests.integration.fleetkit import MakeRepo, repo_named

# Records the process that started it (the process that held the key command's output), prints key.
KEY_SCRIPT = """\
import os, sys
with open(os.environ["NBP_SAFE_TEST_PPID_LOG"], "a", encoding="ascii") as log:
    log.write(str(os.getppid()) + "\\n")
sys.stdout.write(os.environ["NBP_SAFE_TEST_KEY"] + "\\n")
"""


def handles_for(*repos: object) -> list[fleetops.RepoHandle]:
    return [fleetops.open_handle(r.path, i) for i, r in enumerate(repos, start=1)]  # type: ignore[attr-defined]


def test_the_key_command_runs_in_a_child_process_that_is_gone_afterwards(
    make_repo: MakeRepo, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ppid_log = tmp_path / "ppids.txt"
    monkeypatch.setenv("NBP_SAFE_TEST_PPID_LOG", str(ppid_log))
    script = tmp_path / "key.py"
    script.write_text(KEY_SCRIPT, encoding="utf-8")
    repos = []
    for name in ("one", "two"):
        repo = repo_named(make_repo, name)
        repo.set_config("nbp-safe.keyCommand", json.dumps([sys.executable, str(script)]))
        repos.append(repo)
    handles = handles_for(*repos)
    seen: list[fleetops.Outcome] = []
    outcomes = unlockchild.run_in_child(handles, seen.append)
    assert [o.kind for o in outcomes] == ["ok", "ok"], [o.message for o in outcomes]
    assert [o.name for o in outcomes] == ["one", "two"] and seen == outcomes
    assert all(o.code == "unlocked" and o.data["expires_at"] > time.time() for o in outcomes)
    for repo in repos:
        status = unlock.current_status(repo.state_dir)
        assert status is not None and status["locked"] is False
    parents = {int(line) for line in ppid_log.read_text(encoding="ascii").split()}
    assert len(parents) == 1  # one run for the two repositories (one group), in ONE process ...
    assert os.getpid() not in parents  # ... which is NOT this one: the key never entered it
    deadline = time.monotonic() + 10
    (child,) = parents
    while agent.pid_alive(child) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not agent.pid_alive(child)  # short-lived: it is gone, and the memory with it


def test_the_child_reads_the_configuration_itself_and_reports_failures_as_text(
    make_repo: MakeRepo,
) -> None:
    good = repo_named(make_repo, "good")
    other = repo_named(make_repo, "other")
    other.set_config("nbp-safe.keyId", helpers.key_id_of(crypto.generate_key()))  # another key's id
    gone = repo_named(make_repo, "gone")
    handles = handles_for(good, other, gone)
    handles[2] = fleetops.RepoHandle(  # a folder that vanished after the handle was made
        3, gone.path / "missing", "gone", handles[2].repo, handles[2].git, handles[2].cfg, "k" * 24
    )
    outcomes = unlockchild.run_in_child(handles)
    assert [o.kind for o in outcomes] == ["ok", "failed", "warn"]
    assert outcomes[1].code == "key-id-mismatch" and "key-id --accept" in outcomes[1].message
    assert outcomes[2].code == "missing"  # (a vanished folder is a warning, as in `--all`)
    assert unlock.current_status(other.state_dir) is None  # no agent for the refused one


def test_no_key_in_what_the_parent_receives(make_repo: MakeRepo, master_key: bytes) -> None:
    repo = repo_named(make_repo, "clean")
    (outcome,) = unlockchild.run_in_child(handles_for(repo))
    blob = repr(outcome).encode()
    for needle in (crypto.encode_key(master_key).encode(), master_key, master_key.hex().encode()):
        assert needle not in blob


# ------------------------------------------------------------- a child that misbehaves (parent)


def fake_child(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def test_only_well_formed_reports_are_accepted_and_the_rest_is_failed(tmp_path: Path) -> None:
    handles = [
        fleetops.RepoHandle(i, tmp_path / f"r{i}", f"r{i}", None, None, fleetops.Config(), "k" * 24)  # type: ignore[arg-type]
        for i in (1, 2, 3, 4)
    ]
    good = {"index": 1, "kind": "ok", "code": "unlocked", "message": "fine", "expires_at": 123.5}
    reports = [
        json.dumps(good),
        "this is not json",
        json.dumps({"index": 99, "kind": "ok", "code": "x", "message": "out of range"}),
        json.dumps({"index": True, "kind": "ok", "code": "x", "message": "a bool"}),
        json.dumps({"index": 2, "kind": "weird", "code": "x", "message": "m"}),
        json.dumps({"index": 3, "kind": "failed", "code": "Bad Code!", "message": "m"}),
        json.dumps([1, 2]),
        "x" * 9000,  # longer than a line may be
    ]
    code = f"import sys\nfor line in {reports!r}:\n    sys.stdout.write(line + chr(10))\n"
    outcomes = unlockchild.run_in_child(handles, command=fake_child(code), timeout=30)
    assert [o.index for o in outcomes] == [1, 2, 3, 4]
    assert (outcomes[0].kind, outcomes[0].code, outcomes[0].data) == (
        "ok",
        "unlocked",
        {"expires_at": 123.5},
    )
    assert outcomes[2].kind == "failed" and outcomes[2].code == "unexpected"  # reduced
    for position in (1, 3):  # never reported (or reported wrongly): failed, with a fixed text
        assert outcomes[position].kind == "failed" and outcomes[position].code == "unlock-child"
    assert all("Bad Code" not in o.code for o in outcomes)


def test_a_child_that_stalls_is_killed_and_the_run_ends(tmp_path: Path) -> None:
    handles = [
        fleetops.RepoHandle(1, tmp_path / "r", "r", None, None, fleetops.Config(), "k" * 24)  # type: ignore[arg-type]
    ]
    started = time.monotonic()
    outcomes = unlockchild.run_in_child(
        handles, command=fake_child("import time; time.sleep(120)"), timeout=1.5
    )
    assert time.monotonic() - started < 30
    assert outcomes[0].kind == "failed" and outcomes[0].code == "unlock-child"


def test_a_child_that_cannot_be_started_fails_every_repository(tmp_path: Path) -> None:
    handles = [
        fleetops.RepoHandle(i, tmp_path / f"r{i}", f"r{i}", None, None, fleetops.Config(), "k" * 24)  # type: ignore[arg-type]
        for i in (1, 2)
    ]
    outcomes = unlockchild.run_in_child(handles, command=[str(tmp_path / "no-such-program")])
    assert [o.code for o in outcomes] == ["unlock-child", "unlock-child"]
    assert unlockchild.run_in_child([]) == []


# -------------------------------------------------------------------- the child's own side


@pytest.mark.parametrize("text", ["", "not json", "[]", '{"paths": "x"}', '{"paths": [1]}'])
def test_the_child_refuses_bad_input_quietly(text: str) -> None:
    out = io.StringIO()
    assert unlockchild.child_main(io.StringIO(text), out) == 2
    assert out.getvalue() == ""


def test_the_child_command_uses_the_console_interpreter_next_to_pythonw(tmp_path: Path) -> None:
    (tmp_path / "pythonw.exe").write_bytes(b"")
    (tmp_path / "python.exe").write_bytes(b"")
    assert unlockchild.child_python(str(tmp_path / "pythonw.exe")).endswith("python.exe")
    assert unlockchild.child_python(str(tmp_path / "python.exe")).endswith("python.exe")
    assert unlockchild.child_python(str(tmp_path / "other")).endswith("other")
    assert unlockchild.child_command()[1:] == ["-I", "-m", "nbp_git_safe", "unlock-batch"]


@pytest.mark.skipif(sys.platform != "win32", reason="CREATE_NO_WINDOW is a Windows flag")
def test_the_child_works_without_a_console_as_it_does_under_the_tray(
    make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The tray runs under ``pythonw`` and starts every child with ``CREATE_NO_WINDOW``; the pipes
    to the child (and the key command's own) must still work."""
    from nbp_git_safe import gitutil

    monkeypatch.setattr(gitutil, "_hide_windows", True)
    repo = repo_named(make_repo, "windowless")
    (outcome,) = unlockchild.run_in_child(handles_for(repo))
    assert outcome.kind == "ok", outcome.message
    status = unlock.current_status(repo.state_dir)
    assert status is not None and status["locked"] is False
