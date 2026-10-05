# SPDX-License-Identifier: MIT
"""The key id registered for each repository (``nbp-safe.keyId``) and the working directory of
``keyCommand``: the grouping of ``unlock --all`` and the tray is only an optimisation, and a key
meant for another repository is never delivered, never creates a vault and never seals.

Review finding M1: ``["python", "tools/key.py"]`` worked from inside a repository but ran from the
folder of the tray (once, for the whole group) under ``--all``. Keys are throw-away test keys."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from nbp_git_safe import crypto, fleetops, registry, unlock
from tests import helpers
from tests.helpers import NbpRepo, key_id_of
from tests.integration.fleetkit import MakeRepo, repo_named, run, runs

# Picks the key by the NAME of the folder it runs in (one throw-away key per repository), and
# records where it ran: exactly what a ``tools/key.py`` that reads a sibling file would depend on.
KEY_SCRIPT = """\
import os, sys
log = os.environ.get("NBP_SAFE_TEST_CWD_LOG")
if log:
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(os.getcwd() + "\\n")
name = os.path.basename(os.getcwd()).upper()
fallback = os.environ["NBP_SAFE_TEST_KEY"]
sys.stdout.write(os.environ.get("NBP_SAFE_TEST_KEY_" + name, fallback) + "\\n")
"""


def same(a: str | Path, b: str | Path) -> bool:
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))


@pytest.fixture
def cwdlog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "cwd-log.txt"
    monkeypatch.setenv("NBP_SAFE_TEST_CWD_LOG", str(path))
    return path


def relative_repo(
    make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch, name: str, *, own_key: bool = True
) -> tuple[NbpRepo, bytes]:
    """A repository whose keyCommand holds a RELATIVE path (identical argv in every one)."""
    repo = make_repo(name)
    assert isinstance(repo, NbpRepo)
    repo.write("tools/key.py", KEY_SCRIPT)
    repo.set_config("nbp-safe.keyCommand", json.dumps([sys.executable, "tools/key.py"]))
    key = crypto.generate_key() if own_key else repo.master
    monkeypatch.setenv("NBP_SAFE_TEST_KEY_" + name.upper(), crypto.encode_key(key))
    repo.set_config("nbp-safe.keyId", key_id_of(key))
    registry.add(repo.path)
    return repo, key


# ---------------------------------------------------------------- the working directory (M1b)


def test_a_relative_key_command_runs_from_each_repository_root_in_unlock_all(
    make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch, cwdlog: Path
) -> None:
    a, key_a = relative_repo(make_repo, monkeypatch, "alpha")
    b, key_b = relative_repo(make_repo, monkeypatch, "beta")
    result = run("unlock", "--all")
    assert result.code == 0, result.out + result.err
    # identical argv, but a relative path: a prompt (a run) per repository, from ITS root
    ran = runs(cwdlog)
    assert len(ran) == 2 and same(ran[0], a.path) and same(ran[1], b.path)
    for repo, key in ((a, key_a), (b, key_b)):  # each repository got ITS key
        status = unlock.current_status(repo.state_dir)
        assert status is not None and status["key_id"] == key_id_of(key)


def test_the_single_unlock_runs_from_the_repository_root_too(
    make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch, cwdlog: Path
) -> None:
    repo, _key = relative_repo(make_repo, monkeypatch, "solo")
    result = repo.cli("unlock")  # -C: the process itself stays elsewhere
    assert result.code == 0, result.out + result.err
    assert [same(line, repo.path) for line in runs(cwdlog)] == [True]


def test_absolute_commands_still_share_one_prompt(
    make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, cwdlog: Path
) -> None:
    script = tmp_path / "shared-key.py"
    script.write_text(KEY_SCRIPT, encoding="utf-8")
    repos = []
    for name in ("one", "two"):
        repo = make_repo(name)
        assert isinstance(repo, NbpRepo)
        repo.set_config("nbp-safe.keyCommand", json.dumps([sys.executable, str(script)]))
        repo.set_config("nbp-safe.keyId", key_id_of(repo.master))
        registry.add(repo.path)
        repos.append(repo)
    result = run("unlock", "--all")
    assert result.code == 0, result.out + result.err
    assert len(runs(cwdlog)) == 1  # nothing in the argv depends on where it runs: one prompt


# --------------------------------------------------------------------- the key id (M1a)


def handles_of(*repos: NbpRepo) -> list[fleetops.RepoHandle]:
    handles, failures = fleetops.open_all(registry.load().entries)
    assert not failures
    return [h for h in handles if any(same(h.path, r.path) for r in repos)]


def test_a_key_of_another_repository_is_refused_and_leaves_no_agent(
    make_repo: MakeRepo, tmp_path: Path
) -> None:
    mine = repo_named(make_repo, "mine")
    other = repo_named(make_repo, "other")  # the very same argv: one group
    other.set_config("nbp-safe.keyId", key_id_of(crypto.generate_key()))  # meant for another key
    outcomes = {o.name: o for o in fleetops.unlock_all(handles_of(mine, other))}
    assert outcomes["mine"].kind == fleetops.OK
    refused = outcomes["other"]
    assert refused.kind == fleetops.FAILED and refused.code == "key-id-mismatch"
    assert "key-id --accept" in refused.message  # actionable
    assert unlock.current_status(other.state_dir) is None  # no agent was even started
    assert unlock.current_status(mine.state_dir) is not None


def test_a_repository_without_vault_or_key_id_is_not_given_the_groups_key(
    make_repo: MakeRepo, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = tmp_path / "runs.txt"
    monkeypatch.setenv("NBP_SAFE_TEST_KEY_LOG", str(log))
    fresh = repo_named(make_repo, "fresh", key_id=False)
    (outcome,) = fleetops.unlock_all(handles_of(fresh))
    assert outcome.kind == fleetops.FAILED and outcome.code == "no-key-id"
    assert "unlock" in outcome.message and runs(log) == []  # refused BEFORE the prompt
    assert unlock.current_status(fresh.state_dir) is None
    # the explicit way in: unlock inside the repository once (its own command, its own folder)
    assert fresh.cli("unlock").code == 0
    assert fresh.sh("config", "--local", "nbp-safe.keyId").strip() == key_id_of(fresh.master)
    assert fresh.cli("lock").code == 0
    (again,) = fleetops.unlock_all(handles_of(fresh))
    assert again.kind == fleetops.OK  # now the group may deliver it


def test_the_first_seal_that_creates_a_vault_registers_the_key_id(make_repo: MakeRepo) -> None:
    repo = make_repo("sealed")
    assert isinstance(repo, NbpRepo)
    helpers.populate(repo)
    assert repo.raw("config", "--local", "nbp-safe.keyId").stdout.strip() == ""
    thread_agent = repo.unlock_in_thread()
    try:
        assert repo.cli("init").code == 0 and repo.cli("seal").code == 0
        assert repo.sh("config", "--local", "nbp-safe.keyId").strip() == key_id_of(repo.master)
    finally:
        thread_agent.stop()


def test_a_seal_with_another_key_is_refused(make_repo: MakeRepo) -> None:
    repo = make_repo("wrongkey")
    assert isinstance(repo, NbpRepo)
    helpers.populate(repo)
    repo.set_config("nbp-safe.keyId", key_id_of(crypto.generate_key()))  # another key's id
    thread_agent = repo.unlock_in_thread()
    try:
        assert repo.cli("init").code == 0
        sealed = repo.cli("seal")
        assert sealed.code == 1 and "key-id --accept" in sealed.err
        assert (
            repo.raw("rev-parse", "--verify", "-q", "refs/heads/nbp-safe").returncode != 0
        )  # no vault
    finally:
        thread_agent.stop()


# ------------------------------------------------------------- changing the key on purpose


def test_changing_the_key_needs_a_typed_confirmation(
    make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = make_repo("rekey")
    assert isinstance(repo, NbpRepo)
    assert repo.cli("unlock").code == 0 and repo.cli("lock").code == 0
    old_id = key_id_of(repo.master)
    assert repo.sh("config", "--local", "nbp-safe.keyId").strip() == old_id
    new_key = crypto.generate_key()
    new_id = key_id_of(new_key)
    monkeypatch.setenv("NBP_SAFE_TEST_KEY", crypto.encode_key(new_key))  # the key was replaced
    refused = repo.cli("unlock")
    assert refused.code == 1 and old_id in refused.err and new_id in refused.err
    assert f"key-id --accept {new_id}" in refused.err
    assert unlock.current_status(repo.state_dir) is None  # nothing was unlocked
    shown = repo.cli("key-id")
    assert shown.code == 0 and old_id in shown.out
    bare = repo.cli("key-id", "--accept", new_id)  # no terminal: a typed confirmation is needed
    assert bare.code == 1 and f'--confirm "accept key id {new_id}"' in bare.err
    wrong = repo.cli("key-id", "--accept", new_id, "--confirm", "yes")
    assert wrong.code == 1 and repo.sh("config", "--local", "nbp-safe.keyId").strip() == old_id
    bad = repo.cli("key-id", "--accept", "not-a-key-id")
    assert bad.code == 2
    done = repo.cli("key-id", "--accept", new_id, "--confirm", f"accept key id {new_id}")
    assert done.code == 0 and repo.sh("config", "--local", "nbp-safe.keyId").strip() == new_id
    assert repo.cli("unlock").code == 0
    assert unlock.current_status(repo.state_dir)["key_id"] == new_id  # type: ignore[index]


def test_an_agent_holding_another_key_is_replaced_not_kept(make_repo: MakeRepo) -> None:
    """An agent unlocked by hand (or by an older version) with a key other than the registered
    one is not reported as "already unlocked": it is replaced by the registered key's agent."""
    repo = make_repo("replace")
    assert isinstance(repo, NbpRepo)
    repo.set_config("nbp-safe.keyId", key_id_of(repo.master))
    stranger = helpers.ThreadAgent(repo.state_dir, crypto.generate_key())
    try:
        result = repo.cli("unlock")
        assert result.code == 0 and "already unlocked" not in result.out
        status = unlock.current_status(repo.state_dir)
        assert status is not None and status["key_id"] == key_id_of(repo.master)
    finally:
        stranger.stop()


def test_key_id_is_local_config_only(
    make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Neither the environment nor a versioned file can register (or change) the key id."""
    from nbp_git_safe.config import ConfigError, load_config
    from nbp_git_safe.gitutil import discover

    repo = make_repo("localonly")
    assert isinstance(repo, NbpRepo)
    monkeypatch.setenv("NBP_SAFE_KEYID", "0123456789abcdef")
    repo.write(".nbp-safe.config", "[nbp-safe]\n\tkeyId = 0123456789abcdef\n")
    git_repo, git = discover(repo.path)
    assert load_config(git, git_repo).key_id is None
    repo.set_config("nbp-safe.keyId", "ABCDEF0123456789")
    assert load_config(git, git_repo).key_id == "abcdef0123456789"
    repo.set_config("nbp-safe.keyId", "zz")
    with pytest.raises(ConfigError, match="keyId"):
        load_config(git, git_repo)


# ---------------------------------------------------------------------------- doctor (M1c)


def test_doctor_reports_a_relative_command_and_a_missing_or_wrong_key_id(
    make_repo: MakeRepo, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, _key = relative_repo(make_repo, monkeypatch, "doc")
    repo.sh("config", "--local", "--unset", "nbp-safe.keyId")
    report = repo.cli("doctor").out
    assert "keyCommand holds a relative path" in report
    assert "no key id is registered" in report
    repo.set_config("nbp-safe.keyId", key_id_of(crypto.generate_key()))
    assert "no key id is registered" not in repo.cli("doctor").out
    # an agent that holds another key than the registered one is a problem
    thread_agent = repo.unlock_in_thread()
    try:
        wrong = repo.cli("doctor")
        assert wrong.code == 1 and "this repository is registered for key" in wrong.out
    finally:
        thread_agent.stop()
