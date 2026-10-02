# SPDX-License-Identifier: MIT
from __future__ import annotations

import json
from pathlib import Path

import pytest

from nbp_git_safe import config
from nbp_git_safe.config import ConfigError, load_config
from nbp_git_safe.gitutil import Git, Repo, discover
from tests.conftest import IsolatedGit


@pytest.fixture
def repo_git(isolated_git: IsolatedGit, tmp_path: Path) -> tuple[Repo, Git, IsolatedGit]:
    isolated_git.init(tmp_path / "r")
    repo, git = discover(tmp_path / "r", isolated_git.env)
    return repo, git, isolated_git


def _set(ig: IsolatedGit, repo: Repo, key: str, value: str) -> None:
    ig.run("config", "--local", key, value, cwd=repo.toplevel)


def test_defaults(repo_git: tuple[Repo, Git, IsolatedGit]) -> None:
    repo, git, _ = repo_git
    cfg = load_config(git, repo, env={})
    assert cfg.key_command is None
    assert cfg.ttl == 8 * 3600
    assert cfg.idle_timeout is None
    assert (cfg.on_missing, cfg.pad_bucket, cfg.vault_ref) == ("keep", 4096, "refs/heads/nbp-safe")
    assert cfg.time_granularity == 3600
    assert cfg.auto_unlock is False and cfg.auto_push is False
    assert cfg.key_command_timeout == 120.0
    assert cfg.remote_vault_ref == "refs/remotes/origin/nbp-safe"


def test_precedence_flag_env_gitconfig_versioned(repo_git: tuple[Repo, Git, IsolatedGit]) -> None:
    repo, git, ig = repo_git
    (repo.toplevel / ".nbp-safe.config").write_text(
        "[pad]\n\tbucket = 1024\n[nbp-safe]\n\tonMissing = remove\n"
    )
    assert load_config(git, repo, env={}).pad_bucket == 1024  # versioned beats default
    # review M6: onMissing decides whether a locally deleted file leaves the vault, so a versioned
    # file (a collaborator's commit) cannot set it; only the local config can
    assert load_config(git, repo, env={}).on_missing == "keep"
    _set(ig, repo, "nbp-safe.onMissing", "remove")
    assert load_config(git, repo, env={}).on_missing == "remove"
    ig.run("config", "--local", "--unset", "nbp-safe.onMissing", cwd=repo.toplevel)
    _set(ig, repo, "nbp-safe.padBucket", "2048")
    assert load_config(git, repo, env={}).pad_bucket == 2048  # .git/config beats versioned
    env = {"NBP_SAFE_PADBUCKET": "512"}
    assert load_config(git, repo, env=env).pad_bucket == 512  # env beats .git/config
    flags = {"padbucket": "256"}
    assert load_config(git, repo, flags, env=env).pad_bucket == 256  # flag beats env
    assert load_config(git, repo, {"padbucket": None}, env=env).pad_bucket == 512


def test_values_are_parsed(repo_git: tuple[Repo, Git, IsolatedGit]) -> None:
    repo, git, ig = repo_git
    for key, value in {
        "ttl": "2h",
        "idleTimeout": "15m",
        "autoUnlock": "yes",
        "autoPush": "false",
        "timeGranularity": "day",
        "keyCommandTimeout": "2.5",
    }.items():
        _set(ig, repo, f"nbp-safe.{key}", value)
    cfg = load_config(git, repo, env={})
    assert (cfg.ttl, cfg.idle_timeout) == (7200, 900)
    assert cfg.auto_unlock is True and cfg.auto_push is False
    assert cfg.time_granularity == 86400
    assert cfg.key_command_timeout == 2.5


def test_key_command_only_from_local_git_config(repo_git: tuple[Repo, Git, IsolatedGit]) -> None:
    repo, git, ig = repo_git
    argv = ["op", "document", "get", "ITEM", "--vault", "VAULT"]
    _set(ig, repo, "nbp-safe.keyCommand", json.dumps(argv))
    assert load_config(git, repo, env={}).key_command == tuple(argv)
    # flags and environment cannot set it ...
    cfg = load_config(
        git, repo, {"keycommand": '["evil"]'}, env={"NBP_SAFE_KEYCOMMAND": '["evil"]'}
    )
    assert cfg.key_command == tuple(argv)
    # ... and neither can the versioned file (it is ignored, and reported)
    ig.run("config", "--local", "--unset", "nbp-safe.keyCommand", cwd=repo.toplevel)
    (repo.toplevel / ".nbp-safe.config").write_text(
        '[nbp-safe]\n\tkeyCommand = ["evil"]\n[core]\n\thooksPath = /x\n'
        "[vault]\n\tref = refs/heads/nbp-safe\n"
    )
    cfg = load_config(git, repo, env={"NBP_SAFE_KEYCOMMAND": '["evil"]'})
    assert cfg.key_command is None
    # vault.ref joined the ignored keys in the second review (it used to be honoured)
    assert set(cfg.ignored_versioned_keys) == {"nbp-safe.keycommand", "core.hookspath", "vault.ref"}


def test_vault_ref_is_a_local_option_only(repo_git: tuple[Repo, Git, IsolatedGit]) -> None:
    repo, git, ig = repo_git
    (repo.toplevel / ".nbp-safe.config").write_text("[vault]\n\tref = refs/heads/nbp-safe-x\n")
    cfg = load_config(git, repo, env={})
    assert cfg.vault_ref == "refs/heads/nbp-safe" and "vault.ref" in cfg.ignored_versioned_keys
    _set(ig, repo, "nbp-safe.vaultRef", "refs/heads/nbp-safe-2026")  # the local decision
    assert load_config(git, repo, env={}).vault_ref == "refs/heads/nbp-safe-2026"
    flagged = load_config(git, repo, {"vaultref": "refs/heads/nbp-safe-y"}, env={})
    assert flagged.vault_ref == "refs/heads/nbp-safe-y"
    from_env = load_config(git, repo, env={"NBP_SAFE_VAULTREF": "refs/heads/nbp-safe-z"})
    assert from_env.vault_ref == "refs/heads/nbp-safe-z"


def test_repr_hides_key_command(repo_git: tuple[Repo, Git, IsolatedGit]) -> None:
    repo, git, ig = repo_git
    _set(ig, repo, "nbp-safe.keyCommand", '["op","read","op://SECRET-ITEM"]')
    assert "SECRET-ITEM" not in repr(load_config(git, repo, env={}))


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("ttl", "soon"),
        ("ttl", "0"),
        ("ttl", "9999d"),
        ("idleTimeout", "x"),
        ("onMissing", "explode"),
        ("padBucket", "0"),
        ("padBucket", "abc"),
        ("padBucket", str(2**21)),
        ("vaultRef", "refs/heads/main"),
        ("vaultRef", "refs/heads/nbp-safe..x"),
        ("vaultRef", "refs/heads/nbp-safe.lock"),
        ("timeGranularity", "fortnight"),
        ("autoUnlock", "maybe"),
        ("keyCommandTimeout", "x"),
        ("keyCommandTimeout", "0"),
        ("keyCommand", "op read"),
        ("keyCommand", "[]"),
        ("keyCommand", "[1, 2]"),
        ("keyCommand", '["", "x"]'),
        ("keyCommand", '{"a": 1}'),
    ],
)
def test_invalid_values_are_rejected(
    repo_git: tuple[Repo, Git, IsolatedGit], key: str, value: str
) -> None:
    repo, git, ig = repo_git
    _set(ig, repo, f"nbp-safe.{key}", value)
    with pytest.raises(ConfigError):
        load_config(git, repo, env={})


def test_error_messages_never_include_the_value(repo_git: tuple[Repo, Git, IsolatedGit]) -> None:
    repo, git, ig = repo_git
    _set(ig, repo, "nbp-safe.keyCommand", "op read op://VERY-SECRET-REFERENCE")
    with pytest.raises(ConfigError) as exc:
        load_config(git, repo, env={})
    assert "VERY-SECRET-REFERENCE" not in str(exc.value)


def test_idle_off_and_bool_variants(repo_git: tuple[Repo, Git, IsolatedGit]) -> None:
    repo, git, _ = repo_git
    assert load_config(git, repo, {"idletimeout": "off"}, env={}).idle_timeout is None
    assert load_config(git, repo, {"autounlock": "1"}, env={}).auto_unlock is True
    assert load_config(git, repo, {"autounlock": "off"}, env={}).auto_unlock is False


def test_granularity_names_and_seconds(repo_git: tuple[Repo, Git, IsolatedGit]) -> None:
    repo, git, _ = repo_git
    assert load_config(git, repo, {"timegranularity": "minute"}, env={}).time_granularity == 60
    assert load_config(git, repo, {"timegranularity": "90"}, env={}).time_granularity == 90


def test_invalid_versioned_file_is_an_error(repo_git: tuple[Repo, Git, IsolatedGit]) -> None:
    repo, git, _ = repo_git
    (repo.toplevel / ".nbp-safe.config").write_text("[unterminated\n")
    with pytest.raises(ConfigError, match="not valid"):
        load_config(git, repo, env={})


def test_environment_defaults_to_os_environ(
    repo_git: tuple[Repo, Git, IsolatedGit], monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, git, _ = repo_git
    monkeypatch.setenv("NBP_SAFE_TTL", "45m")
    assert load_config(git, repo).ttl == 45 * 60


def test_parse_duration_units() -> None:
    assert config.parse_duration("90", what="x") == 90
    assert config.parse_duration("2 d", what="x") == 172800
    assert config.parse_duration("0", what="x", allow_zero=True) == 0
    assert (
        config.versioned_config_path(Repo(Path("/a"), Path("/a/.git"), Path("/a/.git"))).name
        == ".nbp-safe.config"
    )
