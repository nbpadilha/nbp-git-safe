# SPDX-License-Identifier: MIT
"""Regressions for the recommended review items: M4 (a .gitignore negation re-exposes protected
files), M5 (NFD names vs NFC patterns), M6 (versioned config cannot weaken), M7 (executables are
not looked up in the current directory), B1 (no names in the OS temp dir), B3 (conflict and temp
files are guarded), B5 (purge instructions)."""

from __future__ import annotations

import os
import shutil
import sys
import unicodedata
from pathlib import Path

import pytest

from nbp_git_safe import config, gitutil, multi
from nbp_git_safe.config import load_config
from nbp_git_safe.gitutil import Git, discover
from tests.conftest import IsolatedGit
from tests.integration.conftest import Env
from tests.integration.guardkit import commit, first_protected, prune_unreachable, staged


# ------------------------------------------------------------------------------------ M4
def test_a_gitignore_negation_is_reported_and_the_commit_guard_still_holds(hooked: Env) -> None:
    repo = hooked.repo
    repo.write(".gitignore", "!reports/\n!reports/**\n")
    report = repo.cli("doctor")  # before anything is staged
    assert report.code == 1
    assert "NOT ignored by git" in report.out
    repo.sh("add", "-A")
    assert any(p.startswith("reports/") for p in staged(repo)), "layer 1 is defeated by design"
    blocked = commit(repo, "everything")
    assert blocked.returncode != 0 and "matches the protected set" in blocked.stderr
    prune_unreachable(repo)


def test_doctor_is_quiet_when_git_ignores_every_protected_file(hooked: Env) -> None:
    assert "NOT ignored" not in hooked.repo.cli("doctor").out


# ------------------------------------------------------------------------------------ M5
def test_an_nfd_name_is_caught_by_an_nfc_pattern_at_commit_time(hooked: Env) -> None:
    repo = hooked.repo
    (repo.path / ".git" / "info" / "nbp-safe").write_text("relatório*.txt\n", encoding="utf-8")
    assert repo.cli("init").code == 0
    nfd = unicodedata.normalize("NFD", "relatório-anual.txt")
    repo.write(nfd, f"secret {repo.canaries[2]}\n")
    repo.sh("add", "-A")  # git compares bytes: layer 1 cannot see it, layer 2 can
    blocked = commit(repo, "x")
    if sys.platform == "darwin":
        # macOS git (core.precomposeunicode) normalises the name to NFC itself, so the exclude
        # block (layer 1) already ignores it: nothing is staged and no commit is made.
        assert blocked.returncode != 0
        assert not [n for n in repo.sh("ls-files").splitlines() if "anual" in n]
    else:
        assert blocked.returncode != 0 and "matches the protected set" in blocked.stderr
    prune_unreachable(repo)


def test_non_ascii_patterns_get_a_lint_warning() -> None:
    from nbp_git_safe import guard

    warnings = guard.lint_patterns("relatório*.txt\nplain/\n")
    assert len(warnings) == 1 and "line 1" in warnings[0] and "non-ASCII" in warnings[0]
    assert guard.lint_patterns("plain/\n*.csv\n") == []


# ------------------------------------------------------------------------------------ M6
def versioned_config(isolated_git: IsolatedGit, tmp_path: Path, text: str):  # type: ignore[no-untyped-def]
    root = isolated_git.init(tmp_path / "cfg")
    (root / ".nbp-safe.config").write_text(text)
    repo, git = discover(root, isolated_git.env)
    return repo, git, load_config(git, repo, env={})


def test_versioned_config_cannot_weaken_padding_or_rounding(
    isolated_git: IsolatedGit, tmp_path: Path
) -> None:
    _r, _g, cfg = versioned_config(
        isolated_git, tmp_path, "[pad]\n\tbucket = 1\n[commit]\n\ttimeGranularity = 1\n"
    )
    assert cfg.pad_bucket == config.MIN_VERSIONED_BUCKET == 1024
    assert cfg.time_granularity == config.MIN_VERSIONED_GRANULARITY == 60
    assert set(cfg.raised_versioned_keys) == {"padbucket", "timegranularity"}


def test_versioned_config_may_ask_for_more_privacy(
    isolated_git: IsolatedGit, tmp_path: Path
) -> None:
    _r, _g, cfg = versioned_config(
        isolated_git, tmp_path, "[pad]\n\tbucket = 65536\n[commit]\n\ttimeGranularity = day\n"
    )
    assert cfg.pad_bucket == 65536 and cfg.time_granularity == 86400
    assert cfg.raised_versioned_keys == ()


def test_on_missing_only_comes_from_the_local_config(
    isolated_git: IsolatedGit, tmp_path: Path
) -> None:
    repo, git, cfg = versioned_config(isolated_git, tmp_path, "[nbp-safe]\n\tonMissing = remove\n")
    assert cfg.on_missing == "keep"
    assert "nbp-safe.onmissing" in cfg.ignored_versioned_keys
    git.run("config", "--local", "nbp-safe.onMissing", "remove")
    assert load_config(git, repo, env={}).on_missing == "remove"  # the owner may choose it


def test_the_local_config_may_go_below_the_versioned_floor(
    isolated_git: IsolatedGit, tmp_path: Path
) -> None:
    repo, git, _cfg = versioned_config(isolated_git, tmp_path, "[pad]\n\tbucket = 1\n")
    git.run("config", "--local", "nbp-safe.padBucket", "256")
    assert (
        load_config(git, repo, env={}).pad_bucket == 256
    )  # an owner decision, not a collaborator's


def test_doctor_reports_a_raised_value(hooked: Env) -> None:
    hooked.repo.write(".nbp-safe.config", "[pad]\n\tbucket = 1\n")
    assert "below the privacy floor" in hooked.repo.cli("doctor").out


# ------------------------------------------------------------------------------------ M7
def test_resolve_executable_never_picks_the_current_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    here, real = tmp_path / "here", tmp_path / "real"
    here.mkdir()
    real.mkdir()
    name = "toolx.exe" if sys.platform == "win32" else "toolx"
    for folder in (here, real):
        (folder / name).write_bytes(b"x")
        (folder / name).chmod(0o755)
    monkeypatch.chdir(here)
    path = os.pathsep.join(["", ".", "relative-dir", str(here), str(real)])
    found = gitutil.resolve_executable("toolx", {"PATH": path, "PATHEXT": ".EXE;.CMD"})
    assert Path(found) == real / name
    assert gitutil.resolve_executable("nothing-like-this", {"PATH": path}) == "nothing-like-this"
    explicit = str(here / "toolx")
    assert gitutil.resolve_executable(explicit, {"PATH": path}) == explicit  # a path: untouched
    assert gitutil.child_env({"PATH": "1", "A": "1"}) == {
        "PATH": "1",
        "NoDefaultCurrentDirectoryInExePath": "1",
    }


@pytest.mark.skipif(sys.platform != "win32", reason="CreateProcess looks in the current directory")
def test_a_git_exe_in_the_current_directory_is_not_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = Path(sys._base_executable)
    planted = tmp_path / "planted"
    planted.mkdir()
    shutil.copy(base, planted / "git.exe")  # runs "python" instead of git, if it is ever picked
    for dll in base.parent.glob("python3*.dll"):
        shutil.copy(dll, planted)
    monkeypatch.chdir(planted)
    monkeypatch.setattr(gitutil, "_git_exe", {})
    out = Git(planted).text("--version")
    assert out.startswith("git version"), out
    assert Path(gitutil.git_executable()).parent != planted


# ------------------------------------------------------------------------------------ B1
def test_names_of_local_patterns_never_reach_the_os_temp_dir(hooked: Env) -> None:
    repo = hooked.repo
    name = f"private-{repo.canaries[3]}"
    (repo.path / ".git" / "info" / "nbp-safe").write_text(f"{name}*\n", encoding="utf-8")
    assert repo.cli("init").code == 0
    repo.write(f"{name}-file.txt", f"content {repo.canaries[3]}\n")
    repo.write("plain.txt", "ordinary\n")
    repo.sh("add", "-A")
    assert commit(repo, "work").returncode == 0  # runs the matcher through the hooks
    from tests import helpers
    from tests.leak.harness import assert_no_leaks

    # (info/exclude and info/nbp-safe hold the local patterns by design; the OS temp must not)
    assert_no_leaks(repo.leak_scanner().scan_dir(helpers.SYSTEM_TEMP[0]))
    assert not any(helpers.SYSTEM_TEMP[0].rglob("nbp-match-*"))  # the old scratch dir is gone


# ------------------------------------------------------------------------------------ B3
@pytest.mark.parametrize("suffix", [".nbp-theirs", ".nbp-tmp"])
def test_conflict_and_temp_files_cannot_be_committed(hooked: Env, suffix: str) -> None:
    repo = hooked.repo
    rel = first_protected(repo, ".csv")
    repo.write("copy" + suffix, repo.read(rel))
    repo.sh("add", "-f", "copy" + suffix)
    blocked = commit(repo, "oops")
    assert blocked.returncode != 0 and "copy" + suffix in blocked.stderr
    prune_unreachable(repo)


# ------------------------------------------------------------------------------------ B5
def test_purge_instructions_remove_packed_objects_too(hooked: Env) -> None:
    repo_obj, git = discover(hooked.repo.path, hooked.git.env)
    cfg = load_config(git, repo_obj)
    result = multi.PurgeResult("a" * 40, "b" * 40, [], 1, "c" * 40)
    text = "\n".join(multi.purge_instructions(cfg, result))
    assert "git gc --prune=now" in text
    assert "git prune --expire now" not in text
