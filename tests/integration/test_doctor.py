# SPDX-License-Identifier: MIT
"""``doctor``: what it reports, when it exits non-zero, and that it never changes anything."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from nbp_git_safe import doctor, hooks, protect
from nbp_git_safe.config import load_config
from nbp_git_safe.gitutil import discover
from tests.helpers import NbpRepo
from tests.integration.conftest import Env
from tests.integration.guardkit import commit, first_protected, prune_unreachable
from tests.integration.test_vault_tamper import read_vault, write_vault_commit


def levels(report_out: str, level: str) -> list[str]:
    return [line for line in report_out.splitlines() if line.startswith(f"[{level}]")]


def snapshot_state(repo: NbpRepo) -> dict[str, str]:
    """Hash of everything doctor could change: .git/config, exclude, hooks, refs, working files."""
    result = {}
    for rel in (".git/config", ".git/info/exclude", ".git/packed-refs"):
        path = repo.path / rel
        result[rel] = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else ""
    result["refs"] = repo.sh("for-each-ref")
    result["status"] = repo.sh("status", "--porcelain", "--ignored")
    return result


def test_uninitialised_repository_has_problems(env: Env) -> None:
    report = env.repo.cli("doctor")
    assert report.code == 1
    problems = levels(report.out, "PROBLEM")
    assert any("hook pre-commit" in p for p in problems)
    assert any("exclude block is missing" in p for p in problems)
    assert "problem(s)" in report.out.splitlines()[-1]


def test_initialised_repository_is_clean_and_doctor_is_read_only(hooked: Env) -> None:
    repo = hooked.repo
    before = snapshot_state(repo)
    report = repo.cli("doctor")
    assert report.code == 0, report.out
    assert report.out.splitlines()[-1] == "no problems found"
    assert not levels(report.out, "PROBLEM") and not levels(report.out, "warn")
    for line in ("git 2.", "hook pre-push: installed", "exclude block present", "vault verifies"):
        assert any(line in row for row in report.out.splitlines()), line
    assert snapshot_state(repo) == before


def test_locked_agent_is_informational_not_a_problem(hooked: Env) -> None:
    hooked.agent.stop()
    report = hooked.repo.cli("doctor")
    assert report.code == 0
    assert any("agent is locked" in row for row in levels(report.out, "info"))


def test_tracked_clear_file_is_a_problem_with_the_fix_in_the_message(hooked: Env) -> None:
    repo = hooked.repo
    repo.write("reports/oops.csv", "x")
    repo.sh("add", "-f", "reports/oops.csv")
    assert commit(repo, "bypass", "--no-verify").returncode == 0
    report = repo.cli("doctor")
    assert report.code == 1
    assert any(
        "tracked on the main branch" in p and "git rm --cached" in p
        for p in levels(report.out, "PROBLEM")
    )


def test_stash_with_clear_files_is_a_problem(hooked: Env) -> None:
    repo = hooked.repo
    repo.write("docs/touch.md", "tracked change to stash\n")
    repo.sh("add", "docs/touch.md")
    assert commit(repo, "tracked doc").returncode == 0
    repo.write("docs/touch.md", "modified\n")
    stash = repo.raw("stash", "push", "--all", "-q")
    assert stash.returncode == 0, stash.stderr
    assert repo.sh("stash", "list").strip()
    report = repo.cli("doctor")
    assert report.code == 1
    assert any("inside a stash" in p for p in levels(report.out, "PROBLEM"))
    repo.sh("stash", "drop", "-q")
    prune_unreachable(repo)
    assert repo.cli("doctor").code == 0


def test_hook_tampering_and_disabling_are_detected_and_init_repairs(hooked: Env) -> None:
    repo = hooked.repo
    name = hooks.hook_name("pre-commit")
    repo.sh("config", "--local", f"hook.{name}.command", "echo definitely-not-us")
    repo.sh("config", "--local", f"hook.{hooks.hook_name('pre-push')}.enabled", "false")
    repo.sh("config", "--local", "hook.post-commit.enabled", "false")
    repo.sh("config", "--local", "--add", f"hook.{hooks.hook_name('post-merge')}.event", "pre-push")
    repo.sh("config", "--local", "--unset-all", f"hook.{hooks.hook_name('post-checkout')}.event")
    report = repo.cli("doctor")
    assert report.code == 1
    text = "\n".join(levels(report.out, "PROBLEM"))
    assert "hook pre-commit: config hook command differs" in text
    assert "hook pre-push: hook is disabled" in text
    assert "hook post-commit: all post-commit hooks are disabled" in text
    assert "hook post-merge: config hook has unexpected events" in text
    assert "hook post-checkout:" in text  # no event left: reported as not installed
    repo.sh("config", "--local", "--unset", "hook.post-commit.enabled")
    assert repo.cli("init").code == 0
    assert repo.cli("doctor").code == 0


def test_stale_exclude_block_is_a_warning_and_missing_one_a_problem(hooked: Env) -> None:
    repo = hooked.repo
    repo.write(".nbp-safe", repo.read(".nbp-safe").decode() + "new-private/\n")
    stale = repo.cli("doctor")
    assert stale.code == 0 and any("out of date" in w for w in levels(stale.out, "warn"))
    exclude = repo.path / ".git" / "info" / "exclude"
    exclude.write_text("")
    gone = repo.cli("doctor")
    assert gone.code == 1 and any(
        "exclude block is missing" in p for p in levels(gone.out, "PROBLEM")
    )


def test_settings_are_reported_without_secrets(hooked: Env) -> None:
    repo = hooked.repo
    repo.sh("config", "--local", "core.autocrlf", "true")
    (repo.path / ".nbp-safe.config").write_text(
        "[vault]\nref = refs/heads/nbp-safe\n[core]\neditor = vim\n"
    )
    repo.sh("config", "--local", "--unset", "nbp-safe.keyCommand")
    report = repo.cli("doctor")
    assert any("core.autocrlf=true" in i for i in levels(report.out, "info"))
    warns = "\n".join(levels(report.out, "warn"))
    assert "no keyCommand configured" in warns and "ignored" in warns
    assert "python" not in report.out.lower().replace("pythonic", "")  # no command line echoed


def test_cloud_sync_folder_warning(hooked: Env, tmp_path: Path) -> None:
    repo, git = discover(hooked.repo.path, hooked.git.env)
    cfg = load_config(git, repo)
    findings = doctor.run_doctor(git, repo, cfg, environ={"OneDrive": str(tmp_path)})
    cloud = [f for f in findings if "OneDrive folder" in f.message]
    assert cloud and cloud[0].level == doctor.WARN
    assert not [f for f in doctor.run_doctor(git, repo, cfg, environ={}) if "OneDrive" in f.message]


def test_vault_divergence_with_origin(hooked: Env) -> None:
    repo = hooked.repo
    assert repo.raw("push", "-q", "origin", "main", "nbp-safe").returncode == 0
    base = hooked.tip()
    assert "diverged" not in repo.cli("doctor").out
    repo.write(first_protected(repo, ".json"), '{"v": 2}\n')
    assert commit(repo, "second", "--allow-empty").returncode == 0
    ahead = repo.cli("doctor")
    assert any("1 commit(s) ahead of origin" in i for i in levels(ahead.out, "info"))
    assert repo.raw("push", "-q", "origin", "nbp-safe").returncode == 0
    newer = hooked.tip()
    repo.sh("update-ref", "refs/heads/nbp-safe", base)
    behind = repo.cli("doctor")
    assert any("1 commit(s) behind origin" in i for i in levels(behind.out, "info"))
    write_vault_commit(repo, read_vault(repo), base)  # a sibling of `newer`
    assert hooked.tip() not in (base, newer)
    diverged = repo.cli("doctor")
    assert any("diverged from origin" in w for w in levels(diverged.out, "warn"))


def test_vault_that_does_not_verify_is_a_problem(hooked: Env) -> None:
    repo = hooked.repo
    files = read_vault(repo)
    files["nbp-safe/index"] = b"not an index"
    write_vault_commit(repo, files, hooked.tip())
    report = repo.cli("doctor")
    assert report.code == 1
    assert any("vault does not verify" in p for p in levels(report.out, "PROBLEM"))


def test_nothing_protected_yet_is_a_warning(hooked: Env) -> None:
    repo = hooked.repo
    (repo.path / ".nbp-safe").unlink()
    shutil.rmtree(repo.path / ".git" / "nbp-safe" / protect.VERSIONS_DIR)  # a clone with no memory
    report = repo.cli("doctor")
    assert any("nothing is protected yet" in w for w in levels(report.out, "warn"))


def test_a_deleted_pattern_file_is_still_protecting_through_the_memory(hooked: Env) -> None:
    repo = hooked.repo
    (repo.path / ".nbp-safe").unlink()
    report = repo.cli("doctor")
    assert not any("nothing is protected yet" in w for w in levels(report.out, "warn"))
    assert any("still protected here" in w for w in levels(report.out, "warn"))
