# SPDX-License-Identifier: MIT
"""Pure pieces of the guard, the hooks and the doctor (no repository needed)."""

from __future__ import annotations

from pathlib import Path

import pytest

from nbp_git_safe import doctor, guard, hooks

OID = "a" * 40


def test_parse_raw_handles_plain_diff_and_diff_tree_output() -> None:
    zero = "0" * 40
    plain = (
        f":000000 100644 {zero} {OID} A\0reports/a b.csv\0"
        f":100644 100644 {OID} {'b' * 40} M\0café/ç.txt\0"
        f":000000 160000 {zero} {'c' * 40} A\0sub\0"
    ).encode()
    changes = guard.parse_raw(plain)
    assert [(c.path, c.status, c.commit) for c in changes] == [
        ("reports/a b.csv", "A", None),
        ("café/ç.txt", "M", None),
        ("sub", "A", None),
    ]
    tree = (
        f"{'d' * 40}\0:000000 100644 {zero} {OID} A\0x\0"
        f"{'e' * 40}\0:000000 100755 {zero} {OID} A\0y\0"
    ).encode()
    assert [(c.path, c.commit) for c in guard.parse_raw(tree)] == [("x", "d" * 40), ("y", "e" * 40)]
    assert guard.parse_raw(b"") == []
    assert guard.parse_raw(b":broken\0") == []  # malformed records are skipped, not fatal


def test_pattern_lines_ignores_blanks_comments_and_markers() -> None:
    text = b"# c\n\nreports/\r\n  \n!keep.txt\n# >>> nbp-git-safe managed >>>\n"
    assert guard.pattern_lines(text) == ["reports/", "!keep.txt"]
    assert guard.pattern_lines(None) == []


@pytest.mark.parametrize(
    "line",
    ["Maria Silva/", "reports/Joao_Silva.csv", "João-Pereira/**", "x/Ana.Paula/y", "a@b.com/*"],
)
def test_lint_flags_name_or_email_like_patterns(line: str) -> None:
    warnings = guard.lint_patterns(f"# header\n{line}\n")
    assert len(warnings) == 1 and "line 2" in warnings[0]
    assert line.split("/")[0] not in warnings[0]  # the pattern itself is not echoed


@pytest.mark.parametrize(
    "line",
    [
        "reports/",
        "**/secret-*.txt",
        "build/**",
        "!build/keep.txt",
        "*.xlsx",
        "data/2024/",
        "Reports/",
    ],
)
def test_lint_accepts_generic_patterns(line: str) -> None:
    assert guard.lint_patterns(line + "\n") == []
    assert guard.lint_patterns(b"# Maria Silva in a comment\n\n") == []


def test_violation_rendering_and_report_truncation() -> None:
    assert guard.Violation("path", "a/b", "bad").render() == "path: a/b: bad"
    assert guard.Violation("vault", "", "bad").render() == "vault: bad"
    report = guard.Report([guard.Violation("path", f"f{i}", "x") for i in range(25)])
    lines = guard.format_report(report)
    assert len(lines) == guard.MAX_LISTED + 1 and lines[-1].endswith("and 5 more")
    assert not report.ok and guard.Report().ok
    other = guard.Report([], ["w"])
    report.extend(other)
    assert report.warnings == ["w"]


def test_push_stdin_parsing_and_delete_detection() -> None:
    zero = "0" * 40
    text = (
        f"refs/heads/main {OID} refs/heads/main {zero}\n(delete) {zero} refs/heads/x {OID}\nbad\n"
    )
    updates = guard.parse_push_stdin(text)
    assert len(updates) == 2
    assert not updates[0].is_delete and updates[1].is_delete
    assert guard.parse_push_stdin(text.encode()) == updates


def test_posix_quote_and_shim_roundtrip_with_hostile_paths() -> None:
    assert hooks.posix_quote("a b") == "'a b'"
    assert hooks.posix_quote("it's") == "'it'\\''s'"
    for python in ["C:/Program Files/Python 3/python.exe", "/opt/it's here/python", "/x/ü ñ/py"]:
        for event in hooks.EVENTS:
            text = hooks.shim_text(event, python)
            assert hooks.is_our_shim(text, event)
            assert not hooks.is_our_shim(
                text, "pre-commit" if event != "pre-commit" else "pre-push"
            )
            assert hooks.hook_command(event, python).startswith(
                hooks.posix_quote(python) + " -I -m"
            )
    # anything that is not exactly our shape is "foreign"
    base = hooks.shim_text("pre-commit", "/p/python")
    for text in [
        "",
        "#!/bin/sh\nexit 0\n",
        base + "echo extra\n",
        base.replace("-I -m", "-m"),
        base.replace("exec ", "exec; rm -rf x; "),
        "\n" + base,
    ]:
        assert not hooks.is_our_shim(text, "pre-commit"), text


def test_hook_python_never_returns_pythonw(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "python.exe").write_bytes(b"")
    (tmp_path / "pythonw.exe").write_bytes(b"")
    monkeypatch.setattr("sys.executable", str(tmp_path / "pythonw.exe"))
    monkeypatch.setattr("sys.platform", "win32")
    assert hooks.hook_python().endswith("/python.exe")


@pytest.mark.parametrize(
    ("parts", "expected"),
    [
        (("C:\\", "Users", "x", "OneDrive", "work"), "OneDrive"),
        (("C:\\", "Users", "x", "OneDrive - Contoso", "work"), "OneDrive"),
        (("home", "x", "Dropbox", "p"), "Dropbox"),
        (("G:\\", "My Drive", "p"), "Google Drive"),
        (("home", "x", "Google Drive", "p"), "Google Drive"),
        (("Users", "x", "Library", "Mobile Documents", "p"), "iCloud"),
        (("Users", "x", "iCloud Drive", "p"), "iCloud"),
        (("home", "x", "projects", "p"), None),
        (("home", "x", "onedrivefoo", "p"), None),
    ],
)
def test_cloud_sync_folder_heuristic_by_name(
    tmp_path: Path, parts: tuple[str, ...], expected: str | None
) -> None:
    base = tmp_path.joinpath(*(p.strip("\\:/") or "root" for p in parts))
    assert doctor.cloud_sync_client(base, {}) == expected


def test_cloud_sync_folder_heuristic_by_environment(tmp_path: Path) -> None:
    root = tmp_path / "sync-root"
    (root / "repo").mkdir(parents=True)
    assert doctor.cloud_sync_client(root / "repo", {"OneDriveCommercial": str(root)}) == "OneDrive"
    assert doctor.cloud_sync_client(tmp_path / "elsewhere", {"OneDrive": str(root)}) is None
    assert doctor.cloud_sync_client(root, {}) is None


def test_doctor_exit_code_follows_problems() -> None:
    ok = [doctor.Finding(doctor.OK, "x"), doctor.Finding(doctor.WARN, "w")]
    assert doctor.exit_code(ok) == 0
    assert doctor.exit_code([*ok, doctor.Finding(doctor.PROBLEM, "p")]) == 1
