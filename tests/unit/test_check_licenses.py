# SPDX-License-Identifier: MIT
"""The CI licence gate (``scripts/check_licenses.py``) on synthetic trees."""

from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "check_licenses.py"
spec = importlib.util.spec_from_file_location("check_licenses", SCRIPT)
assert spec is not None and spec.loader is not None
check_licenses = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_licenses)

GOOD = "# SPDX-License-Identifier: MIT\nx = 1\n"


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_clean_tree_passes(tmp_path: Path) -> None:
    write(tmp_path, "src/pkg/a.py", GOOD)
    write(tmp_path, "tests/test_a.py", GOOD)
    assert check_licenses.check(tmp_path) == []


def test_missing_spdx_is_reported(tmp_path: Path) -> None:
    write(tmp_path, "src/pkg/a.py", "x = 1\n")
    problems = check_licenses.check(tmp_path)
    assert len(problems) == 1 and "src/pkg/a.py" in problems[0]


def test_spdx_beyond_the_header_window_does_not_count(tmp_path: Path) -> None:
    write(tmp_path, "src/a.py", "\n" * 60 + GOOD)
    assert len(check_licenses.check(tmp_path)) == 1


def test_copyleft_headers_in_src_are_reported(tmp_path: Path) -> None:
    for i, header in enumerate(
        [
            "# This file is licensed under the GNU General Public License v3\n",
            "# GNU Affero General Public License\n",
            "# Mozilla Public License 2.0\n",
            "# SPDX-License-Identifier: GPL-3.0-or-later\n",
        ]
    ):
        write(tmp_path, f"src/c{i}.py", header + GOOD)
    problems = check_licenses.check(tmp_path)
    assert sum("copyleft" in p for p in problems) == 4


def test_other_license_ids_are_not_flagged_as_copyleft_but_need_mit(tmp_path: Path) -> None:
    write(tmp_path, "src/a.py", "# SPDX-License-Identifier: Apache-2.0\nx = 1\n")
    problems = check_licenses.check(tmp_path)
    assert len(problems) == 1 and "missing" in problems[0]


def test_main_exit_codes(tmp_path: Path, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    write(tmp_path, "src/a.py", GOOD)
    monkeypatch.chdir(tmp_path)
    assert check_licenses.main() == 0
    write(tmp_path, "src/b.py", "x = 1\n")
    assert check_licenses.main() == 1
    assert "failed" in capsys.readouterr().out


def test_this_repository_passes() -> None:
    assert check_licenses.check(SCRIPT.parents[1]) == []
