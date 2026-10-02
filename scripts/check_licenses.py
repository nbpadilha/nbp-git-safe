# SPDX-License-Identifier: MIT
"""Licence gate for CI: every Python file carries ``SPDX-License-Identifier: MIT`` in its first
lines, and no file under ``src/`` has a GPL, AGPL, LGPL or MPL header. Prints file names only.

Run from the repository root: ``python scripts/check_licenses.py``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOTS = ("src", "tests", "scripts")
HEADER_LINES = 40
SPDX_MIT = re.compile(r"SPDX-License-Identifier:\s*MIT\s*$", re.MULTILINE)
# Built from pieces so that this very file does not match its own patterns.
COPYLEFT = re.compile(
    r"GNU\s+(?:Affero\s+|Lesser\s+|Library\s+)?General\s+Public\s+Licen[sc]e"
    r"|Mozilla\s+Public\s+Licen[sc]e"
    r"|SPDX-License-Identifier:\s*\(?\s*(?:A|L)?GPL|SPDX-License-Identifier:\s*\(?\s*MPL",
    re.IGNORECASE,
)


def check(root: Path) -> list[str]:
    problems: list[str] = []
    for top in ROOTS:
        base = root / top
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            rel = path.relative_to(root).as_posix()
            head = "\n".join(path.read_text(encoding="utf-8").splitlines()[:HEADER_LINES])
            if not SPDX_MIT.search(head):
                problems.append(f"{rel}: missing 'SPDX-License-Identifier: MIT'")
            if top == "src" and COPYLEFT.search(head):
                problems.append(f"{rel}: copyleft licence header (GPL/AGPL/LGPL/MPL)")
    return problems


def main() -> int:
    problems = check(Path.cwd())
    for line in problems:
        print(line)
    if problems:
        print(f"licence check failed: {len(problems)} problem(s)")
        return 1
    print("licence check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
