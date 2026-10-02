# SPDX-License-Identifier: MIT
from __future__ import annotations

import pytest

from nbp_git_safe import __version__
from nbp_git_safe.cli import main


def test_main_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert main() == 0
    assert capsys.readouterr().out == f"nbp-git-safe {__version__}\n"
