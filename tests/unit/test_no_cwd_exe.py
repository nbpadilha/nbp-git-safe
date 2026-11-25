# SPDX-License-Identifier: MIT
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

from nbp_git_safe import cli, gitutil, unlock


def test_main_sets_process_variable(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv(gitutil.NO_CWD_EXE, raising=False)
    assert cli.main([]) == 0
    capsys.readouterr()
    assert os.environ[gitutil.NO_CWD_EXE] == "1"


@pytest.mark.skipif(sys.platform != "win32", reason="cwd-in-exe-search is a Windows behavior")
def test_planted_program_in_cwd_does_not_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    planted = tmp_path / "plantedop.exe"
    hostname = Path(os.environ["SYSTEMROOT"]) / "System32" / "hostname.exe"
    shutil.copyfile(hostname, planted)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", str(Path(os.environ["SYSTEMROOT"]) / "System32"))
    monkeypatch.delenv(gitutil.NO_CWD_EXE, raising=False)

    # the planted copy runs (bare name, cwd searched first) and its output is not a key
    with pytest.raises(unlock.KeyCommandError, match="not a valid key"):
        unlock.run_key_command(["plantedop"], 10)

    gitutil.protect_process_env()
    with pytest.raises(unlock.KeyCommandError, match="not found"):
        unlock.run_key_command(["plantedop"], 10)
