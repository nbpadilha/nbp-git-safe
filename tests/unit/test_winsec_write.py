# SPDX-License-Identifier: MIT
"""Who can CHANGE a file or a folder (used for the program that autostart registers): the SDDL
reading is pure and runs everywhere; the real ACL check runs on Windows only, on files created
for the test (``icacls`` adds and removes the extra grant)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from nbp_git_safe import winsec

ME = "S-1-5-21-111-222-333-1001"


@pytest.mark.parametrize(
    "sddl",
    [
        f"D:(A;;FA;;;{ME})(A;;FA;;;SY)(A;;FA;;;BA)",
        "D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)",  # Users: read and execute
        "D:(A;;FRFX;;;AU)(A;;FA;;;BA)",  # Authenticated Users: read only
        "D:(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;SY)",
        "D:(A;;FA;;;CO)(A;;FA;;;LA)",
        "D:(D;;FW;;;BU)(A;;FA;;;BA)",  # a deny entry is not a grant
        "D:",
    ],
)
def test_read_only_for_others_is_fine(sddl: str) -> None:
    assert winsec._dacl_write_problem(sddl, ME) is None


@pytest.mark.parametrize(
    ("sddl", "who"),
    [
        ("D:(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;AU)", "Authenticated Users"),  # Modify
        ("D:(A;;FA;;;WD)", "Everyone"),
        ("D:(A;;GW;;;BU)", "Users"),
        ("D:(A;;FW;;;S-1-5-21-111-222-333-1002)", "another account"),
        ("D:(A;;WD;;;BU)", "Users"),  # may rewrite the ACL
        ("D:(A;;DC;;;AU)", "Authenticated Users"),  # may delete children (replace the file)
        ("D:(A;;0x40000000;;;IU)", "Interactive users"),  # generic write
        ("D:(A;;0x2;;;PU)", "Power Users"),
        ("D:(A;;0xzz;;;BU)", "Users"),  # unreadable rights are not assumed safe
    ],
)
def test_write_access_for_others_is_reported(sddl: str, who: str) -> None:
    problem = winsec._dacl_write_problem(sddl, ME)
    assert problem == f"can be changed by {who}"


def test_a_malformed_entry_is_not_assumed_safe() -> None:
    assert winsec._dacl_write_problem("D:(A;;FA)", ME) == "unrecognised ACL entry"


@pytest.mark.skipif(sys.platform != "win32", reason="ACLs of the real file system")
def test_real_files_report_an_extra_write_grant_and_lose_it_again(tmp_path: Path) -> None:
    folder = tmp_path / "prog"
    folder.mkdir()
    exe = folder / "tool.exe"
    exe.write_bytes(b"MZ")
    # a folder only the user and SYSTEM control (the temp folder of a machine may be shared)
    protect = subprocess.run(
        [
            "icacls",
            str(folder),
            "/inheritance:r",
            "/grant",
            f"*{winsec.current_user_sid()}:(OI)(CI)F",
            "/grant",
            "*S-1-5-18:(OI)(CI)F",
        ],
        capture_output=True,
        check=False,
    )
    assert protect.returncode == 0, protect.stderr
    exe.write_bytes(b"MZ again")  # a file made after the DACL inherits it
    assert winsec.write_exposure(folder) is None
    assert winsec.write_exposure(exe) is None
    grant = subprocess.run(
        ["icacls", str(folder), "/grant", "*S-1-1-0:(OI)(CI)M"],  # Everyone: modify
        capture_output=True,
        check=False,
    )
    assert grant.returncode == 0, grant.stderr
    assert winsec.write_exposure(folder) == "can be changed by Everyone"
    assert winsec.write_exposure(exe) == "can be changed by Everyone"  # inherited by the file
    subprocess.run(["icacls", str(folder), "/remove", "*S-1-1-0"], capture_output=True, check=True)
    assert winsec.write_exposure(folder) is None
    assert winsec.write_exposure(folder / "nothing") == "does not exist"
