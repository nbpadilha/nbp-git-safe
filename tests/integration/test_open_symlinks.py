# SPDX-License-Identifier: MIT
"""``open`` never writes through a link (regression for review M2).

The temporary file used to be ``<target>.nbp-tmp``, a predictable name opened without ``O_EXCL``:
a symlink planted there made ``open`` overwrite whatever it pointed at. Now the temporary file has
a random name and is created exclusively; the destination and every directory on the way are
checked right before the write (links, junctions, reparse points), not only in the planning pass.
"""

from __future__ import annotations

import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

from nbp_git_safe import vault
from tests.integration.conftest import Env
from tests.integration.guardkit import first_protected


def symlink(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError):
        pytest.skip("no symlink privilege on this machine")


def junction(link: Path, target: Path) -> None:
    done = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, check=False
    )
    if done.returncode != 0:
        pytest.skip("cannot create a junction here")


def test_open_does_not_write_through_a_planted_tmp_symlink(hooked: Env, tmp_path: Path) -> None:
    repo = hooked.repo
    rel = first_protected(repo, ".csv")
    plain = repo.read(rel)
    (repo.path / rel).unlink()
    outside = tmp_path / "outside-public.txt"
    outside.write_bytes(b"ORIGINAL\n")
    symlink(repo.path / (rel + ".nbp-tmp"), outside)  # where the old code wrote its temp file
    result = repo.cli("open")
    assert result.code == 0, result.err
    assert outside.read_bytes() == b"ORIGINAL\n"
    assert repo.read(rel) == plain  # the file itself was restored normally


def test_open_survives_even_a_guessed_temp_name(
    hooked: Env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whatever name an attacker predicts, the temp file is created with ``O_EXCL``: the planted
    link is never opened, and the failure is reported instead of followed."""
    repo = hooked.repo
    rel = first_protected(repo, ".csv")
    (repo.path / rel).unlink()
    outside = tmp_path / "outside-public.txt"
    outside.write_bytes(b"ORIGINAL\n")
    monkeypatch.setattr(secrets, "token_hex", lambda *_a: "0123456789ab")
    planted = (repo.path / rel).with_name(".0123456789ab.nbp-tmp")
    symlink(planted, outside)
    result = repo.cli("open")
    assert outside.read_bytes() == b"ORIGINAL\n"
    assert result.code == 1 and "could not be written" in result.err
    assert not (repo.path / rel).exists()


def test_a_symlink_where_the_file_goes_is_refused(hooked: Env, tmp_path: Path) -> None:
    repo = hooked.repo
    rel = first_protected(repo, ".csv")
    (repo.path / rel).unlink()
    outside = tmp_path / "outside-public.txt"
    outside.write_bytes(b"ORIGINAL\n")
    symlink(repo.path / rel, outside)
    result = repo.cli("open")
    assert result.code == 1 and "symbolic link" in result.err
    assert outside.read_bytes() == b"ORIGINAL\n"


@pytest.mark.parametrize("kind", ["symlink", "junction"])
def test_a_linked_directory_on_the_way_is_refused(hooked: Env, tmp_path: Path, kind: str) -> None:
    if kind == "junction" and sys.platform != "win32":
        pytest.skip("junctions are a Windows thing")
    repo = hooked.repo
    rel = first_protected(repo, ".csv")
    top = rel.split("/")[0]
    outside = tmp_path / "outside-dir"
    outside.mkdir()
    for path in sorted((repo.path / top).rglob("*"), reverse=True):  # clear the real directory
        path.unlink() if path.is_file() else path.rmdir()
    (repo.path / top).rmdir()
    (symlink if kind == "symlink" else junction)(repo.path / top, outside)
    result = repo.cli("open")
    assert result.code == 1 and "symbolic link or junction" in result.err
    assert list(outside.iterdir()) == []  # nothing was written through the link


def test_the_write_itself_rechecks_the_path(hooked: Env, tmp_path: Path) -> None:
    """The planning pass checks once; the write checks again (a link planted in between)."""
    repo = hooked.repo
    outside = tmp_path / "outside-dir"
    outside.mkdir()
    top = repo.path / "swapped"
    symlink(top, outside)
    with pytest.raises(OSError, match="blocked"):
        vault._atomic_write(repo.path, "swapped/file.csv", b"data", "100644")
    assert list(outside.iterdir()) == []
    plain = repo.path / "plain" / "file.csv"
    vault._atomic_write(repo.path, "plain/file.csv", b"data", "100644")
    assert plain.read_bytes() == b"data"
    assert not [p for p in plain.parent.iterdir() if p.name.endswith(".nbp-tmp")]  # no leftovers


def test_no_temp_file_is_left_behind_after_a_normal_open(hooked: Env) -> None:
    repo = hooked.repo
    rel = first_protected(repo, ".csv")
    (repo.path / rel).unlink()
    assert repo.cli("open").code == 0
    leftovers = [p for p in repo.path.rglob("*.nbp-tmp") if ".git" not in p.parts]
    assert leftovers == []
