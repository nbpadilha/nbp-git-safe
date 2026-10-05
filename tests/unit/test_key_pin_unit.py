# SPDX-License-Identifier: MIT
"""Pure parts of the key-id and working-directory rules (review finding M1): which ``keyCommand``
argv depends on the folder it runs from, how that changes the grouping of ``unlock --all``, the
check of a key against the registered key id, and the working directory of the command."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from nbp_git_safe import crypto, fleetops, keyid, unlock
from nbp_git_safe.config import Config
from nbp_git_safe.fleetops import RepoHandle


@pytest.mark.parametrize(
    "argv",
    [
        ("python", "tools/key.py"),
        ("tools/key.sh",),
        ("./key",),
        ("../shared/key",),
        (".git/key.sh",),
        ("sh", ".git/key.sh"),
        ("tool", "--file=secrets/key"),
        ("tool", "--file=./key"),
        ("tool", "nested\\path"),
    ],
)
def test_relative_paths_depend_on_the_working_directory(argv: tuple[str, ...]) -> None:
    assert unlock.depends_on_cwd(argv, Path("/nowhere")) is True


def test_portable_commands_do_not(tmp_path: Path) -> None:
    absolute = str(tmp_path / "key.py")
    for argv in (
        ("op", "read", "op://vault/item/field"),
        (sys.executable, absolute),
        ("pass", "-c"),
        ("tool", "--format=json", "--name=plain"),
        ("tool", "--flag"),
        ("python", "key.py"),  # a bare name that does not exist in the root: nothing to resolve
    ):
        assert unlock.depends_on_cwd(argv, tmp_path) is False, argv


def test_a_bare_file_name_that_exists_in_the_root_depends_on_it(tmp_path: Path) -> None:
    (tmp_path / "key.py").write_text("", encoding="utf-8")
    assert unlock.depends_on_cwd(("python", "key.py"), tmp_path) is True
    assert unlock.depends_on_cwd(("key.py",), tmp_path) is False  # the program is never the cwd's


def make_handle(n: int, root: Path, command: tuple[str, ...]) -> RepoHandle:
    cfg = Config(key_command=command)
    return RepoHandle(n, root, root.name, None, None, cfg, f"{n:024x}")  # type: ignore[arg-type]


def test_a_relative_command_makes_each_repository_its_own_group(tmp_path: Path) -> None:
    roots = [tmp_path / name for name in ("a", "b", "c", "d")]
    for root in roots:
        root.mkdir()
    relative = ("python", "tools/key.py")
    portable = ("op", "read", "op://v/i")
    groups = fleetops.group_by_key_command(
        [
            make_handle(1, roots[0], relative),
            make_handle(2, roots[1], relative),
            make_handle(3, roots[2], portable),
            make_handle(4, roots[3], portable),
        ]
    )
    assert [[h.index for h in g] for g in groups] == [[1], [2], [3, 4]]


def test_check_compares_with_the_registered_id_only() -> None:
    key = crypto.generate_key()
    other = crypto.generate_key()
    keyid.check(None, keyid.of_key(key))  # nothing registered: nothing to compare
    keyid.check(keyid.of_key(key), keyid.of_key(key))
    with pytest.raises(keyid.KeyIdMismatchError) as caught:
        keyid.check(keyid.of_key(key), keyid.of_key(other))
    text = str(caught.value)
    assert keyid.of_key(other) in text and keyid.of_key(key) in text
    assert f"key-id --accept {keyid.of_key(other)}" in text
    assert crypto.encode_key(key) not in text and crypto.encode_key(other) not in text


def test_is_valid() -> None:
    assert keyid.is_valid("0123456789abcdef")
    for bad in ("", "0123456789ABCDEF", "0123456789abcde", "0123456789abcdefg", "xyz"):
        assert not keyid.is_valid(bad)


@pytest.mark.skipif(sys.platform == "win32", reason="a shell script needs a POSIX shell")
def test_key_command_runs_in_the_given_directory_and_resolves_a_relative_program(
    tmp_path: Path, master_key: bytes
) -> None:
    root = tmp_path / "repo"
    (root / "tools").mkdir(parents=True)
    script = root / "tools" / "key.sh"
    script.write_text(f"#!/bin/sh\necho '{crypto.encode_key(master_key)}'\n", encoding="ascii")
    script.chmod(0o755)
    other = tmp_path / "elsewhere"
    other.mkdir()
    previous = Path.cwd()
    os.chdir(other)
    try:
        assert unlock.run_key_command(("tools/key.sh",), 30, cwd=root) == master_key
    finally:
        os.chdir(previous)


def test_key_command_script_runs_from_the_given_directory(
    tmp_path: Path, master_key: bytes
) -> None:
    root = tmp_path / "repo"
    (root / "tools").mkdir(parents=True)
    (root / "tools" / "key.py").write_text(
        "import os, sys\nsys.stdout.write(os.environ['NBP_SAFE_TEST_KEY'])\n", encoding="utf-8"
    )
    other = tmp_path / "elsewhere"
    other.mkdir()
    previous = Path.cwd()
    os.chdir(other)
    try:
        key = unlock.run_key_command((sys.executable, "tools/key.py"), 30, cwd=root)
        assert key == master_key
        with pytest.raises(unlock.KeyCommandError):  # without cwd it looks next to the caller
            unlock.run_key_command((sys.executable, "tools/key.py"), 30)
    finally:
        os.chdir(previous)
