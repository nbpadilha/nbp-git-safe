# SPDX-License-Identifier: MIT
"""The per-user registry of repositories: round trip, strict reading, damaged files, concurrency."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from nbp_git_safe import agent, registry, statefile


def reg_file() -> Path:
    return agent.runtime_root() / registry.REGISTRY_NAME


def make_dirs(tmp_path: Path, *names: str) -> list[Path]:
    out = []
    for name in names:
        path = tmp_path / name
        path.mkdir()
        out.append(path)
    return out


def test_round_trip_and_only_paths_and_dates_are_stored(tmp_path: Path) -> None:
    a, b = make_dirs(tmp_path, "alpha", "beta repo")
    assert registry.add(a, now=1_700_000_000) is True
    assert registry.add(b, now=1_700_000_100) is True
    assert registry.add(a) is False  # already there
    loaded = registry.load()
    assert [e.path for e in loaded.entries] == [registry.canonical(a), registry.canonical(b)]
    assert [e.added for e in loaded.entries] == [1_700_000_000, 1_700_000_100]
    assert loaded.warnings == [] and not loaded.damaged
    document = json.loads(reg_file().read_text(encoding="ascii"))
    assert set(document) == {"version", "repos"}
    for item in document["repos"]:
        assert set(item) == {"path", "added"}
    assert registry.remove(a) is True
    assert registry.remove(a) is False
    assert [e.path for e in registry.load().entries] == [registry.canonical(b)]


def test_nothing_is_created_by_reading(tmp_path: Path) -> None:
    assert registry.load().entries == []
    assert not os.path.lexists(agent.runtime_root())


def test_the_same_folder_by_another_spelling_is_one_entry(tmp_path: Path) -> None:
    (folder,) = make_dirs(tmp_path, "Spelled")
    assert registry.add(folder) is True
    assert registry.add(tmp_path / "other" / ".." / "Spelled") is False
    if sys.platform == "win32":
        assert registry.add(str(folder).upper()) is False  # case-insensitive file system
    assert len(registry.load().entries) == 1


def test_remove_works_for_a_folder_that_is_gone(tmp_path: Path) -> None:
    (folder,) = make_dirs(tmp_path, "gone")
    registry.add(folder)
    folder.rmdir()
    assert registry.remove(folder) is True
    assert registry.load().entries == []


def test_prune_drops_missing_and_non_repositories(tmp_path: Path) -> None:
    keep, drop, vanish = make_dirs(tmp_path, "keep", "drop", "vanish")
    for folder in (keep, drop, vanish):
        registry.add(folder)
    vanish.rmdir()
    dropped = registry.prune(lambda p: Path(p) == Path(registry.canonical(keep)))
    assert sorted(dropped) == sorted([registry.canonical(drop), registry.canonical(vanish)])
    assert [e.path for e in registry.load().entries] == [registry.canonical(keep)]
    assert registry.prune(lambda _p: True) == []


# ------------------------------------------------------------------ strict reading


def doc(*repos: object, version: object = 1) -> bytes:
    return json.dumps({"version": version, "repos": list(repos)}).encode()


def good(path: Path, added: object = 5) -> dict[str, object]:
    return {"path": registry.canonical(path), "added": added}


@pytest.mark.parametrize(
    "bad",
    [
        "relative/path",
        "",
        ".",
        "..",
        "../escape",
    ],
)
def test_hostile_or_relative_paths_are_ignored(bad: str) -> None:
    result = registry.parse(doc({"path": bad, "added": 1}))
    assert result.entries == [] and result.damaged and result.warnings


def test_dotdot_unnormalised_and_control_characters(tmp_path: Path) -> None:
    base = registry.canonical(tmp_path)
    sep = os.sep
    cases = [
        base + sep + ".." + sep + "x",
        base + sep + "." + sep + "x",
        base + sep + sep + "x",  # doubled separator
        base + sep + "x" + sep,  # trailing separator
        base + sep + "x\x00y",
        base + sep + "x\ny",
    ]
    for case in cases:
        assert registry.parse(doc({"path": case, "added": 1})).entries == [], case
    assert registry.path_problem("x" * (registry.MAX_PATH_CHARS + 1)) == "path too long"


@pytest.mark.skipif(os.name != "nt", reason="UNC and device paths exist on Windows")
@pytest.mark.parametrize(
    "path",
    [
        r"\\server\share\repo",
        "//server/share/repo",
        r"\\?\C:\repo",
        r"\\.\pipe\x",
        r"C:repo",
        r"\repo",
        r"C:\re<po",
        r"C:\repo:stream",
        "C:/forward/slashes",
    ],
)
def test_windows_network_device_and_odd_paths_are_ignored(path: str) -> None:
    assert registry.path_problem(path) is not None
    assert registry.parse(doc({"path": path, "added": 1})).entries == []


@pytest.mark.parametrize(
    "item",
    [None, 5, "text", [], {"path": 5, "added": 1}, {"path": None, "added": 1}, {"added": 1}],
)
def test_wrong_types_in_entries_are_ignored(item: object, tmp_path: Path) -> None:
    result = registry.parse(doc(item, good(tmp_path)))
    assert [e.path for e in result.entries] == [registry.canonical(tmp_path)]
    assert result.damaged and len(result.warnings) == 1


@pytest.mark.parametrize("added", [None, "1", -1, 1.5, True, registry.MAX_DATE + 1, [1]])
def test_bad_dates_are_ignored(added: object, tmp_path: Path) -> None:
    result = registry.parse(doc(good(tmp_path, added)))
    assert result.entries == [] and result.damaged


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not json",
        b"\xff\xfe\x00",
        b"[]",
        b"{}",
        b'{"version": 1}',
        b'{"version": 1, "repos": {}}',
        b'{"version": "1", "repos": []}',
        b'{"version": true, "repos": []}',
        b"[" * 100000,  # recursion
    ],
    ids=[
        "empty",
        "text",
        "bytes",
        "list",
        "object",
        "no-repos",
        "repos-object",
        "str-version",
        "bool-version",
        "deep",
    ],
)
def test_malformed_documents_give_no_entries_and_never_raise(raw: bytes) -> None:
    result = registry.parse(raw)
    assert result.entries == [] and result.damaged and result.warnings


def test_a_newer_version_is_read_only(tmp_path: Path) -> None:
    result = registry.parse(doc(good(tmp_path), version=2))
    assert result.unsupported and result.entries == []
    (folder,) = make_dirs(tmp_path, "x")
    agent.private_root(create=True)
    reg_file().write_bytes(doc(good(tmp_path), version=2))
    before = reg_file().read_bytes()
    with pytest.raises(registry.RegistryError, match="newer version"):
        registry.add(folder)
    assert reg_file().read_bytes() == before


def test_duplicates_collapse_and_the_cap_is_enforced(tmp_path: Path) -> None:
    result = registry.parse(doc(good(tmp_path), good(tmp_path)))
    assert len(result.entries) == 1 and not result.damaged
    many = [good(tmp_path / str(i)) for i in range(registry.MAX_ENTRIES + 5)]
    capped = registry.parse(doc(*many))
    assert len(capped.entries) == registry.MAX_ENTRIES and capped.damaged


def test_oversized_file_and_link_are_not_read(tmp_path: Path) -> None:
    agent.private_root(create=True)
    reg_file().write_bytes(b" " * (registry.MAX_FILE_BYTES + 1))
    loaded = registry.load()
    assert loaded.entries == [] and loaded.damaged and loaded.warnings


# ------------------------------------------------------------------ damaged files


def test_a_corrupt_file_never_breaks_load_and_is_backed_up_before_a_write(tmp_path: Path) -> None:
    (folder,) = make_dirs(tmp_path, "repo")
    agent.private_root(create=True)
    reg_file().write_bytes(b"{ this is not json")
    loaded = registry.load()
    assert loaded.entries == [] and loaded.damaged
    assert registry.add(folder) is True
    backup = reg_file().with_name(registry.REGISTRY_NAME + ".bak")
    assert backup.read_bytes() == b"{ this is not json"  # kept, not overwritten silently
    assert [e.path for e in registry.load().entries] == [registry.canonical(folder)]
    # a second damage does not replace the first backup
    reg_file().write_bytes(b"also broken")
    registry.remove(folder)
    assert backup.read_bytes() == b"{ this is not json"
    assert reg_file().with_name(registry.REGISTRY_NAME + ".2.bak").read_bytes() == b"also broken"


def test_a_partly_bad_file_keeps_the_good_entries_and_a_backup(tmp_path: Path) -> None:
    keep, extra = make_dirs(tmp_path, "keep", "extra")
    agent.private_root(create=True)
    original = doc(good(keep), {"path": "relative", "added": 1})
    reg_file().write_bytes(original)
    assert registry.add(extra) is True
    paths = [e.path for e in registry.load().entries]
    assert paths == [registry.canonical(keep), registry.canonical(extra)]
    assert reg_file().with_name(registry.REGISTRY_NAME + ".bak").read_bytes() == original


@pytest.mark.skipif(sys.platform == "win32", reason="needs symlink privileges on Windows")
def test_a_link_in_place_of_the_registry_is_not_followed(tmp_path: Path) -> None:
    secret = tmp_path / "elsewhere.json"
    secret.write_bytes(doc(good(tmp_path)))
    agent.private_root(create=True)
    os.symlink(secret, reg_file())
    loaded = registry.load()
    assert loaded.entries == [] and loaded.damaged


def test_a_state_directory_that_is_not_private_is_not_used(tmp_path: Path) -> None:
    root = agent.runtime_root()
    root.mkdir(parents=True)
    if sys.platform == "win32":
        pytest.skip("the Windows DACL case is covered in the agent trust tests")
    root.chmod(0o755)
    loaded = registry.load()
    assert loaded.entries == [] and loaded.warnings
    with pytest.raises(registry.RegistryError, match="not private"):
        registry.add(tmp_path)


# ------------------------------------------------------------------ concurrency


def test_concurrent_writers_in_threads_lose_nothing(tmp_path: Path) -> None:
    folders = make_dirs(tmp_path, *[f"r{i}" for i in range(12)])
    errors: list[BaseException] = []

    def work(folder: Path) -> None:
        try:
            registry.add(folder)
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=work, args=(f,)) for f in folders]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert {e.path for e in registry.load().entries} == {registry.canonical(f) for f in folders}


def test_concurrent_writers_in_processes_lose_nothing(tmp_path: Path) -> None:
    folders = make_dirs(tmp_path, *[f"p{i}" for i in range(6)])
    code = (
        "import sys; from nbp_git_safe import agent, registry; "
        "from pathlib import Path; agent.set_runtime_root(Path(sys.argv[1])); "
        "[registry.add(p) for p in sys.argv[2:]]"
    )
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(agent.runtime_root()), str(f)],
            env={**os.environ},
        )
        for f in folders
    ]
    assert [p.wait(60) for p in procs] == [0] * len(procs)
    assert {e.path for e in registry.load().entries} == {registry.canonical(f) for f in folders}


def test_a_leftover_lock_file_is_free_and_a_live_holder_times_out(tmp_path: Path) -> None:
    (folder,) = make_dirs(tmp_path, "x")
    base = agent.private_root(create=True)
    assert base is not None
    lock = base / registry.LOCK_NAME
    lock.write_bytes(b"")  # what a dead writer leaves: the file, held by nobody
    old = os.stat(lock).st_mtime - 10_000
    os.utime(lock, (old, old))
    assert registry.add(folder) is True  # nothing to take over: the system dropped the lock
    with statefile.file_lock(lock):  # a live holder (this process) blocks the others
        other = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; from pathlib import Path; from nbp_git_safe import statefile; "
                "statefile.file_lock(Path(sys.argv[1]), wait=0.2).__enter__()",
                str(lock),
            ],
            capture_output=True,
            check=False,
        )
        assert other.returncode != 0 and b"another process" in other.stderr


def test_write_is_atomic_no_temporary_files_remain(tmp_path: Path) -> None:
    (folder,) = make_dirs(tmp_path, "x")
    registry.add(folder)
    names = sorted(p.name for p in agent.runtime_root().iterdir())
    assert names == [registry.REGISTRY_NAME, registry.LOCK_NAME]  # no temporary file remains


def test_add_refuses_a_path_the_registry_would_not_read(tmp_path: Path) -> None:
    if os.name != "nt":
        pytest.skip("every absolute POSIX path is acceptable")
    with pytest.raises(registry.RegistryError, match="cannot register"):
        registry.add("\\\\server\\share\\repo")


@pytest.mark.skipif(os.name != "nt", reason="mapped drives and UNC paths exist on Windows")
def test_the_message_for_a_network_path_names_the_mapped_drive_case() -> None:
    problem = registry.path_problem(r"\server\share\repo")
    assert problem is not None
    assert "mapped network drive" in problem and "local drive" in problem
