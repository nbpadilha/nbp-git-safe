# SPDX-License-Identifier: MIT
from __future__ import annotations

import copy
import unicodedata

import pytest

from nbp_git_safe import index as ix
from nbp_git_safe.index import Entry, Index, IndexValidationError

KEY_ID = bytes(range(8))
MAC = "ab" * 32
FID1, FID2 = "1" * 32, "2" * 32


def _entry(path: str = "reports/a.csv", **kw: object) -> dict:
    base = {"path": path, "mode": "100644", "size": 3, "mac": MAC, "created": 1, "updated": 2}
    base.update(kw)
    return base


def _index(entries: dict | None = None, **kw: object) -> dict:
    data = {
        "v": 2,
        "key_id": KEY_ID.hex(),
        "entries": entries if entries is not None else {FID1: _entry()},
        "seq": 1,
        "prev": "",
    }
    data.update(kw)
    return data


@pytest.mark.parametrize(
    "path",
    [
        "a.txt",
        "reports/a b/c.csv",
        "relat\u00f3rio/nota final.txt",
        "deep/er/est/file",
        "comma,semi;colon.txt",
        "con-not-reserved.txt",
        "aux2/file",
        ".github/workflows/x.yml",
        "dot.in.middle.txt",
    ],
)
def test_valid_paths(path: str) -> None:
    assert ix.validate_path(path) == path


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/abs/path",
        "../up",
        "a/../b",
        "a/./b",
        "a//b",
        "a/",
        ".",
        "..",
        ".git/config",
        "sub/.GIT/hooks/x",
        "sub/.git /x",
        "GIT~1/x",
        "x/.gitattributes",
        ".gitignore",
        "a/.gitmodules",
        ".nbp-safe",
        "dir/.nbp-safe.config",
        "file.nbp-tmp",
        "file.nbp-theirs",
        "C:/windows",
        "a\\b",
        "a:b",
        "a<b",
        "a|b",
        "a?b",
        "a*b",
        'a"b',
        "tab\there",
        "nl\nx",
        "nul",
        "CON",
        "dir/aux.txt",
        "com1",
        "LPT9.log",
        "COM\u00b9",
        "trailing.",
        "trailing ",
        "x" * 300,
        "a/" + "y" * 256,
        "bad\udcff",
        "e\u0301.txt",  # NFD, not NFC
    ],
)
def test_invalid_paths(path: str) -> None:
    with pytest.raises(IndexValidationError):
        ix.validate_path(path)


def test_non_string_and_oversized_paths() -> None:
    for bad in (None, 5, b"x", ["a"]):
        with pytest.raises(IndexValidationError):
            ix.validate_path(bad)
    with pytest.raises(IndexValidationError):
        ix.validate_path("a/" * 600 + "b")


def test_error_messages_do_not_leak_the_path() -> None:
    with pytest.raises(IndexValidationError) as exc:
        ix.validate_path("SECRET-NAME/../x")
    assert "SECRET-NAME" not in str(exc.value)


def test_normalize_path_is_nfc() -> None:
    nfd = unicodedata.normalize("NFD", "relat\u00f3rio")
    assert ix.normalize_path(nfd) == "relat\u00f3rio"


def test_roundtrip_and_sorting() -> None:
    data = _index({FID2: _entry("b.txt"), FID1: _entry("a.txt")})
    parsed = Index.from_dict(data, KEY_ID)
    assert parsed.to_dict() == data
    assert list(parsed.to_dict()["entries"]) == [FID1, FID2]
    assert parsed.by_path() == {"a.txt": FID1, "b.txt": FID2}
    assert Index.empty(KEY_ID).to_dict() == _index({}, seq=0)  # not written yet
    assert isinstance(parsed.entries[FID1], Entry)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(v=1),  # the format before the rollback chain
        lambda d: d.update(v=3),
        lambda d: d.update(extra=1),
        lambda d: d.pop("entries"),
        lambda d: d.update(key_id="00" * 8),
        lambda d: d.update(entries=[]),
        lambda d: d["entries"].update({"short": _entry()}),
        lambda d: d["entries"].update({"A" * 32: _entry("z")}),
        lambda d: d["entries"].update({"3" * 32: "notadict"}),
        lambda d: d["entries"][FID1].update(mode="120000"),
        lambda d: d["entries"][FID1].update(mac="xyz"),
        lambda d: d["entries"][FID1].update(mac=5),
        lambda d: d["entries"][FID1].update(size=-1),
        lambda d: d["entries"][FID1].update(size=True),
        lambda d: d["entries"][FID1].update(created="1"),
        lambda d: d["entries"][FID1].update(extra=1),
        lambda d: d["entries"][FID1].pop("size"),
        lambda d: d["entries"][FID1].update(path="../x"),
    ],
)
def test_structure_validation(mutate) -> None:  # type: ignore[no-untyped-def]
    data = copy.deepcopy(_index())
    mutate(data)
    with pytest.raises(IndexValidationError):
        Index.from_dict(data, KEY_ID)


def test_case_collisions_and_file_dir_conflicts_rejected() -> None:
    with pytest.raises(IndexValidationError, match="collide"):
        Index.from_dict(
            _index({FID1: _entry("Reports/A.txt"), FID2: _entry("reports/a.TXT")}), KEY_ID
        )
    with pytest.raises(IndexValidationError, match="collide"):  # NFC/casefold equivalents
        ix.check_collisions(["stra\u00dfe.txt", "STRASSE.txt"])
    with pytest.raises(IndexValidationError, match="file and a directory"):
        Index.from_dict(_index({FID1: _entry("a"), FID2: _entry("a/b")}), KEY_ID)
    with pytest.raises(IndexValidationError):
        Index.from_dict(_index({FID1: _entry("A/b"), FID2: _entry("a")}), KEY_ID)
    ix.check_collisions(["a/b", "a/c", "ab"])


def test_protected_set_and_tracked_validation() -> None:
    idx = Index.from_dict(
        _index({FID1: _entry("reports/a.txt"), FID2: _entry("reports/b.txt")}), KEY_ID
    )
    everything = lambda paths: set(paths)  # noqa: E731
    ix.validate_against_protected(idx, everything)
    with pytest.raises(IndexValidationError, match="outside the protected set"):
        ix.validate_against_protected(idx, lambda paths: {"reports/a.txt"})
    with pytest.raises(IndexValidationError, match="tracked"):
        ix.validate_against_protected(idx, everything, tracked=["Reports/B.txt"])
    ix.validate_against_protected(idx, everything, tracked=["other.txt"])


def test_is_valid_file_id() -> None:
    assert ix.is_valid_file_id("a" * 32)
    for bad in ("A" * 32, "a" * 31, "g" * 32, 5, None):
        assert not ix.is_valid_file_id(bad)


# ------------------------------------------------------------ the rollback chain (review M1)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("seq"),
        lambda d: d.pop("prev"),
        lambda d: d.update(seq=0),
        lambda d: d.update(seq=-3),
        lambda d: d.update(seq=True),
        lambda d: d.update(seq="2"),
        lambda d: d.update(seq=1.5),
        lambda d: d.update(seq=1 << 60),
        lambda d: d.update(prev="zz"),
        lambda d: d.update(prev="ab" * 31),
        lambda d: d.update(prev="AB" * 32),
        lambda d: d.update(prev=None),
        lambda d: d.update(v=1),
    ],
)
def test_chain_fields_are_validated(mutate) -> None:  # type: ignore[no-untyped-def]
    data = copy.deepcopy(_index())
    mutate(data)
    with pytest.raises(IndexValidationError):
        Index.from_dict(data, KEY_ID)


def test_successor_and_digest() -> None:
    root = Index.from_dict(_index({FID1: _entry()}), KEY_ID)
    assert root.seq == 1 and root.prev == ""
    assert len(root.digest()) == 64 and root.digest() == root.digest()
    entries = {**root.entries, FID2: Entry(**_entry("b.txt"))}
    child = root.successor(entries)
    assert child.seq == 2 and child.prev == root.digest()
    assert Index.from_dict(child.to_dict(), KEY_ID) == child
    merged = child.successor({}, other_parents=[7, 3])
    assert merged.seq == 8 and merged.prev == child.digest()
    first = Index.empty(KEY_ID).successor(root.entries)  # no vault yet: seq 1, no prev
    assert first.seq == 1 and first.prev == ""


def test_digest_depends_on_every_field() -> None:
    base = Index.from_dict(_index(), KEY_ID)
    other_seq = Index.from_dict(_index(seq=2), KEY_ID)
    other_prev = Index.from_dict(_index(prev="00" * 32), KEY_ID)
    other_entries = Index.from_dict(_index({FID2: _entry("z.txt")}), KEY_ID)
    digests = {x.digest() for x in (base, other_seq, other_prev, other_entries)}
    assert len(digests) == 4
