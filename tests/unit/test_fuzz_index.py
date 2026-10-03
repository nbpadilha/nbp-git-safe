# SPDX-License-Identifier: MIT
"""Deterministic fuzzing of the index parser/validator (fixed seed, no extra dependency).

The invariant for every input: the validator either ACCEPTS something safe or raises the typed
``IndexValidationError`` (or, for the encrypted container, a typed ``NbpCryptoError``). Never any
other exception, and an accepted path can never point outside the directory it is joined to.
"""

from __future__ import annotations

import copy
import json
import os
import random
import unicodedata
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import pytest

from nbp_git_safe import crypto
from nbp_git_safe import index as ix
from nbp_git_safe.index import Index, IndexValidationError

SEED = 20261003
KEY_ID = bytes(range(8))
MAC = "cd" * 32
FID = [f"{n:x}" * 32 for n in range(1, 10)]

HOSTILE_COMPONENTS = [
    "..",
    ".",
    ".git",
    ".GIT",
    ".git.",
    "git~1",
    "GIT~12",
    "C:",
    "c:evil",
    "file.txt:stream",
    "file.txt::$DATA",
    "a:b",
    "\\\\server\\share",
    "\\\\?\\C:\\x",
    "//server/share/x",
    "CON",
    "con.txt",
    "Nul.tar.gz",
    "aux ",
    "LPT1",
    "COM9",
    "com\u00b2",
    "CONIN$",
    "trailing.",
    "trailing ",
    "e\u0301",  # NFD
    "\u00e9",  # NFC
    "ok.csv",
    "relat\u00f3rio",
    "tab\tname",
    "nl\nname",
    "nul\x00byte",
    "esc\x1bseq",
    "del\x7f",
    "\u202eevil",  # bidi override: allowed by the validator, but must not break anything
    "a<b",
    "a>b",
    'a"b',
    "a|b",
    "a?b",
    "a*b",
    ".gitattributes",
    ".gitignore",
    ".gitmodules",
    ".nbp-safe",
    ".nbp-safe.config",
    "x.nbp-tmp",
    "x.nbp-theirs",
    "x" * 255,
    "x" * 256,
    "y" * 5000,
    "",
    " ",
    "\ud800",  # lone surrogate
    "\udcff",
]


def random_path(rng: random.Random) -> Any:
    if rng.random() < 0.04:
        return rng.choice([None, 0, 1, 1.5, True, False, b"a/b", ["a"], {"a": 1}, ()])
    parts = [rng.choice(HOSTILE_COMPONENTS) for _ in range(rng.randint(1, 5))]
    path = rng.choice(["/", "/", "/", "\\", "//"]).join(parts)
    roll = rng.random()
    if roll < 0.1:
        path = "/" + path
    elif roll < 0.15:
        path = "C:\\" + path
    elif roll < 0.2:
        path = "\\\\host\\share\\" + path
    elif roll < 0.25:
        path += "/"
    elif roll < 0.3:
        path = "a/" * rng.randint(0, 700) + path
    elif roll < 0.35:
        path = unicodedata.normalize(rng.choice(["NFD", "NFKC", "NFKD"]), path)
    return path


def assert_safe_when_accepted(path: str, tmp_path: Path) -> None:
    """What 'accepted' must mean for a path that will be joined to the working tree."""
    assert unicodedata.is_normalized("NFC", path)
    assert not path.startswith("/") and "\\" not in path and ":" not in path
    assert not PurePosixPath(path).is_absolute()
    assert not PureWindowsPath(path).is_absolute() and not PureWindowsPath(path).drive
    parts = path.split("/")
    assert all(p not in ("", ".", "..") for p in parts)
    assert all(p.casefold() != ".git" and not p.endswith((".", " ")) for p in parts)
    assert all(ord(c) >= 0x20 and ord(c) != 0x7F for c in path)
    assert len(path) <= ix.MAX_PATH_LEN and all(len(p) <= ix.MAX_COMPONENT_LEN for p in parts)
    assert os.path.normpath(path).replace(os.sep, "/") == path  # nothing collapses or climbs
    base = tmp_path.resolve()
    target = (base / path).resolve()
    assert target == base or base in target.parents  # "never writes outside"


def test_fuzz_validate_path(tmp_path: Path) -> None:
    rng = random.Random(SEED)  # noqa: S311 - a fixed seed, not a secret
    accepted = rejected = 0
    for _ in range(2500):
        path = random_path(rng)
        try:
            result = ix.validate_path(path)
        except IndexValidationError as exc:
            rejected += 1
            if isinstance(path, str) and len(path) > 40:
                assert path not in str(exc)  # messages never echo the path
            continue
        accepted += 1
        assert result == path and isinstance(result, str)
        assert_safe_when_accepted(result, tmp_path)
    assert accepted > 20 and rejected > 1000  # the corpus exercises both sides


def entry_fields() -> dict[str, Any]:
    return {"mode": "100644", "size": 1, "mac": MAC, "created": 1, "updated": 2}


def valid_index(rng: random.Random) -> dict[str, Any]:
    entries = {}
    for n in range(rng.randint(0, 4)):
        entries[FID[n]] = {
            **entry_fields(),
            "path": f"reports/f{n}.csv",
            "mode": rng.choice(ix.MODES),
            "size": rng.randint(0, 10**6),
            "created": rng.randint(0, 2**31),
            "updated": rng.randint(0, 2**31),
        }
    return {
        "v": ix.INDEX_VERSION,
        "key_id": KEY_ID.hex(),
        "entries": entries,
        "seq": rng.randint(1, 1000),
        "prev": rng.choice(["", MAC]),
    }


WRONG_VALUES = [
    None,
    True,
    False,
    -1,
    0,
    1,
    2**53,
    2**64,
    1.0,
    float("nan"),
    "",
    "x",
    "0" * 32,
    "g" * 32,
    "A" * 64,
    [],
    {},
    [1],
    {"a": 1},
    "100664",
    "100644\n",
]


def mutate(rng: random.Random, data: Any) -> Any:
    """Randomly corrupt one place of a JSON-like structure (type, value, key set)."""
    data = copy.deepcopy(data)
    spots: list[tuple[Any, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key in list(node):
                spots.append((node, key))
                walk(node[key])
        elif isinstance(node, list):
            for i in range(len(node)):
                spots.append((node, i))
                walk(node[i])

    walk(data)
    if not spots:
        return data
    container, key = rng.choice(spots)
    action = rng.random()
    if action < 0.5:
        container[key] = rng.choice(WRONG_VALUES)
    elif action < 0.65 and isinstance(container, dict):
        del container[key]
    elif action < 0.8 and isinstance(container, dict):
        container[rng.choice(["extra", "v", "path", "seq"])] = rng.choice(WRONG_VALUES)
    elif action < 0.9 and isinstance(container[key], str):
        container[key] = random_path(rng) if key == "path" else container[key][::-1]
    else:
        container[key] = {"nested": [container[key]]}
    return data


def check_index_input(data: Any) -> Index | None:
    try:
        parsed = Index.from_dict(data, KEY_ID)
    except IndexValidationError:
        return None
    # accepted: it must round-trip and be internally consistent
    assert Index.from_dict(parsed.to_dict(), KEY_ID).to_dict() == parsed.to_dict()
    for entry in parsed.entries.values():
        ix.validate_path(entry.path)
    return parsed


def test_fuzz_index_from_dict_mutations() -> None:
    rng = random.Random(SEED + 1)  # noqa: S311
    accepted = 0
    for _ in range(2500):
        data = valid_index(rng)
        for _ in range(rng.randint(1, 3)):
            data = mutate(rng, data)
        if check_index_input(data) is not None:
            accepted += 1
    assert 0 < accepted < 2500


def test_fuzz_index_hostile_paths_inside_an_otherwise_valid_index(tmp_path: Path) -> None:
    rng = random.Random(SEED + 2)  # noqa: S311
    for _ in range(1500):
        data = valid_index(rng)
        data["entries"] = {FID[0]: {**entry_fields(), "path": random_path(rng)}}
        parsed = check_index_input(data)
        if parsed is not None:
            for entry in parsed.entries.values():
                assert_safe_when_accepted(entry.path, tmp_path)


def test_fuzz_index_collisions_and_ids() -> None:
    rng = random.Random(SEED + 3)  # noqa: S311
    names = ["a", "A", "a/b", "A/B", "a/B", "\u00e9", "e\u0301", "E\u0301", "b"]
    bad_ids = ["z" * 32, "", 5, None, "ab", FID[0].upper()]
    for _ in range(400):
        picked = rng.sample(names, rng.randint(1, 4))
        entries: dict[Any, Any] = {}
        for i, name in enumerate(picked):
            fid = rng.choice(bad_ids) if rng.random() < 0.15 else FID[i]
            entries[fid] = {**entry_fields(), "path": unicodedata.normalize("NFC", name)}
        parsed = check_index_input({**valid_index(rng), "entries": entries})
        if parsed is not None:  # accepted: no two paths may collide case-insensitively
            keys = [ix.collision_key(e.path) for e in parsed.entries.values()]
            assert len(keys) == len(set(keys))


def test_fuzz_index_json_documents_give_typed_errors_only() -> None:
    """Whatever JSON the decrypted index holds, only typed errors may come out of the pipeline
    (``_parse_index`` -> ``Index.from_dict``)."""
    rng = random.Random(SEED + 4)  # noqa: S311
    base = valid_index(rng)
    text = json.dumps(base).encode()
    docs: list[bytes] = [
        b"",
        b"null",
        b"[]",
        b"123",
        b'"str"',
        b"{",
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b"\xff\xfe\x00",
        b"[" * 100000,
        b'{"v":' + b"[" * 50000,
        text,
        text[:-1],
    ]
    for _ in range(400):
        cut = rng.randint(0, len(text))
        docs.append(text[:cut])
        pos = rng.randrange(len(text))
        docs.append(text[:pos] + bytes([rng.randrange(256)]) + text[pos + 1 :])
        docs.append(text[:pos] + text[pos + rng.randint(1, 5) :])
    for doc in docs:
        try:
            parsed = crypto._parse_index(doc)
            Index.from_dict(parsed, KEY_ID)
        except (crypto.IndexFormatError, IndexValidationError):
            pass


def test_fuzz_index_encrypted_container_roundtrip() -> None:
    """Valid indexes survive encrypt -> decrypt -> parse unchanged."""
    rng = random.Random(SEED + 5)  # noqa: S311
    keys = crypto.KeySet(bytes(range(64)))
    for _ in range(60):
        data = valid_index(rng)
        data["key_id"] = keys.key_id.hex()
        again = crypto.decrypt_index(keys, crypto.encrypt_index(keys, data, 4096))
        assert again == data
        assert Index.from_dict(again, keys.key_id).to_dict() == data


@pytest.mark.parametrize("bad", [None, 0, "x", [], b"{}"])
def test_from_dict_wrong_top_level_type_is_a_typed_error(bad: Any) -> None:
    with pytest.raises(IndexValidationError):
        Index.from_dict(bad, KEY_ID)
