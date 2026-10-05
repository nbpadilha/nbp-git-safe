# SPDX-License-Identifier: MIT
# ruff: noqa: S311 - fixed seeds for reproducible fuzzing, not secrets
"""Deterministic fuzzing (fixed seed) of the two parsers that read files a hostile process of the
same user could have planted: the repository registry and the tray configuration. Invariants: they
never raise anything but their own typed error, never hang, and every entry they accept satisfies
the acceptance rules."""

from __future__ import annotations

import json
import os
import random
from pathlib import Path

from nbp_git_safe import fleet, registry, trayconfig

SEED = 20261005
ROUNDS = 1500


def mutate(rng: random.Random, raw: bytes) -> bytes:
    data = bytearray(raw)
    for _ in range(rng.randint(1, 6)):
        if not data:
            data.append(rng.randrange(256))
            continue
        pos = rng.randrange(len(data))
        kind = rng.randrange(5)
        if kind == 0:
            data[pos] = rng.randrange(256)
        elif kind == 1:
            del data[pos : pos + rng.randint(1, 8)]
        elif kind == 2:
            data[pos:pos] = rng.randbytes(rng.randint(1, 8))
        elif kind == 3:
            data[pos:pos] = rng.choice([b'"', b"\\", b"{", b"}", b"[", b"]", b",", b":", b"\x00"])
        else:
            data[pos:] = data[: pos + rng.randint(0, 4)]  # truncate
    return bytes(data)


def random_json(rng: random.Random, depth: int = 0) -> object:
    kind = rng.randrange(8 if depth < 3 else 5)
    if kind == 0:
        return None
    if kind == 1:
        return rng.choice([True, False])
    if kind == 2:
        return rng.choice([0, 1, -1, 2**63, 10**30, 1.5, float("1e308")])
    if kind == 3:
        return rng.choice(["", "a", "..", "/", "C:\\", "\x00", "x" * 5000, "\u202e", os.sep + "z"])
    if kind == 4:
        return rng.randbytes(3).hex()
    if kind == 5:
        return [random_json(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    return {
        rng.choice(["path", "added", "repos", "version", "x"]): random_json(rng, depth + 1)
        for _ in range(rng.randint(0, 4))
    }


def valid_registry(tmp: Path) -> bytes:
    entries = [
        {"path": registry.canonical(tmp / f"r{i}"), "added": 1_700_000_000 + i} for i in range(3)
    ]
    return json.dumps({"version": 1, "repos": entries}).encode()


def check_registry_result(result: registry.Loaded) -> None:
    assert len(result.entries) <= registry.MAX_ENTRIES
    keys = [registry.key_of(e.path) for e in result.entries]
    assert len(keys) == len(set(keys))
    for entry in result.entries:
        assert registry.path_problem(entry.path) is None
        assert 0 <= entry.added <= registry.MAX_DATE


def test_registry_parser_survives_mutations_of_a_valid_file(tmp_path: Path) -> None:
    rng = random.Random(SEED)
    base = valid_registry(tmp_path)
    assert len(registry.parse(base).entries) == 3
    for _ in range(ROUNDS):
        check_registry_result(registry.parse(mutate(rng, base)))


def test_registry_parser_survives_random_structures() -> None:
    rng = random.Random(SEED + 1)
    for _ in range(ROUNDS):
        value = {"version": rng.choice([1, 1, 1, 2, "1"]), "repos": random_json(rng)}
        if rng.random() < 0.3:
            value = random_json(rng)  # type: ignore[assignment]
        raw = json.dumps(value).encode("utf-8", "surrogatepass")
        check_registry_result(registry.parse(raw))


def test_registry_parser_survives_random_bytes() -> None:
    rng = random.Random(SEED + 2)
    for _ in range(ROUNDS):
        check_registry_result(registry.parse(rng.randbytes(rng.randint(0, 300))))


def test_registry_paths_are_never_accepted_unless_canonical_and_absolute() -> None:
    rng = random.Random(SEED + 3)
    pieces = [
        "a",
        "b c",
        "..",
        ".",
        "",
        "x" + os.sep,
        os.sep,
        "C:",
        "\\\\",
        "//",
        "~",
        "%x%",
        "\u202e",
    ]
    for _ in range(4000):
        text = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 6)))
        if registry.path_problem(text) is None:
            assert os.path.isabs(text) and os.path.normpath(text) == text
            assert ".." not in text.replace("\\", "/").split("/")


def test_tray_config_parser_survives_mutations_and_random_values() -> None:
    rng = random.Random(SEED + 4)
    base = json.dumps(
        {
            "sealIntervalMinutes": 15,
            "sealPush": False,
            "unlockAtLogin": True,
            "warnExpiryMinutes": 30,
        }
    ).encode()
    accepted = 0
    for _ in range(ROUNDS):
        for raw in (
            mutate(rng, base),
            rng.randbytes(rng.randint(0, 80)),
            json.dumps(random_json(rng)).encode(),
        ):
            try:
                config = trayconfig.parse(raw)
            except trayconfig.TrayConfigError:
                continue
            accepted += 1
            assert 1 <= config.sealIntervalMinutes <= 1440
            assert 0 <= config.warnExpiryMinutes <= 1440 and 0 <= config.warnPendingMinutes <= 1440
            assert isinstance(config.sealPush, bool) and isinstance(config.unlockAtLogin, bool)
    assert accepted > 0  # the fuzzer does reach valid documents


def test_menu_command_parser_survives_random_ids() -> None:
    rng = random.Random(SEED + 5)
    parts = [
        "repo",
        "all",
        "set",
        "app",
        "unlock",
        "seal",
        "quit",
        "a" * 24,
        "x",
        "",
        "1",
        ":",
        "\n",
        "-",
    ]
    for _ in range(5000):
        text = rng.choice([":", ""]).join(rng.choice(parts) for _ in range(rng.randint(0, 5)))
        command = fleet.parse_command(text)
        if command is not None:
            assert command.scope in ("repo", "all", "set", "app")
            if command.scope == "repo":
                assert len(command.key) == 24
