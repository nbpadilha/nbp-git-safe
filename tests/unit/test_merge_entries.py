# SPDX-License-Identifier: MIT
"""Three-way merge of vault indexes (pure: no git, no key)."""

from __future__ import annotations

import fnmatch
import random
from collections.abc import Callable
from dataclasses import replace

import pytest

from nbp_git_safe import index as index_mod
from nbp_git_safe import multi
from nbp_git_safe.index import Entry


def mac(tag: str) -> str:
    return (tag.encode().hex() * 64)[:64]


def entry(
    path: str, content: str, *, mode: str = "100644", created: int = 1, updated: int = 1
) -> Entry:
    return Entry(path, mode, len(content), mac(content), created, updated)


def fid(n: int) -> str:
    return f"{n:032x}"


def everything(paths: list[str]) -> set[str]:
    return set(paths)


def only(*patterns: str) -> Callable[[list[str]], set[str]]:
    return lambda paths: {p for p in paths if any(fnmatch.fnmatch(p, pat) for pat in patterns)}


def counter() -> Callable[[], str]:
    state = {"n": 1000}

    def new_id() -> str:
        state["n"] += 1
        return fid(state["n"])

    return new_id


def merge(base: dict, ours: dict, theirs: dict, matcher=everything) -> multi.MergeOutcome:  # type: ignore[no-untyped-def]
    return multi.merge_entries(base, ours, theirs, matcher, new_id=counter())


def test_disjoint_changes_are_combined() -> None:
    base = {fid(1): entry("a.txt", "a"), fid(2): entry("b.txt", "b")}
    ours = {**base, fid(3): entry("ours-new.txt", "n1")}
    theirs = {**base, fid(4): entry("theirs-new.txt", "n2")}
    out = merge(base, ours, theirs)
    assert set(out.merged) == {fid(1), fid(2), fid(3), fid(4)}
    assert out.from_theirs == {fid(4)} and not out.copies and out.conflicts == 0


def test_one_sided_changes_and_removals() -> None:
    base = {fid(1): entry("a.txt", "a"), fid(2): entry("b.txt", "b"), fid(3): entry("c.txt", "c")}
    ours = {fid(1): entry("a.txt", "a2", updated=5), fid(2): base[fid(2)], fid(3): base[fid(3)]}
    theirs = {fid(1): base[fid(1)], fid(2): entry("b.txt", "b2", updated=6)}  # c removed
    out = merge(base, ours, theirs)
    assert out.merged[fid(1)].mac == mac("a2") and fid(1) not in out.from_theirs
    assert out.merged[fid(2)].mac == mac("b2") and fid(2) in out.from_theirs
    assert fid(3) not in out.merged  # their removal wins over our non-change
    assert out.conflicts == 0


def test_identical_change_on_both_sides_is_not_a_conflict() -> None:
    base = {fid(1): entry("a.txt", "a")}
    both = entry("a.txt", "same", updated=9)
    out = merge(base, {fid(1): both}, {fid(1): both})
    assert out.merged == {fid(1): both} and not out.from_theirs and out.conflicts == 0


def test_removed_on_one_side_modified_on_the_other_keeps_the_data() -> None:
    base = {fid(1): entry("a.txt", "a"), fid(2): entry("b.txt", "b")}
    ours = {fid(2): base[fid(2)]}  # we removed a
    theirs = {fid(1): entry("a.txt", "a-edited", updated=4), fid(2): entry("b.txt", "b-edited")}
    ours2 = {fid(1): entry("a.txt", "a-ours"), fid(2): base[fid(2)]}
    theirs2 = {fid(2): base[fid(2)]}  # they removed a, we modified it
    out = merge(base, ours, theirs)
    assert out.merged[fid(1)].mac == mac("a-edited") and fid(1) in out.from_theirs
    assert out.conflicts == 1 and "removed on one side" in out.notes[0]
    out2 = merge(base, ours2, theirs2)
    assert out2.merged[fid(1)].mac == mac("a-ours") and out2.conflicts == 1


def test_move_on_one_side_edit_on_the_other_combine() -> None:
    base = {fid(1): entry("old/name.txt", "v1")}
    ours = {fid(1): replace(base[fid(1)], path="new/name.txt", updated=3)}
    theirs = {fid(1): entry("old/name.txt", "v2", updated=4)}
    out = merge(base, ours, theirs)
    merged = out.merged[fid(1)]
    assert merged.path == "new/name.txt" and merged.mac == mac("v2") and merged.updated == 4
    assert fid(1) in out.from_theirs and out.conflicts == 0


def test_both_moved_to_different_paths_keeps_ours_and_notes_it() -> None:
    base = {fid(1): entry("a.txt", "x")}
    out = merge(
        base,
        {fid(1): replace(base[fid(1)], path="ours.txt")},
        {fid(1): replace(base[fid(1)], path="theirs.txt")},
    )
    assert out.merged[fid(1)].path == "ours.txt" and out.conflicts == 1


def test_both_edited_keeps_ours_in_place_and_theirs_as_a_conflict_copy() -> None:
    base = {fid(1): entry("reports/q1.csv", "base")}
    ours = {fid(1): entry("reports/q1.csv", "ours", updated=5)}
    theirs = {fid(1): entry("reports/q1.csv", "theirs", updated=6)}
    out = merge(base, ours, theirs)
    assert out.merged[fid(1)].mac == mac("ours") and fid(1) not in out.from_theirs
    ((new_id, (src, copy)),) = out.copies.items()
    assert src == fid(1) and new_id != fid(1) and new_id in out.merged
    assert copy.mac == mac("theirs")
    assert copy.path == f"reports/q1.conflict-{mac('theirs')[:8]}.csv"
    assert out.conflicts == 1
    index_mod.check_collisions(e.path for e in out.merged.values())


def test_conflict_copy_for_a_file_without_extension_and_taken_names() -> None:
    base = {fid(1): entry("data/notes", "base")}
    ours = {fid(1): entry("data/notes", "ours")}
    theirs = {fid(1): entry("data/notes", "theirs")}
    blocker = f"data/notes.conflict-{mac('theirs')[:8]}"
    ours[fid(9)] = entry(blocker, "squatter")
    out = merge(base, ours, theirs)
    paths = {e.path for e in out.merged.values()}
    assert blocker in paths and f"{blocker}-2" in paths  # counter when the name is taken


def test_same_new_path_on_both_sides_different_content_becomes_two_entries() -> None:
    ours = {fid(1): entry("reports/x.csv", "from-ours", updated=3)}
    theirs = {fid(2): entry("reports/x.csv", "from-theirs", updated=2)}
    out = merge({}, ours, theirs)
    by_path = {e.path: e for e in out.merged.values()}
    assert by_path["reports/x.csv"].mac == mac("from-ours")  # ours keeps the name
    assert by_path[f"reports/x.conflict-{mac('from-theirs')[:8]}.csv"].mac == mac("from-theirs")
    assert fid(2) in out.from_theirs and out.conflicts == 1


def test_same_new_file_on_both_sides_is_deduplicated() -> None:
    ours = {fid(1): entry("reports/x.csv", "same", updated=3)}
    theirs = {fid(2): entry("reports/x.csv", "same", updated=2)}
    out = merge({}, ours, theirs)
    assert list(out.merged) == [fid(1)] and "identical file added on both sides" in out.notes[0]


def test_unrelated_histories_merge_by_path() -> None:
    ours = {fid(1): entry("a.txt", "a"), fid(2): entry("b.txt", "b")}
    theirs = {fid(3): entry("a.txt", "a"), fid(4): entry("c.txt", "c")}
    out = merge({}, ours, theirs)
    assert {e.path for e in out.merged.values()} == {"a.txt", "b.txt", "c.txt"}


def test_file_versus_directory_conflict_is_resolved() -> None:
    ours = {fid(1): entry("docs/x", "file")}
    theirs = {fid(2): entry("docs/x/y.txt", "nested")}
    out = merge({}, ours, theirs)
    index_mod.check_collisions(e.path for e in out.merged.values())
    assert {"docs/x/y.txt"} <= {e.path for e in out.merged.values()}
    assert any(".conflict-" in e.path for e in out.merged.values())


def test_a_conflict_copy_outside_the_protected_set_is_refused() -> None:
    base = {fid(1): entry("exact-name.txt", "base")}
    ours = {fid(1): entry("exact-name.txt", "ours")}
    theirs = {fid(1): entry("exact-name.txt", "theirs")}
    with pytest.raises(multi.SyncError, match="outside the protected set"):
        merge(base, ours, theirs, matcher=only("exact-name.txt"))
    # an extension pattern or a directory pattern keeps the copy inside the set
    out = merge(base, ours, theirs, matcher=only("*.txt"))
    assert out.conflicts == 1
    dir_ours = {fid(1): entry("reports/exact", "ours")}
    dir_theirs = {fid(1): entry("reports/exact", "theirs")}
    out2 = merge(
        {fid(1): entry("reports/exact", "base")}, dir_ours, dir_theirs, matcher=only("reports/*")
    )
    assert any(e.path.startswith("reports/exact.conflict-") for e in out2.merged.values())


def test_conflict_marks_never_use_forbidden_names() -> None:
    path = multi.conflict_path("reports/a.csv", "deadbeef", set(), everything)
    index_mod.validate_path(path)
    assert path == "reports/a.conflict-deadbeef.csv"
    assert multi.conflict_path(".hidden", "t", set(), everything) == ".hidden.conflict-t"


@pytest.mark.parametrize("seed", range(40))
def test_random_merges_never_collide_and_never_lose_content(seed: int) -> None:
    rng = random.Random(seed)  # noqa: S311 - reproducible test data, not cryptography
    names = ["a.txt", "b.txt", "A.TXT", "d/x.txt", "d", "d/y.txt", "e.csv"]
    contents = ["c0", "c1", "c2", "c3"]

    def random_side(base: dict[str, Entry]) -> dict[str, Entry]:
        side = dict(base)
        for _ in range(rng.randint(0, 4)):
            roll = rng.random()
            ids = sorted(side)
            if roll < 0.25 and ids:
                del side[rng.choice(ids)]
            elif roll < 0.55 and ids:
                key = rng.choice(ids)
                side[key] = replace(
                    side[key],
                    **entry(side[key].path, rng.choice(contents)).__dict__
                    | {"path": side[key].path},
                )
            elif roll < 0.7 and ids:
                key = rng.choice(ids)
                side[key] = replace(side[key], path=rng.choice(names))
            else:
                side[fid(rng.randint(100, 999))] = entry(rng.choice(names), rng.choice(contents))
        # a side is a valid index: drop path collisions it could not have produced itself
        seen: set[str] = set()
        for key in sorted(side):
            ck = index_mod.collision_key(side[key].path)
            if ck in seen:
                del side[key]
            seen.add(ck)
        try:
            index_mod.check_collisions(e.path for e in side.values())
        except index_mod.IndexValidationError:
            return dict(base)
        return side

    base = {}
    for n in range(rng.randint(0, 3)):
        candidate = entry(rng.choice(names), rng.choice(contents))
        base[fid(n + 1)] = candidate
    try:
        index_mod.check_collisions(e.path for e in base.values())
    except index_mod.IndexValidationError:
        base = {}
    ours, theirs = random_side(base), random_side(base)
    out = merge(base, ours, theirs)
    index_mod.check_collisions(e.path for e in out.merged.values())  # a valid index
    merged_macs = {e.mac for e in out.merged.values()}
    for side in (ours, theirs):
        for key, e in side.items():
            before = base.get(key)
            if before is None or before.mac != e.mac:  # new or edited on that side: it survives
                assert e.mac in merged_macs, (seed, key)
    assert all(index_mod.is_valid_file_id(k) for k in out.merged)
    assert out.from_theirs <= set(out.merged)
