# SPDX-License-Identifier: MIT
"""Second machine: ``git clone`` -> ``init`` (adopts ``origin/nbp-safe``, installs hooks) ->
``unlock`` -> ``open``; then ``post-merge`` / ``post-checkout`` reopen the vault by themselves."""

from __future__ import annotations

from collections.abc import Callable

from tests.helpers import NbpRepo
from tests.integration.conftest import Env
from tests.integration.guardkit import commit, first_protected

CloneFactory = Callable[..., NbpRepo]


def publish(env: Env) -> None:
    result = env.repo.raw("push", "-q", "origin", "main", "nbp-safe")
    assert result.returncode == 0, result.stderr


def test_clone_init_unlock_open_flow(
    hooked: Env, clone_factory: CloneFactory, unlock_fast: Callable[..., object]
) -> None:
    publish(hooked)
    clone = clone_factory(hooked)
    assert clone.sh("for-each-ref", "refs/heads/nbp-safe").strip() == ""  # clones have no branch
    assert "refs/remotes/origin/nbp-safe" in clone.sh("for-each-ref", "--format=%(refname)")
    # without the key a clone only has opaque store/<hex>
    tree = clone.sh("ls-tree", "-r", "--name-only", "refs/remotes/origin/nbp-safe")
    assert all(
        line.startswith("store/") or "/" not in line or line == "nbp-safe/index"
        for line in tree.splitlines()
    )
    result = clone.cli("init")
    assert result.code == 0
    assert "created local branch nbp-safe tracking the vault on origin" in result.err
    assert clone.sh("rev-parse", "refs/heads/nbp-safe") == hooked.repo.sh(
        "rev-parse", "refs/heads/nbp-safe"
    )
    assert "git config hooks" in result.err
    assert "created local branch" not in clone.cli("init").err  # idempotent
    unlock_fast(clone)
    opened = clone.cli("open")
    assert opened.code == 0 and "4 written" in opened.out, opened.err
    for rel in ("data-private/plain.bin",):
        assert clone.read(rel) == hooked.repo.read(rel)
    assert clone.sh("status", "--porcelain").strip() == ""  # hidden by the exclude block
    clone.assert_no_leak(hooked.bare)


def test_post_checkout_reopens_files_deleted_locally(
    hooked: Env, clone_factory: CloneFactory, unlock_fast: Callable[..., object]
) -> None:
    publish(hooked)
    clone = clone_factory(hooked)
    assert clone.cli("init").code == 0
    unlock_fast(clone)
    assert clone.cli("open").code == 0
    victim = first_protected(clone, ".csv")
    expected = clone.read(victim)
    (clone.path / victim).unlink()
    switched = clone.raw("checkout", "-q", "-b", "other")  # a branch switch: flag 1
    assert switched.returncode == 0, switched.stderr
    assert "vault opened: 1 file(s) written" in switched.stderr
    assert clone.read(victim) == expected
    # checking out a single file (flag 0) does not trigger anything
    (clone.path / victim).unlink()
    clone.sh("checkout", "-q", "main", "--", ".nbp-safe")
    assert not (clone.path / victim).exists()


def test_post_merge_reopens_after_a_pull(
    hooked: Env, clone_factory: CloneFactory, unlock_fast: Callable[..., object]
) -> None:
    publish(hooked)
    clone = clone_factory(hooked)
    assert clone.cli("init").code == 0
    unlock_fast(clone)
    assert clone.cli("open").code == 0
    victim = first_protected(clone, ".json")
    expected = clone.read(victim)
    (clone.path / victim).unlink()
    hooked.repo.write("docs/news.md", "new on main\n")
    hooked.repo.sh("add", "docs/news.md")
    assert commit(hooked.repo, "news").returncode == 0
    publish(hooked)
    pulled = clone.raw("pull", "-q")
    assert pulled.returncode == 0, pulled.stderr
    assert "vault opened" in pulled.stderr
    assert clone.read(victim) == expected
    clone.assert_no_leak(hooked.bare)


def test_locked_clone_gets_a_hint_and_nothing_is_written(
    hooked: Env, clone_factory: CloneFactory
) -> None:
    publish(hooked)
    clone = clone_factory(hooked)
    assert clone.cli("init").code == 0
    switched = clone.raw("checkout", "-q", "-b", "other")
    assert switched.returncode == 0
    assert "vault not opened" in switched.stderr and "nbp-git-safe unlock" in switched.stderr
    assert not (clone.path / "reports").exists()
    assert not (clone.path / "data-private" / "plain.bin").exists()
    clone.assert_no_leak(hooked.bare)


def test_checkout_refreshes_the_exclude_block_for_new_patterns(
    hooked: Env, clone_factory: CloneFactory
) -> None:
    clone = clone_factory(hooked)
    publish(hooked)
    assert clone.raw("pull", "-q").returncode == 0
    assert clone.cli("init").code == 0
    hooked.repo.write(".nbp-safe", hooked.repo.read(".nbp-safe").decode() + "fresh-private/\n")
    hooked.repo.sh("add", ".nbp-safe")
    assert commit(hooked.repo, "more patterns").returncode == 0
    publish(hooked)
    assert clone.raw("pull", "-q").returncode == 0
    exclude = (clone.path / ".git" / "info" / "exclude").read_text()
    assert "fresh-private/" in exclude  # post-merge refreshed the managed block
