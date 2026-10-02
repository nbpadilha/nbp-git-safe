# SPDX-License-Identifier: MIT
"""End-to-end vault scenarios with real git, a local bare remote and canaries in contents AND
names. After EVERY scenario the bare remote and the whole local .git are scanned (the gate)."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import unicodedata
from collections.abc import Callable
from pathlib import Path

import pytest

from nbp_git_safe import agent, crypto, vault
from nbp_git_safe.config import load_config
from nbp_git_safe.gitutil import discover
from tests.helpers import NbpRepo, populate
from tests.integration.conftest import Env
from tests.leak.harness import LeakScanner

CloneFactory = Callable[..., NbpRepo]


def env_entries(clone: NbpRepo, env: Env) -> set[str]:
    repo, git = discover(clone.path, clone.git.env)
    with env.backend() as backend:
        state = vault.load_vault(git, backend, load_config(git, repo))
    return {e.path for e in state.index.entries.values()}


def protected_files(env: Env) -> dict[str, bytes]:
    """The protected plaintext files currently on disk (everything except unprotected ones)."""
    root = env.repo.path
    result = {}
    for sub in ("reports", "data-private"):
        for path in (root / sub).rglob("*"):
            if path.is_file() and path.name != "keep-public.txt":
                result[path.relative_to(root).as_posix()] = path.read_bytes()
    return result


def set_old_mtime(env: Env) -> None:
    """Make files look old so the stat cache is allowed to trust them."""
    old = 1_600_000_000
    for rel in protected_files(env):
        os.utime(env.repo.path / rel, (old, old))


# ------------------------------------------------------------------ full cycle (real agent)


def test_full_cycle_init_unlock_seal_push_clone_unlock_open(
    make_repo, isolated_git, tmp_path: Path, clone_factory: CloneFactory
) -> None:  # type: ignore[no-untyped-def]
    """The headline scenario, with the real detached agent process on both 'machines'."""
    repo: NbpRepo = make_repo()
    bare = isolated_git.init(tmp_path / "remote.git", bare=True)
    repo.sh("remote", "add", "origin", str(bare))
    files = populate(repo)
    assert repo.cli("init").code == 0
    assert repo.cli("unlock").code == 0
    sealed = repo.cli("seal")
    assert sealed.code == 0 and "4 new" in sealed.out, sealed.err
    repo.sh("add", "-A")
    repo.sh("commit", "-q", "-m", "main work")
    repo.sh("push", "-q", "origin", "main", "nbp-safe")
    repo.assert_no_leak(bare)
    assert repo.sh("status", "--porcelain").strip() == ""

    from tests.integration.conftest import make_clone

    clone = make_clone(isolated_git, bare, tmp_path / "second-machine", repo.master, repo.canaries)
    assert clone.cli("status").code == 3  # locked: not unlocked yet
    assert clone.cli("open").code == 3  # fails closed, nothing materialized
    assert not (clone.path / "reports").exists()
    assert clone.cli("unlock").code == 0
    listing = clone.cli("ls")
    assert listing.code == 0
    for rel in files:
        assert rel in listing.out
    opened = clone.cli("open")
    assert opened.code == 0 and "4 written" in opened.out, opened.err
    for rel, content in files.items():
        assert clone.read(rel) == content.encode("utf-8")
    assert clone.sh("status", "--porcelain").strip() == ""  # hidden by the exclude block
    clone.assert_no_leak(bare)
    assert clone.cli("open").out.startswith("opened: 0 written, 4 unchanged")


# ---------------------------------------------------------------------- vault structure


def test_vault_structure_identity_and_no_worktree(env: Env) -> None:
    env.repo.sh("add", ".nbp-safe", "README.md")
    index_before = (env.repo.path / ".git" / "index").read_bytes()
    assert env.seal().code == 0
    assert (env.repo.path / ".git" / "index").read_bytes() == index_before  # main index untouched
    assert env.repo.sh("worktree", "list").count("\n") == 1  # no worktree was created
    files = env.vault_files()
    assert {".gitattributes", "README.md", "nbp-safe/index"} <= files.keys()
    stores = [p for p in files if p.startswith("store/")]
    assert len(stores) == 4 and all(len(p) == len("store/") + 32 for p in stores)
    assert set(files) == {".gitattributes", "README.md", "nbp-safe/index", *stores}

    def show(path: str) -> bytes:
        return subprocess.run(
            ["git", "show", f"refs/heads/nbp-safe:{path}"],
            cwd=env.repo.path,
            env=env.git.env,
            capture_output=True,
            check=True,
        ).stdout

    assert show(".gitattributes") == b"* -text -diff -merge\n"
    assert b"opaque" in show("README.md")
    for path in ["nbp-safe/index", *stores]:
        assert show(path).startswith(crypto.MAGIC)
    log = env.repo.sh("log", "--format=%an|%ae|%cn|%ce|%s|%at|%ct", "refs/heads/nbp-safe").strip()
    author, email, committer, cemail, subject, at, ct = log.split("|")
    assert (author, email, subject) == ("nbp-safe", "nbp-safe@localhost.invalid", "nbp-safe: seal")
    assert (committer, cemail) == (author, email)
    assert int(at) % 3600 == 0 and int(ct) % 3600 == 0  # rounded to the hour
    assert env.repo.sh("rev-parse", "refs/heads/nbp-safe^{tree}")  # a real orphan root
    assert env.repo.sh("rev-list", "--max-parents=0", "refs/heads/nbp-safe").strip() == env.tip()
    env.gate()


def test_tracked_protected_files_are_reported_not_sealed(env: Env) -> None:
    env.repo.sh("add", "-A")  # before any exclude block exists: protected files get staged
    result = env.seal()
    assert result.code == 0 and "nothing to seal" in result.out
    assert "tracked on the main branch and were NOT sealed" in result.err


def test_no_change_means_no_new_commit_and_touch_does_not_matter(env: Env) -> None:
    assert env.seal().code == 0
    tip, count = env.tip(), env.commits()
    again = env.seal()
    assert again.code == 0 and "nothing to seal" in again.out
    assert env.tip() == tip
    for rel in protected_files(env):  # same bytes, new mtimes
        os.utime(env.repo.path / rel, None)
    assert "nothing to seal" in env.seal().out
    assert (env.tip(), env.commits()) == (tip, count)
    env.gate()


def test_no_vault_when_nothing_is_protected(env: Env) -> None:
    for sub in ("reports", "data-private"):
        for path in sorted((env.repo.path / sub).rglob("*")):
            if path.is_file() and path.name != "keep-public.txt":
                path.unlink()
    assert "nothing to seal" in env.seal().out
    assert not env.has_vault()


# --------------------------------------------------------------------------- scenarios


def test_changed_file_gets_a_new_blob_under_the_same_id(env: Env) -> None:
    assert env.seal().code == 0
    target = next(p for p in protected_files(env) if p.endswith(".json"))
    before = env.entries()[target]
    blob_before = env.vault_files()[f"store/{before[0]}"]
    env.repo.write(target, '{"secret": "changed", "marker": "' + env.repo.canaries[2] + '"}\n')
    result = env.seal()
    assert result.code == 0 and "1 changed" in result.out
    after = env.entries()[target]
    assert after[0] == before[0] and after[1].mac != before[1].mac
    assert env.vault_files()[f"store/{before[0]}"] != blob_before
    assert env.commits() == 2
    env.gate()


def test_moved_file_keeps_its_id(env: Env) -> None:
    assert env.seal().code == 0
    old = next(p for p in protected_files(env) if p.endswith(".csv"))
    fid = env.entries()[old][0]
    blob = env.vault_files()[f"store/{fid}"]
    new = f"reports/archive área/{Path(old).name}"
    (env.repo.path / new).parent.mkdir(parents=True)
    os.replace(env.repo.path / old, env.repo.path / new)
    result = env.seal()
    assert result.code == 0 and "1 moved" in result.out and "0 new" in result.out
    entries = env.entries()
    assert old not in entries and entries[new][0] == fid
    assert env.vault_files()[f"store/{fid}"] == blob  # content blob untouched
    env.gate()


def test_moved_and_edited_is_a_new_entry(env: Env) -> None:
    assert env.seal().code == 0
    old = next(p for p in protected_files(env) if p.endswith(".csv"))
    old_id = env.entries()[old][0]
    new = "reports/renamed-and-edited.csv"
    content = env.repo.read(old) + b"extra row\n"
    (env.repo.path / old).unlink()
    env.repo.write(new, content)
    # default onMissing=keep: the vanished path stays in the vault (and a warning is given)
    kept = env.seal()
    assert kept.code == 0 and "1 new" in kept.out and "kept in the vault" in kept.err
    entries = env.entries()
    assert entries[new][0] != old_id and entries[old][0] == old_id
    env.gate()


def test_removed_file_is_kept_by_default_and_removed_on_request(env: Env) -> None:
    assert env.seal().code == 0
    victim = next(p for p in protected_files(env) if p.endswith("plain.bin"))
    victim_id = env.entries()[victim][0]
    (env.repo.path / victim).unlink()

    kept = env.seal()
    assert kept.code == 0 and "nothing to seal" in kept.out
    assert "missing from the working tree" in kept.err
    assert victim in env.entries()
    status = env.repo.cli("status")
    assert "pending missing: 1" in status.out

    removed = env.repo.cli("seal", "--on-missing", "remove")
    assert removed.code == 0 and "1 removed" in removed.out
    assert victim not in env.entries()
    assert f"store/{victim_id}" not in env.vault_files()  # gone from the tip ...
    old = env.repo.sh("log", "--format=%H", "refs/heads/nbp-safe", "--", f"store/{victim_id}")
    assert old.strip()  # ... but history keeps it
    env.gate()


def test_on_missing_remove_from_git_config(env: Env) -> None:
    assert env.seal().code == 0
    env.repo.set_config("nbp-safe.onMissing", "remove")
    victim = next(p for p in protected_files(env) if p.endswith(".csv"))
    (env.repo.path / victim).unlink()
    assert "1 removed" in env.seal().out
    env.gate()


def test_on_missing_ask_without_a_terminal_keeps(env: Env) -> None:
    assert env.seal().code == 0
    env.repo.set_config("nbp-safe.onMissing", "ask")
    victim = next(p for p in protected_files(env) if p.endswith(".csv"))
    (env.repo.path / victim).unlink()
    assert "nothing to seal" in env.seal().out
    assert victim in env.entries()


def test_explicit_rm_removes_from_vault_and_working_tree(env: Env) -> None:
    assert env.seal().code == 0
    victim = next(p for p in protected_files(env) if p.endswith("plain.bin"))
    env.repo.write(victim, b"unsealed edit")
    refused = env.repo.cli("rm", victim)
    assert refused.code == 1 and "unsealed" in refused.err and (env.repo.path / victim).exists()
    done = env.repo.cli("rm", "--force", victim)
    assert done.code == 0 and "1 removed" in done.out
    assert not (env.repo.path / victim).exists()
    assert victim not in env.entries()
    assert "nothing to seal" in env.seal().out  # not re-added
    assert env.repo.cli("rm", victim).code == 1  # no longer in the vault
    env.gate()


def test_explicit_mv_with_edit_keeps_identity(env: Env) -> None:
    assert env.seal().code == 0
    old = next(p for p in protected_files(env) if p.endswith(".csv"))
    fid = env.entries()[old][0]
    new = "reports/moved-by-command.csv"
    done = env.repo.cli("mv", old, new)
    assert done.code == 0 and "1 moved" in done.out, done.err
    assert not (env.repo.path / old).exists() and (env.repo.path / new).exists()
    assert env.entries()[new][0] == fid and old not in env.entries()
    # move + edit through the command keeps the id (the automatic path cannot)
    edited = "reports/moved-and-edited.csv"
    env.repo.write(new, env.repo.read(new) + b"more\n")
    done = env.repo.cli("mv", new, edited)
    assert done.code == 0 and "1 moved" in done.out and "1 changed" in done.out
    entries = env.entries()
    assert entries[edited][0] == fid and new not in entries
    assert env.repo.cli("mv", "reports/nope.csv", "reports/x.csv").code == 1
    assert env.repo.cli("mv", edited, "data-private/keep-public.txt").code == 1  # not protected
    assert (env.repo.path / edited).exists()  # a failed mv puts the file back
    env.gate()


def test_names_with_accents_and_spaces_roundtrip(env: Env, clone_factory: CloneFactory) -> None:
    assert env.seal().code == 0
    env.gate()
    assert any("relatório final" in p for p in env.entries())
    clone = clone_factory(env)
    assert clone.cli("unlock").code == 0
    assert clone.cli("open").code == 0
    for rel, data in protected_files(env).items():
        assert clone.read(rel) == data
    assert clone.sh("status", "--porcelain").strip() == ""
    clone.assert_no_leak(env.bare)


def test_nfd_filenames_are_stored_as_nfc(env: Env) -> None:
    nfd = unicodedata.normalize("NFD", "reports/café.txt")
    env.repo.write(nfd, b"x")
    assert env.seal().code == 0
    names = env.entries().keys()
    assert "reports/café.txt" in names and nfd not in names


# ----------------------------------------------------------------------------- autocrlf


def test_autocrlf_true_changes_nothing(env: Env, clone_factory: CloneFactory) -> None:
    env.repo.set_config("core.autocrlf", "true")
    payload = b"unix\nwindows\r\nmixed\r\nlast\n" + env.repo.canaries[0].encode()
    env.repo.write("reports/crlf-test.txt", payload)
    spy = env.repo.path / "spy-marker"
    env.repo.write(".gitattributes", "*.txt text eol=crlf\n*.csv filter=spy\n")
    env.repo.set_config("filter.spy.clean", f"\"{sys.executable}\" -c \"open(r'{spy}', 'w')\"")
    env.repo.set_config("filter.spy.smudge", f"\"{sys.executable}\" -c \"open(r'{spy}', 'w')\"")
    result = env.seal()
    assert result.code == 0, result.err
    assert "warning: in the working copy" not in result.err
    with env.backend() as backend:
        repo, git = discover(env.repo.path, env.git.env)
        state = vault.load_vault(git, backend, load_config(git, repo))
        assert vault.vault_content(git, backend, state, "reports/crlf-test.txt") == payload
    env.gate()

    clone = clone_factory(env)
    clone.set_config("core.autocrlf", "true")
    clone.write(".gitattributes", "*.txt text eol=crlf\n")
    assert clone.cli("unlock").code == 0
    assert clone.cli("open").code == 0
    assert clone.read("reports/crlf-test.txt") == payload  # not a single byte altered
    assert not spy.exists() and not (clone.path / "spy-marker").exists()  # no filter ever ran
    refused = clone.cli("seal")  # a vault exists on origin: never start an unrelated second one
    assert refused.code == 1 and "git branch nbp-safe origin/nbp-safe" in refused.err
    clone.sh("branch", "nbp-safe", "origin/nbp-safe")
    assert "nothing to seal" in clone.cli("seal").out  # the clone sees nothing changed


# ------------------------------------------------------------------------------- CAS


def test_cas_loser_fails_closed_and_nothing_is_corrupted(env: Env) -> None:
    assert env.seal().code == 0
    repo, git = discover(env.repo.path, env.git.env)
    cfg = load_config(git, repo)
    env.repo.write("reports/first-writer.txt", "first")
    with env.backend() as backend:
        state = vault.load_vault(git, backend, cfg)
        a = vault.plan_seal(
            repo, cfg, backend, vault.analyze(git, repo, cfg, backend, state), now=1_700_000_000
        )
        env.repo.write("reports/second-writer.txt", "second")
        state2 = vault.load_vault(git, backend, cfg)
        b = vault.plan_seal(
            repo, cfg, backend, vault.analyze(git, repo, cfg, backend, state2), now=1_700_000_000
        )
        assert a is not None and b is not None and a.parent == b.parent
        winner = vault.commit_plan(git, repo, a, cfg, now=1_700_000_000)
        assert winner and env.tip() == winner
        with pytest.raises(vault.VaultConflictError):
            vault.commit_plan(git, repo, b, cfg, now=1_700_000_000)
        assert env.tip() == winner  # the ref was not moved by the loser
        reloaded = vault.load_vault(git, backend, cfg)
        assert "reports/first-writer.txt" in {e.path for e in reloaded.index.entries.values()}
    assert not list((env.repo.path / ".git" / "nbp-safe").glob("index.tmp-*"))
    env.repo.sh("fsck", "--strict")
    # the loser simply retries and wins
    assert env.seal().code == 0
    assert {"reports/first-writer.txt", "reports/second-writer.txt"} <= env.entries().keys()
    env.gate()


def test_concurrent_seals_never_corrupt_the_vault(env: Env) -> None:
    assert env.seal().code == 0
    repo, _ = discover(env.repo.path, env.git.env)
    outcomes: list[str] = []
    barrier = threading.Barrier(4)

    def worker(n: int) -> None:
        git = discover(env.repo.path, env.git.env)[1]
        cfg = load_config(git, repo)
        env.repo.write(f"reports/concurrent-{n}.txt", f"payload {n}")
        with env.backend() as backend:
            barrier.wait()
            try:
                vault.seal(git, repo, cfg, backend)
                outcomes.append("ok")
            except vault.VaultConflictError:
                outcomes.append("conflict")
            except Exception:
                import traceback

                outcomes.append("unexpected " + traceback.format_exc())

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert set(outcomes) <= {"ok", "conflict"} and "ok" in outcomes, outcomes
    env.repo.sh("fsck", "--strict")
    assert env.seal().code == 0  # whatever lost is picked up now
    names = env.entries().keys()
    assert all(f"reports/concurrent-{n}.txt" in names for n in range(4))
    assert not list((env.repo.path / ".git" / "nbp-safe").glob("index.tmp-*"))
    env.gate()


# --------------------------------------------------------------- locked / absent agent


def test_seal_and_open_fail_closed_without_agent(env: Env, clone_factory: CloneFactory) -> None:
    assert env.seal().code == 0
    env.gate()
    tip = env.tip()
    env.repo.write("reports/new-while-locked.txt", "x")
    env.agent.stop()
    result = env.seal()
    assert result.code == 3 and "unlock" in result.err
    assert env.tip() == tip
    clone = clone_factory(env)
    assert clone.cli("open").code == 3
    assert not (clone.path / "reports").exists()
    assert not (clone.path / "data-private" / "plain.bin").exists()
    leftovers = [p for p in clone.path.rglob("*") if p.name.endswith((".nbp-tmp", ".nbp-theirs"))]
    assert leftovers == []


def test_wrong_key_fails_closed(env: Env, clone_factory: CloneFactory) -> None:
    assert env.seal().code == 0
    env.gate()
    clone = clone_factory(env)
    wrong = clone.unlock_in_thread()
    wrong.stop()
    from tests.helpers import ThreadAgent

    other = ThreadAgent(clone.state_dir, crypto.generate_key())
    try:
        result = clone.cli("open")
        assert result.code == 1 and "different key" in result.err
        assert not (clone.path / "reports").exists()
        assert clone.cli("ls").code == 1
    finally:
        other.stop()


# ----------------------------------------------------------------------- size / paths


def test_files_over_64_mib_are_refused_clearly(env: Env) -> None:
    assert env.seal().code == 0
    small = next(p for p in protected_files(env) if p.endswith(".csv"))
    big = env.repo.path / small
    with open(big, "wb") as handle:  # grows an already-sealed file beyond the limit
        handle.truncate(crypto.MAX_DATA_SIZE + 1)
    huge_new = env.repo.path / "reports" / "huge-new.bin"
    with open(huge_new, "wb") as handle:
        handle.truncate(crypto.MAX_DATA_SIZE + 5)
    env.repo.write("reports/small-new.txt", "ok")
    env.repo.set_config("nbp-safe.onMissing", "remove")
    result = env.seal()
    assert result.code == 1
    assert "larger than the 64 MiB limit" in result.err
    assert "1 new" in result.out  # the small file was still sealed
    entries = env.entries()
    assert small in entries and "reports/huge-new.bin" not in entries
    assert "reports/small-new.txt" in entries
    big.unlink()
    huge_new.unlink()
    env.gate()


def test_names_not_allowed_in_a_vault_are_refused(env: Env) -> None:
    env.repo.write("reports/aux.txt", "reserved name on Windows")
    env.repo.write("reports/fine.txt", "fine")
    result = env.seal()
    assert result.code == 1 and "not allowed in a vault" in result.err
    names = env.entries().keys()
    assert "reports/fine.txt" in names and "reports/aux.txt" not in names


# --------------------------------------------------------------- open: divergence etc.


def test_open_never_overwrites_diverging_plaintext(env: Env, clone_factory: CloneFactory) -> None:
    assert env.seal().code == 0
    env.gate()
    clone = clone_factory(env)
    assert clone.cli("unlock").code == 0
    target = next(p for p in protected_files(env) if p.endswith(".csv"))
    clone.write(target, "my own local version\n")
    opened = clone.cli("open")
    assert opened.code == 0 and f"{target}.nbp-theirs" in opened.err
    assert clone.read(target) == b"my own local version\n"  # untouched
    assert clone.read(f"{target}.nbp-theirs") == env.repo.read(target)
    assert clone.sh("status", "--porcelain").strip() == ""  # .nbp-theirs is excluded too
    clone.sh("add", "-A")
    assert clone.sh("diff", "--cached", "--name-only").strip() == ""
    again = clone.cli("open")  # idempotent: same theirs file, no duplicates
    assert again.code == 0 and clone.read(f"{target}.nbp-theirs") == env.repo.read(target)
    assert not [p for p in clone.path.rglob("*.nbp-tmp")]
    clone.sh("branch", "nbp-safe", "origin/nbp-safe")
    sealed = clone.cli("seal")  # the local edit is sealed; the .nbp-theirs file never is
    assert "1 changed" in sealed.out
    assert not any(p.endswith(".nbp-theirs") for p in env_entries(clone, env))


def test_open_reports_blocked_paths_without_aborting(env: Env, clone_factory: CloneFactory) -> None:
    assert env.seal().code == 0
    env.gate()
    clone = clone_factory(env)
    assert clone.cli("unlock").code == 0
    clone.write("reports", "a file where a directory is needed")
    result = clone.cli("open")
    assert result.code == 1 and "in the way" in result.err
    assert (clone.path / "data-private" / "plain.bin").exists()  # other entries were written
    assert clone.read("reports") == b"a file where a directory is needed"


def test_open_refuses_to_follow_links(
    env: Env, clone_factory: CloneFactory, tmp_path: Path
) -> None:
    assert env.seal().code == 0
    env.gate()
    clone = clone_factory(env)
    assert clone.cli("unlock").code == 0
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        os.symlink(outside, clone.path / "reports", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted here")
    result = clone.cli("open")
    assert result.code == 1 and "link" in result.err
    assert list(outside.iterdir()) == []  # nothing escaped through the link


# ------------------------------------------------------ main branch is left alone


def test_add_all_on_main_does_not_capture_protected_files(env: Env) -> None:
    assert env.seal().code == 0
    env.repo.sh("add", "-A")
    staged = env.repo.sh("diff", "--cached", "--name-only", "-z").split("\0")
    assert set(filter(None, staged)) == {".nbp-safe", "README.md", "data-private/keep-public.txt"}
    env.repo.sh("commit", "-q", "-m", "main")
    assert env.repo.sh("status", "--porcelain").strip() == ""
    tracked = env.repo.sh("ls-files", "-z")
    assert not any(c in tracked for c in env.repo.canaries)
    env.gate()


def test_exclude_block_lifecycle(env: Env) -> None:
    repo, git = discover(env.repo.path, env.git.env)
    from nbp_git_safe import protect

    exclude = protect.exclude_path(repo)
    exclude.parent.mkdir(exist_ok=True)
    exclude.write_bytes(b"# user line\r\nmy-own-ignore\r\n")
    assert protect.install_exclude_block(repo) is True
    first = exclude.read_bytes()
    assert protect.install_exclude_block(repo) is False  # idempotent
    assert exclude.read_bytes() == first and first.count(protect.BLOCK_BEGIN.encode()) == 1
    text = first.decode()
    assert text.startswith("# user line\r\nmy-own-ignore\r\n")
    for pattern in (
        "reports/",
        "data-private/**",
        "!data-private/keep-public.txt",
        "*.nbp-tmp",
        "*.nbp-theirs",
    ):
        assert pattern in text

    env.repo.write(".nbp-safe", "reports/\nnew-pattern/\n")  # update
    assert protect.install_exclude_block(repo) is True
    updated = exclude.read_text()
    # review A3: a pattern that disappears from .nbp-safe (here: by a local edit, upstream it would
    # be a pull) is NOT dropped from the block; only `unprotect` forgets it
    assert "new-pattern/" in updated and "data-private/**" in updated
    assert "!data-private/keep-public.txt" not in updated  # a negation is never kept alive
    assert updated.count(protect.BLOCK_BEGIN) == 1
    assert protect.unprotect(git, repo, "data-private/**").status == "removed"
    assert protect.install_exclude_block(repo) is True
    assert "data-private/**" not in exclude.read_text()

    # a local negation must not re-expose a versioned pattern; local plain patterns are added
    local = repo.common_dir / "info" / "nbp-safe"
    local.write_text("extra-local/\n!reports/\n")
    protect.install_exclude_block(repo)
    block = exclude.read_text()
    assert "extra-local/" in block and "!reports/" not in block

    assert protect.remove_exclude_block(repo) is True
    assert protect.remove_exclude_block(repo) is False
    assert not protect.has_exclude_block(repo)
    assert exclude.read_bytes().startswith(b"# user line")
    assert b"nbp-git-safe" not in exclude.read_bytes()


def test_unterminated_block_is_replaced_not_duplicated(env: Env) -> None:
    from nbp_git_safe import protect

    repo, _ = discover(env.repo.path, env.git.env)
    exclude = protect.exclude_path(repo)
    exclude.parent.mkdir(exist_ok=True)
    exclude.write_text(f"before\n{protect.BLOCK_BEGIN}\nstale-half-block\n")
    protect.install_exclude_block(repo)
    text = exclude.read_text()
    assert text.startswith("before\n") and "stale-half-block" not in text
    assert text.count(protect.BLOCK_BEGIN) == 1 and text.count(protect.BLOCK_END) == 1


# ------------------------------------------------------------------ stat cache / status


def test_statcache_skips_rehashing_and_holds_no_names(env: Env) -> None:
    set_old_mtime(env)
    assert env.seal().code == 0
    cache = env.repo.path / ".git" / "nbp-safe" / "statcache"
    assert cache.exists()
    raw = cache.read_bytes()
    assert b"reports" not in raw and b"data-private" not in raw and b"csv" not in raw
    scanner = LeakScanner(env.repo.canaries, git_env=env.git.env)
    assert scanner.scan_bytes(raw, "statcache") == []

    repo, git = discover(env.repo.path, env.git.env)
    cfg = load_config(git, repo)

    class Counting:
        def __init__(self, inner: agent.AgentClient) -> None:
            self.inner, self.content_macs = inner, 0

        def mac(self, data: bytes) -> bytes:
            if not data.startswith(b"nbp-git-safe/path\x00"):
                self.content_macs += 1
            return self.inner.mac(data)

        def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
            return getattr(self.inner, name)

    with env.backend() as client:
        counting = Counting(client)
        state = vault.load_vault(git, counting, cfg)  # type: ignore[arg-type]
        analysis = vault.analyze(git, repo, cfg, counting, state)  # type: ignore[arg-type]
        assert counting.content_macs == 0 and not analysis.changed and not analysis.new
        # a real edit (new mtime and size) is still noticed
        target = next(iter(protected_files(env)))
        env.repo.write(target, "edited content, different size")
        analysis = vault.analyze(git, repo, cfg, counting, state)  # type: ignore[arg-type]
        assert analysis.changed == [target] and counting.content_macs == 1


def test_status_ls_log_diff(env: Env) -> None:
    assert env.seal().code == 0
    target = next(
        p for p in protected_files(env) if p.endswith("nota " + env.repo.canaries[1] + ".txt")
    )
    env.repo.write(target, "line one\nline TWO changed\nline three\n")
    status = env.repo.cli("status")
    assert status.code == 0 and "pending changed: 1" in status.out and target in status.out
    assert env.seal().code == 0

    log = env.repo.cli("log", target)
    assert log.code == 0 and len(log.out.strip().splitlines()) == 2

    env.repo.write(target, "line one\nline THREE\n")
    diff = env.repo.cli("diff", target)
    assert diff.code == 0
    assert (
        "-line TWO changed" in diff.out
        and "+line THREE" in diff.out
        and f"vault:{target}" in diff.out
    )
    assert env.repo.cli("diff", "--exit-code", target).code == 1
    first_commit = log.out.strip().splitlines()[-1].split("\t")[0]
    older = env.repo.cli("diff", "--from", first_commit, target)
    assert "-line TWO" not in older.out and "line two" not in older.out.lower().replace(
        "line three", ""
    )
    env.repo.write(target, "line one\nline TWO changed\nline three\n")
    assert env.repo.cli("diff", "--exit-code", target).out == ""  # equal -> no output

    binary = next(p for p in protected_files(env) if p.endswith("plain.bin"))
    env.repo.write(binary, b"\xff\xfe\x00binary")
    assert "Binary files differ" in env.repo.cli("diff", binary).out
    assert env.repo.cli("diff", "reports/not-there.txt").code == 1

    listing = env.repo.cli("ls")
    assert listing.code == 0 and len(listing.out.strip().splitlines()) == 4
    assert env.repo.cli("log", "reports/not-there.txt").code == 1
    assert env.repo.cli("log", "../outside").code == 1


def test_no_filters_ever_run(env: Env) -> None:
    spy = env.repo.path / "spy-marker"
    env.repo.write(".gitattributes", "* filter=spy\n")
    command = f"\"{sys.executable}\" -c \"open(r'{spy}', 'w')\""
    env.repo.set_config("filter.spy.clean", command)
    env.repo.set_config("filter.spy.smudge", command)
    env.repo.set_config("filter.spy.required", "true")
    assert env.seal().code == 0
    assert env.repo.cli("open").code == 0
    assert not spy.exists()


# ------------------------------------------------------------------- failure injection


def test_agent_dying_mid_seal_leaves_the_ref_unchanged(env: Env) -> None:
    assert env.seal().code == 0
    tip = env.tip()
    env.repo.write("reports/new-one.txt", "one")
    env.repo.write("reports/new-two.txt", "two")
    repo, git = discover(env.repo.path, env.git.env)
    cfg = load_config(git, repo)

    class Dying:
        """Delegates to the agent, but the agent dies after the first blob is encrypted."""

        def __init__(self, inner: agent.AgentClient) -> None:
            self.inner, self.blobs = inner, 0

        def enc_blob(self, *args: object, **kwargs: object) -> bytes:
            self.blobs += 1
            if self.blobs == 2:
                env.agent.stop()
            return self.inner.enc_blob(*args, **kwargs)  # type: ignore[arg-type]

        def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
            return getattr(self.inner, name)

    with env.backend() as client, pytest.raises(agent.AgentError):  # locked or gone
        vault.seal(git, repo, cfg, Dying(client))  # type: ignore[arg-type]
    assert env.tip() == tip  # the ref never moved
    assert not list((env.repo.path / ".git" / "nbp-safe").glob("index.tmp-*"))
    env.repo.sh("fsck", "--strict")
    env.gate()


def test_disk_full_while_opening_leaves_no_partial_files(
    env: Env, clone_factory: CloneFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert env.seal().code == 0
    env.gate()
    clone = clone_factory(env)
    assert clone.cli("unlock").code == 0
    real_write_bytes = vault.os.replace
    victim = next(p for p in protected_files(env) if p.endswith(".csv"))

    def failing_replace(src: object, dst: object) -> None:
        if str(dst).replace("\\", "/").endswith(victim):
            raise OSError(28, "No space left on device")
        real_write_bytes(src, dst)  # type: ignore[arg-type]

    monkeypatch.setattr(vault.os, "replace", failing_replace)
    result = clone.cli("open")
    assert result.code == 1 and "could not be written" in result.err
    assert not (clone.path / victim).exists()
    assert not list(clone.path.rglob("*.nbp-tmp"))  # the temp file was cleaned up
    others = [p for p in protected_files(env) if p != victim]
    assert all((clone.path / p).exists() for p in others)  # the rest was materialized
    monkeypatch.undo()
    assert clone.cli("open").code == 0  # retry succeeds
    assert (clone.path / victim).exists()


def test_seal_writes_all_blobs_without_one_process_per_file(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression (found by a rehearsal on thousands of files): sealing must not spawn one
    ``git hash-object`` per blob (about 40 ms each on Windows); the blobs go in one batch."""
    for i in range(30):
        env.repo.write(f"reports/bulk-{i}.csv", f"{env.repo.canaries[0]},{i}\n" * 20)
    calls: list[list[str]] = []
    real_run = subprocess.run

    def spying(
        argv: list[str], *args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        calls.append([str(a) for a in argv])
        return real_run(argv, *args, **kwargs)  # type: ignore[call-overload]

    monkeypatch.setattr(subprocess, "run", spying)
    sealed = env.seal()
    assert sealed.code == 0, sealed.err
    hash_object_calls = [c for c in calls if c[:2] == ["git", "hash-object"]]
    assert not hash_object_calls
    assert len(env.vault_files()) >= 30 + 3
    env.gate()
