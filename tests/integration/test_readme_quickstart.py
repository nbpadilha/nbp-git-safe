# SPDX-License-Identifier: MIT
"""The documentation as a test.

* Every ``nbp-git-safe ...`` command written in a code block or inline code of ``README.md``,
  ``docs/GUARD.md`` and ``docs/MULTI.md`` is parsed by the real argparse parser (the subcommand
  and every flag must exist). Nothing destructive is executed by this part.
* The README quickstart, daily flow, second machine, sync, rotate and purge are then RUN, in this
  order and with the commands as written (only the password-manager command is replaced by the
  test key command), in throw-away repositories with a local bare remote, and the observable
  promises of the text are asserted.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import shlex
import sys
import time
from pathlib import Path

import pytest

from nbp_git_safe import cli, crypto, hooks
from nbp_git_safe.config import load_config, parse_key_command
from nbp_git_safe.gitutil import discover
from tests import helpers
from tests.conftest import IsolatedGit
from tests.helpers import NbpRepo

ROOT = Path(__file__).resolve().parents[2]
DOCS = [ROOT / "README.md", ROOT / "docs" / "GUARD.md", ROOT / "docs" / "MULTI.md"]
PROG = "nbp-git-safe"
YEAR = time.gmtime().tm_year

# ------------------------------------------------------------------ extraction of the commands


def code_blocks(text: str) -> list[str]:
    return re.findall(r"^```[a-z]*\n(.*?)^```", text, flags=re.DOTALL | re.MULTILINE)


def _placeholders_out(token: str) -> str:
    """``<path>...`` -> ``x``; ``[--flag]`` brackets (optional syntax) are dropped."""
    token = re.sub(r"<[^<>]+>(\.\.\.)?", "x", token)
    return token.replace("[", "").replace("]", "")


def _argv_of(segment: str) -> list[str] | None:
    """The argv after ``nbp-git-safe`` in a shell-ish segment, or ``None`` if it is not ours."""
    try:
        tokens = shlex.split(segment, comments=True)
    except ValueError:
        return None
    if not tokens or tokens[0] != PROG:
        return None
    return [_placeholders_out(t) for t in tokens[1:]]


def doc_commands(path: Path) -> list[list[str]]:
    """Commands from fenced blocks (split on ``&&``/``;``) and from inline code spans."""
    text = path.read_text(encoding="utf-8")
    found: list[list[str]] = []
    for block in code_blocks(text):
        for line in block.splitlines():
            for segment in re.split(r"&&|;|\|\|", line):
                argv = _argv_of(segment.strip())
                if argv is not None:
                    found.append(argv)
    without_blocks = re.sub(r"^```.*?^```", "", text, flags=re.DOTALL | re.MULTILINE)
    for span in re.findall(r"`([^`\n]+)`", without_blocks):
        argv = _argv_of(span)
        if argv:  # a bare `nbp-git-safe` (the program name) is prose, not a command
            found.append(argv)
    return found


def parse_with_real_parser(argv: list[str]) -> None:
    parser = cli.build_parser()
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            parser.parse_args(argv)
    except SystemExit as exc:
        if exc.code not in (0, None):  # --version / --help exit 0
            pytest.fail(f"`{PROG} {shlex.join(argv)}` is not accepted by the CLI: {err.getvalue()}")


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_every_documented_command_exists_in_the_cli(doc: Path) -> None:
    commands = doc_commands(doc)
    assert commands, f"{doc.name}: no command found (the extractor is broken)"
    for argv in commands:
        parse_with_real_parser(argv)


def test_the_extractor_sees_the_commands_it_should() -> None:
    """Guards the guard: the key commands of the README are really extracted."""
    seen = {tuple(c[:1]) for c in doc_commands(ROOT / "README.md")}
    for sub in ("keygen", "init", "unlock", "seal", "open", "rotate", "purge"):
        assert (sub,) in seen, sub
    multi = [c for c in doc_commands(ROOT / "docs" / "MULTI.md")]
    assert ["open", "--confirm-first-adopt"] in multi
    assert ["sync", "--accept-remote-rewrite"] in multi
    assert any(c[:1] == ["purge"] and "--confirm" in c for c in multi)


def test_a_wrong_flag_would_be_caught() -> None:
    with pytest.raises(pytest.fail.Exception):
        parse_with_real_parser(["open", "--confirm-first-adoption"])
    with pytest.raises(pytest.fail.Exception):
        parse_with_real_parser(["frobnicate"])


def test_useful_commands_line_of_the_readme_names_real_subcommands() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    paragraph = re.search(r"^Useful commands:.*?(?:\n\n|\Z)", text, re.DOTALL | re.MULTILINE)
    assert paragraph is not None
    spans = re.findall(r"`([^`]+)`", paragraph.group(0).replace("\n", " "))
    assert len(spans) >= 8
    subcommands = {
        name for action in cli.build_parser()._subparsers._group_actions for name in action.choices
    }
    for span in spans:
        assert shlex.split(_placeholders_out(span))[0] in subcommands, span
    # and every hook event named in GUARD.md exists
    guard = (ROOT / "docs" / "GUARD.md").read_text(encoding="utf-8")
    for event in re.findall(r"hook \"nbp-git-safe-([a-z-]+)\"", guard):
        assert event in hooks.EVENTS


def test_the_version_is_the_same_everywhere() -> None:
    from nbp_git_safe import __version__

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    declared = re.search(r'^version = "([^"]+)"', pyproject, flags=re.MULTILINE)
    assert declared and declared.group(1) == __version__
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    newest = re.search(r"^## (\d+\.\d+\.\d+)", changelog, flags=re.MULTILINE)
    assert newest and newest.group(1) == __version__
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    pinned = set(re.findall(r"nbp-git-safe==(\d+\.\d+\.\d+)", readme))
    assert pinned == {__version__}


# ------------------------------------------------------------------------------ the quickstart


def pinned_block(markdown: str, heading: str) -> str:
    """The first fenced block after a heading of the README (so the test runs what is printed)."""
    start = markdown.index(heading)
    blocks = code_blocks(markdown[start:])
    return blocks[0]


def machine(isolated_git: IsolatedGit, path: Path, key_text: str, canaries: list[str]) -> NbpRepo:
    repo = NbpRepo(path, isolated_git, canaries, crypto.decode_key(key_text))
    repo.set_config("nbp-safe.ttl", "5m")
    repo.sh("config", "--local", "user.name", "Test User")
    repo.sh("config", "--local", "user.email", "test@example.invalid")
    return repo


def use_test_key_command(repo: NbpRepo) -> None:
    repo.set_config("nbp-safe.keyCommand", json.dumps([sys.executable, str(helpers.KEYCMD), "ok"]))


def printed_commands(stderr: str) -> list[str]:
    """The git commands a command prints for the owner (indented ``git ...`` lines)."""
    return [ln.strip() for ln in stderr.splitlines() if ln.strip().startswith("git ")]


def run_printed(isolated_git: IsolatedGit, line: str, cwd: Path) -> None:
    command = line.split("#", 1)[0].strip()  # the trailing explanation is a shell comment
    args = shlex.split(command)
    assert args[0] == "git"
    isolated_git.run(*args[1:], cwd=cwd)


def test_readme_quickstart_daily_flow_second_machine_sync_rotate_purge(
    isolated_git: IsolatedGit,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    canaries = helpers.new_canaries()
    bare = isolated_git.init(tmp_path / "remote.git", bare=True)

    # ---------------------------------------------------------------- Quickstart
    work = isolated_git.init(tmp_path / "my-repo")
    # the quickstart block, as printed: the pattern file is made by the printf of step 1
    quick = pinned_block(readme, "## Quickstart")
    assert "printf '%s\\n' '*.csv' 'reports/' > .nbp-safe" in quick
    (work / ".nbp-safe").write_bytes(b"*.csv\nreports/\n")  # what that printf writes
    first = machine(isolated_git, work, crypto.encode_key(bytes(64)), canaries)  # key set below
    first.sh("remote", "add", "origin", str(bare))

    # step 2: keygen prints the key ONCE on stdout and stores nothing
    keygen = first.cli("keygen")
    assert keygen.code == 0 and "shown ONCE" in keygen.err
    key_text = keygen.out.strip()
    assert keygen.out == key_text + "\n" and "\n" not in key_text
    master = crypto.decode_key(key_text)
    first.master = master
    assert key_text not in keygen.err
    monkeypatch.setenv(helpers.TEST_KEY_ENV, key_text)  # the "password manager item"

    # step 3: the README's literal keyCommand is accepted by the config parser ...
    literal = re.search(r"git config nbp-safe\.keyCommand '(\[.*?\])'", quick)
    assert literal is not None
    first.set_config("nbp-safe.keyCommand", literal.group(1))
    _repo, git = discover(work, isolated_git.env)
    assert parse_key_command(literal.group(1)) == (
        "op", "document", "get", "<ITEM_ID>", "--vault", "<VAULT_ID>",
    )  # fmt: skip
    cfg = load_config(git, _repo)
    assert cfg.key_command is not None and cfg.key_command[0] == "op"
    # ... and the test replaces only the password manager
    use_test_key_command(first)

    # some files that exist before the first seal (generic names, fake content)
    first.write("reports/q1.csv", f"id,v\n1,{canaries[0]}\n")
    first.write("notes.csv", f"a,b\n{canaries[1]},2\n")
    first.write("reports/deep/er/plan.txt", f"{canaries[2]}\n")
    first.write("src/app.py", "print('hi')\n")

    # step 4: init, unlock, seal
    init = first.cli("init")
    assert init.code == 0, init.err
    unlock = first.cli("unlock")
    assert unlock.code == 0, unlock.err
    sealed = first.cli("seal")
    assert sealed.code == 0 and "3 new" in sealed.out, sealed.err
    assert first.sh("rev-list", "--count", "refs/heads/nbp-safe").strip() == "1"

    # ------------------------------------------------------------------ Daily flow
    # "git add -A" never sees the protected files; the hooks seal on commit
    first.sh("add", "-A")
    staged = first.sh("diff", "--cached", "--name-only").split()
    assert sorted(staged) == [".nbp-safe", "src/app.py"]
    committed = first.raw("commit", "-q", "-m", "first")
    assert committed.returncode == 0, committed.stderr
    first.write("reports/q1.csv", f"id,v\n1,{canaries[0]}\n2,changed\n")
    first.write("src/app.py", "print('hello')\n")
    first.sh("add", "-A")
    assert first.sh("diff", "--cached", "--name-only").split() == ["src/app.py"]
    committed = first.raw("commit", "-q", "-m", "second")
    assert committed.returncode == 0, committed.stderr
    assert first.sh("rev-list", "--count", "refs/heads/nbp-safe").strip() == "2"  # post-commit
    pushed = first.raw("push", "-q", "origin", "main", "nbp-safe")  # as written in the README
    assert pushed.returncode == 0, pushed.stderr
    refs = bare_refs(isolated_git, bare)
    assert {"refs/heads/main", "refs/heads/nbp-safe"} <= set(refs)
    first.assert_no_leak(bare)

    # "Useful commands: status, ls, log <path>, diff <path>, mv, rm, doctor, lock"
    status = first.cli("status")
    assert status.code == 0 and "agent: unlocked" in status.out and "pending: nothing" in status.out
    listing = first.cli("ls")
    assert listing.code == 0 and "reports/q1.csv" in listing.out and "notes.csv" in listing.out
    log = first.cli("log", "reports/q1.csv")
    assert log.code == 0 and log.out.strip()
    first.write("reports/q1.csv", f"id,v\n1,{canaries[0]}\n2,changed\n3,more\n")
    diff = first.cli("diff", "reports/q1.csv", "--exit-code")
    assert diff.code == 1 and "+3,more" in diff.out
    assert first.cli("seal").code == 0
    doctor = first.cli("doctor")
    assert doctor.code in (0, 1), doctor.err  # a report; its verdict is not the README's claim

    # "A file moved to another protected path keeps its identity when its content is unchanged"
    ids_before = {e.path: fid for fid, e in entries_of(first, git).items()}
    (work / "reports" / "deep").rename(work / "reports" / "moved")
    first.sh("add", "-A")
    first.sh("commit", "-q", "--allow-empty", "-m", "moved")
    ids_after = {e.path: fid for fid, e in entries_of(first, git).items()}
    assert ids_after["reports/moved/er/plan.txt"] == ids_before["reports/deep/er/plan.txt"]
    assert "reports/deep/er/plan.txt" not in ids_after
    # "mv <old> <new>" is the explicit form
    assert first.cli("mv", "reports/moved/er/plan.txt", "reports/plan.txt").code == 0
    assert entries_of(first, git) and (work / "reports" / "plan.txt").exists()

    # "A file you delete locally stays in the vault by default (onMissing=keep); rm removes it"
    (work / "notes.csv").unlink()
    assert first.cli("seal").code == 0
    assert "notes.csv" in first.cli("ls").out
    removed = first.cli("rm", "notes.csv")
    assert removed.code == 0, removed.err
    assert "notes.csv" not in first.cli("ls").out

    # "Locked, commits still work: nothing is sealed, and a hint is printed"
    tip_before = first.sh("rev-parse", "refs/heads/nbp-safe").strip()
    assert first.cli("lock").code == 0
    first.write("reports/q1.csv", f"id,v\n1,{canaries[0]}\nlocked edit\n")
    first.write("src/app.py", "print('locked')\n")
    first.sh("add", "-A")
    locked_commit = first.raw("commit", "-q", "-m", "while locked")
    assert locked_commit.returncode == 0, locked_commit.stderr
    assert "nbp-git-safe unlock" in locked_commit.stderr  # the hint
    assert first.sh("rev-parse", "refs/heads/nbp-safe").strip() == tip_before
    assert first.sh("status", "--porcelain").strip() == ""  # protected files stay hidden
    assert first.cli("unlock").code == 0
    assert first.cli("seal").code == 0
    assert first.sh("rev-parse", "refs/heads/nbp-safe").strip() != tip_before

    # "nbp-git-safe init --auto-push, then a plain `git push`"
    auto = first.cli("init", "--auto-push")
    assert auto.code == 0, auto.err
    first.write("reports/auto.csv", "x,y\n1,2\n")
    first.sh("add", "-A")
    first.sh("commit", "-q", "--allow-empty", "-m", "auto push")
    plain_push = first.raw("push", "-q")
    assert plain_push.returncode == 0, plain_push.stderr
    assert (
        bare_refs(isolated_git, bare)["refs/heads/nbp-safe"]
        == first.sh("rev-parse", "refs/heads/nbp-safe").strip()
    )
    first.assert_no_leak(bare)

    # ------------------------------------------------------------------ A new machine
    second_dir = tmp_path / "second"
    isolated_git.run("clone", "-q", str(bare), str(second_dir))
    second = machine(isolated_git, second_dir, key_text, canaries)
    use_test_key_command(second)
    # "Without the key a clone only shows store/<hex> objects"
    tree = second.sh("ls-tree", "-r", "--name-only", "refs/remotes/origin/nbp-safe").split()
    assert all(re.fullmatch(r"store/[0-9a-f]{32}", n) or n in KNOWN_VAULT_FILES for n in tree)
    assert not any("q1" in n or "csv" in n for n in tree)
    second_init = second.cli("init")
    assert second_init.code == 0, second_init.err
    assert "created local branch nbp-safe tracking the vault on origin" in second_init.err
    assert "exclude block" in second_init.err and "hooks" in second_init.err
    assert second.cli("unlock").code == 0
    refused = second.cli("open")  # first time: stops and shows key id, seq and tip
    assert refused.code != 0 and not (second_dir / "reports").exists()
    assert "key id" in refused.err and "seq" in refused.err and "tip" in refused.err
    key_id = crypto.KeySet(master).key_id.hex()
    assert key_id in refused.err
    seen_status = second.cli("status")  # the values the README says to compare
    assert seen_status.code == 0 and key_id in seen_status.out
    adopted = second.cli("open", "--confirm-first-adopt")
    assert adopted.code == 0, adopted.err
    assert (second_dir / "reports" / "q1.csv").exists()
    assert (second_dir / "reports" / "auto.csv").exists()
    assert second.sh("status", "--porcelain").strip() == ""
    second.assert_no_leak(bare)

    # "git pull keeps the machine current (post-merge merges and opens the vault)"
    first.write("reports/from-first.csv", "p,q\n1,2\n")
    first.sh("add", "-A")
    first.sh("commit", "-q", "--allow-empty", "-m", "from first")
    assert first.raw("push", "-q").returncode == 0
    pulled = second.raw("pull", "-q", "--no-rebase", "--no-edit", "origin", "main")
    assert pulled.returncode == 0, pulled.stderr
    fetched = second.raw("fetch", "-q", "origin")
    assert fetched.returncode == 0, fetched.stderr
    assert second.cli("sync", "--no-fetch").code == 0
    assert (second_dir / "reports" / "from-first.csv").read_text() == "p,q\n1,2\n"

    # "Two machines that diverge converge with sync: ... both versions are kept"
    first.write("reports/q1.csv", "first,version\n")
    assert first.cli("seal").code == 0
    assert first.cli("push").code == 0
    second.write("reports/q1.csv", "second,version\n")
    assert second.cli("seal").code == 0
    synced = second.cli("sync")
    assert synced.code == 0, synced.err
    copies = sorted(p.name for p in (second_dir / "reports").glob("q1.conflict-*"))
    assert len(copies) == 1, copies  # "<name>.conflict-<hex>.<ext>"
    assert re.fullmatch(r"q1\.conflict-[0-9a-f]+\.csv", copies[0])
    assert second.cli("push").code == 0  # "Nothing is ever force-pushed"
    assert first.cli("sync").code == 0
    assert (work / "reports" / copies[0]).exists()
    second.assert_no_leak(bare)

    # ------------------------------------------------------- Key rotation and erasure
    rotated = first.cli("rotate")
    assert rotated.code == 0, rotated.err
    new_key = rotated.out.strip()
    assert crypto.decode_key(new_key) != master and "shown ONCE" in rotated.err
    assert f"nbp-safe-{YEAR}" in rotated.err or f"nbp-safe-{YEAR}" in rotated.out
    assert first.sh("rev-list", "--count", f"refs/heads/nbp-safe-{YEAR}").strip() == "1"

    target = "reports/auto.csv"
    old_blobs = blobs_of(first, "refs/heads/nbp-safe", target, git)
    assert old_blobs
    # `purge <path>... --confirm "purge nbp-safe"`: wrong text refuses, the typed text rewrites
    assert first.cli("purge", target, "--confirm", "purge").code != 0
    purged = first.cli("purge", target, "--confirm", "purge nbp-safe")
    assert purged.code == 0 and "purged 1 entry" in purged.out, purged.err
    instructions = printed_commands(purged.err)
    assert len(instructions) == 3, instructions
    assert instructions[0].startswith("git push --force-with-lease=refs/heads/nbp-safe:")
    assert "never" not in purged.out
    # the owner runs EXACTLY what was printed ...
    (work / target).unlink()  # "delete the plain file or the next seal brings it back"
    for line in instructions:
        run_printed(isolated_git, line, work)
    # ... and then the purged blobs are gone from the local object database
    for sha in old_blobs:
        assert first.raw("cat-file", "-e", sha).returncode != 0, sha
    assert (
        bare_refs(isolated_git, bare)["refs/heads/nbp-safe"]
        == first.sh("rev-parse", "refs/heads/nbp-safe").strip()
    )


KNOWN_VAULT_FILES = {".gitattributes", "README.md", "nbp-safe/index"}


def bare_refs(isolated_git: IsolatedGit, bare: Path) -> dict[str, str]:
    out = isolated_git.run("for-each-ref", "--format=%(refname) %(objectname)", cwd=bare)
    return dict(line.split(" ", 1) for line in out.splitlines())


def entries_of(repo: NbpRepo, git: object) -> dict:
    from nbp_git_safe import agent, vault

    found, git_obj = discover(repo.path, repo.git.env)
    cfg = load_config(git_obj, found)
    with agent.AgentClient.connect(found.state_dir) as backend:
        return dict(vault.load_vault(git_obj, backend, cfg).index.entries)


def blobs_of(repo: NbpRepo, ref: str, path: str, git: object) -> set[str]:
    """Every blob sha the vault history ever stored for ``path``."""
    from nbp_git_safe import agent, vault

    found, git_obj = discover(repo.path, repo.git.env)
    shas: set[str] = set()
    with agent.AgentClient.connect(found.state_dir) as backend:
        for commit_id in repo.sh("rev-list", ref).split():
            state = vault.load_commit(git_obj, backend, commit_id)
            for fid, entry in state.index.entries.items():
                if entry.path == path and f"store/{fid}" in state.files:
                    shas.add(state.files[f"store/{fid}"])
    return shas
