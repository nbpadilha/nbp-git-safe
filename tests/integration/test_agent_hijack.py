# SPDX-License-Identifier: MIT
"""The key agent against hijacking (regressions for review findings A1 and A2), with real
detached agent processes.

* A1: a process that plants an ``agent.json`` of its own (own pipe, own authkey, live pid) must
  receive neither the master key from ``unlock`` nor plaintext from ``seal``.
* A2: a package named ``nbp_git_safe`` planted in the temp directory, in the current directory or
  on ``PYTHONPATH`` must not be imported by the process that holds the key.
"""

from __future__ import annotations

import dataclasses
import os
import tempfile
import threading
from pathlib import Path

import pytest

from nbp_git_safe import agent, crypto
from tests.helpers import NbpRepo, populate


class EvilServer(agent.AgentServer):
    """An impostor that speaks the agent protocol and records whatever it is sent."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.stolen: list[bytes] = []

    def _handle(self, op: int, body: bytes) -> tuple[int, bytes, bool]:
        if op == agent.OP_LOCK:
            return agent.STATUS_OK, b"", False  # ignores `lock`, like a hostile process would
        if op == agent.OP_LOAD_KEY:
            (raw,) = agent.unpack_args(body, 1)
            self.stolen.append(raw)
        if op == agent.OP_ENC_BLOB:
            _fid, _bucket, data = agent.unpack_args(body, 3)
            self.stolen.append(data)
        return super()._handle(op, body)


def plant_impostor(state_dir: Path) -> EvilServer:
    """What the review's PoC does: start a server and write an ``agent.json`` that points at it,
    with its own pipe, its own authkey and nonce, and a live pid. (It cannot know the secret.)"""
    own = dataclasses.replace(
        agent.new_endpoint(state_dir), nonce=os.urandom(32), authkey=os.urandom(32)
    )
    evil = EvilServer(state_dir, 120.0, None, exit_func=lambda _c: None, key_wait=600, endpoint=own)
    evil.start()
    threading.Thread(target=evil.serve_forever, daemon=True).start()
    return evil


def test_planted_agent_json_receives_neither_the_key_nor_plaintext(make_repo) -> None:  # type: ignore[no-untyped-def]
    repo: NbpRepo = make_repo()
    populate(repo)
    evil = plant_impostor(repo.state_dir)
    try:
        # plaintext: seal talks to whatever agent.json names; the impostor fails the handshake
        sealed = repo.cli("seal")
        assert sealed.code != 0
        assert evil.stolen == []

        # the key: unlock never delivers it to an agent it merely found through a file
        unlocked = repo.cli("unlock")
        assert unlocked.code == 0, unlocked.err
        assert evil.stolen == []
        info = agent.read_agent_info(repo.state_dir)
        assert info is not None and info.pid != os.getpid()  # a NEW agent process has the key
        assert info.address != evil.info.address  # type: ignore[union-attr]

        # and from here on the real agent serves the repository, the impostor still sees nothing
        assert repo.cli("seal").code == 0
        assert repo.cli("status").code == 0
        assert evil.stolen == []
        assert crypto.encode_key(repo.master) not in unlocked.out + unlocked.err
    finally:
        evil.shutdown("test")


def test_a_locked_impostor_in_the_way_is_replaced_not_trusted(make_repo) -> None:  # type: ignore[no-untyped-def]
    """Same attack with ``status`` first: an unauthenticated answer never counts as 'locked' or
    'unlocked'."""
    repo: NbpRepo = make_repo()
    evil = plant_impostor(repo.state_dir)
    try:
        assert repo.cli("status").code == 1  # an error, not a cheerful 'locked'
        assert repo.cli("unlock").code == 0
        assert evil.stolen == []
    finally:
        evil.shutdown("test")


FAKE_PACKAGE = """\
import os
with open({marker!r}, "a") as handle:
    handle.write("imported from " + os.path.dirname(__file__))
raise SystemExit(0)
"""


def plant_fake_package(parent: Path, marker: Path) -> Path:
    package = parent / "nbp_git_safe"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(FAKE_PACKAGE.format(marker=str(marker)))
    return parent


def test_the_agent_never_imports_a_package_planted_where_it_starts(
    make_repo,  # type: ignore[no-untyped-def]
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo: NbpRepo = make_repo()
    marker = tmp_path / "IMPORTED-THE-FAKE"
    fake_temp = plant_fake_package(tmp_path / "fake-temp", marker)
    fake_cwd = plant_fake_package(tmp_path / "fake-cwd", marker)
    fake_path = plant_fake_package(tmp_path / "fake-pythonpath", marker)
    monkeypatch.setattr(tempfile, "tempdir", str(fake_temp))  # where the old code ran the agent
    monkeypatch.chdir(fake_cwd)
    monkeypatch.setenv("PYTHONPATH", str(fake_path))
    monkeypatch.setenv("PYTHONSTARTUP", str(fake_path / "nbp_git_safe" / "__init__.py"))

    info = agent.spawn_agent(repo.state_dir, 60, None)  # a failure leaves it to the reaper fixture
    with agent.AgentClient.connect_info(info) as client:
        status = client.status()
        assert status["locked"] is True and status["pid"] == info.pid
        client.lock()
    assert not marker.exists(), marker.read_text() if marker.exists() else ""
