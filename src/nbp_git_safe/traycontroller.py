# SPDX-License-Identifier: MIT
"""The tray's brain, with no window in it (neutral: a macOS or Linux front end reuses it).

A front end owns the notification icon and the menu and does four things: call ``tick()`` every
few seconds, call ``view()`` to get the icon colour, the tooltip and the menu tree, call
``command(id)`` with the id of the chosen item, and call ``drain_notices()`` to show balloons. The
controller never touches a window; when something changed on a worker thread it calls ``wake()``
(which must be thread-safe) so the front end can redraw.

Threads: ``tick`` and ``command`` return at once. The slow things (reading the agents of all
repositories, the slower health check, sealing, pushing, and above all ``unlock``, which may wait
up to two minutes for the password manager, and a push to a remote that does not answer) run on
three worker lanes: one serial lane for unlocking (one password-manager prompt at a time), one for
pushing (a push that hangs delays only the next push: it has a hard time limit, and the icon, the
state and the warnings never wait for it) and one for everything else. A failure in a job becomes
an error code on the repository and a log line, never an exception in the front end.

Keys: the controller holds none, and with the ``unlock_runner`` the Windows tray passes
(``unlockchild.run_in_child``) the key never enters this long-lived process at all: it lives in a
short-lived child that hands it to the agent and exits. (Without a runner, ``fleetops.unlock_all``
runs in this process, as ``nbp-git-safe unlock`` does in its own.) Nothing here stores, logs or
shows a key. Every repository's own ``.git/config`` decides its ``keyCommand``.
"""

from __future__ import annotations

import contextlib
import functools
import hashlib
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Protocol

from nbp_git_safe import fleet, fleetops, registry, trayconfig
from nbp_git_safe.fleet import ERROR, LOCKED, MISSING, UNLOCKED, MenuItem, MenuSettings, RepoState
from nbp_git_safe.fleetops import FAILED, OK, SKIPPED, WARN, RepoHandle
from nbp_git_safe.traylog import TrayLog

REFRESH_SECONDS = 30.0  # how often the agents of all repositories are read
DEEP_SECONDS = 600.0  # the slower health check (doctor, vault versus origin, pending files)
CONFIG_SECONDS = 60.0  # how often tray.json is read again
DEFAULT_PENDING_GRACE = fleet.DEFAULT_PENDING_GRACE


class Worker(Protocol):
    def submit(self, job: Callable[[], None]) -> None: ...


class SerialWorker:
    """One daemon thread that runs submitted jobs one after the other."""

    def __init__(self, name: str) -> None:
        self._queue: queue.Queue[Callable[[], None]] = queue.Queue()
        self._thread = threading.Thread(target=self._loop, name=name, daemon=True)
        self._thread.start()

    def submit(self, job: Callable[[], None]) -> None:
        self._queue.put(job)

    def _loop(self) -> None:
        while True:
            job = self._queue.get()
            with contextlib.suppress(Exception):  # jobs report their own errors; the lane lives on
                job()


class InlineWorker:
    """Runs a job in the caller's thread (tests)."""

    def submit(self, job: Callable[[], None]) -> None:
        job()


@dataclass(frozen=True)
class View:
    color: fleet.Color
    tooltip: str
    menu: tuple[MenuItem, ...]
    states: tuple[RepoState, ...]


@dataclass
class CommandResult:
    quit: bool = False
    message: str = ""


def _synthetic_key(path: str) -> str:
    return hashlib.sha256(b"unavailable\0" + registry.key_of(path).encode()).hexdigest()[:24]


class TrayController:
    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.time,
        load_registry: Callable[[], registry.Loaded] = registry.load,
        load_config: Callable[[], tuple[trayconfig.TrayConfig, str | None]] = trayconfig.load,
        update_config: Callable[..., trayconfig.TrayConfig] = trayconfig.update,
        ops: Any = fleetops,
        log: TrayLog | None = None,
        unlock_worker: Worker | None = None,
        work_worker: Worker | None = None,
        push_worker: Worker | None = None,
        unlock_runner: Callable[..., list[fleetops.Outcome]] | None = None,
        autostart_get: Callable[[], bool | None] = lambda: None,
        autostart_set: Callable[[bool], None] | None = None,
        open_folder: Callable[[Path], None] = lambda _p: None,
        open_config: Callable[[], None] = lambda: None,
        wake: Callable[[], None] = lambda: None,
        autostart_label: str = "Start with Windows",
    ) -> None:
        self._clock = clock
        self._load_registry = load_registry
        self._load_config = load_config
        self._update_config = update_config
        self._ops = ops
        self._log = log or TrayLog(None)
        self._unlock_worker = unlock_worker or SerialWorker("nbp-unlock")
        self._work_worker = work_worker or SerialWorker("nbp-work")
        self._push_worker = push_worker or SerialWorker("nbp-push")
        self._unlock_runner = unlock_runner
        self._autostart_get = autostart_get
        self._autostart_set = autostart_set
        self._open_folder = open_folder
        self._open_config = open_config
        self._wake = wake
        self._autostart_label = autostart_label
        self._lock = threading.RLock()
        self._config, self._config_error = self._load_config()
        now = clock()
        self._schedule = fleet.Schedule(
            {
                "refresh": REFRESH_SECONDS,
                "deep": DEEP_SECONDS,
                "config": CONFIG_SECONDS,
                "seal": self._config.sealIntervalMinutes * 60.0,
            },
            now,
            immediately=("refresh",),
        )
        self._handles: dict[str, RepoHandle] = {}
        self._failed: dict[str, tuple[str, str, str]] = {}  # synthetic key -> (path, code, name)
        self._order: list[str] = []  # keys in registry order (handles and failures)
        self._index: dict[str, int] = {}
        self._states: tuple[RepoState, ...] = ()
        self._dups: set[str] = set()
        self._views: dict[str, fleetops.AgentView] = {}
        self._refresh_lock = threading.RLock()
        self._busy: dict[str, str] = {}
        self._errors: dict[str, str] = {}
        self._deep: dict[str, fleetops.DeepCheck] = {}
        self._deep_failed: dict[str, str] = {}  # the health check itself could not run: code
        self._pushing: set[str] = set()  # a push is queued or running (never queued twice)
        self._pending_since: dict[str, float] = {}
        self._notices: list[fleet.Notice] = []
        self._tracker = fleet.NoticeTracker()
        self._autostart: bool | None = None
        self._started = False

    # ----------------------------------------------------------------------- front end API

    def start(self) -> None:
        """First refresh at the next ``tick``; with ``unlockAtLogin`` also one ``unlock --all``."""
        self._log.write("start", version=1)
        self._started = True
        if self._config.unlockAtLogin:
            self._submit_unlock(None, "login")

    def tick(self) -> None:
        """Start whatever is due. Cheap; call it every few seconds from the UI thread."""
        for name in self._schedule.due(self._clock()):
            self._work_worker.submit(functools.partial(self._run_job, name))

    def view(self) -> View:
        with self._lock:
            now = self._clock()
            states = self._states
            grace = (self._config.warnPendingMinutes or 0) * 60.0 or DEFAULT_PENDING_GRACE
            settings = MenuSettings(
                seal_minutes=self._config.sealIntervalMinutes,
                seal_push=self._config.sealPush,
                unlock_at_login=self._config.unlockAtLogin,
                autostart=self._autostart,
                autostart_label=self._autostart_label,
                config_error=self._config_error or "",
            )
        return View(
            fleet.aggregate_color(states, now, pending_grace=grace),
            fleet.tooltip(states, now, pending_grace=grace),
            fleet.build_menu(states, now, settings),
            states,
        )

    def drain_notices(self) -> list[fleet.Notice]:
        with self._lock:
            out, self._notices = self._notices, []
        return out

    def command(self, command_id: str) -> CommandResult:
        """Run the command a menu item carries. Unknown ids do nothing."""
        parsed = fleet.parse_command(command_id)
        if parsed is None:
            return CommandResult(message="unknown command")
        if parsed.scope == "app":
            return self._command_app(parsed)
        if parsed.scope == "set":
            return self._command_setting(parsed)
        if parsed.scope == "all":
            self._command_all(parsed.action)
        else:
            self._command_repo(parsed.key, parsed.action)
        return CommandResult()

    # ------------------------------------------------------------------------- commands

    def _command_app(self, command: fleet.Command) -> CommandResult:
        if command.action == "quit":
            self._log.write("quit")
            return CommandResult(quit=True)
        if self._autostart_set is not None and self._autostart is not None:
            try:
                self._autostart_set(not self._autostart)
                self._autostart = self._autostart_get()
            except Exception as exc:
                self.report("autostart", None, fleetops.classify(exc)[0])
            self._changed()
        return CommandResult()

    def _command_setting(self, command: fleet.Command) -> CommandResult:
        try:
            if command.action == "edit-config":
                if not trayconfig.config_path().exists():
                    self._update_config()  # writes the defaults so there is a file to edit
                self._open_config()
                return CommandResult()
            if command.action == "seal-interval":
                self._update_config(sealIntervalMinutes=int(command.value))
            elif command.action == "toggle-push":
                self._update_config(sealPush=not self._config.sealPush)
            else:
                self._update_config(unlockAtLogin=not self._config.unlockAtLogin)
        except (trayconfig.TrayConfigError, ValueError) as exc:
            self.report("config", None, "config-invalid")
            return CommandResult(message=str(exc))
        self._reload_config()
        self._changed()
        return CommandResult()

    def _command_all(self, action: str) -> None:
        with self._lock:
            handles = [self._handles[k] for k in self._order if k in self._handles]
        if action == "unlock":
            self._submit_unlock(handles, "menu")
        else:
            for handle in handles:
                self._submit_work(handle, action)

    def _command_repo(self, key: str, action: str) -> None:
        with self._lock:
            handle = self._handles.get(key)
        if handle is None:
            return  # the repository left the registry since the menu was drawn
        if action == "unlock":
            self._submit_unlock([handle], "menu")
        elif action == "open-folder":
            with contextlib.suppress(Exception):
                self._open_folder(handle.path)
        elif action == "toggle-autounlock":
            self._work_worker.submit(lambda: self._toggle_auto_unlock(handle))
        else:
            self._submit_work(handle, action)

    # --------------------------------------------------------------------------- jobs

    def _run_job(self, name: str) -> None:
        try:
            if name == "refresh":
                self._refresh(reopen=False)
            elif name == "deep":
                self._refresh(reopen=True)
                self._deep_check()
            elif name == "seal":
                self._seal_unlocked()
            elif name == "config":
                self._reload_config()
        except Exception as exc:
            self.report(name, None, fleetops.classify(exc)[0])
        finally:
            self._schedule.done(name, self._clock())
            self._changed()

    def _begin(self, key: str, what: str) -> bool:
        with self._lock:
            if key in self._busy:
                return False
            self._busy[key] = what
            return True

    def _end(self, key: str) -> None:
        with self._lock:
            self._busy.pop(key, None)
        self._rebuild()

    def _submit_unlock(self, handles: list[RepoHandle] | None, why: str) -> None:
        """Queue an unlock of ``handles`` (all registered ones when ``None``) on the serial lane."""
        marked: list[str] = []
        if handles is not None:
            for handle in handles:
                if self._begin(handle.key, "unlocking"):
                    marked.append(handle.key)
            if not marked:
                return
        self._rebuild()
        self._unlock_worker.submit(lambda: self._unlock_job(handles, marked, why))

    def _unlock_job(self, handles: list[RepoHandle] | None, marked: list[str], why: str) -> None:
        try:
            if handles is None:
                self._refresh(reopen=True)  # every configuration is read again, right now
                with self._lock:
                    handles = [self._handles[k] for k in self._order if k in self._handles]
                    for handle in handles:
                        if handle.key not in self._busy:
                            self._busy[handle.key] = "unlocking"
                            marked.append(handle.key)
            self._rebuild()
            by_key = {h.key: h for h in (handles or [])}
            fresh = (self._fresh(by_key[k], "unlock") for k in marked if k in by_key)
            wanted = [h for h in fresh if h is not None]
            runner = self._unlock_runner or self._ops.unlock_all
            for outcome in runner(wanted, on_outcome=self._after_unlock):
                self._log.write("unlock", outcome.index, code=outcome.code or outcome.kind)
        except Exception as exc:
            self.report("unlock", None, fleetops.classify(exc)[0])
        finally:
            for key in marked:
                with self._lock:
                    self._busy.pop(key, None)
            self._refresh_safely()
            self._changed()

    def _fresh(self, handle: RepoHandle, what: str) -> RepoHandle | None:
        """``handle`` with the repository's own configuration read again NOW: the periodic refresh
        re-reads it only every few minutes, and a ``keyCommand`` changed a moment ago must apply
        to the unlock or push about to run. ``None`` (and the error code on the repository) when
        the repository can no longer be opened."""
        try:
            fresh: RepoHandle = self._ops.open_handle(str(handle.path), handle.index)
        except Exception as exc:
            code = exc.code if isinstance(exc, fleetops.HandleError) else fleetops.classify(exc)[0]
            with self._lock:
                self._errors[handle.key] = code
            self.report(what, handle.index, code)
            return None
        with self._lock:
            if fresh.key == handle.key and handle.key in self._handles:
                self._handles[handle.key] = fresh
        return fresh

    def _after_unlock(self, outcome: fleetops.Outcome) -> None:
        with self._lock:
            key = next((k for k, i in self._index.items() if i == outcome.index), None)
            if key is None:
                return
            if outcome.kind == FAILED:
                self._errors[key] = outcome.code or "failed"
            else:
                self._errors.pop(key, None)
        self._rebuild()
        self._changed()

    def _submit_work(self, handle: RepoHandle, action: str) -> None:
        if action not in ("lock", "seal"):
            return
        if not self._begin(handle.key, "locking" if action == "lock" else "sealing"):
            return
        self._rebuild()
        self._work_worker.submit(lambda: self._work_job(handle, action))

    def _work_job(self, handle: RepoHandle, action: str) -> None:
        try:
            outcome = self._ops.lock_one(handle) if action == "lock" else self._ops.seal_one(handle)
            self._record(handle, action, outcome)
            if action == "seal" and outcome.kind == OK:
                self._queue_push(handle)
        except Exception as exc:
            self.report(action, handle.index, fleetops.classify(exc)[0])
        finally:
            self._end(handle.key)
            self._refresh_safely()
            self._changed()

    def _toggle_auto_unlock(self, handle: RepoHandle) -> None:
        try:
            self._ops.set_auto_unlock(handle, not handle.cfg.auto_unlock)
            self._refresh(reopen=True)
        except Exception as exc:
            self.report("auto-unlock", handle.index, fleetops.classify(exc)[0])
        self._changed()

    def _queue_push(self, handle: RepoHandle) -> None:
        """After a seal, with ``sealPush``: push on the push lane, never on the seal's own."""
        if not self._config.sealPush:
            return
        with self._lock:
            if handle.key in self._pushing:
                return
            self._pushing.add(handle.key)
        self._push_worker.submit(lambda: self._push_job(handle))

    def _push_job(self, handle: RepoHandle) -> None:
        try:
            fresh = self._fresh(handle, "push")
            if fresh is not None:
                self._record(fresh, "push", self._ops.push_one(fresh))
        except Exception as exc:
            code = fleetops.classify(exc)[0]
            with self._lock:
                self._errors[handle.key] = code
            self.report("push", handle.index, code)
        finally:
            with self._lock:
                self._pushing.discard(handle.key)
            self._rebuild()
            self._changed()

    def _record(self, handle: RepoHandle, what: str, outcome: fleetops.Outcome) -> None:
        self._log.write(
            what,
            handle.index,
            code=outcome.code or outcome.kind,
            sealed=int(outcome.data.get("sealed", 0)),
        )
        if what == "push":  # its own code never clears (or is cleared by) a seal's
            with self._lock:
                if outcome.kind in (FAILED, WARN):
                    self._errors[handle.key] = outcome.code or "failed"
                elif outcome.kind == OK and self._errors.get(handle.key, "").startswith("push-"):
                    self._errors.pop(handle.key, None)
            return
        with self._lock:
            if outcome.kind in (FAILED, WARN):
                self._errors[handle.key] = outcome.code or "failed"
            elif outcome.kind == OK and not self._errors.get(handle.key, "").startswith("push-"):
                self._errors.pop(handle.key, None)  # (a push problem is cleared by a push)
            if what == "seal" and outcome.kind in (OK, WARN):
                self._pending_since.pop(handle.key, None)
                if handle.key in self._deep:
                    self._deep[handle.key] = replace(self._deep[handle.key], pending=0)

    def _seal_unlocked(self) -> None:
        with self._lock:
            ready = [
                self._handles[s.key]
                for s in self._states
                if s.status == UNLOCKED and s.key in self._handles and s.key not in self._busy
            ]
        for handle in ready:
            if not self._begin(handle.key, "sealing"):
                continue
            self._rebuild()
            try:
                outcome = self._ops.seal_one(handle)
                if outcome.kind != SKIPPED:
                    self._record(handle, "seal", outcome)
                if outcome.kind == OK:
                    self._queue_push(handle)
            except Exception as exc:
                self.report("seal", handle.index, fleetops.classify(exc)[0])
            finally:
                self._end(handle.key)
        self._rebuild()

    # ------------------------------------------------------------------- state building

    def _refresh_safely(self) -> None:
        try:
            self._refresh(reopen=False)
        except Exception as exc:
            self.report("refresh", None, fleetops.classify(exc)[0])

    def _open(self, entry: registry.Entry, position: int) -> RepoHandle | tuple[str, str]:
        """A handle for ``entry``, or ``(code, name)`` when it cannot be opened."""
        try:
            handle: RepoHandle = self._ops.open_handle(entry.path, position)
        except fleetops.HandleError as exc:
            return exc.code, fleetops.short_name(entry.path)
        return handle

    def _sync_handles(self, reopen: bool) -> None:
        """Bring the handles in line with the registry: new entries are opened, gone ones dropped,
        and with ``reopen`` every configuration is read again. A repository that could not be
        opened is retried only on ``reopen`` (or when a missing folder came back)."""
        loaded = self._load_registry()
        with self._lock:
            known = {registry.key_of(h.path): h for h in self._handles.values()}
            known_failed = dict(self._failed)
            known_dups = set(self._dups)
        handles: dict[str, RepoHandle] = {}
        failed: dict[str, tuple[str, str, str]] = {}
        dups: set[str] = set()
        order: list[str] = []
        index: dict[str, int] = {}
        for position, entry in enumerate(loaded.entries, start=1):
            path_key = registry.key_of(entry.path)
            synthetic = _synthetic_key(entry.path)
            handle: RepoHandle | None = known.get(path_key)
            prior = known_failed.get(synthetic)
            if path_key in known_dups and not reopen:
                dups.add(path_key)  # a worktree of a repository that is already listed
                continue
            if handle is not None and not Path(entry.path).is_dir():
                # the folder went away after the handle was opened (deleted, moved, drive gone)
                failed[synthetic] = (entry.path, "missing", fleetops.short_name(entry.path))
                order.append(synthetic)
                index[synthetic] = position
                continue
            keep_failure = (
                handle is None
                and prior is not None
                and not reopen
                and not (prior[1] == "missing" and Path(entry.path).is_dir())
            )
            if keep_failure:
                assert prior is not None
                failed[synthetic] = prior
                order.append(synthetic)
                index[synthetic] = position
                continue
            if handle is None or reopen:
                opened = self._open(entry, position)
                if isinstance(opened, tuple):
                    failed[synthetic] = (entry.path, opened[0], opened[1])
                    order.append(synthetic)
                    index[synthetic] = position
                    continue
                handle = opened
            handle = replace(handle, index=position)
            if handle.key in handles:
                dups.add(path_key)
                continue
            handles[handle.key] = handle
            order.append(handle.key)
            index[handle.key] = position
        with self._lock:
            self._handles, self._failed, self._order, self._index = handles, failed, order, index
            self._dups = dups
            live = set(order)
            self._busy = {k: v for k, v in self._busy.items() if k in live}
            self._errors = {k: v for k, v in self._errors.items() if k in live}
            self._deep = {k: v for k, v in self._deep.items() if k in live}
            self._deep_failed = {k: v for k, v in self._deep_failed.items() if k in live}
            self._pending_since = {k: v for k, v in self._pending_since.items() if k in live}

    def _refresh(self, *, reopen: bool) -> None:
        with self._refresh_lock:
            self._sync_handles(reopen)
            with self._lock:
                handles = [self._handles[k] for k in self._order if k in self._handles]
            views = {h.key: self._ops.read_agent(h) for h in handles}
            with self._lock:
                self._views = views
                failed = len(self._failed)
            with contextlib.suppress(Exception):
                self._autostart = self._autostart_get()
            self._log.write("refresh", repos=len(handles), unavailable=failed)
            self._rebuild()

    def _rebuild(self) -> None:
        """Recompute ``RepoState`` for every registered repository from what is known, and queue
        the notices that became due."""
        now = self._clock()
        with self._lock:
            views = self._views
            states: list[RepoState] = []
            for key in self._order:
                busy = self._busy.get(key, "")
                error = self._errors.get(key, "")
                handle = self._handles.get(key)
                if handle is None:
                    path, code, name = self._failed[key]
                    status = MISSING if code == "missing" else ERROR
                    states.append(
                        RepoState(
                            key,
                            self._index[key],
                            name,
                            path,
                            status,
                            busy=busy,
                            error=error or code,
                        )
                    )
                    continue
                view = views.get(key)
                deep = self._deep.get(key)
                status, expires = LOCKED, None
                if view is not None and view.state == "unlocked":
                    status, expires = UNLOCKED, view.expires_at
                elif view is not None and view.state == "error":
                    status, error = ERROR, error or view.code
                pending = deep.pending if deep is not None and deep.pending else 0
                since = self._pending_since.get(key)
                if pending and since is None:
                    since = self._pending_since[key] = now
                elif not pending:
                    self._pending_since.pop(key, None)
                    since = None
                states.append(
                    RepoState(
                        key=key,
                        index=handle.index,
                        name=handle.name,
                        path=str(handle.path),
                        status=status,
                        expires_at=expires,
                        auto_unlock=handle.cfg.auto_unlock,
                        problems=None if deep is None else deep.problems,
                        divergent=bool(deep and deep.divergent),
                        pending=pending,
                        pending_since=since,
                        busy=busy,
                        error=error,
                        check_error=self._deep_failed.get(key, ""),
                    )
                )
            self._states = tuple(states)
            notices = self._tracker.update(
                self._states,
                now,
                warn_expiry_minutes=self._config.warnExpiryMinutes,
                warn_pending_minutes=self._config.warnPendingMinutes,
                minimal=self._config.notifications == "minimal",
            )
            self._notices.extend(notices)

    def _deep_check(self) -> None:
        with self._lock:
            handles = [self._handles[k] for k in self._order if k in self._handles]
        for handle in handles:
            try:
                result = self._ops.deep_check(handle)
            except Exception as exc:
                code = fleetops.classify(exc)[0]
                self.report("deep", handle.index, code)
                with self._lock:  # a check that cannot run is not a clean bill of health
                    self._deep_failed[handle.key] = code
                    self._errors[handle.key] = code
                continue
            with self._lock:
                if self._deep_failed.pop(handle.key, None) is not None:
                    self._errors.pop(handle.key, None)
                self._deep[handle.key] = result
            self._log.write(
                "deep",
                handle.index,
                problems=result.problems,
                divergent=result.divergent,
                pending=-1 if result.pending is None else result.pending,
            )
        self._rebuild()

    def _reload_config(self) -> None:
        config, error = self._load_config()
        with self._lock:
            changed = config != self._config
            self._config, self._config_error = config, error
        if changed:
            self._schedule.set_interval("seal", config.sealIntervalMinutes * 60.0, self._clock())
            self._log.write("config", seal=config.sealIntervalMinutes)
        self._rebuild()

    def report(self, what: str, repo: int | None, code: str) -> None:
        self._log.write("error", repo, job=what.replace("_", "-"), code=code)

    def _changed(self) -> None:
        with contextlib.suppress(Exception):
            self._wake()
