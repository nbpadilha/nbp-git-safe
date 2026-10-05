# Several repositories and the tray

For one person with many repositories: see all of them at a glance, unlock them with one
password-manager approval per key, and have unsealed files sealed in the background. Everything is
built on the same rules as the single-repository tool; nothing here holds a key.

* Cross-platform part (works everywhere): the **registry**, `status|unlock|lock|seal|doctor --all`,
  the model and the controller behind the tray.
* Windows part: the tray icon itself (`nbp-git-safe tray`) and `autostart`.
* macOS and Linux front ends are **welcome as forks or pull requests**: section 7 says exactly what to
  implement.

## 1. The registry

`nbp-git-safe init` registers the repository, `uninstall` removes it. By hand:

```
nbp-git-safe registry list
nbp-git-safe registry add [PATH]
nbp-git-safe registry remove [PATH]
nbp-git-safe registry prune
```

`prune` forgets entries whose folder is gone or is no longer a git repository.

The registry is `repos.json` in the private per-user state directory (`%LOCALAPPDATA%\nbp-git-safe`
on Windows; `~/.cache/nbp-git-safe-<uid>` elsewhere; `NBP_SAFE_RUNTIME_DIR` overrides it): the same
directory, with the same ownership and permission checks, as the agent state. It holds **absolute
canonical paths and dates only**:

```json
{"version": 1, "repos": [{"path": "D:\\work\\some-repo", "added": 1790000000}]}
```

It only says where to look. Every operation reads the configuration of the repository itself
(`.git/config`, where `keyCommand` lives); nothing in the registry is executed or interpreted as a
command, and a repository does not get any trust from being listed.

Reading is strict and fails safe. A malformed file, a wrong type, a relative path, a `..` or `.`
component, a path that is not in canonical form, a UNC or device path, a control character or a bad
date gives an ignored entry and a warning; the commands go on. A file written by a newer version is
read-only. Writing is atomic (a temporary file, `fsync`, `os.replace`) under a lock file, so two
writers lose nothing, and a damaged file is first **moved to `repos.json.bak`** (`.2.bak`, ... when
that exists), never overwritten silently. Two registered paths that are worktrees of one repository
are one repository to the `--all` commands (they share one agent).

## 2. The `--all` commands

```
nbp-git-safe status --all
nbp-git-safe unlock --all
nbp-git-safe lock --all
nbp-git-safe seal --all --push
nbp-git-safe doctor --all
```

They walk the registry in order, one repository after the other, and **continue after a failure**.
Output is one block per repository (`[3] name: ...`), never a key and never a protected file name
(counts only), and a last line with the totals. `--all` cannot be combined with `-C`.

Exit codes: `0` everything fine (a registry that is empty, or a repository that was merely skipped
because it is locked, is fine); `1` at least one repository failed (could not be opened, key command
failed, seal refused, doctor found a problem); `3` for `status --all` when nothing failed but some
repository is locked. A folder that no longer exists is a warning (`registry prune` removes it), not
a failure.

**`unlock --all` and the password manager.** Repositories are grouped by an identical `keyCommand`
(the same argv, compared exactly) and the command is run **once per group**; the key it prints is
handed to the agent of every repository of the group, one after the other, over the usual
authenticated channel. A group whose command fails (a refused prompt, a timeout) fails as a group:
the command is not asked again for the next repository of it. Groups run one at a time, so there is
at most one prompt on screen. A repository that is already unlocked does not need the key and
causes no run. The key reaches an agent only if this process has just started that agent and
authenticated it (as in `nbp-git-safe unlock`); it is never put in an argument, an environment
variable, a file or a message, and the buffer the group owns is zeroed afterwards (Python cannot
reach the immutable copies it made on the way; the single-repository `unlock` has the same limit).

**`seal --all`** seals the repositories whose agent is unlocked and **never unlocks** anything: a
locked repository is skipped with one status line. `--push` then runs
`git push origin refs/heads/nbp-safe` (no force, never tags) in the repositories that have
`nbp-safe.autoPush` set **and** an `origin`. The push never prompts and gives up on a stalled
transfer (`GIT_TERMINAL_PROMPT=0`, low-speed limits); a remote that cannot be reached is a warning
(the line says to run `nbp-git-safe push` in that repository), not a failure; a rejection (origin
has commits you do not) or a refusal by the push guard is a failure. The text git printed is not
repeated (it may contain a URL).

## 3. The tray (Windows)

```
nbp-git-safe tray                 # run it (use pythonw or the autostart below to have no console)
nbp-git-safe tray --config        # show the configuration file and its values
nbp-git-safe tray --config sealIntervalMinutes=30 sealPush=true
nbp-git-safe autostart install    # start the tray at login (HKCU Run key, no administrator)
nbp-git-safe autostart status
nbp-git-safe autostart remove
```

One tray per user session (a named mutex; a second start leaves quietly). No dependency was added:
the window, the icon, the menu and the balloons are `ctypes` calls (`user32`, `shell32`, `gdi32`,
`kernel32`), and the icons are drawn in memory.

### Icon

| Colour | Meaning |
|---|---|
| gray | no repository is registered |
| green | every repository has an unlocked agent with at least an hour left, and nothing needs attention |
| yellow | some repository is locked, its folder is missing, or an unlocked agent has less than an hour left |
| red | some repository needs attention: it cannot be opened or its agent cannot be reached, `doctor` reports a problem, the vault diverged from origin (or went back, or was replaced), or protected files stayed unsealed for longer than `warnPendingMinutes` (30 by default) |

Red wins over yellow. The tooltip says the same in words (`2 unlocked, 1 locked; 1 need attention;
next expiry 25m`), so colour is never the only signal.

### Menu

One row per repository (`name: unlocked, 5h 12m left, 2 unsealed`), each with a submenu **Unlock**,
**Lock**, **Seal now**, **Open folder** and **Auto-unlock** (a checkbox that sets
`nbp-safe.autoUnlock` in that repository's `.git/config`). Then **Unlock all**, **Lock all**, **Seal all
now**, **Settings** (seal interval, push when sealing, unlock at login, open the configuration
file), **Start with Windows** (checked according to the Run key) and **Quit**. Names that repeat get
`(2)`; `&` in a name is escaped.

### What runs when

| Job | When | What it does |
|---|---|---|
| refresh | every 30 s | reads the registry and the agent of every repository **in this process** (a handshake and a status call, no child process) |
| health check | every 10 min | `doctor` problems, the vault against origin, and (unlocked only) how many protected files wait to be sealed; also re-reads each repository's configuration |
| periodic seal | `sealIntervalMinutes` (15) | the equivalent of `seal --all` for the unlocked repositories (and `--push` with `sealPush`), which closes the gap "a script wrote a file and it only enters the vault at the next commit" |
| configuration | every minute | re-reads `tray.json` |
| unlock | on a menu click, or once at start with `unlockAtLogin` | `unlock` of one repository or of all (section 2); on its own serial lane, because the password manager may take up to two minutes |

Nothing blocks the message loop: every slow thing runs on a worker thread and reports through a
short error code on the repository and a line in the menu (`last: key-command`); an exception in a
job is logged and swallowed. The periodic seal never unlocks. The tray unlocks only when you click
Unlock, or at start when you turned `unlockAtLogin` on (the "one approval a day").

### Balloons

When an agent has `warnExpiryMinutes` (30) left (once per unlock), when protected files have been
unsealed for `warnPendingMinutes` (30; once per episode), and when an operation fails (once per
error code until it succeeds again). `0` turns a warning off.

### Configuration

`tray.json` next to `repos.json`, edited from the menu or with `tray --config name=value`:

| Name | Default | Range |
|---|---|---|
| `sealIntervalMinutes` | 15 | 1 to 1440 |
| `sealPush` | false | true or false |
| `unlockAtLogin` | false | true or false |
| `warnExpiryMinutes` | 30 | 0 to 1440 (0: off) |
| `warnPendingMinutes` | 30 | 0 to 1440 (0: off; the red rule still uses 30) |

Validation is strict: an unknown name, a string where a number belongs, a boolean written as `1`,
or a number out of range makes the whole file invalid; the tray then runs on the defaults, says so
at the top of its menu and never rewrites the file for you.

### Log

`tray.log` in the same directory, rotated at 64 KiB to `tray.log.1`. A line is a time, an event, the
**position of the repository in the registry** and whole numbers or short codes
(`seal repo=2 code=sealed sealed=3`). The writer replaces anything else by `?`: no path, no folder
name, no file name, no exception text, no key. Writing the log never raises.

### Autostart

`autostart install` writes the value `nbp-git-safe-tray` under
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` with the command
`"<pythonw.exe>" -I -m nbp_git_safe tray`: absolute path of the `pythonw.exe` that sits next to the
interpreter running the install (the one of the `uv tool` or virtual environment), quoted for paths
with spaces, no shell, isolated mode. `install` again is idempotent (it reports `unchanged` or
`updated`), `remove` deletes exactly that value, and `status` says whether the stored command is what
`install` would write now (it is not after you move or upgrade the environment: run `install`
again). A path containing `%` or `"` is refused.

### Limits

* **Elevation.** An agent started from an elevated terminal cannot be inspected by a non-elevated
  tray (and the reverse): the repository shows an error (`other-elevation`) and nothing is sent to
  that agent. Unlock from the same kind of terminal, or unlock from the tray.
* **A desktop is required.** Without a notification area (a service session) the tray exits with an
  error. Only the current user's session is served.
* **The key command runs without a console window** (`CREATE_NO_WINDOW`, also for git: a process
  without a console must not flash one per child). A key command that needs to type in a console
  cannot work from the tray; password-manager CLIs that show their own dialog work.
* **Not verified by the test suite:** behaviour on high-DPI and high-contrast themes (the icon is
  drawn at `SM_CXSMICON`, with the process marked DPI-aware), the real password-manager prompt from
  the tray, and sessions other than a normal interactive one.
* Python cannot wipe memory reliably (see `THREAT_MODEL.md`); the tray adds no new copy of a key
  beyond the one `unlock` already makes while it hands the key to the agent.

## 4. What is stored, and where

| File | Content |
|---|---|
| `repos.json` (+ `.bak`) | paths and dates |
| `tray.json` | the five options |
| `tray.log` (+ `.1`) | codes and counts |
| `repos.json.lock`, `tray.json.lock` | empty, exist while a writer works |

No key, no plaintext, no protected file name. The tests scan all of them (and every `.git`) for the
test keys and canary names after real runs.

## 5. Data model (for front ends)

`nbp_git_safe.fleet` (pure, no I/O, the clock is a parameter):

* `RepoState`: `key` (the agent's repository key, 24 hex), `index` (registry position, 1-based),
  `name`, `path`, `status` (`unlocked`, `locked`, `missing`, `error`), `expires_at`, `auto_unlock`,
  `problems`, `divergent`, `pending`, `pending_since`, `busy`, `error`.
* `aggregate_color(states, now)`, `tooltip(states, now)`: the rules of section 3.
* `build_menu(states, now, MenuSettings)` returns a tree of `MenuItem(id, label, enabled, checked,
  separator, children)`; `parse_command(id)` is the strict parser of the ids (`repo:<key>:<action>`,
  `all:<action>`, `set:<name>[:<value>]`, `app:<action>`): a front end never builds a command from
  user text.
* `Schedule`, `NoticeTracker`, `render_icon_bgra(color, size)` (a BGRA bitmap of the status circle).

`nbp_git_safe.traycontroller.TrayController` ties it together and is what a front end drives:

| Call | Use |
|---|---|
| `start()` | once, after the icon exists (honours `unlockAtLogin`) |
| `tick()` | every few seconds from the UI thread; starts the jobs that are due; returns at once |
| `view()` | `View(color, tooltip, menu, states)`; cheap, call it whenever the icon or menu is needed |
| `command(id)` | when a menu item is chosen; returns `CommandResult(quit=...)` |
| `drain_notices()` | `Notice(title, text, level)` list to show as balloons or notifications |

Constructor hooks: `wake` (called from worker threads when something changed: it must be
thread-safe and should only post a message to the UI thread), `open_folder`, `open_config`,
`autostart_get`/`autostart_set` (leave `None` when the platform has no such thing and the menu item
disappears), `autostart_label`, `log`, and the clock and the two workers for tests.

## 6. Layers

```
registry.py     the file of repositories                       neutral
statefile.py    atomic write, lock, small reads                neutral
trayconfig.py   tray.json                                      neutral
traylog.py      the name-free log                              neutral
fleetops.py     operations over repositories (unlock_all ...)  neutral
fleetcli.py     --all, registry, autostart, tray options       neutral
fleet.py        pure model: colours, menu, schedule, notices   neutral
traycontroller  jobs, threads, state; drives a front end       neutral
autostart.py    HKCU Run value (winreg imported lazily)        Windows
tray_win.py     ctypes window, icon, menu, balloons            Windows
```

Nothing outside `tray_win.py`, `winsec.py` and the lazy `winreg` import in `autostart.py` loads a
Windows module, so the other layers run (and are tested) on Linux and macOS in CI.

## 7. Porting to macOS or Linux

Pull requests and forks are welcome. The work is a thin front end:

1. A process that creates the status item (a menu-bar item with `NSStatusItem` through a binding, or
   `StatusNotifierItem`/AppIndicator on Linux) and builds `TrayController(...)` with `wake` posting
   to the main loop and `open_folder`/`open_config` calling the platform opener.
2. On a timer of a few seconds call `controller.tick()` then redraw from `controller.view()` when
   the colour or tooltip changed; show `drain_notices()` as notifications.
3. Draw the menu from the `MenuItem` tree and, when an item is chosen, call
   `controller.command(item.id)`; quit when the result says so.
4. Draw the icon from `fleet.render_icon_bgra(color, size)` (convert the bytes to your toolkit's
   image type) or ship your own glyphs for the four `fleet.Color` values.
5. Single instance per user (a lock file or the toolkit's own mechanism), and autostart through the
   platform's login-item mechanism, exposed as `autostart_get`/`autostart_set`.
6. Add a `tray` subcommand branch for your platform in `fleetcli.cmd_tray` (today it says
   "not supported on this platform", exit code 2).

Things that are the same everywhere and already done for you: the state directory checks
(`agent.private_root`), the registry, strict configuration, the log, the one-prompt-per-key unlock,
the seal and push rules, and the tests of all of it (`tests/unit/test_traycontroller.py` shows how
to drive the controller without a window: fake operations, an injected clock and inline workers).
POSIX agents already exist and are exercised by CI; what has not been tried is the unlock lane with
a desktop password-manager prompt, so say what you tested in the pull request.
