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
causes no run.

Two rules keep the grouping honest. **The command always runs from the root of the repository it
is for** (`nbp-git-safe unlock`, a hook, `--all` and the tray all give it the same working
directory), and a `keyCommand` that holds a **relative path** (`["python", "tools/key.py"]`,
`["sh", ".git/key.sh"]`, or `python key.py` with the file in the repository) is not the same
command in two repositories even when the argv is identical: such a repository is a group of its
own, with its own prompt (a plain `pass show team/key` is reported the same way, which costs one
prompt more; an absolute path or a URI such as `op://vault/item` does not). And **each repository
records the public id of its key** (8 bytes derived from the key, already printed by `status` and
written in every vault blob; never the key) in its local `.git/config` as `nbp-safe.keyId`: by the
first `unlock` run inside the repository, by the first `seal` (which also proves the key opens the
vault), or by `nbp-git-safe key-id --accept <id>`. Every delivery of a key and every seal is
checked against it, so a key meant for another repository is refused before any agent starts
(`key-id-mismatch`, with the two ids and the command to accept a deliberate change), whatever the
commands are. A repository that has no registered id and no vault yet is not handed a group's key
at all (`no-key-id`: run `nbp-git-safe unlock` inside it once). After `rotate` the new key has a
new id: the printed next steps include `nbp-git-safe key-id --accept <id>`, which needs a typed
confirmation (`--confirm "accept key id <id>"` without a terminal). `doctor` reports a missing id,
a relative path in `keyCommand`, and an agent that holds another key than the registered one. The key reaches an agent only if this process has just started that agent and
authenticated it (as in `nbp-git-safe unlock`); it is never put in an argument, an environment
variable, a file or a message, and the buffer the group owns is zeroed afterwards (Python cannot
reach the immutable copies it made on the way; the single-repository `unlock` has the same limit).

**`seal --all`** seals the repositories whose agent is unlocked and **never unlocks** anything: a
locked repository is skipped with one status line. `--push` then runs
`git push origin refs/heads/nbp-safe` (no force, never tags) in the repositories that have
`nbp-safe.autoPush` set **and** an `origin`. The push has a **hard time limit of 120 seconds**; when
it runs out the whole process tree (git, `ssh`, a credential helper) is killed and the line says so
(`push-timeout`, a warning). It never waits for a person: no terminal prompt
(`GIT_TERMINAL_PROMPT=0`), no Git Credential Manager window (`GCM_INTERACTIVE=never`), slow HTTP
transfers abandoned (low-speed limits), and, **only when you set no ssh command of your own**
(`GIT_SSH_COMMAND`, `GIT_SSH` or `core.sshCommand` are never overridden), an `ssh` that is
non-interactive and gives up on a dead connection (`BatchMode=yes`, `ConnectTimeout`,
`ServerAliveInterval`). A remote that cannot be reached is a warning (the line says to run
`nbp-git-safe push` in that repository), not a failure; a rejection (origin has commits you do not),
a refusal by origin's own rules (a hook, a protected branch: `push-refused`, `sync` will not help) or
a refusal by the push guard is a failure. The text git printed is not repeated (it may contain a
URL). The pushes a person starts (`nbp-git-safe push`, `sync`) have a limit of ten minutes and keep
their terminal prompts. The vault is pushed with `--no-follow-tags`, never `--tags`.

## 3. The tray (Windows)

```
nbp-git-safe tray                 # run it (use pythonw or the autostart below to have no console)
nbp-git-safe tray --config        # show the configuration file and its values
nbp-git-safe tray --config sealIntervalMinutes=30 sealPush=true
nbp-git-safe autostart install    # start the tray at login (HKCU Run key, no administrator)
nbp-git-safe autostart status
nbp-git-safe autostart remove
```

One tray per user session (a named mutex; a second start leaves quietly). If the name is held by
an account or a privilege level this process cannot open (access denied), that is **not** "already
running": the tray says so in a message box, writes `mutex-denied` to its log and exits with code 4
(a normal second start exits with 0). No dependency was added:
the window, the icon, the menu and the balloons are `ctypes` calls (`user32`, `shell32`, `gdi32`,
`kernel32`), and the icons are drawn in memory.

### Icon

| Colour | Meaning |
|---|---|
| gray | no repository is registered |
| green | every repository has an unlocked agent with at least an hour left, and nothing needs attention |
| yellow | some repository is locked, its folder is missing, or an unlocked agent has less than an hour left |
| red | some repository needs attention: it cannot be opened or its agent cannot be reached (including a state directory that is not private: `insecure-state`, shown as an error, never as "locked"), `doctor` reports a problem, **the slower health check itself failed** (not a clean bill of health), the vault diverged from origin (or went back, or was replaced), or protected files stayed unsealed for longer than `warnPendingMinutes` (30 by default) |

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
| periodic seal | `sealIntervalMinutes` (15) | the equivalent of `seal --all` for the unlocked repositories, which closes the gap "a script wrote a file and it only enters the vault at the next commit" |
| push | after a seal, with `sealPush` | `git push origin refs/heads/nbp-safe` where `autoPush` is set and an `origin` exists; on its **own lane**, with the hard time limit of section 2 |
| configuration | every minute | re-reads `tray.json` |
| unlock | on a menu click, or once at start with `unlockAtLogin` | `unlock` of one repository or of all (section 2); on its own serial lane, because the password manager may take up to two minutes |

Nothing blocks the message loop: every slow thing runs on a worker thread and reports through a
short error code on the repository and a line in the menu (`last: key-command`); an exception in a
job is logged and swallowed. There are three lanes: unlocking, pushing and everything else, so a
push that hangs (an `origin` that never answers, a credential helper with a window of its own)
delays only the next push: the icon, the state and the warnings keep updating, and a push that ran
out of time is a short code on the repository (`push-timeout`) and a discreet balloon. A push is
never queued twice for one repository. The periodic seal never unlocks. The tray unlocks only when
you click Unlock, or at start when you turned `unlockAtLogin` on (the "one approval a day"). The
configuration of the repository is read again right before every unlock and every push, so a
`keyCommand` you changed a moment ago applies at once (the periodic refresh reads it every ten
minutes). With `onMissing=ask` the tray (like `--all`) keeps a file that was deleted locally, as
`keep` does, because nobody is there to answer; such a file is not counted as pending.

### Balloons

When an agent has `warnExpiryMinutes` (30) left (once per unlock), when protected files have been
unsealed for `warnPendingMinutes` (30; once per episode), and when an operation fails (once per
error code until it succeeds again; a push that did not complete is a warning, not an alarm). `0`
turns a warning off.

**Windows keeps a history of notifications** (the notification centre), and a balloon that names a
folder leaves that name there, outside this tool's control. With `notifications=minimal` a balloon
says `repository 3` (its position in `registry list`) instead of the folder's name; the menu, which
is not kept, still shows names.

### Configuration

`tray.json` next to `repos.json`, edited from the menu or with `tray --config name=value`:

| Name | Default | Range |
|---|---|---|
| `sealIntervalMinutes` | 15 | 1 to 1440 |
| `sealPush` | false | true or false |
| `unlockAtLogin` | false | true or false |
| `warnExpiryMinutes` | 30 | 0 to 1440 (0: off) |
| `warnPendingMinutes` | 30 | 0 to 1440 (0: off; the red rule still uses 30) |
| `notifications` | full | `full` or `minimal` (no folder name in a balloon) |

Validation is strict: an unknown name, a string where a number belongs, a boolean written as `1`,
a word that is not in the list, or a number out of range makes the whole file invalid; the tray then runs on the defaults, says so
at the top of its menu and never rewrites the file for you.

### Log

`tray.log` in the same directory, rotated at 64 KiB to `tray.log.1`. A line is a time, an event, the
**position of the repository in the registry** and whole numbers or short codes
(`seal repo=2 code=sealed sealed=3`). The writer replaces anything else by `?`: no path, no folder
name, no file name, no exception text, no key. Writing the log never raises.

### Autostart

`autostart install` first checks who can change what it is about to register: the interpreter
(`pythonw.exe`) **and the folder it sits in** (a replaced program or library there would run at
every login with your rights). If another account (Users, Everyone, Authenticated Users, another
SID) has write access to either, it **refuses** and says which; `--allow-writable` installs it
anyway, knowingly. `autostart status` runs the same check on the stored program and also says when
that program **no longer exists** (a moved or deleted environment leaves a dead value: run
`autostart remove`, then `install` again). It writes the value `nbp-git-safe-tray` under
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
* **The tray does not handle a key itself.** Unlocking from the menu or at login runs
  `python -I -m nbp_git_safe unlock-batch` in a short-lived **child process**: the tray hands it the
  folders (paths only, on stdin) and reads back one JSON line per repository (a code and a message,
  parsed strictly and reduced to known shapes), and the child opens each repository, runs each
  distinct key command once, gives the key to the agents it starts and exits. The key therefore
  never enters the tray's own address space, which lives for weeks. Python still cannot wipe the
  copies the interpreter makes (see `THREAT_MODEL.md`): they stay in the child's memory (and in a
  crash dump or the page file, if one is written) until the system reuses the pages, a few seconds
  after the unlock instead of after the agent has expired. A child that dies, stalls (it is killed
  after the sum of the key commands' limits plus a minute) or says something unintelligible leaves
  the repositories it did not report as `unlock-child` failures. `nbp-git-safe unlock --all` from a
  terminal is a process of its own that exits as well.
* **Windows messages.** The tray's hidden window accepts a notification-area message only when it
  carries the icon's own id, and never opens a second menu while one is open. A process of the same
  user can still post such a message (there is no sender to check) and make the menu appear, and
  Windows' message filtering separates **integrity levels, not users**; it cannot choose an item,
  because the numeric ids come from the tray's own table (see `THREAT_MODEL.md`).

## 4. What is stored, and where

| File | Content |
|---|---|
| `repos.json` (+ `.bak`) | paths and dates |
| `tray.json` | the six options |
| `tray.log` (+ `.1`) | codes and counts |
| `repos.json.lock`, `tray.json.lock` | empty; the lock is an operating-system lock on the file (released by the system if its holder dies), so the files stay |

No key, no plaintext, no protected file name. The tests scan all of them (and every `.git`) for the
test keys and canary names after real runs.

## 5. Data model (for front ends)

`nbp_git_safe.fleet` (pure, no I/O, the clock is a parameter):

* `RepoState`: `key` (the agent's repository key, 24 hex), `index` (registry position, 1-based),
  `name`, `path`, `status` (`unlocked`, `locked`, `missing`, `error`), `expires_at`, `auto_unlock`,
  `problems`, `divergent`, `pending`, `pending_since`, `busy`, `error`, `check_error` (the slower
  health check could not run: red).
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
disappears), `autostart_label`, `unlock_runner` (how an unlock is run: the default is
`fleetops.unlock_all` in this process, the Windows tray passes `unlockchild.run_in_child`, which does
it in a short-lived child so the key never enters the tray), `log`, and the clock and the three
workers (unlock, push, everything else) for tests.

## 6. Layers

```
registry.py     the file of repositories                       neutral
statefile.py    atomic write, OS lock, small reads             neutral
keyid.py        the registered public id of a repository's key neutral
keypin.py       recording and checking it around an unlock     neutral
trayconfig.py   tray.json                                      neutral
traylog.py      the name-free log                              neutral
fleetops.py     operations over repositories (unlock_all ...)  neutral
unlockchild.py  the tray's unlock in a short-lived process     neutral
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
