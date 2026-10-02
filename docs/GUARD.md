# Guard on the main branch

How nbp-git-safe keeps protected files (and their content) out of ordinary commits and pushes.
The vault itself is described in `FORMAT.md`.

## Layers

| # | Layer | Stops | Needs the key |
|---|-------|-------|---------------|
| 1 | managed block in `.git/info/exclude` (`init`) | `git add -A`, `git add .`, `git status` noise | no |
| 2 | `pre-commit` by **path** | `git add -f <protected>` then commit | no |
| 3 | `pre-commit` by **content** | a renamed or copied protected file | yes (agent unlocked) |
| 4 | `pre-push` over every commit being pushed, plus vault validation | anything that got past 2/3 (for instance `--no-verify`) | content part: yes |
| 5 | optional managed block in the versioned `.gitignore` (`init --gitignore-block`) | collaborators without the tool adding the files | no |

The protected set is the **union** of `.nbp-safe` at `HEAD`, in the index, in the working tree (and,
on push, at the pushed tip) plus the local `.git/info/nbp-safe`. Each version is matched on its own
with git's own matcher and the results are unioned, so removing a pattern or adding a local `!`
negation never unprotects something that another version still protects.

### pre-commit

* **path**: every staged added/modified/copied/type-changed path that matches the protected set blocks
  the commit (deletions are fine: that is how a file is untracked).
* **content** (agent unlocked): the MAC of every staged blob whose size equals the size of a protected
  file is compared with the MACs of the vault index **and** of the protected files currently on
  disk (so a copy of a file that is not sealed yet is caught too). Files shorter than 16 bytes
  are ignored (empty files, `.gitkeep` and one-line placeholders such as `1` or `{}` would match
  unrelated files; sensitive files are larger). Locked agent: this check is skipped with a warning
  (`run nbp-git-safe unlock`), the path check still runs.
* **pattern file**: a commit that removes a pattern from `.nbp-safe` (or deletes the file, or adds a
  `!` negation to an existing one) is blocked. Override for one commit:
  `NBP_SAFE_ALLOW_UNPROTECT=1` (deliberately never suggested by the tool's messages). Creating the
  file for the first time with negations is fine.
* **lint** (warning only, never blocks): a line of `.nbp-safe` that contains an e-mail address, or
  two or more consecutive Capitalized words inside one path segment (`Maria Silva`, `Joao_Silva`),
  is reported by line number only. It is a heuristic and can over-warn; patterns should be generic
  (personal names belong in `.git/info/nbp-safe`).

Failure is closed: an unexpected error inside the hook blocks the commit.

### pre-push

For every pushed ref (deletions are skipped) the hook lists the commits that are not on the remote
yet (`remote_oid..local_oid`, or everything not reachable from a remote-tracking ref for a new
branch/tag) and repeats the path and content checks on every one of them: a file that was added and
removed again is still in the history being sent.

For a vault branch (`refs/heads/nbp-safe[-suffix]`) it validates every new commit instead:

* tree contains only `.gitattributes`, `README.md`, `nbp-safe/index` and `store/<32 hex>` (all mode
  100644), `.gitattributes` and `README.md` are the canonical blobs, an index exists;
* the index and every `store/*` blob start with the nbp-safe magic/version header, and all of them
  carry the same `key_id`;
* with the agent unlocked also: the tip's index authenticates under the key and every entry has its
  blob.

Per-blob authentication is *not* done here (it needs a decryption of every blob); `open` and
`status` do it. A locked agent gets a structural check and a warning.

**Seal before checking.** With the agent unlocked, `pre-push` first runs `seal`, so a protected
file edited after the last commit is in the vault. If the vault tip moves while the vault branch is
part of the same push, the pushed (older) tip goes out and the hook says to push again.

**Out-of-date vault never blocks the code.** A locked agent, a stale vault or a vault that is behind
the remote only produce warnings; what blocks is a protected file in the clear and a vault that is
not a valid vault.

### post-commit / post-merge / post-checkout

`post-commit` seals when the agent is unlocked (silent when there is nothing to seal; a one-line hint
when locked and protected files exist). `post-merge` and `post-checkout` (branch switches only)
refresh the exclude block and, when unlocked and a vault exists, run `open`; locked, they print a
hint. They never fail git.

Hooks never ask the password manager on their own. Only `nbp-safe.autoUnlock=true` (opt-in, local
`.git/config`) lets a hook run `keyCommand`, with the `keyCommand` timeout; on failure the hook
degrades to the path check and says why.

## How the hooks are installed

**By git config** (git 2.54 or newer, per its release notes; verified in practice on 2.55.0 only):
one entry per event, named `nbp-git-safe-<event>` (git forbids a name equal to an event):

```
[hook "nbp-git-safe-pre-commit"]
    command = '<python>' -I -m nbp_git_safe hook pre-commit
    event = pre-commit
```

Git runs config hooks in addition to the script in the hooks directory, so a hand-written hook, a
husky-style `core.hooksPath` or the pre-commit framework keep working and nothing in those
directories is ever written. The command is a shell one-liner, so the interpreter path is
POSIX-quoted; it is the interpreter that ran `init` (no `PATH` lookup), and `-I` keeps the current
directory out of `sys.path`.

**Shim fallback** (git older than 2.54, or `init --shim` for clients that ignore config hooks): a
three-line script in the hooks directory, written **only** if no file is there and only inside this
repository's own `.git`. A foreign file is never overwritten; a shim that was edited is treated as
foreign. `uninstall` removes only a file that has exactly the shape of ours. A `core.hooksPath` that
points outside `.git` (a versioned or shared directory) gets no shim.

`doctor` verifies the installed state: command and events equal to the expected ones, not disabled
(`hook.<name>.enabled`, `hook.<event>.enabled`), and listed by `git hook list`. `init` repairs.

## Limits (documented, tested)

* `git commit --no-verify` skips `pre-commit`; the exclude block still protects `git add -A`.
  `git add -f <protected>` **plus** `--no-verify` leaks into a local commit. `pre-push` then blocks
  the push when it can see it (always by path; by content with the agent unlocked), and `doctor`
  flags the tracked file. History that was never pushed can be rewritten locally.
* `git add -f` writes the file's content into `.git/objects` at once (before any hook can run). A
  blocked commit leaves that unreachable blob behind until `git prune --expire now`.
* Locked agent: no content check (a renamed copy can pass `pre-commit` and, if also bypassed, a
  locked `pre-push`).
* `git stash -a` / `-u` can put protected files into the object database; `doctor` reports a stash
  that holds them.
* Clients that do not run git hooks at all (some GUIs, libgit2-based tools) bypass layers 2-4;
  the exclude block (layer 1) still applies to them.
* Plain files at rest in the working tree are not protected from indexers, antivirus or cloud sync;
  `doctor` warns when the repository is inside a OneDrive / Dropbox / Google Drive / iCloud folder
  (heuristic by folder name and the `OneDrive*` environment variables).
