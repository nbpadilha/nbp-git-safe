# Several machines: sync, push, rotate, purge

Nothing here ever forces anything on the remote. `push` sends the vault branch without `+` and
reports a rejection; `sync` merges; `purge` and `rotate` print the commands the **owner** has to run
for the remote side. All of them need the agent unlocked (they read or write encrypted data).

## Second machine

```
git clone <url> && cd <repo>
nbp-git-safe init        # exclude block, hooks, local branch nbp-safe tracking origin/nbp-safe
nbp-git-safe unlock      # keyCommand -> agent (RAM only)
nbp-git-safe open        # first time: refuses, and shows the vault's key id, seq and tip
nbp-git-safe open --confirm-first-adopt   # real names and files appear (see below)
```

Without the key only `store/<hex>` exist. **First adoption (trust on first use).** A clone that
has never verified a vault branch cannot know that the tip it found is the newest one: an older,
authentic commit of the real history, pushed as the branch by someone with write access, verifies
under your key too. So the first `open` or `sync` of a branch stops after verifying the chain and
authenticating the index, and prints the key id, the `seq` and the tip; compare them with
`nbp-git-safe status` on a machine that already has the vault (same key id, `seq` not lower), then
repeat with `--confirm-first-adopt`. `init --confirm-first-adopt` (agent unlocked) does the same at
once. Nothing is recorded as verified (or as "seen" on origin) before that. The hooks never adopt:
`post-merge` prints the reason. The same confirmation is needed when you point the clone at another
vault ref yourself (`git config nbp-safe.vaultRef ...`, for example on another machine after
`rotate`) and when the
record `.git/nbp-safe/vault-seq.json` is lost; a record that exists but is unreadable stops `open`,
`sync` and `seal` until it is repaired this way (it is never read as empty). The vault ref is a
local setting: a `vault.ref` in the versioned `.nbp-safe.config` is ignored and reported.

`git pull` keeps the machine current: the `post-merge` hook merges the vault that was just fetched
(`sync --no-fetch`, offline) and runs `open`; a local file that still equals an older vault version
is updated in place, a file with local edits is never overwritten (`<name>.nbp-theirs`).

## sync

`sync` = seal local changes, `git fetch origin +refs/heads/nbp-safe:refs/remotes/origin/nbp-safe`,
then:

| Relation | Result |
|----------|--------|
| origin has nothing newer | `up-to-date` / `ahead` (nothing to do; `push` publishes) |
| local is an ancestor of origin | fast-forward (the new tip is authenticated and every changed blob is decrypted and checked against the index first) |
| diverged | three-way merge by index entries (below), merge commit with two parents, message `nbp-safe: sync` |

Merge, per file id, against the merge base (no base: empty): a change on one side wins; the same
change on both sides is one change; removed on one side and modified on the other keeps the data;
a move on one side and an edit on the other combine; **both edited**: ours keeps the id and the
path, theirs is re-encrypted under a new id as `<name>.conflict-<8 hex of its mac>.<ext>` (or
`<name>.<ext>.conflict-...` when that would leave the protected set); the same new path on both
sides under different ids is a conflict copy too (identical content: merged into one). Both versions
are preserved; resolve by editing or removing the copy. If no conflict-copy name fits the protected
patterns, `sync` stops and asks for a pattern such as `*.conflict-*`. If the remote vault contains
paths outside your `.nbp-safe`, it asks for a `git pull` first. Everything adopted from the remote is
authenticated before it enters our history.

### Rollback and replacement of the remote branch

`.git/nbp-safe/remote-seen.json` remembers the tip of the remote vault this clone last saw (commit
ids only). A fetch that finds origin's tip to be an **ancestor** of it (a rollback) or **unrelated**
to it (replaced history) is reported by `status`, `doctor` (a problem) and refused by `sync` unless
`--accept-remote-rewrite` is given. Pushing your own newer history is an ordinary fast-forward and
repairs a rolled-back remote. A rewrite by the legitimate owner (`purge`, below) looks the same.
On every OTHER machine, after checking with the owner that the rewrite is the purge:

```
git branch -D nbp-safe                          # drop the local copy of the pre-purge history
nbp-git-safe sync --accept-remote-rewrite       # fetches, verifies the new chain, adopts it, opens
git reflog expire --expire=now --all && git gc --prune=now    # the old objects, if you want them gone
```

A `sync` with no local vault branch (deleted, or never created) does not adopt an origin tip that is
older than, or does not contain, the newest tip this clone verified: it stops with the same
message, whatever `remote-seen.json` says; `--accept-remote-rewrite` is the explicit way.

`init` is not part of it: it only re-creates a local branch that tracks origin (and records
nothing); `open` still refuses a history that replaced the one it verified, and `sync
--accept-remote-rewrite` is what adopts it, whether the branch is deleted or was re-created by
`init`. If you keep the old local branch instead, the same command **merges** the two histories and
can bring the purged data back.

## push

`nbp-git-safe push` seals (when unlocked) and runs `git push origin refs/heads/nbp-safe:refs/heads/nbp-safe`.
A rejection means origin has commits you do not have: run `sync`, then push again.
A refusal by origin's own rules (a server-side hook, a protected branch) is reported as such, and
`sync` will not help. Neither `push` nor `sync` waits for ever: each has a limit of ten minutes, after
which the whole process tree (git, `ssh`, a credential helper) is stopped and the command says so; the
vault is pushed with `--no-follow-tags`, never `--tags`. (The tray's background push has a limit of
two minutes and never prompts: `docs/TRAY.md`.)
`nbp-git-safe init --auto-push` sets `remote.origin.push` (the current branch, if you had no
refspecs, plus the vault) so a plain `git push` carries the vault; `uninstall` removes exactly the
refspecs it added.

## rotate

`nbp-git-safe rotate [--name nbp-safe-2027] [--delete-old --confirm "delete nbp-safe"]`

1. generates a new 64-byte key and prints it **once** on stdout (never stored);
2. re-encrypts the current state into a new orphan branch `nbp-safe-<year>` (fresh file ids, MACs
   recomputed with the new key, no history), and verifies every file with the new key;
3. leaves the old branch alone. `--delete-old` deletes the old LOCAL branch only after the typed
   confirmation `delete <branch>` (flag or interactive prompt). The remote copy is deleted only by
   you (`git push origin :refs/heads/nbp-safe`). A compromised key exposes the whole old history:
   rotation protects what is written from now on and lets you retire the old branch.

Next steps, printed by the command: replace the key in the password manager item used by
`keyCommand`, `git config nbp-safe.vaultRef refs/heads/nbp-safe-<year>`,
`nbp-git-safe key-id --accept <id>` (each repository records the public id of its key, and
the old id refuses the new key until you accept it on purpose; the command prints the id and asks
for a typed confirmation), `lock && unlock`, `git push origin nbp-safe-<year>` (the pre-push guard
validates the new branch with the new key, so switch first).

## purge

`nbp-git-safe purge <path>... --confirm "purge nbp-safe"` (or type it at the prompt) rewrites the
**local** vault history without every entry that ever had one of the paths: blobs and index rows are
removed from every commit, merge commits are kept, commits that only touched purged data disappear.
It verifies that no commit of the new history has the entries, then prints what you must do:

```
git push --force-with-lease=refs/heads/nbp-safe:<old remote tip> origin refs/heads/nbp-safe:refs/heads/nbp-safe
git reflog expire --expire=now refs/heads/nbp-safe refs/remotes/origin/nbp-safe
git gc --prune=now            # repacks and removes ALL unreachable objects, loose or packed
```

The tool does not run any of them. Until the forced push, `sync` refuses to run (it would merge the
old history back) and `status`/`doctor` say so. The plain file in the working tree is not touched:
delete it or take it out of the protected set, or the next seal brings it back. Erasure on GitHub may
also need a support request (forks, cached views). Other machines: see "Rollback and replacement".
