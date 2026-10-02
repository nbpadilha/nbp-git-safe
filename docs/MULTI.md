# Several machines: sync, push, rotate, purge

Nothing here ever forces anything on the remote. `push` sends the vault branch without `+` and
reports a rejection; `sync` merges; `purge` and `rotate` print the commands the **owner** has to run
for the remote side. All of them need the agent unlocked (they read or write encrypted data).

## Second machine

```
git clone <url> && cd <repo>
nbp-git-safe init        # exclude block, hooks, local branch nbp-safe tracking origin/nbp-safe
nbp-git-safe unlock      # keyCommand -> agent (RAM only)
nbp-git-safe open        # real names and files appear; without the key only store/<hex> exist
```

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
repairs a rolled-back remote. A rewrite by the legitimate owner (`purge`, below) looks the same: on
the other machines delete the local vault branch and run `init` to adopt the new history;
`--accept-remote-rewrite` merges and can bring purged data back.

## push

`nbp-git-safe push` seals (when unlocked) and runs `git push origin refs/heads/nbp-safe:refs/heads/nbp-safe`.
A rejection means origin has commits you do not have: run `sync`, then push again.
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
`keyCommand`, `git config nbp-safe.vaultRef refs/heads/nbp-safe-<year>`, `lock && unlock`,
`git push origin nbp-safe-<year>` (the pre-push guard validates the new branch with the new key, so
switch first).

## purge

`nbp-git-safe purge <path>... --confirm "purge nbp-safe"` (or type it at the prompt) rewrites the
**local** vault history without every entry that ever had one of the paths: blobs and index rows are
removed from every commit, merge commits are kept, commits that only touched purged data disappear.
It verifies that no commit of the new history has the entries, then prints what you must do:

```
git push --force-with-lease=refs/heads/nbp-safe:<old remote tip> origin refs/heads/nbp-safe:refs/heads/nbp-safe
git reflog expire --expire=now refs/heads/nbp-safe refs/remotes/origin/nbp-safe
git prune --expire now        # removes ALL unreachable objects of this repository
```

The tool does not run any of them. Until the forced push, `sync` refuses to run (it would merge the
old history back) and `status`/`doctor` say so. The plain file in the working tree is not touched:
delete it or take it out of the protected set, or the next seal brings it back. Erasure on GitHub may
also need a support request (forks, cached views). Other machines: see "Rollback and replacement".
