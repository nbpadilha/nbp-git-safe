# Releasing and publishing

Nothing in this repository publishes by itself: CI has no secrets and no deploy step. Publishing is
a manual act of the owner, and the first push is the delicate one.

## What is in the local history

* `main`: this project's history. It starts from the history of
  [transcrypt](https://github.com/elasticdog/transcrypt) (MIT), kept on purpose (the licence and
  `THIRD_PARTY.md` say so).
* **The upstream tags** `v0.9.4` ... `v2.3.2` come from transcrypt. They are *not* releases of this
  project and must never be published as such: they would show up as releases of
  `nbp-git-safe` with versions that are not ours (and `v1.x` / `v2.x` would suggest a maturity that
  does not exist).
* `upstream-base`: a local tag on the transcrypt commit this work started from (see
  `THIRD_PARTY.md`). Our own tags are `v0.1.0` and later.

## Before tagging

```
uv sync --frozen
uv run ruff check && uv run ruff format --check
python scripts/check_licenses.py
uv run pytest -q tests/unit                   # 100% branch coverage of crypto.py
uv run pytest -q --no-cov                     # the whole suite (about 25 minutes)
git status                                    # clean
```

Update the version in `pyproject.toml` and `src/nbp_git_safe/__init__.py` (and the `nbp-git-safe`
entry of `uv.lock`: `uv lock --offline`), write the `CHANGELOG.md` entry, commit, and tag **that**
commit with an annotated tag:

```
git tag -a v0.1.0 -m "nbp-git-safe 0.1.0"
```

## First publication (safe procedure)

1. Create the empty repository on GitHub (private first, if you want a last look). No README, no
   licence, no `.gitignore` from the web form.
2. Add the remote and **push by name, never with `--tags` or `--mirror`**:

   ```
   git remote add origin <url>
   git push origin main v0.1.0
   ```

   `git push --tags` would send all 21 local tags (the 20 upstream release tags and
   `upstream-base` included). For the same
   reason do not set `push.followTags` globally for this repository, and do not use
   `git push --all --tags`.
3. `upstream-base` stays local. If you want it on the remote (it documents where the history
   comes from), push it consciously and alone: `git push origin upstream-base`.
4. Check what the remote has: `git ls-remote --tags origin` must list `v0.1.0` (and, if you chose
   so, `upstream-base`), nothing else.
5. Later releases: `git push origin main vX.Y.Z`, always the tag by name.

If an upstream tag did get pushed by mistake, delete it on the remote at once
(`git push origin :refs/tags/v2.3.2`) and check the releases page; a published tag may already have
been mirrored by others, so treat it as public.

## What a release must not contain

Real names, e-mail addresses or contents (the tests use fake data and random canaries); keys or
tokens; the `.venv/`, caches or coverage files (`.gitignore` covers them). The vault branch
`nbp-safe` of a *user's* repository is never part of this repository.
