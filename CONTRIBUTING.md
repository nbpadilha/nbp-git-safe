# Contributing

Thanks for looking. The project is small and security-sensitive, so changes are reviewed with that in
mind.

## Set up and test

```
uv sync                                  # Python 3.11+, versions pinned in uv.lock
uv run ruff check
uv run ruff format --check
uv run pytest -q tests/unit              # fast; enforces 100% branch coverage of crypto.py
uv run pytest -q --no-cov tests/integration tests/leak   # real git in temp dirs; slow (many minutes)
python scripts/check_licenses.py         # SPDX / licence gate (also run in CI)
```

Integration tests use throw-away repositories under a temp directory, isolated from your git
configuration (`GIT_CONFIG_GLOBAL` / `GIT_CONFIG_SYSTEM`). They never touch the network.

## Rules for changes

* **Fake data only.** Tests, docs and examples never contain real names, e-mails or contents; use
  placeholders and random canaries (`tests/leak/harness.py`).
* **Leak tests are a gate.** Anything that writes to the object database must keep the canary scans
  green: no plaintext content and no real file name in the remote or in `.git`.
* **Fail closed.** An error must never result in plaintext written somewhere new or in a silently
  skipped check.
* **No custom cryptography.** Only the primitives already used (`AESSIV`, `HKDF`, `HMAC`). A format
  change needs a `docs/FORMAT.md` update and a version bump.
* **No network, no telemetry, no LLM** in code or tests. Runtime dependency: `cryptography` only;
  every dependency pinned exactly, from a release at least 7 days old, with `uv.lock` committed.
* **Style:** `ruff` (config in `pyproject.toml`), type hints, small functions, an
  `# SPDX-License-Identifier: MIT` line at the top of every Python file.
* Commit messages in English, imperative mood, one logical change per commit.

## Licence policy

The project is MIT. Contributions are accepted under MIT.

* **Never copy or adapt code from GPL, LGPL, AGPL or MPL projects** (for example git-crypt,
  git-remote-gcrypt, sops), and do not read their source while implementing a feature: ideas and
  public documentation only.
* Code from MIT/BSD/Apache-2.0 projects may be adapted with attribution (a comment in the file plus
  `NOTICE` / `THIRD_PARTY.md`). The base of this repository is transcrypt (MIT).
* CI runs `scripts/check_licenses.py`: every Python file needs the SPDX MIT header and nothing under
  `src/` may carry a copyleft header.

## Releases and the upstream tags

The repository carries the tags of the transcrypt history it started from (`v0.9.4` ... `v2.3.2`,
plus the local `upstream-base`). They are not releases of this project. Publish **only** `main` and
our own tags, by name: `git push origin main v0.1.0`, never `--tags`, `--mirror` or `--all --tags`.
The whole procedure is in [docs/RELEASING.md](docs/RELEASING.md).

## Reporting vulnerabilities

Not through issues or pull requests: see [SECURITY.md](SECURITY.md).
