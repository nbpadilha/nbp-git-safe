# Third-party notices

## Derived work

| Project | License | Use |
|---------|---------|-----|
| [transcrypt](https://github.com/elasticdog/transcrypt) (base commit `1b59c8e505c0f0eb396dce4d36274a12a446e2d6`) | MIT | Repository history, test-isolation approach (`GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM`) |

## Runtime dependencies

| Package | License | Use |
|---------|---------|-----|
| [cryptography](https://github.com/pyca/cryptography) | Apache-2.0 OR BSD-3-Clause | AES-SIV, HKDF, HMAC primitives (no custom constructions) |
| [cffi](https://github.com/python-cffi/cffi) (transitive, via `cryptography`) | MIT-0 (MIT No Attribution) | C foreign-function interface used by `cryptography`'s bindings |
| [pycparser](https://github.com/eliben/pycparser) (transitive, via `cffi`; not installed on PyPy) | BSD-3-Clause | C parser used by `cffi` |

**OpenSSL inside the `cryptography` wheels.** The binary wheels of `cryptography` embed a statically
linked OpenSSL (the build used for development reports `OpenSSL 4.0.2`, which is licensed under
Apache-2.0). Its licence text ships with the wheel; anyone redistributing the wheels (or a frozen
application built from them) has to carry the notices of the `cryptography` distribution
(`LICENSE`, `LICENSE.APACHE`, `LICENSE.BSD`). This project does not redistribute `cryptography`; it
only depends on it by exact version.

## Development dependencies (not distributed)

Licences below were read from the metadata of the packages installed from `uv.lock`
(`*.dist-info/METADATA` and the licence files next to it).

| Package | Version | License | Why |
|---------|---------|---------|-----|
| pytest | 9.1.1 | MIT | test runner |
| pytest-cov | 7.1.0 | MIT | coverage plugin |
| coverage | 7.16.1 | Apache-2.0 | coverage measurement (the `crypto.py` gate) |
| ruff | 0.16.9 | MIT | lint and format |
| colorama | 0.4.6 | BSD-3-Clause | transitive (pytest, Windows console colours) |
| iniconfig | 2.3.0 | MIT | transitive (pytest) |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause | transitive (pytest) |
| pluggy | 1.6.0 | MIT | transitive (pytest) |
| Pygments | 2.21.0 | BSD-2-Clause | transitive (pytest, output highlighting) |
| tomli | 2.4.1 | MIT (upstream; see note) | in the lock only for `coverage[toml]` on Python 3.11.0 and older; not installed with the Python 3.11.x used here, so its licence could not be read from installed metadata |
| hatchling (build backend, pinned in `pyproject.toml`) | 1.32.4 | MIT | builds the wheel; not installed in the development environment |
