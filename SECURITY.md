# Security policy

## Status

nbp-git-safe is pre-release (0.1.1 in preparation) software. **It has not been audited by any third
party.** The cryptography is built only from `AES-SIV`, `HKDF-SHA256` and `HMAC-SHA256` of the
`cryptography` package, with RFC 5297 test vectors in the suite, but the vault layout, the key agent
and the git integration are new code. Do not rely on it for data whose exposure would be
catastrophic. An external review is a goal for the 0.1 release and is not done yet.

## Threat model in short

Protects: contents and file names against anyone who can read the Git remote, its forks and clones
(and the local object database) without the key; integrity of blobs and of the index (authenticated
encryption; a blob cannot be moved to another id; a tampered vault is rejected).

Does not protect: the number, approximate size (padded) and timing of changes, equality of
unchanged files, the existence and name of the vault branch, a compromised key (the whole history
of that vault), a compromised machine with an unlocked agent, plaintext at rest in the working
tree, files forced past the hooks (`git add -f`, `--no-verify`, `git stash -a`), or the need to
rewrite history to erase data. The full list is in [THREAT_MODEL.md](THREAT_MODEL.md).

## Supported versions

Only the latest released version (and `main`) receives fixes. Before 0.1.0 there is no release.

## Reporting a vulnerability

Please report privately through GitHub: on the repository page open **Security > Report a
vulnerability** (a private security advisory). Do not open a public issue or pull request for a
vulnerability.

Useful details: version (`nbp-git-safe --version`), OS and git version, what you expected and what
happened, and a minimal reproduction **with fake data only**. Never attach real keys, real
protected files or real repositories.

You can expect an acknowledgement within a few days. This is a one-person project with no bug
bounty; credit in the changelog is offered if you want it. Coordinated disclosure is appreciated:
please allow reasonable time for a fix before publishing details.

## Out of scope

* Attacks that need an already compromised machine with an unlocked agent, or physical access to
  the unlocked session.
* Reading plaintext files that the user deliberately left in the working tree.
* Bypassing hooks with `--no-verify`, `git add -f` or clients that skip hooks (documented limits in
  [docs/GUARD.md](docs/GUARD.md)); a bypass that defeats the *documented* guarantees is in scope.
* Weaknesses in `cryptography`, git, Python or the password manager used for `keyCommand`; report
  those upstream.
