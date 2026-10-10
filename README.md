# nbp-git-safe

Keep sensitive files in an ordinary Git repository, **encrypted**, with the latest version and the
**full history** inside the same repo, and with **file names and paths hidden** from the remote.
The key is never written to disk: it lives in the memory of a small local agent that is fed by your
password manager.

> **Status: 0.1.1 in preparation. Not audited by any third party.** The cryptography is
> `AES-SIV` / `HKDF-SHA256` / `HMAC-SHA256` from the `cryptography` package (no home-made
> construction), but the project is young. Read [SECURITY.md](SECURITY.md) and
> [THREAT_MODEL.md](THREAT_MODEL.md) before trusting it with anything you cannot afford to lose.

Português: veja o [resumo no fim](#resumo-pt-br).

## The problem

Some repositories generate files that must be versioned but must not be readable by whoever can read
the repository: reports with personal data, exported backups, credentials-adjacent artifacts.
Requirements that usually pull in different directions:

* the files keep living at their **normal paths** and scripts keep writing them there;
* `git add / commit / push` stays the daily routine;
* GitHub (and forks, clones, backups of the remote) must see **neither contents nor names**;
* history must be kept (no "latest snapshot" tarball);
* the decryption key must **not** sit in a file or in the shell history.

## How it works

```
main branch                          nbp-safe branch (orphan, built with git plumbing)
-----------                          ------------------------------------------------
code, docs, .nbp-safe (patterns)     .gitattributes   README.md   nbp-safe/index (encrypted)
                                     store/3f9a...e1  store/b07c...42  ...  (encrypted blobs)
protected files: NOT here            real names and paths: only inside the encrypted index
```

* **Protected set.** `.nbp-safe` (versioned, `.gitignore` syntax) lists generic patterns such as
  `*.csv` or `reports/`. The files stay in the working tree at their real paths and are hidden from
  the main branch by a managed block in `.git/info/exclude`, so `git add -A` never sees them.
* **Vault branch.** `refs/heads/nbp-safe` is an orphan branch that contains only an encrypted index
  and one encrypted blob per file under an **opaque random name** (`store/<32 hex>`). The index maps
  ids to real paths and is itself encrypted. Commits carry a fixed message and identity and a
  timestamp rounded to the hour. The branch is written with git plumbing
  (`hash-object`, `update-index` on a private index, `write-tree`, `commit-tree`,
  `update-ref` as compare-and-swap): no worktree, and the index and working tree of your main branch
  are never touched. **Plain content and real names never enter the git object database.**
* **Encryption.** One 64-byte master key; HKDF-SHA256 derives separate keys for blobs, index and
  content MACs. Each blob is AES-SIV with the file id bound as associated data (a blob copied to
  another id fails authentication), padded to a size bucket. See [docs/FORMAT.md](docs/FORMAT.md).
* **Key agent.** `nbp-git-safe unlock` runs your `keyCommand` (a JSON argv, run **without a shell**,
  for example `op document get ...`), validates the key and hands it to a detached agent process
  over an authenticated local channel (a named pipe on Windows, a Unix socket on POSIX; mutual
  HMAC handshake). The key lives only in that process and expires after a TTL (default 8 h) or on
  `lock`. Nothing that executes a command is ever read from a versioned file.
* **Hooks.** `post-commit` seals changed protected files into the vault; `pre-commit` and
  `pre-push` keep protected files and their content out of the main branch and validate the vault
  branch; `post-merge` / `post-checkout` merge and open the vault after `git pull`. Hooks are
  installed through git config (git 2.54+) so they coexist with husky, the pre-commit framework or
  hand-written hooks; older git gets a shim that never overwrites a foreign hook. See
  [docs/GUARD.md](docs/GUARD.md).
* **Fail closed.** No agent, wrong key, failed authentication or bad index means a non-zero exit and
  nothing written. Hooks never prompt for the key by themselves (opt in with `autoUnlock`).

## How it compares

An honest, high-level comparison written from public documentation. All of these tools are older,
more widely used and more battle-tested than this one; pick them when they fit.

| | File names hidden | History in the same repo | Key handling | Granularity | Notes |
|---|---|---|---|---|---|
| **git-crypt** | no (content only) | yes | GPG keys or a key file on disk | per file, via git filters | transparent in the working tree; GPL |
| **transcrypt** | no (content only) | yes | password in git config | per file, via git filters | shell script; MIT; this project started as a fork |
| **age** | n/a (a file encryptor) | no (you manage files) | key files or passphrase | whole files | excellent primitive; no Git integration |
| **sops** | keys of structured files stay visible | yes | KMS / PGP / age | values inside YAML/JSON/ENV | ideal for config; not for arbitrary files |
| **git-remote-gcrypt** | yes | yes | GPG | the **whole** remote repository is encrypted | the remote holds only encrypted data; GPL |
| **nbp-git-safe** | **yes** (opaque ids + encrypted index) | yes (a branch in the same repo) | RAM-only agent fed by a password manager | per file, selected by patterns | young, unaudited, whole-file blobs (no delta compression), Windows-first |

What this tool trades: you get hidden names and a key that is never on disk, in exchange for a
custom branch layout, a background agent process, and whole-file re-encryption on every change.

## Install

Requires Python 3.11+ and git 2.54+ (older git works with hook shims; 2.55 is what the test suite
was run on).

```
uv tool install nbp-git-safe==0.1.1      # once published
# from a checkout today:
uv tool install .
```

The only runtime dependency is `cryptography`. The tool makes no network calls and sends no
telemetry.

## Quickstart (with the 1Password CLI as the key source)

```
cd my-repo

# 1. Say what is sensitive (generic patterns, versioned). Personal names belong in
#    .git/info/nbp-safe, which is local and never versioned.
printf '%s\n' '*.csv' 'reports/' > .nbp-safe

# 2. Create a key. It is printed ONCE on stdout and stored nowhere.
nbp-git-safe keygen
#    Store that text as the only content of a password-manager item (for 1Password: a Document or
#    Secure Note item). It cannot be recovered afterwards: lose it and the vault is unreadable.

# 3. Tell this clone how to fetch the key. Local config only (.git/config), never versioned.
git config nbp-safe.keyCommand '["op","document","get","<ITEM_ID>","--vault","<VAULT_ID>"]'

# 4. Prepare the repository, unlock, and seal what exists.
nbp-git-safe init
nbp-git-safe unlock
nbp-git-safe seal
```

Use vault and item **UUIDs**, not names (names get renamed; ids do not). `op vault list` and
`op item list` show them.

## Daily flow

Keep generating and editing the files where you always did. Then, as usual:

```
git add -A && git commit -m "..."     # hooks seal changed protected files into the vault
git push origin main nbp-safe         # or: nbp-git-safe init --auto-push, then a plain `git push`
```

The agent has to be unlocked: run `nbp-git-safe unlock` once per TTL window (8 h by default), or set
`git config nbp-safe.autoUnlock true` so a hook may run your `keyCommand` itself (your password
manager will prompt). Locked, commits still work: the main branch stays protected by path, nothing
is sealed, and a hint is printed.

**Unattended runs** (a scheduled task, CI, a script: stderr is not a terminal, `CI` is set, or
`NBP_SAFE_NONINTERACTIVE=1`) must not end "green" with a stale vault. There, when the agent is
locked or expired and `autoUnlock` is off, `post-commit` prints an `ERROR` line and exits non-zero
(git ignores that status, so the commit itself still succeeds) and `pre-push` **refuses the push**
(nothing was sealed and the content check could not run). Unlock first (`nbp-git-safe unlock`, then
commit and push), or set `autoUnlock true`. At a terminal the old behaviour stays: a warning, and
you decide (`NBP_SAFE_NONINTERACTIVE=0` forces it). A local vault that fails to seal (damaged)
refuses an unattended push of the vault branch, never a push of the code alone.
If `pre-push` seals a new vault commit while the vault branch is being pushed, git would send the
old one (it read the refs before the hook ran): the push is refused, run `git push` again.

Useful commands: `status`, `ls`, `log <path>`, `diff <path>`, `mv <old> <new>` (keeps a file's
identity), `rm <path>`, `doctor` (checks the setup), `lock`.

* A file you delete locally stays in the vault by default (`onMissing=keep`); use `rm <path>` to
  remove it for real, or set `nbp-safe.onMissing`.
* A file moved to another protected path keeps its identity when its content is unchanged;
  moved **and** edited counts as remove + new. Use `mv` for an explicit move.

## A new machine

```
git clone <url> && cd <repo>
uv tool install nbp-git-safe==0.1.1
git config nbp-safe.keyCommand '["op","document","get","<ITEM_ID>","--vault","<VAULT_ID>"]'
nbp-git-safe init       # hooks, exclude block, local branch tracking origin/nbp-safe
nbp-git-safe unlock
nbp-git-safe open       # first time: stops and shows the vault's key id, seq and tip
nbp-git-safe open --confirm-first-adopt   # after comparing them with another machine
```

The first `open` (or `sync`) of a vault branch this clone has never verified asks for that
confirmation: a fresh clone cannot know that the tip it found is the newest one (trust on first
use, see [THREAT_MODEL.md](THREAT_MODEL.md)).

Without the key a clone only shows `store/<hex>` objects. `git pull` keeps the machine current
(`post-merge` merges and opens the vault). Two machines that diverge converge with `sync`: a
three-way merge by file id; when both edited the same file, both versions are kept (one as
`<name>.conflict-<hex>.<ext>`). Nothing is ever force-pushed. See [docs/MULTI.md](docs/MULTI.md).

## Key rotation and erasure

* `nbp-git-safe rotate` re-encrypts the current state under a **new key** into a new branch
  (`nbp-safe-<year>`). It protects what is written from now on; **the old history stays decryptable
  with the old key**, so rotate after a leak and retire the old branch.
* `nbp-git-safe purge <path>... --confirm "purge nbp-safe"` rewrites the local vault history without
  those files. Making the remote forget them needs a forced push that **you** run (the tool prints
  the commands and never runs them) and possibly a request to your Git host. See
  [docs/MULTI.md](docs/MULTI.md).

## Limitations (read these)

* **Not audited.** Treat it as unreviewed software.
* **Plaintext at rest.** Protected files sit unencrypted in the working tree. Indexers, antivirus,
  backup tools and cloud-sync folders can read them; `doctor` warns when the repo is inside a
  OneDrive / Dropbox / Google Drive / iCloud folder.
* **What the remote still learns:** that a vault exists, the branch name, how many files, their
  approximate sizes (padded to 4 KiB buckets by default), when they change, and which files have
  identical content (deterministic encryption per id; equal content in two files gives different
  blobs, but a file unchanged between commits keeps its blob).
* **A compromised key exposes the whole history** of that vault. A compromised machine with an
  unlocked agent exposes everything the agent can decrypt.
* **Bypasses exist.** `git commit --no-verify` skips the commit hook, and `git add -f` writes the
  content into `.git/objects` before any hook runs. The push guard blocks what it can see, but
  nothing outside your control stops a determined user. See [docs/GUARD.md](docs/GUARD.md).
* **Whole-file blobs.** Every change stores a new encrypted blob of the full file, so repositories
  with large, frequently rewritten files grow fast. One file is limited to 64 MiB.
* Python cannot reliably wipe memory; the key lives in ordinary objects for the agent's lifetime.
* Erasure (LGPD/GDPR) needs a history rewrite and may need your Git host's help.
* Clients that do not run git hooks (some GUIs, libgit2-based tools) bypass the hook layers.

## Security FAQ

**Where is the key?** Only in the agent's memory and in your password manager. The agent's small
state file lives in a private per-user directory outside the repository and holds the pipe address,
the PID and a public nonce, never the encryption key (the channel's key is derived from a separate
secret file in that directory).

**Can someone with the repository read my files or names?** Not without the key: contents are
AES-SIV blobs and names exist only inside the encrypted index. They can see counts, sizes (bucketed)
and timing.

**What if the agent is killed or the TTL expires?** The next command fails closed and tells you to
unlock. Nothing is sealed and no plaintext is written anywhere new.

**Can a malicious remote or collaborator plant something?** Everything adopted from the remote is
authenticated first; a malicious index cannot write outside the protected set, and a rollback or
replacement of the remote vault is detected and refused unless you pass `--accept-remote-rewrite`.

**Why not just encrypt the whole repository?** That is a fine design (git-remote-gcrypt). This tool
is for repositories where the code is meant to be readable and only some generated files are not.

**Does it phone home?** No. No network calls, no telemetry.

**How do I report a vulnerability?** See [SECURITY.md](SECURITY.md).

## Development

```
uv sync
uv run ruff check && uv run ruff format --check
uv run pytest -q             # unit + integration + leak tests, with real git in temp dirs
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Design: [PLAN-SPEC.md](PLAN-SPEC.md). Format:
[docs/FORMAT.md](docs/FORMAT.md). Hooks: [docs/GUARD.md](docs/GUARD.md). Multi-machine:
[docs/MULTI.md](docs/MULTI.md).

License: MIT. Derived from [transcrypt](https://github.com/elasticdog/transcrypt); see `NOTICE`.

## Resumo (PT-BR)

Versiona arquivos sensiveis em um repositorio Git comum, cifrados, com a ultima versao e todo o
historico no mesmo repo, e com **nomes e caminhos ocultos** no remoto. A chave nunca e gravada em
disco: vive na memoria de um agente local, alimentado pelo seu gerenciador de senhas (por exemplo
`op document get <ITEM_ID> --vault <VAULT_ID>` do 1Password).

Como funciona: os arquivos continuam nos caminhos de sempre, escondidos do branch principal por um
bloco em `.git/info/exclude`; uma branch orfa `nbp-safe` guarda um indice cifrado e um blob cifrado
por arquivo com nome aleatorio. Os hooks do git selam sozinhos a cada `git commit`; basta fazer
`nbp-git-safe unlock` uma vez por periodo (8 h por padrao) e `git push origin main nbp-safe`.
Em outra maquina: `git clone`, `init`, `unlock`, `open` (a primeira vez pede `--confirm-first-adopt`
apos conferir o key id, a seq e a ponta mostrados).

Limites honestos: nao foi auditado por terceiros; os arquivos ficam em texto claro na pasta de
trabalho; o remoto ainda ve quantidade, tamanho aproximado e momento das mudancas; chave vazada
expoe todo o historico (rotacionar protege so o que vier depois); `--no-verify` e `git add -f`
furam as protecoes locais; apagar de verdade (LGPD) exige reescrever o historico. Veja
[SECURITY.md](SECURITY.md) e [THREAT_MODEL.md](THREAT_MODEL.md).
