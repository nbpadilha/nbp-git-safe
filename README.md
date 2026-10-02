# nbp-git-safe

Version sensitive files in a Git repository, encrypted, with the latest version and the full
history inside the same repo. File names and paths are hidden from the remote and the key is never
written to disk.

Status: early development (phases 0-5: crypto core, agent, vault, main-branch guard, multi-machine).
Not released. See `PLAN-SPEC.md` for the design, `docs/FORMAT.md` for the on-disk format,
`docs/GUARD.md` for the hooks and what they do and do not stop, `docs/MULTI.md` for sync, push,
rotate and purge.

License: MIT. Derived from [transcrypt](https://github.com/elasticdog/transcrypt) (see `NOTICE`).

## Resumo (PT-BR)

Versiona arquivos sensiveis em um repositorio Git de forma cifrada, com a ultima versao e todo o
historico no mesmo repo. Nomes e caminhos ficam ocultos no remoto e a chave nunca e gravada em
disco. Fases 0 a 5 implementadas (nucleo, agente, cofre, guarda do branch principal, multi-maquina); ainda
sem versao publicada.
