# nbp-git-safe

Version sensitive files in a Git repository, encrypted, with the latest version and the full
history inside the same repo. File names and paths are hidden from the remote and the key is never
written to disk.

Status: early development (phase 1: crypto core and leak-test harness). Not usable yet. See
`PLAN-SPEC.md` for the design and `docs/FORMAT.md` for the on-disk format.

License: MIT. Derived from [transcrypt](https://github.com/elasticdog/transcrypt) (see `NOTICE`).

## Resumo (PT-BR)

Versiona arquivos sensiveis em um repositorio Git de forma cifrada, com a ultima versao e todo o
historico no mesmo repo. Nomes e caminhos ficam ocultos no remoto e a chave nunca e gravada em
disco. Fase atual: nucleo criptografico e harness de testes de vazamento; ainda nao utilizavel.
