# Contributing

Thanks for helping. This is a Python project; issues and pull requests are welcome.

## Set up and check your change

Needs Python 3.11+ (the kind end-to-end test runs in CI). Caches and virtual environments stay in git-ignored folders inside the repo.

```bash
make setup   # install dependencies
make lint    # ruff, ruff format, mypy --strict
make test    # full test suite
make check   # generated configs match deploy/mesh.json
make demo    # local mTLS demo
make audit   # known-vulnerability check (as in CI)
```

After changing `deploy/mesh.json` or a renderer, run `make render` and commit the regenerated
files in `deploy/generated/`; CI fails when they are stale.

A pull request is ready when `make lint`, `make test` and `make check` pass and CI is green.

## Guidelines

- Keep each change focused; explain the problem it solves in the pull request.
- Add or update a test for every behaviour change, and update `docs/results/` when numbers change.
- Significant design changes need an ADR in `docs/adr/` (copy `0001` for the format).
- Keep function comments to one short phrase; let names and tests explain the rest.
- Never commit real keys, tokens or certificates; fixtures are generated at test time.
- Report security problems privately, as described in [SECURITY.md](SECURITY.md).

By contributing you agree that your work is released under the [MIT License](LICENSE).
