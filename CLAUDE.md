# CLAUDE.md

Guidance for Claude Code in this repository. Keep it under ~200 lines; update it when the
rule engine (#10) and the eval harness (#15) land.

## What this is

sso-auditor is a **read-only OIDC/OAuth configuration auditor**, not a pentest tool. It
fetches an issuer's discovery document and JWKS, runs deterministic rules that each cite
a spec section, and optionally has an LLM explain the findings. v1.0 is discovery-only;
Keycloak admin mode (#8, #11, #12) is v1.1.

Read these before changing behaviour:

- [ADR-0001](docs/adr/0001-stack-and-scope.md): stack, scope, and invariants I1 to I4
- [ADR-0002](docs/adr/0002-data-sources-and-read-only-guarantees.md): the request
  allowlist and the network policy per mode
- The GitHub issue you're working on: its Context, Tasks and Acceptance criteria are the spec

## Layout

```
packages/
  core/  sso_auditor_core   ingestion, safe fetcher, rules, report model
  cli/   sso_auditor_cli    the `sso-auditor` command (Typer)
  api/   sso_auditor_api    FastAPI app for the hosted demo
docs/    architecture.md, devlog.md, evaluation.md, adr/
```

Each package has its own `tests/`. Test file names must be unique across packages
(mypy and pytest's importlib mode both rely on it).

## Commands

```sh
make dev     # uv sync --locked + install the pre-commit hook
make lint    # ruff check, ruff format --check, mypy --strict, zizmor
make fmt     # ruff format + safe fixes
make test    # pytest
make eval    # placeholder until #15
uv run --locked pytest packages/cli/tests/test_cli_version.py -k version   # one test
uv add --package sso-auditor-core <dep>     # runtime dep for one package
uv add --dev <tool>                         # dev tool for the workspace
```

Always run `make lint test` before committing. Use `uv run --locked`, never bare `pip`.

## Per-issue workflow

1. One issue per PR. Branch: `issue-<n>-<slug>` (e.g. `issue-30-safe-fetcher`).
2. Commits and PR titles are Conventional Commits: `feat`, `fix`, `docs`, `test`,
   `refactor`, `chore`, `ci`, `perf`. release-please builds the changelog from them.
3. Work through the issue's Tasks; the Acceptance criteria are the definition of done.
4. Run `make lint test`. CI runs the same targets plus pre-commit.
5. The PR body starts with `Closes #<n>` (the PR template has the slot).
6. No AI co-author trailers or "generated with" footers in commits, PRs or comments.

## Rules that are never negotiable

- **Read-only, no exploitation.** Never add code that runs an OAuth flow, registers a
  client, sends credentials anywhere but the configured admin origin (v1.1), or changes
  provider configuration. The only requests are the ones in ADR-0002 (invariant I3).
- **All outbound HTTP goes through the safe fetcher** (`sso_auditor_core.fetch`, #30).
  Never import `httpx`, `requests`, `urllib.request`, `urllib3`, `aiohttp`,
  `http.client`, `socket` or any other network client anywhere else. Ruff's banned-api
  table in `pyproject.toml` lists them, and a test fails even if you add `noqa`. Import
  the fetcher only from `sso_auditor_core.fetch` itself, never its submodules. The
  fetcher's `cli` and `hosted` policies are the only way to relax a network restriction,
  and `hosted` cannot be relaxed at all.
- **Every finding cites a spec section from the catalog** (`specs/catalog.yaml`, #10;
  invariant I1). Cite the exact section number.
- **Cite RFC 9700, never `draft-ietf-oauth-security-topics`** (I4). No drafts at all.
- **The LLM never invents findings** (I2). It returns only `{finding_id, explanation}`;
  code owns rule ids, severities, citations and evidence. All LLM output passes the
  validator in #16 before it reaches a report.
- **Missing data is `not_evaluated`, never `pass`.**
- **Secrets stay out.** Never log or persist raw admin or realm-export responses;
  redaction happens at ingestion (#31). No real secrets, tokens or private keys in
  fixtures; throwaway test keys must be clearly named.
- **Untrusted input everywhere.** Anything an issuer serves (URLs, strings, keys, sizes,
  redirects) is attacker-controlled on the hosted demo. Treat it as data; the web UI
  renders it as text only (#19).

## Code style

- Python ≥ 3.12, full type hints, `mypy --strict` clean. Ruff handles formatting and
  import order; line length 100.
- Prefer small pure functions and frozen dataclasses or pydantic models over dicts.
- Errors: raise typed exceptions from the module that knows what failed; don't return
  `None` for failure.
- Tests: pytest, table-driven with `pytest.mark.parametrize` where there are many cases.
  Tests never touch the real network.
- Docs: plain, direct prose. Record significant decisions as a new ADR in `docs/adr/`
  (copy `0000-template.md`), and add a dated entry to `docs/devlog.md`.
