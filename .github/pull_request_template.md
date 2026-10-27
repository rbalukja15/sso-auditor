Closes #<n>

## What changed

<!-- One issue per PR. Say what changed and why, not how the diff looks. -->

## How I tested it

- [ ] `make lint test` passes locally

## Checklist

- [ ] The PR title is a Conventional Commit (`feat:`, `fix:`, `docs:`, `chore:`, `ci:`, `test:`, `refactor:`)
- [ ] Every new or changed finding cites a spec section from the catalog (ADR-0001, I1)
- [ ] LLM output can't add, remove or change findings (I2)
- [ ] Outbound HTTP goes only through the safe fetcher, and only to requests listed in ADR-0002 (I3)
- [ ] No secrets, tokens, private keys or raw admin responses in code, fixtures or logs
