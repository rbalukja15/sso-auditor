# ADR-0001: Stack and scope

- **Status:** Accepted
- **Date:** 2026-10-22
- **Issue:** #3

## Context

sso-auditor reads an identity provider's public OpenID Connect metadata and reports
configuration weaknesses, each tied to the spec section it breaks. It is meant to be
trusted by people who run identity providers, so two things have to be settled before
any code exists:

1. **Scope.** What the tool is (a configuration auditor) and what it is not (a
   penetration-testing tool), written as rules that code and reviews can check.
2. **Stack.** The language and libraries for a core library, a CLI, an HTTP API for the
   hosted demo and a small web UI. One constraint comes from the safe fetcher (#30): the
   HTTP client must be able to connect to an IP address we have already resolved and
   validated, while still sending SNI and checking the certificate against the hostname.
   Without that, DNS rebinding defeats any SSRF check.

## Decision

### Scope

sso-auditor is a **read-only configuration auditor**. It compares what an issuer
publishes with what the specs require or recommend, and explains the gap. It never tries
to exploit anything, never runs an OAuth flow, and never changes configuration.

Findings come from **deterministic rules**. Each rule cites a spec section, and the same
input always produces the same findings. An LLM may **explain** findings in plain
language for the specific configuration, but it never decides what is a finding.

#### Scope invariants

Later issues reference these by number. Each one is checkable by a test or a review.

| Id | Invariant | Enforced by |
| --- | --- | --- |
| **I1** | Every finding has a `spec_ref` that is a key in the spec catalog (`specs/catalog.yaml`). A rule without a valid `spec_ref` cannot be registered. | Rule engine and its catalog test (#10) |
| **I2** | LLM output cannot add, remove or change findings. The model returns only `{finding_id, explanation}` pairs; code joins rule id, severity, `spec_ref` and evidence, and drops anything that doesn't match an existing finding. | Explanation validator and mocked-LLM tests (#16, #34) |
| **I3** | The tool makes only the requests listed in ADR-0002, and every one of them goes through the safe fetcher. | ADR-0002 (#6), safe fetcher and its import check (#30) |
| **I4** | OAuth security citations use RFC 9700 sections, never `draft-ietf-oauth-security-topics`. Citations point at published RFCs and OpenID specs, never drafts. | Catalog test that rejects `draft-` documents (#10) |

#### Release scope

- **v1.0 is discovery-only.** It audits the discovery document and JWKS of any OIDC
  issuer with no credentials. This is also the only mode the hosted demo will ever have.
- **v1.1 adds admin mode** for Keycloak: an opt-in, local-CLI-only read of realm and
  client settings through the admin REST API with a view-only service account (#8, #11,
  #12). Until then, admin-only rules report `not_evaluated`.

#### Supported providers

| Provider | What is audited |
| --- | --- |
| **Keycloak 24 to 26** | Discovery document and JWKS in v1.0; realm and client settings through the admin API or a realm export in v1.1. Issuers under `/realms/{realm}` and the legacy `/auth/realms/{realm}` are both recognised. Older Keycloak versions get the discovery and JWKS checks but are untested. A newer major version is supported once a recorded fixture from it passes. |
| **Any other OIDC issuer** (Google, Microsoft Entra ID, Auth0, Okta, ...) | Discovery document and JWKS only. |

#### Non-goals

- **SAML.** Despite "SSO" in the name, sso-auditor only covers OpenID Connect and OAuth 2.0.
- **Relying-party token validation.** Checking that an application validates `aud`,
  `iss` or signatures is the application's job and needs the application's code.
- **Other vendors' management APIs** (Okta, Auth0, Entra ID). Only Keycloak's admin API is
  in scope, and only from v1.1.
- **Active testing.** No authorization requests, no token requests against user flows,
  no client registration, no fuzzing. ADR-0002 lists the only requests the tool makes.
- **Changing configuration.** Remediation is advice; the tool never applies it.

#### Prior art and differentiation

- **[kcwarden](https://pypi.org/project/kcwarden/)** (iteratec, Apache-2.0) audits a
  Keycloak realm's configuration from the inside: you export the realm with admin access
  and kcwarden checks the file offline. sso-auditor is **complementary**: it checks any
  OIDC provider from the outside with no credentials, quotes the spec text behind every
  finding, reports what it could not evaluate, and explains findings for the specific
  configuration. Someone running Keycloak with admin access should use both.
- **The [OpenID conformance suite](https://openid.net/certification/)** is an active
  tester. It registers clients and runs real flows to certify that an implementation
  follows the spec. sso-auditor is passive and much narrower: it reads published metadata
  and reports deployment configuration, with no client registration or flows.

#### Citation rule

Every finding cites the exact section of a published spec (RFC, OpenID Foundation final
spec). For OAuth security best current practice that means **RFC 9700** and its section
numbers, never `draft-ietf-oauth-security-topics`. The catalog stores a verbatim excerpt
of the normative text so reports quote the spec rather than paraphrase it (#10).

### Stack

| Concern | Decision | Why |
| --- | --- | --- |
| Language and version | **Python ≥ 3.12**; CI tests 3.12, 3.13 and 3.14 | Mature HTTP, TLS and data-validation libraries; the same ecosystem as kcwarden, so its users can install both the same way. |
| Package manager | **uv**, one workspace, `uv.lock` committed | Fast, reproducible installs; `uv sync --locked` in CI. |
| Build backend | **hatchling** | Standard PEP 517 backend; no custom build steps needed. |
| Packages | `sso-auditor-core` (ingestion, fetcher, rules, report model), `sso-auditor` (the CLI, published to PyPI under the project's name), `sso-auditor-api` (the hosted demo's HTTP API) | The hosted service has a home from the start, and the CLI and API share one core. |
| CLI library | **Typer** (built on Click) | Typed options, generated help, Rich output for the report. |
| HTTP client | **httpx** (sync), used only inside the safe fetcher (#30) | Connects to a pre-resolved, validated IP while keeping SNI and hostname verification through httpcore's `sni_hostname` request extension. Redirects, proxies and environment settings are switched off so the fetcher controls every hop. |
| Data models | **pydantic v2** | Config model, finding and report schemas, and the LLM output schema with validation in one place. |
| Web/API framework | **FastAPI** on **uvicorn** | Typed request and response models; the report schema is shared with the CLI's `--format json`. |
| Frontend | **Static HTML and CSS with vanilla JavaScript modules**, no framework and no build step, served by the API from the same origin | The UI is one report page. Building the DOM with text nodes only and a strict CSP (`default-src 'self'`, no inline script) is simplest without a framework, and there is no npm dependency tree to keep patched (#19). |
| LLM provider, model, SDK | **Anthropic Claude**, model **`claude-opus-5-5`**, through the official **`anthropic`** Python SDK with structured outputs (`output_config.format`, `client.messages.parse()`) | Structured outputs constrain the response to the `[{finding_id, explanation}]` schema I2 requires. Explanations are optional: with no API key, every finding uses its rule's template text. |
| Tests, lint, types | **pytest**, **ruff** (lint and format), **mypy --strict**, **pre-commit** with local hooks only | One toolchain, every version pinned in `uv.lock`. |
| Hosting target | **Fly.io**: one Docker image on a small machine, secrets in Fly's secret store | Simple container deploys, a trustworthy client-IP header (`Fly-Client-IP`) for rate limiting (#20). |
| License | **Apache-2.0** | Permissive with an explicit patent grant; the same license as kcwarden. |

## Consequences

- **#1** scaffolds a uv workspace with the three packages above, and `make lint test`
  runs ruff, mypy and pytest.
- **#30** builds the fetcher on httpx and must disable everything that would bypass its
  checks: automatic redirects, `HTTP(S)_PROXY` from the environment (a proxy would do its
  own DNS resolution and defeat IP pinning), and connection reuse across hostnames.
- **#16** pins `claude-opus-5-5` and versions its prompts. The Messages API no longer
  accepts sampling parameters such as `temperature`, so **#34** gets reproducible scores
  by committing recorded model responses, not by setting `temperature` to 0. Refusals
  (`stop_reason: "refusal"`) fall back to the rule's template text, like any other LLM
  failure.
- **#20** owns cost control on the demo: a cap on explained findings per audit, a
  `max_tokens` limit, a daily budget, the `LLM_ENABLED=false` kill switch, and a separate
  demo-only key with a provider-side spend limit.
- **#19** ships plain files with no build step. If the UI ever needs a framework, that
  is a new ADR.
- **#23** publishes `sso-auditor` to PyPI with trusted publishing.
- A switch of language, HTTP client or LLM provider supersedes this ADR.
