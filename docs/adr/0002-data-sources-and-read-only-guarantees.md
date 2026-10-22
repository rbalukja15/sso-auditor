# ADR-0002: Data sources and read-only guarantees

- **Status:** Accepted
- **Date:** 2026-10-22
- **Issue:** #6
- **Implemented by:** #30 (safe fetcher), #7 (discovery and JWKS client), #31 (redaction),
  #8 (Keycloak admin client, v1.1), #33 (hosted API)

## Context

"Read-only" has to mean something precise for a tool that sends requests to other
people's identity providers. A blanket rule like "never request a token" doesn't work:
Keycloak's admin REST API (#8) only accepts a bearer token from the realm's token
endpoint. So instead of a prohibition, this ADR lists every request the tool may make
(invariant I3 in [ADR-0001](0001-stack-and-scope.md)), and the network policy those
requests run under.

Admin mode ships in v1.1 (ADR-0001, release scope). It is specified here so the fetcher,
the config model and the threat model are designed for it from the start.

## Decision

### Data sources

| Source | How it arrives | Mode | Release |
| --- | --- | --- | --- |
| Discovery document (`/.well-known/openid-configuration`) | Fetched (R1) or a local file (`--discovery-file`) | Discovery (default), hosted | v1.0 |
| JWKS | Fetched from `jwks_uri` (R2) or a local file (`--jwks-file`) | Discovery, hosted | v1.0 |
| Keycloak realm and client settings | Admin REST API (R3 to R8) | Admin, local CLI only, opt-in | v1.1 |
| Keycloak realm export | Local file (`--realm-export`) | Admin, local CLI only | v1.1 |

File inputs make no network requests at all.

### Request allowlist

These are the only requests sso-auditor makes. A request not in this table is a bug.

| Id | Method | URL | Mode | Redirects |
| --- | --- | --- | --- | --- |
| **R1** | `GET` | `{issuer}/.well-known/openid-configuration`, with a terminating `/` stripped from the issuer first (OIDC Discovery §4.1); or the full discovery URL the user entered | All | Up to 3, each re-validated |
| **R2** | `GET` | The `jwks_uri` from the discovery document. It may be on another host (Google's is). | All | Up to 3, each re-validated |
| **R3** | `POST` | `{admin-origin}{prefix}/realms/{realm}/protocol/openid-connect/token` with `grant_type=client_credentials` | Admin (v1.1) | None |
| **R4** | `GET` | `{admin-origin}{prefix}/admin/realms/{realm}` | Admin (v1.1) | None |
| **R5** | `GET` | `{admin-origin}{prefix}/admin/realms/{realm}/clients` | Admin (v1.1) | None |
| **R6** | `GET` | `{admin-origin}{prefix}/admin/realms/{realm}/client-scopes` | Admin (v1.1) | None |
| **R7** | `GET` | `{admin-origin}{prefix}/admin/realms/{realm}/client-policies/policies?include-global-policies=true` | Admin (v1.1) | None |
| **R8** | `GET` | `{admin-origin}{prefix}/admin/realms/{realm}/client-policies/profiles?include-global-profiles=true` | Admin (v1.1) | None |

`{prefix}` is empty for Keycloak 17 and later, or `/auth` for the legacy layout, matching
the issuer the user entered.

**Never called**, even though discovery advertises them: the authorization, userinfo,
registration, pushed authorization (PAR), CIBA backchannel authentication, device
authorization, introspection, revocation and end-session endpoints. Checks about those
endpoints look only at whether and how the discovery document lists them.

**Accepted side effect.** In admin mode, R3 is a real login: the identity provider records
a service-account login (Keycloak's `CLIENT_LOGIN` event). That is the price of reading
settings through the API, and the docs for admin mode say so.

### Admin mode rules (v1.1)

- **Read-only credentials.** A dedicated confidential client in the audited realm, with
  a service account holding only the `realm-management` roles `view-realm` and
  `view-clients` (plus `view-identity-providers` only if a rule needs it). No password
  grant, no user credentials, no master-realm admin.
- **The tool checks its own token.** It decodes the access token from R3 and refuses to
  continue, unless explicitly overridden, when the token carries `manage-*`,
  `create-client`, `realm-admin` or `impersonation` (#8).
- **The admin origin comes from the user**: the issuer origin they typed, or
  `--admin-url`. It is never taken from the fetched discovery document, so a malicious
  document can't redirect credentials.
- **Credentials come only from environment variables, a file, or an interactive
  prompt.** Never from command-line arguments (they leak into shell history and process
  lists). They are never logged, persisted or sent anywhere but R3.
- **Local CLI only.** The hosted demo is discovery-only. It runs with admin mode
  disabled and rejects any request that carries a credential parameter (#33).
- **No user data.** No `view-users` role and no user ingestion.

### Network policy

Every request goes through the safe fetcher (#30), the only HTTP client in the codebase.
It parses each URL once, validates it, resolves the hostname, validates every address in
the answer, and connects to the validated IP while sending SNI and checking the
certificate against the hostname. Each redirect hop goes through the same checks. HTTP
proxies from the environment are ignored: a proxy resolves hostnames itself, which would
bypass the address checks.

| Rule | `hosted` profile | `cli` profile (default) | `cli` with flags |
| --- | --- | --- | --- |
| Schemes | `https` | `https` | `--allow-http`: also `http`, but only when every resolved address is loopback |
| Ports | 443 | 443 | `--allow-port N` adds a port (self-hosted Keycloak often uses 8443) |
| Public unicast addresses | Allowed | Allowed | Allowed |
| Private ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `fc00::/7`, loopback `127.0.0.0/8` and `::1` | Blocked | Blocked | `--allow-private-network`: allowed. `--allow-http` alone allows loopback for `http` URLs. |
| Link-local and cloud metadata: `169.254.0.0/16`, `fe80::/10`, `fd00:ec2::254`, `100.100.100.200` | Blocked | Blocked | Blocked, always |
| Everything else that is not global unicast: `0.0.0.0/8`, multicast, reserved, documentation and benchmarking ranges, `192.0.0.0/24`, deprecated IPv6 forms | Blocked | Blocked | Blocked, always |
| IPv4-mapped, NAT64 (`64:ff9b::/96`) and 6to4 addresses | Judged by the embedded IPv4 address | Same | Same |
| Hostnames `localhost`, `*.localhost`, `*.local`, `*.internal`, `*.home.arpa`, and single-label names | Refused | Refused | `--allow-private-network`: allowed (the addresses they resolve to are still checked). `--allow-http`: `localhost` and `*.localhost` allowed for `http`. |
| Cloud metadata hostnames (`metadata.google.internal`, `metadata`, `instance-data`, ...) | Refused | Refused | Refused, always |
| URLs with userinfo, or IPv4 literals in a non-canonical form (`2130706433`, `0x7f.1`, `0177.0.0.1`, `127.1`) | Refused | Refused | Refused, always |
| Redirects | At most 3, each re-validated; none for credentialed requests or `POST` | Same | Same |
| Limits | Connect, read and total timeouts; body cap after decompression; JSON depth cap; JWKS key-count and RSA modulus caps | Same | Same |

- **`hosted` is fixed.** It is chosen by the server's configuration, takes no parameters,
  and refuses to be constructed in a relaxed form. No request parameter can change it.
- **`cli` relaxations are explicit and loud.** Each flag prints a warning on every run.
- **TLS.** Certificates are always verified against the hostname, with TLS 1.2 or later.
  Private CAs are supported with `--ca-bundle PATH` or `SSL_CERT_FILE`. There is no
  insecure mode.

### LLM provider traffic

Explanations (#16) call the LLM provider through its official SDK, which has its own HTTP
client. That traffic goes only to the provider's fixed API endpoint from configuration,
never to a URL derived from user input or from a fetched document, so it is outside the
SSRF surface and is the one exception to "every request goes through the safe fetcher".
Only the explanation module may make that call.

### Secret handling

Admin API responses and realm exports can contain client secrets, keys and credentials.
They are redacted at ingestion, before anything is logged, stored, reported or sent to an
LLM, and the config model keeps only the fields rules read (#31). Raw admin and export
JSON is never logged or persisted.

### Self-hosted and hosted issuers

- **Keycloak** is recognised by its issuer path: `/realms/{realm}`, or
  `/auth/realms/{realm}` for the legacy layout. The realm name and the `/auth` prefix for
  R3 to R8 come from that path.
- **Any other issuer** (Google, Entra ID, Auth0, Okta, ...) gets R1 and R2 only.
- Self-hosted issuers on private networks need `--allow-private-network` and, often,
  `--allow-port` and `--ca-bundle`. The hosted demo can only reach public issuers.

### Threat model

The [threat model](../threat-model.md) explains what this policy defends against:
malicious issuer operators, demo abusers and prompt injectors.

## Consequences

- #30 implements the network policy table and both profiles, and gets a test for every
  row.
- #7 builds R1 and R2 on the fetcher; #8 builds R3 to R8 in v1.1. Any new request needs
  an update to this ADR first.
- Networks that force an HTTP proxy can't run live audits; file inputs still work.
- Admin mode leaves a login event on the identity provider. Operators should expect it.
