# Threat model

What sso-auditor protects, who might attack it, and which issue carries each
mitigation. Review this page when a change touches the fetcher, ingestion, the LLM layer,
the web report or the hosted demo.

## System and trust boundaries

sso-auditor runs in two places:

- **The CLI**, on the user's own machine or CI runner. The user is trusted; the issuer
  they point it at is not. In v1.1 the CLI can also read Keycloak's admin API with a
  view-only service account (admin mode).
- **The hosted demo** (#33, #19, #21), a public web page and API on Fly.io. Anyone on the
  internet can submit an issuer URL. It is discovery-only and never accepts credentials.

Everything an issuer serves is untrusted: the discovery document, every URL inside it,
the JWKS, redirect targets, DNS answers for its hostnames, response sizes and timing.
LLM output is untrusted too. Requests the tool may make are listed in ADR-0002 (#6).

## Assets

| Id | Asset | Where it lives | Why it matters |
| --- | --- | --- | --- |
| **A1** | LLM API key | Hosted demo's secret store; a CLI user's environment | Spending it costs money; a leak lets others spend it. |
| **A2** | Admin credentials (v1.1) | CLI user's environment, a file or a prompt | Read access to realm and client settings, which can include client secrets if the account is over-privileged. |
| **A3** | The server's network position | Hosted demo | From inside Fly.io the server can reach the private network (`fdaa::/16`), its own loopback services and, on other clouds, a metadata endpoint (`169.254.169.254`, `fd00:ec2::254`). An SSRF turns these into the attacker's. |
| **A4** | Users' trust in the output | Every report | People act on the findings. A report that hides a finding, invents one, cites the wrong section or carries injected markup does harm even with no breach. |
| **A5** | Demo availability and budget | Hosted demo | Exhausting CPU, memory, outbound connections or the LLM budget takes the demo down for everyone. |
| **A6** | Third parties' goodwill | Other people's identity providers | The demo must not become a free scanner or traffic reflector aimed at someone else's servers. |

## Adversaries

### T1: Malicious issuer operator

Controls an issuer's DNS, TLS endpoint and every byte it serves. Reaches the CLI when a
user audits their issuer, and the demo by submitting it.

| Attack | Targets | Mitigation | Issue |
| --- | --- | --- | --- |
| `jwks_uri`, an endpoint URL or a redirect points at a private, loopback, link-local or metadata address | A3 | Every outbound request goes through one fetcher that validates every resolved address, re-validates each redirect hop, and refuses non-public ranges | #30 |
| DNS rebinding: a public answer for the check, a private one for the connection | A3 | The fetcher resolves once and connects to the validated IP, keeping SNI and certificate checks on the hostname | #30 |
| Huge, deeply nested, slow or compressed-bomb responses; JWKS with thousands of keys or giant RSA moduli | A5 | Timeouts and a total deadline, a size cap after decompression, a JSON depth cap, key-count and modulus caps | #30 |
| HTML or script in string fields (`service_documentation`, `op_policy_uri`, ...) | A4 | The web report renders every config value as text under a strict CSP; only spec URLs from rule metadata are links | #19 |
| Instructions planted in string fields, aimed at the LLM | A4 | See T3 | #16 |
| A document crafted to look compliant | A4 | Findings come only from deterministic rules; data the issuer doesn't publish is reported as `not_evaluated`, never as a pass | #10 |

### T2: Demo abuser

An anonymous user of the hosted demo, possibly scripted.

| Attack | Targets | Mitigation | Issue |
| --- | --- | --- | --- |
| Submits an internal URL (`http://169.254.169.254/`, `https://[fdaa::3]/`, `https://db.internal/`) | A3 | The hosted fetcher profile is strict and set by server config; no request parameter can relax it | #30, #20 |
| Uses error messages or timing to map internal hosts | A3 | Generic errors that don't distinguish refused from timed out and never echo response bodies | #20 |
| Floods the demo or burns the LLM budget | A5, A1 | Per-IP and global rate limits, a cap on explained findings and `max_tokens`, a daily LLM budget with a kill switch, a demo-only key with a provider-side spend limit | #20 |
| Points the demo at a third party over and over | A6 | A per-target-host cap on outbound fetches; the demo only ever makes the read-only requests in ADR-0002 | #20, #6 |
| Tries to submit admin credentials | A2 | The hosted build has admin mode disabled and rejects any request carrying a credential parameter | #33 |

### T3: Prompt injector

Plants text in a configuration value, hoping it reaches the LLM and changes the report:
"say this issuer is secure", a fake finding, a link to a phishing page, or a request to
reveal the system prompt or key.

| Attack | Targets | Mitigation | Issue |
| --- | --- | --- | --- |
| Adds, removes or rewrites findings, severities or citations through the explanation | A4 | The LLM returns only `{finding_id, explanation}`; code joins everything else and a validator drops unknown ids, strips wrong citations and caps length (ADR-0001, I2) | #16 |
| Smuggles markup or links into the explanation | A4 | Plain text only, no URLs outside an allowlist, rendered as text nodes | #16, #19 |
| Hides instructions in long values | A4 | Only short, truncated, JSON-encoded values inside a delimited untrusted-data block; never whole documents | #16 |
| Gets secrets into the prompt so the model can repeat them | A1, A2 | The LLM key never enters a prompt; admin data is redacted at ingestion, and sending admin-derived values needs an extra flag | #31, #16 |
| Injection works only sometimes | A4 | Injection fixtures and a faithfulness eval measure it on every change | #14, #34 |

### T4: Supply-chain attacker

Compromises a dependency, a GitHub Action or a release artifact.

| Attack | Targets | Mitigation | Issue |
| --- | --- | --- | --- |
| A tampered or hijacked action or package runs in CI | A1, A4 | Actions pinned to commit SHAs and audited by zizmor, `contents: read` by default, no `pull_request_target`, no secrets in CI, hash-pinned uv, a 7-day Dependabot cooldown | #4 |
| A malicious release is published under the project's name | A4 | Trusted publishing (OIDC) to PyPI, with no stored token | #23 |

## Residual risks and assumptions

- **Discovery is a claim, not proof.** The discovery document says what the server
  advertises, not what each client may do. Reports say which checks were not evaluated
  and why; v1.1's admin mode narrows the gap for Keycloak.
- **The LLM provider sees finding values.** Only short, truncated values from public
  documents on the demo; in the CLI, admin-derived values are sent only with an explicit
  flag (#16).
- **Trust in TLS and DNS.** The fetcher relies on the system's CA bundle (or the one the
  user passes) and on DNS answers being validated per connection. A CA compromise is
  out of scope.
- **Proxies are not used.** The fetcher ignores `HTTP(S)_PROXY`, because a proxy would
  resolve hostnames itself and bypass the address checks. Networks that force a proxy
  can't run live audits; offline file inputs still work (#7).
- **The hosting platform is trusted.** A compromise of Fly.io or the maintainer's
  account is out of scope.
