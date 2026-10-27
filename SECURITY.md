# Security policy

sso-auditor is a security tool, so a flaw in it can hurt the people who rely on its
output and, on the hosted demo, the infrastructure it runs on. Thank you for reporting
problems privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/rbalukja15/sso-auditor/security/advisories/new)**
(Security tab → Report a vulnerability). Please don't open a public issue, discussion or
pull request for a vulnerability.

Include what you found, how to reproduce it, and the impact you think it has. A
discovery document or JWKS that triggers the problem is ideal; those are public data.

This is a one-maintainer project. You can expect:

- an acknowledgement within 7 days;
- an assessment and a plan, or a request for more detail, within 14 days;
- credit in the advisory and release notes when the fix ships, unless you'd rather not.

## Supported versions

| Version | Supported |
| --- | --- |
| Latest release, and `main` | Yes |
| Anything older | No: upgrade to the latest release |

Before v1.0.0, only the latest release gets fixes. From v1.0.0, the latest minor release
of the current major version does.

## Scope

**In scope**

- The `sso-auditor` CLI and the `sso-auditor-core` and `sso-auditor-api` packages.
- The hosted demo, once it is live (the link will be in the README).
- In particular:
  - **SSRF**: any way to make the fetcher connect to a private, loopback, link-local or
    metadata address, a hostname it should refuse, or a port or scheme its policy
    doesn't allow, including through redirects, DNS rebinding or URL parsing tricks.
  - **Resource exhaustion** through crafted responses (size, nesting, slow delivery, key
    material) that gets past the fetcher's limits.
  - **Secret leakage**: credentials, client secrets or private keys reaching logs,
    reports, fixtures or an LLM prompt.
  - **Report integrity**: an LLM response or a crafted configuration that adds, removes
    or changes findings, severities or citations, or that injects markup or script into
    the web report.
  - **Demo abuse controls**: bypassing rate limits, the per-target cap or the LLM budget.

**Out of scope**

- Findings about a third-party identity provider's configuration. Report those to that
  provider; sso-auditor only describes what they publish.
- Volumetric denial of service against the hosted demo.
- Vulnerabilities in dependencies that sso-auditor doesn't expose. Report those
  upstream. If sso-auditor's use of a dependency makes it exploitable, that is in scope.
- Social engineering, and anything that needs a compromised machine or hosting account.

### Testing the hosted demo

You may test the demo's SSRF and input handling with URLs and DNS names **you control**.
Don't point it at third-party systems, don't try to read data that isn't yours, and keep
request rates low; the demo has rate limits for everyone's sake. Good-faith research
within these limits is welcome.

## Responsible use

- **Audit only issuers you operate or are authorised to assess.** sso-auditor reads only
  public metadata, but an audit is still a security assessment of someone's system.
  Don't publish findings about providers you don't run without talking to them first.
- **Use admin mode (planned for v1.1) only with credentials the realm's owner issued for
  that purpose**: a dedicated service account with view-only roles, never a personal or
  master-realm admin login. Admin mode runs only in the local CLI; the hosted demo never
  accepts credentials.
- **What the hosted demo logs.** For each audit: the time, the issuer URL's host, the
  outcome (number of findings, or the class of error), how long it took, and the LLM
  tokens used. Client IP addresses are held in memory for rate limiting and are not
  written to the application's logs; the hosting platform's edge proxy keeps its own
  access logs under its own policy. The demo never logs fetched documents, response
  bodies, or LLM prompts and responses. Application logs are kept for 30 days at most,
  and for less where that's practical: a submitted host name can itself be sensitive.
  The demo sends the LLM provider only short, truncated values from public documents.
  #20 and #21 implement this policy; until the demo is live, nothing is logged anywhere.

The [threat model](docs/threat-model.md) explains what these rules protect against.
