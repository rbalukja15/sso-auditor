# Devlog

A dated log of decisions, dead ends and lessons learned while building sso-auditor, newest entry first.

## 2026-10-27

- Releases start at 0.1.0. With no earlier release, release-please proposed 1.0.0 for the
  first release PR; `initial-version` in `release-please-config.json` fixes that. v1.0.0
  stays the M6 release.
- release-please reads both a PR's own commits and GitHub's merge commit, whose body
  repeats the PR title, so a PR merged with a merge commit shows up twice in the
  changelog. Squash merging, with the PR title as the commit message, gives one entry per
  PR.

## 2026-10-22

- Accepted ADR-0001: Python with uv, Typer, httpx, FastAPI and Claude for explanations.
- Cut v1.0 to discovery-only. Admin mode (Keycloak admin API) moves to v1.1, so the
  first release needs no credentials and matches what the hosted demo can do.
- Positioned the project next to kcwarden rather than against it: kcwarden audits a
  Keycloak realm from the inside with admin access, sso-auditor audits any OIDC issuer
  from the outside with none.
- Built the safe fetcher (#30) on httpx's transport layer rather than its `Client`: the
  client would follow redirects, read proxy settings from the environment and resolve
  hostnames itself. Talking to the transport directly, with the validated IP in the URL
  and the hostname in the `sni_hostname` extension, keeps the checked address and the
  contacted address the same. Keep-alive is off so a connection to an IP is never reused
  for a hostname whose certificate wasn't checked on it.
- The fetcher refuses a redirect from `https` to `http` even when `--allow-http` is on.
  `--allow-http` is for a local Keycloak, not for letting a remote issuer bounce the
  fetcher onto loopback.
- An adversarial review of the fetcher found no SSRF under the strict profiles, but ways
  to hold it open or make it do extra work. The main one: httpcore's timeouts apply to
  one socket operation at a time, so a server dripping headers, `100 Continue` responses
  or chunk trailers a byte at a time could keep a fetch open as long as it liked. The
  transport now uses its own httpcore network backend, which caps every connect, TLS
  handshake, read and write by the time left. httpx 0.28 has no parameter for it, so the
  pool is swapped after construction; real-socket tests fail if that ever stops working.
- Other fixes from the review: at most 4 addresses tried per hop, alternating address
  families, so a hostile DNS answer can't fan one fetch out to hundreds of hosts; DNS on
  daemon threads with a fixed slot pool; a 20,000-value JSON cap; all of AWS's
  `fd00:ec2::/32` plus the GCP and OCI IPv6 metadata addresses; redirects only for a plain
  `GET`; a TLS context built by hand so `SSLKEYLOGFILE` is never honoured; and an import
  guard that follows attribute access and refuses the fetch package's internals.
- A second pass over those fixes found three more. httpcore's write gives every partial
  `send()` the full timeout, so a server that reads slowly could stretch a large request
  body far past the deadline; the transport now does its own send loop and caps each
  send. A DNS slot leaked when its thread couldn't start. And logging's network handlers
  (`HTTPHandler`, `SysLogHandler` and the rest) open connections that neither ruff nor
  the import guard saw; they are banned now.
- A last correctness pass found that `json.loads` recurses in C until CPython's recursion
  limit, which a 1 MiB thread stack can't hold: 14 KB of brackets segfaulted the process
  on such a thread. The depth is now measured on the raw bytes first, with a linear scan.
  It also found truncated `deflate` bodies accepted silently, `home.arpa` itself (not
  just its subdomains) treated as public, and an ADR row that overstated how NAT64 and
  6to4 addresses are judged.
