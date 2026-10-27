# Devlog

A dated log of decisions, dead ends and lessons learned while building sso-auditor, newest entry first.

## 2026-10-22

- Accepted ADR-0001: Python with uv, Typer, httpx, FastAPI and Claude for explanations.
- Cut v1.0 to discovery-only. Admin mode (Keycloak admin API) moves to v1.1, so the
  first release needs no credentials and matches what the hosted demo can do.
- Positioned the project next to kcwarden rather than against it: kcwarden audits a
  Keycloak realm from the inside with admin access, sso-auditor audits any OIDC issuer
  from the outside with none.
