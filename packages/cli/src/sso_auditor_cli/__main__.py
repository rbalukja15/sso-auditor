"""Allow ``python -m sso_auditor_cli``."""

from sso_auditor_cli.main import app

if __name__ == "__main__":
    app(prog_name="sso-auditor")
