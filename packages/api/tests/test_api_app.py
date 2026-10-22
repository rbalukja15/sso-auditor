from importlib.metadata import version

from sso_auditor_api.app import app, create_app


def test_app_reports_package_version() -> None:
    assert app.version == version("sso-auditor-api")


def test_create_app_returns_a_fresh_app() -> None:
    assert create_app() is not app
