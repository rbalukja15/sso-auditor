"""ASGI application for the hosted demo. Endpoints arrive with #33."""

from fastapi import FastAPI

from sso_auditor_api import __version__


def create_app() -> FastAPI:
    """Build the API application."""
    return FastAPI(title="sso-auditor API", version=__version__)


app = create_app()
