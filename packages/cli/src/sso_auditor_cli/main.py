"""The ``sso-auditor`` command."""

from typing import Annotated

import typer

from sso_auditor_cli import __version__

app = typer.Typer(
    add_completion=False,
    help="Read-only OIDC/OAuth configuration auditor.",
)


def _print_version(value: bool) -> None:
    if value:
        typer.echo(f"sso-auditor {__version__}")
        raise typer.Exit


@app.command()
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Show the version and exit.",
            callback=_print_version,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Audit an OpenID Connect issuer's published configuration.

    The audit itself arrives with the CLI audit command (#18).
    """
    typer.echo(ctx.get_help())
