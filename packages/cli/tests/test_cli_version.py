"""Smoke tests: ``sso-auditor --version`` prints the version."""

import subprocess
import sys
from importlib.metadata import version
from pathlib import Path

from click import unstyle
from typer.testing import CliRunner

from sso_auditor_cli.main import app

EXPECTED = f"sso-auditor {version('sso-auditor')}"


def test_version_flag_prints_version() -> None:
    result = CliRunner().invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == EXPECTED


def test_installed_console_script_prints_version() -> None:
    # The POSIX layout: on Windows the script is sso-auditor.exe in Scripts/. CI is Linux.
    script = Path(sys.executable).with_name("sso-auditor")
    assert script.exists(), f"console script not installed next to {sys.executable}"

    completed = subprocess.run(
        [str(script), "--version"], capture_output=True, text=True, check=True, timeout=30
    )

    assert completed.stdout.strip() == EXPECTED


def test_no_arguments_prints_help() -> None:
    result = CliRunner().invoke(app, [])

    assert result.exit_code == 0
    # Typer forces colour when GITHUB_ACTIONS is set, which splits "--version" with ANSI codes.
    assert "--version" in unstyle(result.output)
