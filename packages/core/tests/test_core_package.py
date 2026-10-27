from importlib.metadata import version

import sso_auditor_core


def test_version_matches_package_metadata() -> None:
    assert sso_auditor_core.__version__ == version("sso-auditor-core")
