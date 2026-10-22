"""The safe fetcher is the only network client in the codebase (#30, ADR-0002).

Ruff's banned-api rule (TID251) reports these imports while editing, but a ``noqa``
comment silences it. This test reads the same table from pyproject.toml and checks every
source file outside ``sso_auditor_core/fetch/``, comments or not. It also catches what
the rule can't see:

- a banned name reached through an attribute (``import asyncio as aio``, then
  ``aio.open_connection``), and event-loop methods that open connections or resolve names;
- an import of the fetch package's internals rather than its public API, such as the raw
  transport in ``fetch.transport``;
- calls to ``__import__``, ``exec`` and ``eval``, which can load any module by name.

It guards against mistakes, not a determined author: review is still the control for code
written to slip past it. Some things no static check can see, such as a logging config
that names ``logging.handlers.HTTPHandler`` as a string.
"""

import ast
import tomllib
from collections.abc import Iterator
from pathlib import Path

import pytest

import sso_auditor_core.fetch

ROOT = Path(__file__).resolve().parents[3]
FETCH_PACKAGE = ROOT / "packages" / "core" / "src" / "sso_auditor_core" / "fetch"
FETCH_MODULE = "sso_auditor_core.fetch"
PUBLIC_API = frozenset(sso_auditor_core.fetch.__all__)

# asyncio event-loop methods that open sockets or resolve names. The loop is an object, so
# no import names them; any attribute with one of these names is refused.
LOOP_METHODS = frozenset(
    {
        "create_connection",
        "create_datagram_endpoint",
        "create_unix_connection",
        "getaddrinfo",
        "getnameinfo",
        "sock_connect",
    }
)
DYNAMIC_BUILTINS = frozenset({"__import__", "exec", "eval"})


def banned_names() -> frozenset[str]:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return frozenset(config["tool"]["ruff"]["lint"]["flake8-tidy-imports"]["banned-api"])


def source_files() -> list[Path]:
    files = sorted(ROOT.glob("packages/*/src/**/*.py"))
    return [path for path in files if not path.is_relative_to(FETCH_PACKAGE)]


def module_name(path: Path) -> str:
    """``packages/cli/src/sso_auditor_cli/main.py`` is ``sso_auditor_cli.main``."""
    parts = path.relative_to(ROOT).with_suffix("").parts
    dotted = parts[parts.index("src") + 1 :]
    return ".".join(dotted[:-1] if dotted[-1] == "__init__" else dotted)


def absolute_module(node: ast.ImportFrom, module: str, is_package: bool) -> str:
    if node.level == 0:
        return node.module or ""
    package = module.split(".") if is_package else module.split(".")[:-1]
    base = package[: len(package) - node.level + 1]
    return ".".join([*base, node.module] if node.module else base)


def referenced_names(source: str, module: str, *, is_package: bool = False) -> Iterator[str]:
    """Every dotted name the source imports or reaches through an imported name.

    Bindings are tracked per module, not per scope, which errs on the side of reporting.
    """
    tree = ast.parse(source)
    bound: dict[str, str] = {}
    local_names = _locally_bound(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
                if alias.asname:
                    bound[alias.asname] = alias.name
                else:
                    head = alias.name.split(".")[0]
                    bound[head] = head
        elif isinstance(node, ast.ImportFrom):
            source_module = absolute_module(node, module, is_package)
            yield source_module
            for alias in node.names:
                yield f"{source_module}.{alias.name}"
                bound[alias.asname or alias.name] = f"{source_module}.{alias.name}"
                if alias.name in LOOP_METHODS:
                    yield f"<event loop>.{alias.name}"

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            if node.attr in LOOP_METHODS:
                yield f"<event loop>.{node.attr}"
            chain = [node.attr]
            value = node.value
            while isinstance(value, ast.Attribute):
                chain.append(value.attr)
                value = value.value
            if isinstance(value, ast.Name) and value.id in bound:
                yield ".".join([bound[value.id], *reversed(chain)])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            name = node.func.id
            if name in DYNAMIC_BUILTINS and name not in bound and name not in local_names:
                yield f"<builtin>.{name}"


def _locally_bound(tree: ast.AST) -> frozenset[str]:
    """Names the module binds itself: assignments, parameters, functions and classes."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.add(node.name)
    return frozenset(names)


def is_banned(name: str, banned: frozenset[str]) -> bool:
    if name.startswith(("<event loop>.", "<builtin>.")):
        return True
    parts = name.split(".")
    if any(".".join(parts[:i]) in banned for i in range(1, len(parts) + 1)):
        return True
    # Outside the fetch package, only its public API may be used.
    if name.startswith(f"{FETCH_MODULE}."):
        return name.split(".")[2] not in PUBLIC_API
    return False


def offenders(source: str, module: str = "sso_auditor_cli.example") -> list[str]:
    banned = banned_names()
    return [name for name in referenced_names(source, module) if is_banned(name, banned)]


def test_the_banned_list_covers_the_common_clients() -> None:
    assert {"httpx", "httpcore", "requests", "urllib3", "aiohttp"} <= banned_names()
    assert {"urllib.request", "http.client", "socket", "importlib.import_module"} <= (
        banned_names()
    )


def test_the_scan_sees_the_source_tree() -> None:
    files = source_files()
    assert ROOT / "packages" / "cli" / "src" / "sso_auditor_cli" / "main.py" in files
    assert not any(path.is_relative_to(FETCH_PACKAGE) for path in files)


@pytest.mark.parametrize(
    "source",
    [
        "import httpx",
        "import httpx._client as c",
        "from httpx import Client",
        "from urllib import request",
        "from urllib.request import urlopen",
        "import urllib.robotparser",
        "from http import client",
        "from asyncio import open_connection",
        "import asyncio\nasyncio.open_connection('h', 443)",
        "import asyncio as aio\naio.open_connection('h', 443)",
        "import asyncio\nasyncio.streams.open_connection('h', 443)",
        "import asyncio\nasyncio.get_running_loop().create_connection(Proto, 'h', 443)",
        "async def f(loop):\n    await loop.getaddrinfo('h', 443)",
        "import ssl\nssl.get_server_certificate(('h', 443))",
        "from anyio import connect_tcp",
        "import socketserver",
        "from multiprocessing.connection import Client",
        "import importlib\nimportlib.import_module('socket')",
        "from importlib import util",
        "__import__('socket')",
        "exec('import socket')",
        "import builtins\nbuiltins.__import__('socket')",
        "import pkgutil\npkgutil.resolve_name('httpx:Client')",
        "import pydoc\npydoc.locate('socket.create_connection')",
        "import runpy\nrunpy.run_module('http.client')",
        "from logging.handlers import HTTPHandler",
        "import logging.handlers\nlogging.handlers.SysLogHandler(address=('h', 514))",
        "from logging.handlers import SocketHandler, DatagramHandler, SMTPHandler",
        "import logging.config\nlogging.config.listen(9030)",
        "from anyio import getaddrinfo",
        "import anyio\nanyio.getnameinfo(('1.2.3.4', 443))",
        "import anyio\nanyio.create_connected_udp_socket('h', 53)",
        "from ssl import create_connection",
        "async def f(loop):\n    await loop.getnameinfo(('1.2.3.4', 443))",
        "from sso_auditor_core.fetch.client import SafeFetcher",
        "from sso_auditor_core.fetch.transport import deadline_transport",
        "from sso_auditor_core.fetch import transport",
        "import sso_auditor_core.fetch.client",
        "from sso_auditor_core import fetch\nfetch.transport.deadline_transport",
    ],
)
def test_the_check_reports_each_form(source: str) -> None:
    assert offenders(source) != []


@pytest.mark.parametrize(
    "source",
    [
        "import urllib.parse",
        "from http import HTTPStatus",
        "from . import socket",
        "import importlib.metadata\nimportlib.metadata.version('sso-auditor')",
        "import asyncio\nasyncio.run(main())",
        "from sso_auditor_core.fetch import SafeFetcher, FetchPolicy",
        "from sso_auditor_core import fetch\nfetch.SafeFetcher(fetch.FetchPolicy.hosted())",
        "import sso_auditor_core.fetch",
        "from sso_auditor_core.fetch import IPAddress, Target",
        "def run(cases, eval):\n    return [c for c in cases if c.score > eval.threshold]",
        "for exec in executions:\n    print(exec.name)",
        "import logging\nlogging.getLogger(__name__).addHandler(logging.StreamHandler())",
    ],
)
def test_the_check_allows_harmless_forms(source: str) -> None:
    assert offenders(source) == []


@pytest.mark.parametrize(
    ("source", "module", "is_package", "expected"),
    [
        ("from .fetch import client", "sso_auditor_core.report", False, True),
        ("from .fetch import SafeFetcher", "sso_auditor_core.report", False, False),
        ("from ..fetch import transport", "sso_auditor_core.rules.base", False, True),
        ("from .fetch.urls import parse_url", "sso_auditor_core", True, True),
    ],
)
def test_relative_imports_are_resolved(
    source: str, module: str, is_package: bool, expected: bool
) -> None:
    banned = banned_names()
    names = referenced_names(source, module, is_package=is_package)
    assert any(is_banned(name, banned) for name in names) is expected


def test_no_network_client_is_reachable_outside_the_fetch_package() -> None:
    banned = banned_names()
    found = [
        f"{path.relative_to(ROOT)}: {name}"
        for path in source_files()
        for name in referenced_names(
            path.read_text(encoding="utf-8"),
            module_name(path),
            is_package=path.name == "__init__.py",
        )
        if is_banned(name, banned)
    ]
    assert found == [], "use sso_auditor_core.fetch.SafeFetcher instead"
