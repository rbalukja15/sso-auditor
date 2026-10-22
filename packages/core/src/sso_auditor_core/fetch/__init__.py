"""The safe fetcher: the only way sso-auditor makes HTTP requests (#30, ADR-0002).

Typical use::

    fetcher = SafeFetcher(FetchPolicy.cli())
    response, document = fetcher.get_json("https://id.example.com/.well-known/openid-configuration")
"""

from sso_auditor_core.fetch.addresses import AddressClass, Classification, IPAddress, classify
from sso_auditor_core.fetch.client import FetchResponse, SafeFetcher, create_ssl_context
from sso_auditor_core.fetch.documents import (
    DocumentError,
    InvalidJSON,
    JSONTooDeep,
    JSONTooLarge,
    JWKSLimitExceeded,
    check_jwks_limits,
    parse_json,
)
from sso_auditor_core.fetch.errors import (
    AddressRejected,
    ConnectFailed,
    FetchError,
    FetchTimeout,
    InvalidResponse,
    RedirectRejected,
    ResolutionFailed,
    ResponseTooLarge,
    TLSFailed,
    URLRejected,
)
from sso_auditor_core.fetch.policy import FetchPolicy
from sso_auditor_core.fetch.resolver import Resolver, SystemResolver
from sso_auditor_core.fetch.urls import Target, parse_url

__all__ = [
    "AddressClass",
    "AddressRejected",
    "Classification",
    "ConnectFailed",
    "DocumentError",
    "FetchError",
    "FetchPolicy",
    "FetchResponse",
    "FetchTimeout",
    "IPAddress",
    "InvalidJSON",
    "InvalidResponse",
    "JSONTooDeep",
    "JSONTooLarge",
    "JWKSLimitExceeded",
    "RedirectRejected",
    "ResolutionFailed",
    "Resolver",
    "ResponseTooLarge",
    "SafeFetcher",
    "SystemResolver",
    "TLSFailed",
    "Target",
    "URLRejected",
    "check_jwks_limits",
    "classify",
    "create_ssl_context",
    "parse_json",
    "parse_url",
]
