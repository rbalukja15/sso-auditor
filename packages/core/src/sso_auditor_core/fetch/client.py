"""The safe fetcher: the only HTTP client in sso-auditor (#30, ADR-0002).

For each hop it parses the URL once, applies the policy, resolves the hostname once,
checks every address in the answer, and connects to a validated address with SNI and
certificate checks on the hostname. It talks to the transport directly, so nothing in
httpx's client layer (redirects, environment proxies, cookies, auth flows) can act on
its own.
"""

import ipaddress
import ssl
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

import certifi
import httpx

from sso_auditor_core import __version__
from sso_auditor_core.fetch.addresses import IPAddress
from sso_auditor_core.fetch.decoding import ACCEPT_ENCODING, BoundedDecoder
from sso_auditor_core.fetch.documents import check_jwks_limits, parse_json
from sso_auditor_core.fetch.errors import (
    ConnectFailed,
    FetchError,
    FetchTimeout,
    InvalidResponse,
    RedirectRejected,
    ResponseTooLarge,
    TLSFailed,
)
from sso_auditor_core.fetch.policy import FetchPolicy
from sso_auditor_core.fetch.resolver import Resolver, SystemResolver
from sso_auditor_core.fetch.transport import Remaining, deadline_transport
from sso_auditor_core.fetch.urls import Target, parse_url

USER_AGENT = f"sso-auditor/{__version__} (+https://github.com/rbalukja15/sso-auditor)"

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
# Headers the fetcher owns. A caller setting them could undo a check (Host) or the size
# cap (Accept-Encoding), or confuse framing.
_RESERVED_HEADERS = frozenset(
    {"host", "accept-encoding", "connection", "content-length", "transfer-encoding", "te"}
)
# Only requests this plain follow redirects: a GET with no body and no caller headers but
# these. Anything else (a token in any header, a form body) is never sent to a new hop.
_REDIRECTABLE_HEADERS = frozenset({"accept"})

type TransportFactory = Callable[[ssl.SSLContext, Remaining], httpx.BaseTransport]


@dataclass(frozen=True)
class FetchResponse:
    """A completed fetch. ``content`` is the decoded body, within the size cap."""

    url: str
    """The URL that was requested, in canonical form."""

    final_url: str
    """The URL that produced this response, after any redirects."""

    status_code: int
    headers: Mapping[str, str]
    """Response headers with lower-case names; repeated headers are joined with ", "."""

    content: bytes
    redirects: tuple[str, ...]
    """Each URL that answered with a redirect, in order."""

    remote_address: str
    """The IP address the final response came from."""

    elapsed: float
    """Seconds from the start of the fetch to the end of the body."""


def create_ssl_context(ca_bundle: str | None = None) -> ssl.SSLContext:
    """TLS 1.2 or later, certificates verified against the hostname, no exceptions.

    Built by hand rather than with ``ssl.create_default_context()``, which reads
    ``SSLKEYLOGFILE`` and would write the session secrets wherever the environment says.
    The verify flags match what Python 3.13's default context sets.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # CERT_REQUIRED and check_hostname
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN | ssl.VERIFY_X509_STRICT
    context.load_verify_locations(cafile=ca_bundle or certifi.where())
    return context


class SafeFetcher:
    """Fetches URLs under a :class:`FetchPolicy`.

    ``resolver``, ``transport_factory`` and ``clock`` exist for tests. Production code
    passes only the policy.
    """

    def __init__(
        self,
        policy: FetchPolicy,
        *,
        resolver: Resolver | None = None,
        transport_factory: TransportFactory | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.policy = policy
        self._resolver = resolver or SystemResolver()
        self._transport_factory = transport_factory or deadline_transport
        self._clock = clock
        ca_bundle = str(policy.ca_bundle) if policy.ca_bundle is not None else None
        self._ssl_context = create_ssl_context(ca_bundle)

    def get(self, url: str, *, accept: str = "application/json") -> FetchResponse:
        """``GET`` a URL, following up to ``policy.max_redirects`` validated redirects."""
        return self.request("GET", url, headers={"Accept": accept})

    def get_json(self, url: str) -> tuple[FetchResponse, Any]:
        """``GET`` a URL and parse the body as JSON within the policy's depth limit.

        The status code is not checked; callers decide what a non-2xx response means.
        """
        response = self.get(url)
        document = parse_json(
            response.content,
            max_depth=self.policy.max_json_depth,
            max_nodes=self.policy.max_json_nodes,
        )
        return response, document

    def get_jwks(self, url: str) -> tuple[FetchResponse, Any]:
        """Like :meth:`get_json`, plus the policy's JWKS key-count and RSA size caps."""
        response, document = self.get_json(url)
        check_jwks_limits(
            document,
            max_keys=self.policy.max_jwks_keys,
            max_rsa_modulus_bits=self.policy.max_rsa_modulus_bits,
        )
        return response, document

    def request(
        self,
        method: Literal["GET", "POST"],
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> FetchResponse:
        """Send a request under the policy.

        Only a ``GET`` with no body and no headers other than ``Accept`` follows
        redirects. For anything else (a ``POST``, a token in a header) a redirect response
        raises :class:`RedirectRejected`, so nothing it carries reaches another hop.
        """
        if method not in {"GET", "POST"}:
            raise ValueError(f"method {method!r} is not allowed")
        extra_headers = dict(headers or {})
        reserved = {name for name in extra_headers if name.lower() in _RESERVED_HEADERS}
        if reserved:
            raise ValueError(f"the fetcher sets these headers itself: {sorted(reserved)}")
        follow = (
            method == "GET"
            and body is None
            and all(name.lower() in _REDIRECTABLE_HEADERS for name in extra_headers)
        )

        start = self._clock()
        deadline = start + self.policy.total_timeout
        target = self._validated_target(url)
        requested = target.url
        redirects: list[str] = []

        while True:
            hop = self._send(method, target, extra_headers, body, deadline)
            if hop.status_code not in _REDIRECT_STATUSES:
                return FetchResponse(
                    url=requested,
                    final_url=target.url,
                    status_code=hop.status_code,
                    headers=hop.headers,
                    content=hop.content,
                    redirects=tuple(redirects),
                    remote_address=hop.remote_address,
                    elapsed=self._clock() - start,
                )

            if not follow:
                raise RedirectRejected(
                    f"{target.url} answered {hop.status_code}, and this request follows "
                    "no redirects",
                    url=target.url,
                )
            if len(redirects) >= self.policy.max_redirects:
                raise RedirectRejected(
                    f"more than {self.policy.max_redirects} redirects", url=requested
                )
            location = hop.headers.get("location")
            if not location:
                raise RedirectRejected(
                    f"{target.url} answered {hop.status_code} without a Location", url=target.url
                )
            try:
                next_url = str(httpx.URL(target.url).join(location))
            except (httpx.InvalidURL, ValueError) as exc:
                # httpx's join runs the stdlib's urljoin, which raises plain ValueErrors.
                raise RedirectRejected(
                    f"{target.url} redirected to a malformed URL", url=target.url
                ) from exc
            next_target = parse_url(next_url)
            if target.scheme == "https" and next_target.scheme == "http":
                raise RedirectRejected(
                    f"{target.url} redirected from https to plain http", url=target.url
                )
            # Every hop is checked exactly like the first request.
            self.policy.check_target(next_target)
            redirects.append(target.url)
            target = next_target

    def _validated_target(self, url: str) -> Target:
        target = parse_url(url)
        self.policy.check_target(target)
        return target

    def _send(
        self,
        method: str,
        target: Target,
        headers: Mapping[str, str],
        body: bytes | None,
        deadline: float,
    ) -> "_Hop":
        addresses = self._addresses(target, deadline)
        # Every address is validated, even the ones that won't be tried.
        self.policy.check_addresses(target, addresses)
        candidates = _connect_order(addresses, self.policy.max_connect_attempts)

        def remaining() -> float:
            return deadline - self._clock()

        failures: list[str] = []
        timed_out = False
        for address in candidates:
            left = self._remaining(deadline, target)
            transport = self._transport_factory(self._ssl_context, remaining)
            try:
                request = self._build_request(method, target, address, headers, body, left)
                try:
                    response = transport.handle_request(request)
                except httpx.ConnectTimeout:
                    # Often an unreachable address family (IPv6 with no route); try the
                    # next validated address while the deadline allows.
                    timed_out = True
                    failures.append(f"{address}: connect timed out")
                    continue
                except httpx.ConnectError as exc:
                    if _is_tls_failure(exc):
                        raise TLSFailed(
                            f"TLS handshake with {target.host} ({address}) failed: {exc}",
                            url=target.url,
                        ) from exc
                    failures.append(f"{address}: {exc}")
                    continue
                except httpx.TimeoutException as exc:
                    raise self._timeout(deadline, target) from exc
                except httpx.HTTPError as exc:
                    raise InvalidResponse(f"{target.url}: {exc}", url=target.url) from exc

                try:
                    return self._read(response, target, address, deadline)
                finally:
                    response.close()
            finally:
                transport.close()

        message = f"could not connect to {target.host}: " + "; ".join(failures)
        if timed_out and len(failures) == len(candidates):
            raise FetchTimeout(message, url=target.url)
        raise ConnectFailed(message, url=target.url)

    def _addresses(self, target: Target, deadline: float) -> list[IPAddress]:
        if target.ip is not None:
            return [target.ip]
        remaining = self._remaining(deadline, target)
        return self._resolver.resolve(target.host, target.port, remaining)

    def _remaining(self, deadline: float, target: Target) -> float:
        remaining = deadline - self._clock()
        if remaining <= 0:
            raise self._timeout(deadline, target)
        return remaining

    def _timeout(self, deadline: float, target: Target) -> FetchTimeout:
        """The error for a timeout: the total deadline if it has passed, else one step."""
        if deadline - self._clock() <= 0:
            message = f"the fetch took longer than {self.policy.total_timeout:g}s"
        else:
            message = f"{target.url} timed out"
        return FetchTimeout(message, url=target.url)

    def _build_request(
        self,
        method: str,
        target: Target,
        address: IPAddress,
        headers: Mapping[str, str],
        body: bytes | None,
        remaining: float,
    ) -> httpx.Request:
        url = httpx.URL(
            scheme=target.scheme, host=str(address), port=target.port, raw_path=target.raw_path
        )
        connect = min(self.policy.connect_timeout, remaining)
        read = min(self.policy.read_timeout, remaining)
        extensions: dict[str, Any] = {
            "timeout": {"connect": connect, "read": read, "write": read, "pool": connect}
        }
        if target.scheme == "https" and target.ip is None:
            # Connect to the validated IP, but send SNI and check the certificate for the
            # hostname. Without this the TLS layer would check the IP instead.
            extensions["sni_hostname"] = target.host
        request_headers = {
            "Host": target.authority,
            "User-Agent": USER_AGENT,
            "Accept-Encoding": ACCEPT_ENCODING,
            "Connection": "close",
            **headers,
        }
        return httpx.Request(
            method, url, headers=request_headers, content=body, extensions=extensions
        )

    def _read(
        self, response: httpx.Response, target: Target, address: IPAddress, deadline: float
    ) -> "_Hop":
        headers = _header_map(response.headers)
        if response.status_code in _REDIRECT_STATUSES:
            # The body of a redirect is never read.
            return _Hop(response.status_code, headers, b"", str(address))

        limit = self.policy.max_body_bytes
        declared = headers.get("content-length", "")
        if declared.isdigit() and int(declared) > limit:
            raise ResponseTooLarge(
                f"{target.url} declares {declared} bytes; the limit is {limit}", url=target.url
            )

        try:
            decoder = BoundedDecoder(headers.get("content-encoding"), limit)
            content = bytearray()
            received = 0
            for chunk in _raw_chunks(response):
                received += len(chunk)
                if received > limit:
                    raise ResponseTooLarge(
                        f"{target.url} sent more than {limit} bytes", url=target.url
                    )
                content += decoder.decode(chunk)
                self._remaining(deadline, target)
            content += decoder.flush()
            # Trailers are read after the last chunk; the transport bounds them, and this
            # catches anything that finished just past the deadline.
            self._remaining(deadline, target)
        except FetchError as exc:
            exc.url = exc.url or target.url
            raise
        except httpx.TimeoutException as exc:
            raise self._timeout(deadline, target) from exc
        except httpx.HTTPError as exc:
            raise InvalidResponse(f"{target.url}: {exc}", url=target.url) from exc
        return _Hop(response.status_code, headers, bytes(content), str(address))


@dataclass(frozen=True)
class _Hop:
    status_code: int
    headers: Mapping[str, str]
    content: bytes
    remote_address: str


def _connect_order(addresses: Sequence[IPAddress], limit: int) -> list[IPAddress]:
    """The addresses to try, at most ``limit``, alternating address families.

    The resolver's order is kept within each family, and the first address's family goes
    first. Alternating means an unreachable family (often IPv6) can't use up every
    attempt, and the cap stops a hostile DNS answer from turning one fetch into
    connections to hundreds of third-party hosts.
    """
    v4 = [a for a in addresses if isinstance(a, ipaddress.IPv4Address)]
    v6 = [a for a in addresses if isinstance(a, ipaddress.IPv6Address)]
    first, second = (v6, v4) if addresses and addresses[0] in v6 else (v4, v6)
    ordered: list[IPAddress] = []
    for index in range(max(len(first), len(second))):
        ordered.extend(family[index] for family in (first, second) if index < len(family))
    return ordered[:limit]


def _raw_chunks(response: httpx.Response) -> Iterator[bytes]:
    stream = response.stream
    if not isinstance(stream, httpx.SyncByteStream):
        raise InvalidResponse("the transport returned an async stream")
    yield from stream


def _header_map(headers: httpx.Headers) -> dict[str, str]:
    merged: dict[str, str] = {}
    for name, value in headers.multi_items():
        key = name.lower()
        merged[key] = f"{merged[key]}, {value}" if key in merged else value
    return merged


def _is_tls_failure(exc: BaseException) -> bool:
    """Whether an ``ssl.SSLError`` caused this error. httpx and httpcore keep the cause
    chain, so the message is never consulted: a refused connection whose text happens to
    mention "SSL" is still a connect failure."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        if isinstance(current, ssl.SSLError):
            return True
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return False
