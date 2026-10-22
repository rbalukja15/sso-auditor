"""Parse a URL once into the parts the fetcher validates and connects with.

The fetcher never hands the original string to the HTTP client. It parses it here, checks
the parts, and builds the request from the same parts, so the host that was validated is
the host that gets contacted.
"""

import ipaddress
import re
from dataclasses import dataclass

import httpx

from sso_auditor_core.fetch.addresses import IPAddress
from sso_auditor_core.fetch.errors import URLRejected

MAX_URL_LENGTH = 2048

_DEFAULT_PORTS = {"https": 443, "http": 80}
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
# A last label that is a number (decimal, octal or hex) makes the WHATWG URL parser and
# inet_aton() read the whole host as an IPv4 address: "127.1", "0x7f.1", "2130706433".
_NUMERIC_LABEL = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$")
_OCTET = r"(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_DOTTED_QUAD = re.compile(rf"^{_OCTET}(\.{_OCTET}){{3}}$")


@dataclass(frozen=True)
class Target:
    """A parsed, syntactically valid http(s) URL."""

    scheme: str
    """``"https"`` or ``"http"``."""

    host: str
    """Lower-case ASCII hostname with no trailing dot, or the IP literal without brackets."""

    ip: IPAddress | None
    """The address when the URL's host is an IP literal, else ``None``."""

    port: int
    raw_path: bytes
    """Path and query, percent-encoded. Never empty. The fragment is dropped."""

    @property
    def authority(self) -> str:
        """The ``Host`` header value: the host, bracketed if IPv6, plus a non-default port."""
        host = f"[{self.host}]" if isinstance(self.ip, ipaddress.IPv6Address) else self.host
        if self.port == _DEFAULT_PORTS[self.scheme]:
            return host
        return f"{host}:{self.port}"

    @property
    def url(self) -> str:
        """The canonical form of the URL, as used in reports and errors."""
        return f"{self.scheme}://{self.authority}{self.raw_path.decode('ascii')}"


def parse_url(url: str) -> Target:
    """Parse ``url`` and check its syntax. Policy checks come separately.

    Raises :class:`URLRejected` for anything that isn't a plain http(s) URL with a valid
    hostname or canonical IP literal.
    """
    if len(url) > MAX_URL_LENGTH:
        raise URLRejected(f"URL is longer than {MAX_URL_LENGTH} characters", url=url[:80])
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F or ch == "\\" for ch in url):
        raise URLRejected("URL contains whitespace, control characters or a backslash", url=url)

    try:
        parsed = httpx.URL(url)
        # Reading raw_host can raise too: httpx accepts a non-ASCII IPv6 zone ID, then
        # can't encode it.
        raw_host = parsed.raw_host
    except (httpx.InvalidURL, ValueError) as exc:
        raise URLRejected(f"malformed URL: {exc}", url=url) from exc

    scheme = parsed.scheme
    if scheme not in _DEFAULT_PORTS:
        raise URLRejected(f"scheme {scheme!r} is not allowed; use https", url=url)
    if parsed.userinfo or "@" in _authority_of(url):
        raise URLRejected("URLs with a username or password are not allowed", url=url)

    host, ip = _parse_host(raw_host, url)

    port = parsed.port if parsed.port is not None else _DEFAULT_PORTS[scheme]
    if not 1 <= port <= 65535:
        raise URLRejected(f"port {port} is out of range", url=url)

    return Target(scheme=scheme, host=host, ip=ip, port=port, raw_path=parsed.raw_path or b"/")


def _authority_of(url: str) -> str:
    rest = url.split("://", 1)[1] if "://" in url else url
    return re.split(r"[/?#]", rest, maxsplit=1)[0]


def _parse_host(raw_host: bytes, url: str) -> tuple[str, IPAddress | None]:
    try:
        host = raw_host.decode("ascii").lower()
    except UnicodeDecodeError as exc:
        raise URLRejected("hostname is not valid ASCII after IDNA encoding", url=url) from exc
    if not host:
        raise URLRejected("URL has no host", url=url)
    if "%" in host:
        raise URLRejected("percent-encoded hosts and IPv6 zone IDs are not allowed", url=url)

    if ":" in host:
        try:
            return host, ipaddress.IPv6Address(host)
        except ValueError as exc:
            raise URLRejected(f"invalid IPv6 literal {host!r}", url=url) from exc

    last_label = host.removesuffix(".").rsplit(".", 1)[-1]
    if _NUMERIC_LABEL.match(last_label):
        if not _DOTTED_QUAD.match(host):
            raise URLRejected(
                f"{host!r} is a non-canonical IPv4 literal; write the address as a.b.c.d",
                url=url,
            )
        return host, ipaddress.IPv4Address(host)

    if host.endswith("."):
        host = host[:-1]
    if len(host) > 253 or not all(_LABEL.match(label) for label in host.split(".")):
        raise URLRejected(f"{host!r} is not a valid hostname", url=url)
    return host, None
