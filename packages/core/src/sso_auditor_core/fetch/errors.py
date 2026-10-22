"""Errors raised by the safe fetcher.

Every failure is a :class:`FetchError` subclass, so callers can catch one type. The
subclasses say *why* a fetch failed, for logs and the CLI. The hosted API must not echo
that distinction to its users (#20): refused, unreachable and timed out should look the
same from outside.
"""


class FetchError(Exception):
    """Base class for every failure of the safe fetcher."""

    def __init__(self, message: str, *, url: str | None = None) -> None:
        super().__init__(message)
        self.url = url


class URLRejected(FetchError):
    """The URL breaks the policy before any network access.

    For example: a scheme other than https, userinfo, a non-canonical IPv4 literal, a
    refused hostname, or a port the policy doesn't allow.
    """


class AddressRejected(FetchError):
    """An IP address the URL points at, or resolves to, is not allowed by the policy."""


class ResolutionFailed(FetchError):
    """The hostname could not be resolved to any address."""


class RedirectRejected(FetchError):
    """A redirect could not be followed: too many hops, a missing or malformed
    ``Location``, or a redirect on a request that must not follow any."""


class ConnectFailed(FetchError):
    """No TCP connection could be made to any validated address."""


class TLSFailed(FetchError):
    """The TLS handshake failed, for example because the certificate didn't verify."""


class FetchTimeout(FetchError):
    """A timeout expired: DNS, connect, read, or the total deadline for the fetch."""


class ResponseTooLarge(FetchError):
    """The response body exceeded the size cap, before or after decompression."""


class InvalidResponse(FetchError):
    """The response could not be read: a protocol error, a dropped connection, or a
    content encoding that is unsupported or corrupt."""
