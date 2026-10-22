"""Test doubles for the safe fetcher: a scripted resolver and a recording transport.
Neither touches the network. Importable because pytest puts this directory on the path."""

import ipaddress
import ssl
from collections.abc import Callable, Sequence

import httpx

from sso_auditor_core.fetch import ResolutionFailed
from sso_auditor_core.fetch.addresses import IPAddress
from sso_auditor_core.fetch.transport import Remaining

type Answer = Sequence[str] | Callable[[int], Sequence[str]]


class FakeResolver:
    """Answers from a table. A callable answer gets the 1-based call count for that host,
    which is how the rebinding tests change the answer between lookups."""

    def __init__(self, answers: dict[str, Answer]) -> None:
        self.answers = answers
        self.calls: list[str] = []

    def resolve(self, host: str, port: int, timeout: float) -> list[IPAddress]:
        self.calls.append(host)
        answer = self.answers.get(host)
        if answer is None:
            raise ResolutionFailed(f"no such host: {host}")
        if callable(answer):
            answer = answer(self.calls.count(host))
        return [ipaddress.ip_address(a) for a in answer]


type Handler = Callable[[httpx.Request], httpx.Response]


class RecordingTransport:
    """A transport factory whose transports pass every request to ``handler`` and
    remember it, so tests can see which IP, Host header and SNI name were used."""

    def __init__(self, handler: Handler) -> None:
        self.handler = handler
        self.requests: list[httpx.Request] = []

    def __call__(self, ssl_context: ssl.SSLContext, remaining: Remaining) -> httpx.BaseTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.handler(request)


def json_response(body: bytes = b'{"issuer": "https://id.example.com"}') -> httpx.Response:
    return httpx.Response(200, content=body, headers={"Content-Type": "application/json"})
