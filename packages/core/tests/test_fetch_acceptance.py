"""The acceptance table from #30, run against both policy profiles.

Each case must fail before any request leaves the fetcher, except where the case is
about a response (size, timeout, redirect), where it must fail without following it.
The ``relaxed`` profile is the cli profile with every flag on; the cases marked
``always`` stay rejected even there.
"""

from collections.abc import Callable
from dataclasses import dataclass

import httpx
import pytest
from fetch_doubles import Answer, FakeResolver, RecordingTransport, json_response

from sso_auditor_core.fetch import (
    AddressRejected,
    FetchError,
    FetchPolicy,
    FetchTimeout,
    RedirectRejected,
    ResponseTooLarge,
    SafeFetcher,
    URLRejected,
)

PUBLIC_IP = "93.184.215.14"
STRICT = {"hosted": FetchPolicy.hosted(), "cli": FetchPolicy.cli()}
RELAXED = FetchPolicy.cli(allow_private_network=True, allow_http=True, extra_ports=[80, 8443])


@dataclass(frozen=True)
class Case:
    url: str
    error: type[FetchError]
    always: bool = False
    """Rejected by every profile, including cli with all flags on."""


URL_CASES = {
    "loopback": Case("https://127.0.0.1/", AddressRejected),
    "10/8": Case("https://10.0.0.1/", AddressRejected),
    "172.16/12": Case("https://172.16.0.1/", AddressRejected),
    "192.168/16": Case("https://192.168.1.1/", AddressRejected),
    "cgnat": Case("https://100.64.0.1/", AddressRejected),
    "metadata ip": Case("https://169.254.169.254/", AddressRejected, always=True),
    "this host": Case("https://0.0.0.0/", AddressRejected, always=True),
    "ipv6 loopback": Case("https://[::1]/", AddressRejected),
    "ipv6 ula": Case("https://[fc00::1]/", AddressRejected),
    "ipv6 link-local": Case("https://[fe80::1]/", AddressRejected, always=True),
    "mapped loopback": Case("https://[::ffff:127.0.0.1]/", AddressRejected),
    "mapped metadata": Case("https://[::ffff:a9fe:a9fe]/", AddressRejected, always=True),
    "decimal ipv4": Case("https://2130706433/", URLRejected, always=True),
    "hex ipv4": Case("https://0x7f.1/", URLRejected, always=True),
    "octal ipv4": Case("https://0177.0.0.1/", URLRejected, always=True),
    "short ipv4": Case("https://127.1/", URLRejected, always=True),
    "userinfo": Case("https://user@169.254.169.254/", URLRejected, always=True),
    "localhost": Case("https://localhost/", URLRejected),
    "internal name": Case("https://keycloak.internal/", URLRejected),
    "mdns name": Case("https://printer.local/", URLRejected),
    "metadata name": Case("https://metadata.google.internal/", URLRejected, always=True),
    # IDNA folds these dots to ".", so each must be judged as the name or literal it becomes.
    "ideographic dots": Case("https://127\u30020\u30020\u30021/", AddressRejected),
    "fullwidth dots": Case("https://169\uff0e254\uff0e169\uff0e254/", AddressRejected, always=True),
    "dotted hex": Case("https://0x7f\u30021/", URLRejected, always=True),
    "halfwidth dot": Case("https://localhost\uff61/", URLRejected),
    "dotted metadata": Case(
        "https://metadata\u3002google\u3002internal/", URLRejected, always=True
    ),
}


def fetcher_for(
    policy: FetchPolicy,
    handler: Callable[[httpx.Request], httpx.Response] = lambda request: json_response(),
    answers: dict[str, Answer] | None = None,
) -> tuple[SafeFetcher, RecordingTransport, FakeResolver]:
    transport = RecordingTransport(handler)
    resolver = FakeResolver(answers or {"id.example.com": [PUBLIC_IP]})
    return SafeFetcher(policy, resolver=resolver, transport_factory=transport), transport, resolver


@pytest.mark.parametrize("profile", STRICT)
@pytest.mark.parametrize("case", URL_CASES.values(), ids=URL_CASES.keys())
def test_strict_profiles_reject_without_sending_a_request(profile: str, case: Case) -> None:
    fetcher, transport, resolver = fetcher_for(STRICT[profile])

    with pytest.raises(case.error):
        fetcher.get(case.url)
    assert transport.requests == []
    assert resolver.calls == []


ALWAYS = {name: case for name, case in URL_CASES.items() if case.always}


@pytest.mark.parametrize("case", ALWAYS.values(), ids=ALWAYS.keys())
def test_some_cases_stay_rejected_with_every_cli_flag_on(case: Case) -> None:
    fetcher, transport, _ = fetcher_for(RELAXED)

    with pytest.raises(case.error):
        fetcher.get(case.url)
    assert transport.requests == []


def test_allow_http_reaches_loopback_only() -> None:
    fetcher, transport, _ = fetcher_for(RELAXED)

    with pytest.raises(AddressRejected, match="only to loopback"):
        fetcher.get("http://10.0.0.1/")
    assert transport.requests == []


@pytest.mark.parametrize("policy", STRICT.values(), ids=STRICT.keys())
class TestResolvedAddresses:
    def test_a_hostname_resolving_to_a_private_ip(self, policy: FetchPolicy) -> None:
        fetcher, transport, _ = fetcher_for(policy, answers={"id.example.com": ["10.1.2.3"]})

        with pytest.raises(AddressRejected, match=r"10\.1\.2\.3"):
            fetcher.get("https://id.example.com/")
        assert transport.requests == []

    @pytest.mark.parametrize(
        "answer", [[PUBLIC_IP, "10.0.0.1"], ["10.0.0.1", PUBLIC_IP], [PUBLIC_IP, "fd00:ec2::254"]]
    )
    def test_a_mixed_public_and_private_answer(
        self, policy: FetchPolicy, answer: list[str]
    ) -> None:
        fetcher, transport, _ = fetcher_for(policy, answers={"id.example.com": answer})

        with pytest.raises(AddressRejected):
            fetcher.get("https://id.example.com/")
        assert transport.requests == []

    def test_a_resolver_that_answers_public_then_private(self, policy: FetchPolicy) -> None:
        # DNS rebinding: the first answer passes validation, the second would be used to
        # connect. The fetcher resolves once per hop and connects to what it validated,
        # and a later hop to the same host is resolved and validated again.
        answers: dict[str, Answer] = {
            "id.example.com": lambda call: [PUBLIC_IP] if call == 1 else ["127.0.0.1"]
        }

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/again":
                return json_response()
            return httpx.Response(302, headers={"Location": "/again"})

        fetcher, transport, resolver = fetcher_for(policy, handler, answers)

        with pytest.raises(AddressRejected, match=r"127\.0\.0\.1"):
            fetcher.get("https://id.example.com/")
        assert [request.url.host for request in transport.requests] == [PUBLIC_IP]
        assert resolver.calls == ["id.example.com", "id.example.com"]


@pytest.mark.parametrize("policy", [*STRICT.values(), RELAXED], ids=[*STRICT, "relaxed"])
class TestResponses:
    def test_a_302_to_plain_http_loopback(self, policy: FetchPolicy) -> None:
        fetcher, transport, _ = fetcher_for(
            policy, lambda request: httpx.Response(302, headers={"Location": "http://127.0.0.1/"})
        )

        with pytest.raises(RedirectRejected):
            fetcher.get("https://id.example.com/")
        assert len(transport.requests) == 1

    def test_a_discovery_document_pointing_jwks_uri_at_cloud_metadata(
        self, policy: FetchPolicy
    ) -> None:
        discovery = (
            b'{"issuer": "https://id.example.com",'
            b' "jwks_uri": "https://169.254.169.254/latest/meta-data/"}'
        )
        fetcher, transport, _ = fetcher_for(policy, lambda request: json_response(discovery))

        _, document = fetcher.get_json("https://id.example.com/.well-known/openid-configuration")
        with pytest.raises(AddressRejected, match="link-local"):
            fetcher.get_json(document["jwks_uri"])
        assert len(transport.requests) == 1

    def test_a_body_over_the_size_cap(self, policy: FetchPolicy) -> None:
        body = b"x" * (policy.max_body_bytes + 1)

        def handler(request: httpx.Request) -> httpx.Response:
            # No Content-Length: the cap has to hold while streaming.
            return httpx.Response(200, content=iter([body[:4096], body[4096:]]))

        fetcher, _, _ = fetcher_for(policy, handler)

        with pytest.raises(ResponseTooLarge):
            fetcher.get("https://id.example.com/")

    def test_a_response_slower_than_the_timeout(self, policy: FetchPolicy) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("timed out", request=request)

        fetcher, _, _ = fetcher_for(policy, handler)

        with pytest.raises(FetchTimeout):
            fetcher.get("https://id.example.com/")
