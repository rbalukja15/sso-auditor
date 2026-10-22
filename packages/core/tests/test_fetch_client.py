"""SafeFetcher behaviour with a scripted resolver and a mock transport: no sockets."""

import gzip
import json
import ssl
from collections.abc import Iterator

import httpx
import pytest
from fetch_doubles import FakeResolver, RecordingTransport, json_response

from sso_auditor_core.fetch import (
    AddressRejected,
    ConnectFailed,
    FetchPolicy,
    FetchTimeout,
    InvalidResponse,
    JSONTooDeep,
    JSONTooLarge,
    JWKSLimitExceeded,
    RedirectRejected,
    ResponseTooLarge,
    SafeFetcher,
    TLSFailed,
    URLRejected,
)
from sso_auditor_core.fetch.client import USER_AGENT
from sso_auditor_core.fetch.transport import Remaining

ISSUER = "https://id.example.com/realms/demo"
DISCOVERY = f"{ISSUER}/.well-known/openid-configuration"
PUBLIC_IP = "93.184.215.14"


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def make_fetcher(
    handler: RecordingTransport,
    resolver: FakeResolver | None = None,
    policy: FetchPolicy | None = None,
    clock: FakeClock | None = None,
) -> SafeFetcher:
    return SafeFetcher(
        policy or FetchPolicy.hosted(),
        resolver=resolver or FakeResolver({"id.example.com": [PUBLIC_IP]}),
        transport_factory=handler,
        clock=clock or FakeClock(),
    )


def redirect(location: str, status: int = 302) -> httpx.Response:
    return httpx.Response(status, headers={"Location": location})


class TestConnectsToTheValidatedAddress:
    def test_pins_the_ip_and_keeps_the_hostname_for_host_and_sni(self) -> None:
        transport = RecordingTransport(lambda request: json_response())
        resolver = FakeResolver({"id.example.com": [PUBLIC_IP]})

        response = make_fetcher(transport, resolver).get(DISCOVERY)

        (request,) = transport.requests
        assert resolver.calls == ["id.example.com"]
        assert request.url.host == PUBLIC_IP
        assert request.url.port is None
        assert request.url.raw_path == b"/realms/demo/.well-known/openid-configuration"
        assert request.headers["host"] == "id.example.com"
        assert request.extensions["sni_hostname"] == "id.example.com"
        assert request.headers["user-agent"] == USER_AGENT
        assert request.headers["accept"] == "application/json"
        assert request.headers["accept-encoding"] == "gzip, deflate"
        assert response.url == response.final_url == DISCOVERY
        assert response.status_code == 200
        assert response.remote_address == PUBLIC_IP
        assert response.redirects == ()
        assert response.headers["content-type"] == "application/json"

    def test_an_ip_literal_is_not_resolved_and_gets_no_sni_name(self) -> None:
        transport = RecordingTransport(lambda request: json_response())
        resolver = FakeResolver({})

        make_fetcher(transport, resolver).get("https://8.8.8.8/x")

        (request,) = transport.requests
        assert resolver.calls == []
        assert request.url.host == "8.8.8.8"
        assert "sni_hostname" not in request.extensions

    def test_a_non_default_port_is_kept_in_the_host_header(self) -> None:
        transport = RecordingTransport(lambda request: json_response())
        policy = FetchPolicy.cli(extra_ports=[8443])

        make_fetcher(transport, policy=policy).get("https://id.example.com:8443/x")

        (request,) = transport.requests
        assert request.url.port == 8443
        assert request.headers["host"] == "id.example.com:8443"

    def test_a_rebinding_resolver_is_asked_once_and_its_second_answer_never_used(self) -> None:
        transport = RecordingTransport(lambda request: json_response())
        resolver = FakeResolver(
            {"id.example.com": lambda call: [PUBLIC_IP] if call == 1 else ["127.0.0.1"]}
        )

        make_fetcher(transport, resolver).get(DISCOVERY)

        assert resolver.calls == ["id.example.com"]
        assert [r.url.host for r in transport.requests] == [PUBLIC_IP]

    def test_falls_back_to_the_next_address_after_a_connect_failure(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "2606:2800:21f:cb07::1":
                raise httpx.ConnectTimeout("no route", request=request)
            return json_response()

        transport = RecordingTransport(handler)
        resolver = FakeResolver({"id.example.com": ["2606:2800:21f:cb07::1", PUBLIC_IP]})

        response = make_fetcher(transport, resolver).get(DISCOVERY)

        assert response.remote_address == PUBLIC_IP
        assert len(transport.requests) == 2

    def test_tries_at_most_max_connect_attempts_addresses(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        transport = RecordingTransport(handler)
        # A hostile answer: every address is public and passes validation.
        answer = [f"93.184.{i // 256}.{i % 256}" for i in range(1000)]
        resolver = FakeResolver({"id.example.com": answer})

        with pytest.raises(ConnectFailed):
            make_fetcher(transport, resolver).get(DISCOVERY)
        assert len(transport.requests) == 4

    def test_alternates_address_families_starting_with_the_first(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("no route", request=request)

        transport = RecordingTransport(handler)
        answer = ["2606:4700::1", "2606:4700::2", "2606:4700::3", PUBLIC_IP, "8.8.4.4"]
        resolver = FakeResolver({"id.example.com": answer})

        with pytest.raises(FetchTimeout):
            make_fetcher(transport, resolver).get(DISCOVERY)
        hosts = [request.url.host for request in transport.requests]
        assert hosts == ["2606:4700::1", PUBLIC_IP, "2606:4700::2", "8.8.4.4"]

    def test_unreachable_addresses_cannot_outlast_the_deadline(self) -> None:
        clock = FakeClock()

        def handler(request: httpx.Request) -> httpx.Response:
            clock.now += 5.0  # each address takes the full connect timeout
            raise httpx.ConnectTimeout("no route", request=request)

        transport = RecordingTransport(handler)
        resolver = FakeResolver({"id.example.com": [PUBLIC_IP, "8.8.4.4", "8.8.8.8", "1.1.1.1"]})

        with pytest.raises(FetchTimeout, match="longer than 15s"):
            make_fetcher(transport, resolver, clock=clock).get(DISCOVERY)
        assert len(transport.requests) == 3


class TestRedirects:
    def test_follows_and_records_validated_hops(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.headers["host"] == "id.example.com":
                return redirect("https://keys.example.net/jwks", 301)
            return json_response(b'{"keys": []}')

        transport = RecordingTransport(handler)
        resolver = FakeResolver({"id.example.com": [PUBLIC_IP], "keys.example.net": ["8.8.4.4"]})

        response = make_fetcher(transport, resolver).get(f"{ISSUER}/certs")

        assert response.final_url == "https://keys.example.net/jwks"
        assert response.redirects == (f"{ISSUER}/certs",)
        assert response.remote_address == "8.8.4.4"
        assert transport.requests[1].extensions["sni_hostname"] == "keys.example.net"

    def test_resolves_relative_locations(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/old":
                return redirect("/new?x=1", 308)
            return json_response()

        transport = RecordingTransport(handler)

        response = make_fetcher(transport).get("https://id.example.com/old")

        assert response.final_url == "https://id.example.com/new?x=1"

    def test_re_resolves_each_hop_so_rebinding_on_a_redirect_is_caught(self) -> None:
        transport = RecordingTransport(
            lambda request: redirect("/second") if request.url.path == "/first" else json_response()
        )
        resolver = FakeResolver(
            {"id.example.com": lambda call: [PUBLIC_IP] if call == 1 else ["127.0.0.1"]}
        )

        with pytest.raises(AddressRejected, match=r"127\.0\.0\.1"):
            make_fetcher(transport, resolver).get("https://id.example.com/first")
        assert len(transport.requests) == 1

    @pytest.mark.parametrize(
        ("location", "error"),
        [
            ("http://127.0.0.1/", RedirectRejected),
            ("http://id.example.com/", RedirectRejected),
            ("https://169.254.169.254/latest/meta-data/", AddressRejected),
            ("https://[::1]/", AddressRejected),
            ("https://localhost/", URLRejected),
            ("https://metadata.google.internal/", URLRejected),
            ("https://user@id.example.com/", URLRejected),
            ("https://2130706433/", URLRejected),
            ("https://id.example.com:8080/", URLRejected),
            ("file:///etc/passwd", URLRejected),
        ],
    )
    def test_rejects_a_hop_that_breaks_the_policy(
        self, location: str, error: type[Exception]
    ) -> None:
        transport = RecordingTransport(lambda request: redirect(location))

        with pytest.raises(error):
            make_fetcher(transport).get(DISCOVERY)
        assert len(transport.requests) == 1

    def test_never_downgrades_from_https_to_http_even_when_http_is_allowed(self) -> None:
        transport = RecordingTransport(lambda request: redirect("http://127.0.0.1:8080/"))
        policy = FetchPolicy.cli(allow_http=True, allow_private_network=True, extra_ports=[8080])

        with pytest.raises(RedirectRejected, match="from https to plain http"):
            make_fetcher(transport, policy=policy).get(DISCOVERY)
        assert len(transport.requests) == 1

    def test_stops_after_max_redirects(self) -> None:
        transport = RecordingTransport(lambda request: redirect(f"/hop{len(transport.requests)}"))

        with pytest.raises(RedirectRejected, match="more than 3 redirects"):
            make_fetcher(transport).get(DISCOVERY)
        assert len(transport.requests) == 4

    def test_a_redirect_without_location_is_an_error(self) -> None:
        transport = RecordingTransport(lambda request: httpx.Response(302))

        with pytest.raises(RedirectRejected, match="without a Location"):
            make_fetcher(transport).get(DISCOVERY)

    def test_post_never_follows_redirects(self) -> None:
        transport = RecordingTransport(lambda request: redirect("https://id.example.com/other"))

        with pytest.raises(RedirectRejected, match="follows no redirects"):
            make_fetcher(transport).request("POST", DISCOVERY, body=b"grant_type=x")
        assert len(transport.requests) == 1

    @pytest.mark.parametrize(
        ("headers", "body"),
        [
            ({"Authorization": "Bearer token"}, None),
            ({"X-Api-Key": "key"}, None),
            ({"Cookie": "session=1"}, None),
            ({}, b"grant_type=x"),
        ],
    )
    def test_only_a_plain_get_follows_redirects(
        self, headers: dict[str, str], body: bytes | None
    ) -> None:
        transport = RecordingTransport(lambda request: redirect("https://id.example.com/other"))

        with pytest.raises(RedirectRejected, match="follows no redirects"):
            make_fetcher(transport).request("GET", DISCOVERY, headers=headers, body=body)
        assert len(transport.requests) == 1

    @pytest.mark.parametrize(
        ("location", "error"),
        [
            (b"https:////[", RedirectRejected),
            (b"https:////[1.2.3.4]", RedirectRejected),
            ("https://[fe80::1%\uff0f]/".encode(), RedirectRejected),
            ("https://[fe80::1%\u00fc]/".encode(), URLRejected),
        ],
    )
    def test_a_malformed_location_is_a_fetch_error(
        self, location: bytes, error: type[Exception]
    ) -> None:
        transport = RecordingTransport(
            lambda request: httpx.Response(302, headers=[(b"Location", location)])
        )

        with pytest.raises(error):
            make_fetcher(transport).get(DISCOVERY)
        assert len(transport.requests) == 1


class TestLimits:
    def test_rejects_a_declared_length_over_the_cap(self) -> None:
        transport = RecordingTransport(
            lambda request: httpx.Response(200, headers={"Content-Length": str(2 * 1024 * 1024)})
        )

        with pytest.raises(ResponseTooLarge, match="declares"):
            make_fetcher(transport).get(DISCOVERY)

    def test_rejects_a_streamed_body_over_the_cap(self) -> None:
        class Endless(httpx.SyncByteStream):
            def __iter__(self) -> Iterator[bytes]:
                while True:
                    yield b"x" * 65536

        transport = RecordingTransport(lambda request: httpx.Response(200, stream=Endless()))

        with pytest.raises(ResponseTooLarge):
            make_fetcher(transport).get(DISCOVERY)

    def test_caps_the_bytes_received_even_when_they_decode_to_nothing(self) -> None:
        class EmptyDeflateBlocks(httpx.SyncByteStream):
            def __iter__(self) -> Iterator[bytes]:
                yield b"\x78\x01"  # zlib header
                while True:
                    yield b"\x00\x00\x00\xff\xff" * 13_000  # empty stored blocks

        transport = RecordingTransport(
            lambda request: httpx.Response(
                200, stream=EmptyDeflateBlocks(), headers={"Content-Encoding": "deflate"}
            )
        )

        with pytest.raises(ResponseTooLarge, match="sent more than"):
            make_fetcher(transport).get(DISCOVERY)

    def test_rejects_a_gzip_bomb(self) -> None:
        bomb = gzip.compress(b" " * 20 * 1024 * 1024)
        transport = RecordingTransport(
            lambda request: httpx.Response(200, content=bomb, headers={"Content-Encoding": "gzip"})
        )

        with pytest.raises(ResponseTooLarge):
            make_fetcher(transport).get(DISCOVERY)

    def test_decodes_gzip_within_the_cap(self) -> None:
        body = b'{"issuer": "https://id.example.com"}'
        transport = RecordingTransport(
            lambda request: httpx.Response(
                200, content=gzip.compress(body), headers={"Content-Encoding": "gzip"}
            )
        )

        assert make_fetcher(transport).get(DISCOVERY).content == body

    def test_enforces_the_total_deadline_while_reading(self) -> None:
        clock = FakeClock()

        class Trickle(httpx.SyncByteStream):
            def __iter__(self) -> Iterator[bytes]:
                for _ in range(100):
                    clock.now += 1.0
                    yield b" "

        transport = RecordingTransport(lambda request: httpx.Response(200, stream=Trickle()))

        with pytest.raises(FetchTimeout, match="longer than 15s"):
            make_fetcher(transport, clock=clock).get(DISCOVERY)

    def test_enforces_the_total_deadline_across_hops(self) -> None:
        clock = FakeClock()

        def handler(request: httpx.Request) -> httpx.Response:
            clock.now += 10.0
            return redirect(f"/hop{len(transport.requests)}")

        transport = RecordingTransport(handler)

        with pytest.raises(FetchTimeout):
            make_fetcher(transport, clock=clock).get(DISCOVERY)
        assert len(transport.requests) == 2

    def test_passes_the_remaining_time_as_the_transport_timeouts(self) -> None:
        transport = RecordingTransport(lambda request: json_response())

        make_fetcher(transport).get(DISCOVERY)

        timeouts = transport.requests[0].extensions["timeout"]
        assert timeouts == {"connect": 5.0, "read": 10.0, "write": 10.0, "pool": 5.0}

    def test_the_transport_timeouts_shrink_to_the_time_left(self) -> None:
        clock = FakeClock()

        def slow_dns(call: int) -> list[str]:
            clock.now += 13.0
            return [PUBLIC_IP]

        transport = RecordingTransport(lambda request: json_response())
        resolver = FakeResolver({"id.example.com": slow_dns})

        make_fetcher(transport, resolver, clock=clock).get(DISCOVERY)

        timeouts = transport.requests[0].extensions["timeout"]
        assert timeouts == {"connect": 2.0, "read": 2.0, "write": 2.0, "pool": 2.0}

    def test_the_transport_is_given_the_time_left_before_the_deadline(self) -> None:
        clock = FakeClock()
        recording = RecordingTransport(lambda request: json_response())
        seen: list[float] = []

        def factory(context: ssl.SSLContext, remaining: Remaining) -> httpx.BaseTransport:
            clock.now += 4.0
            seen.append(remaining())
            return recording(context, remaining)

        fetcher = SafeFetcher(
            FetchPolicy.hosted(),
            resolver=FakeResolver({"id.example.com": [PUBLIC_IP]}),
            transport_factory=factory,
            clock=clock,
        )
        fetcher.get(DISCOVERY)

        assert seen == [11.0]

    def test_get_json_enforces_the_depth_limit(self) -> None:
        transport = RecordingTransport(lambda request: json_response(b"[" * 40 + b"]" * 40))

        with pytest.raises(JSONTooDeep):
            make_fetcher(transport).get_json(DISCOVERY)

    def test_get_json_enforces_the_node_limit(self) -> None:
        body = b"[" + b",".join([b"1"] * 20_001) + b"]"
        transport = RecordingTransport(lambda request: json_response(body))

        with pytest.raises(JSONTooLarge):
            make_fetcher(transport).get_json(DISCOVERY)

    def test_get_jwks_enforces_the_key_limit(self) -> None:
        body = json.dumps({"keys": [{"kty": "EC"}] * 101}).encode()
        transport = RecordingTransport(lambda request: json_response(body))

        with pytest.raises(JWKSLimitExceeded):
            make_fetcher(transport).get_jwks(f"{ISSUER}/certs")

    def test_get_jwks_returns_the_document(self) -> None:
        body = json.dumps({"keys": [{"kty": "EC", "crv": "P-256"}]}).encode()
        transport = RecordingTransport(lambda request: json_response(body))

        _, document = make_fetcher(transport).get_jwks(f"{ISSUER}/certs")

        assert document == {"keys": [{"kty": "EC", "crv": "P-256"}]}

    def test_get_json_returns_the_document(self) -> None:
        transport = RecordingTransport(lambda request: json_response())

        response, document = make_fetcher(transport).get_json(DISCOVERY)

        assert response.status_code == 200
        assert document == {"issuer": "https://id.example.com"}


class TestTransportErrors:
    @pytest.mark.parametrize(
        ("raised", "expected"),
        [
            (httpx.ReadTimeout("slow"), FetchTimeout),
            (httpx.WriteTimeout("slow"), FetchTimeout),
            (httpx.PoolTimeout("slow"), FetchTimeout),
            (httpx.ConnectTimeout("slow"), FetchTimeout),
            (httpx.ConnectError("refused"), ConnectFailed),
            (httpx.RemoteProtocolError("garbage"), InvalidResponse),
            (httpx.ReadError("reset"), InvalidResponse),
        ],
    )
    def test_maps_transport_errors(self, raised: Exception, expected: type[Exception]) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise raised

        with pytest.raises(expected):
            make_fetcher(RecordingTransport(handler)).get(DISCOVERY)

    def test_a_certificate_failure_is_a_tls_error_and_is_not_retried(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            error = httpx.ConnectError("handshake failed")
            error.__cause__ = ssl.SSLCertVerificationError("certificate verify failed")
            raise error

        transport = RecordingTransport(handler)
        resolver = FakeResolver({"id.example.com": [PUBLIC_IP, "8.8.4.4"]})

        with pytest.raises(TLSFailed):
            make_fetcher(transport, resolver).get(DISCOVERY)
        assert len(transport.requests) == 1

    def test_unsupported_content_encoding_is_an_invalid_response(self) -> None:
        transport = RecordingTransport(
            lambda request: httpx.Response(200, content=b"x", headers={"Content-Encoding": "br"})
        )

        with pytest.raises(InvalidResponse):
            make_fetcher(transport).get(DISCOVERY)

    def test_non_2xx_responses_are_returned(self) -> None:
        transport = RecordingTransport(lambda request: httpx.Response(404, content=b"nope"))

        response = make_fetcher(transport).get(DISCOVERY)

        assert response.status_code == 404
        assert response.content == b"nope"


class TestRequestArguments:
    @pytest.mark.parametrize("header", ["Host", "accept-encoding", "Content-Length", "Connection"])
    def test_reserved_headers_are_refused(self, header: str) -> None:
        fetcher = make_fetcher(RecordingTransport(lambda request: json_response()))

        with pytest.raises(ValueError, match="sets these headers"):
            fetcher.request("GET", DISCOVERY, headers={header: "x"})

    def test_only_get_and_post_are_allowed(self) -> None:
        fetcher = make_fetcher(RecordingTransport(lambda request: json_response()))

        with pytest.raises(ValueError, match="not allowed"):
            fetcher.request("DELETE", DISCOVERY)  # type: ignore[arg-type]

    def test_post_sends_the_body(self) -> None:
        transport = RecordingTransport(lambda request: json_response())

        make_fetcher(transport).request(
            "POST",
            DISCOVERY,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=b"grant_type=client_credentials",
        )

        (request,) = transport.requests
        assert request.method == "POST"
        assert request.content == b"grant_type=client_credentials"
