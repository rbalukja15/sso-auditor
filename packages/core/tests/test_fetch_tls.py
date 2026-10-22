"""SafeFetcher against a real HTTPS server on 127.0.0.1, with certificates from trustme.

These tests cover what the mock transport can't: that the fetcher really connects to the
validated IP while sending SNI and checking the certificate for the hostname, that a bad
certificate fails, that timeouts fire on a real socket, and that proxies set in the
environment are ignored. A few use plain sockets, for servers that never get as far as
speaking HTTP or TLS properly.
"""

import dataclasses
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
import trustme
from fetch_doubles import FakeResolver

from sso_auditor_core.fetch import (
    AddressRejected,
    FetchPolicy,
    FetchTimeout,
    SafeFetcher,
    TLSFailed,
    create_ssl_context,
)

HOST = "id.example.com"

type Responder = Callable[["_Handler"], None]


class _Server(ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True

    def __init__(self, respond: Responder) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.respond = respond
        self.requests: list[tuple[str, dict[str, str]]] = []
        self.sni_names: list[str | None] = []
        # Set at teardown so slow handlers stop waiting and the server can shut down.
        self.release = threading.Event()

    @property
    def port(self) -> int:
        return int(self.server_address[1])

    def handle_error(self, request: Any, client_address: Any) -> None:
        # The client hanging up on a slow handler is expected; keep test output clean.
        pass


class _Handler(BaseHTTPRequestHandler):
    server: _Server
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self.server.requests.append((self.path, dict(self.headers.items())))
        self.server.respond(self)

    def log_message(self, format: str, *args: Any) -> None:
        pass


def send_json(handler: _Handler, body: bytes = b'{"issuer": "https://id.example.com"}') -> None:
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def stall(handler: _Handler) -> None:
    handler.server.release.wait(timeout=10)


def drip(handler: _Handler) -> None:
    """Send the body one byte at a time, each byte well inside the read timeout."""
    handler.send_response(200)
    handler.send_header("Content-Length", "1000")
    handler.end_headers()
    for _ in range(1000):
        if handler.server.release.wait(timeout=0.05):
            return
        handler.wfile.write(b" ")


def drip_bytes(handler: _Handler, head: bytes, unit: bytes) -> None:
    """Send ``head``, then ``unit`` every 50 ms: each read gets data well inside the read
    timeout, so only a deadline on every socket read can end the fetch."""
    handler.wfile.write(head)
    for _ in range(200):
        if handler.server.release.wait(timeout=0.05):
            return
        handler.wfile.write(unit)


def drip_headers(handler: _Handler) -> None:
    drip_bytes(handler, b"HTTP/1.1 200 OK\r\nX-Drip: ", b"a")


def flood_continues(handler: _Handler) -> None:
    drip_bytes(handler, b"", b"HTTP/1.1 100 Continue\r\n\r\n")


def drip_trailers(handler: _Handler) -> None:
    head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n \r\n0\r\nX-Trailer: "
    drip_bytes(handler, head, b"a")


@pytest.fixture(scope="module")
def ca() -> trustme.CA:
    return trustme.CA()


@pytest.fixture
def ca_bundle(ca: trustme.CA, tmp_path: Path) -> Path:
    path = tmp_path / "ca.pem"
    ca.cert_pem.write_to_path(str(path))
    return path


@contextmanager
def https_server(
    ca: trustme.CA, cert_for: str, respond: Responder = send_json
) -> Iterator[_Server]:
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ca.issue_cert(cert_for).configure_cert(context)
    server = _Server(respond)
    context.sni_callback = lambda sock, name, ctx: server.sni_names.append(name)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        yield server
    finally:
        server.release.set()
        server.shutdown()
        thread.join()
        server.server_close()


def local_fetcher(server: _Server, ca_bundle: Path | None, **limits: Any) -> SafeFetcher:
    """A cli fetcher that may reach the local server, resolving HOST to 127.0.0.1."""
    policy = FetchPolicy.cli(
        allow_private_network=True, extra_ports=[server.port], ca_bundle=ca_bundle
    )
    return SafeFetcher(
        dataclasses.replace(policy, **limits),
        resolver=FakeResolver({HOST: ["127.0.0.1"]}),
    )


def test_connects_to_the_validated_ip_with_sni_and_the_hostname_certificate(
    ca: trustme.CA, ca_bundle: Path
) -> None:
    with https_server(ca, HOST) as server:
        response, document = local_fetcher(server, ca_bundle).get_json(
            f"https://{HOST}:{server.port}/realms/demo/.well-known/openid-configuration"
        )

    assert document == {"issuer": "https://id.example.com"}
    assert response.remote_address == "127.0.0.1"
    assert server.sni_names == [HOST]
    ((path, headers),) = server.requests
    assert path == "/realms/demo/.well-known/openid-configuration"
    assert headers["Host"] == f"{HOST}:{server.port}"
    assert headers["Connection"] == "close"


def test_an_ip_literal_is_checked_against_the_certificate_ip_address(
    ca: trustme.CA, ca_bundle: Path
) -> None:
    with https_server(ca, "127.0.0.1") as server:
        response = local_fetcher(server, ca_bundle).get(f"https://127.0.0.1:{server.port}/")

    assert response.status_code == 200
    assert server.sni_names == [None]


@pytest.mark.parametrize("cert_for", ["127.0.0.2", HOST])
def test_an_ip_literal_with_a_certificate_for_something_else_fails(
    ca: trustme.CA, ca_bundle: Path, cert_for: str
) -> None:
    with https_server(ca, cert_for) as server:
        fetcher = local_fetcher(server, ca_bundle)
        with pytest.raises(TLSFailed, match="mismatch"):
            fetcher.get(f"https://127.0.0.1:{server.port}/")

    assert server.requests == []


def test_a_certificate_for_another_hostname_fails(ca: trustme.CA, ca_bundle: Path) -> None:
    with https_server(ca, "other.example.com") as server:
        fetcher = local_fetcher(server, ca_bundle)
        with pytest.raises(TLSFailed, match="certificate"):
            fetcher.get(f"https://{HOST}:{server.port}/")

    assert server.requests == []


def test_a_certificate_from_an_untrusted_ca_fails(ca: trustme.CA) -> None:
    with https_server(ca, HOST) as server:
        fetcher = local_fetcher(server, ca_bundle=None)
        with pytest.raises(TLSFailed):
            fetcher.get(f"https://{HOST}:{server.port}/")

    assert server.requests == []


def test_a_server_slower_than_the_read_timeout_times_out(ca: trustme.CA, ca_bundle: Path) -> None:
    with https_server(ca, HOST, respond=stall) as server:
        fetcher = local_fetcher(server, ca_bundle, read_timeout=0.2)
        with pytest.raises(FetchTimeout):
            fetcher.get(f"https://{HOST}:{server.port}/")


def test_a_body_dripped_slower_than_the_total_timeout_times_out(
    ca: trustme.CA, ca_bundle: Path
) -> None:
    with https_server(ca, HOST, respond=drip) as server:
        fetcher = local_fetcher(server, ca_bundle, total_timeout=0.5)
        with pytest.raises(FetchTimeout, match=r"longer than 0\.5s"):
            fetcher.get(f"https://{HOST}:{server.port}/")


@pytest.mark.parametrize("respond", [drip_headers, flood_continues, drip_trailers])
def test_a_response_dripped_outside_the_body_stops_at_the_total_timeout(
    ca: trustme.CA, ca_bundle: Path, respond: Responder
) -> None:
    with https_server(ca, HOST, respond=respond) as server:
        fetcher = local_fetcher(server, ca_bundle, total_timeout=0.5)
        start = time.monotonic()
        with pytest.raises(FetchTimeout):
            fetcher.get(f"https://{HOST}:{server.port}/")
        elapsed = time.monotonic() - start

    assert elapsed < 1.5


def test_a_server_that_never_answers_the_tls_handshake_times_out() -> None:
    # The kernel completes the TCP handshake from the listen backlog; nothing ever
    # reads the ClientHello.
    with socket.create_server(("127.0.0.1", 0)) as silent:
        port = silent.getsockname()[1]
        policy = FetchPolicy.cli(allow_private_network=True, extra_ports=[port])
        fetcher = SafeFetcher(
            dataclasses.replace(policy, total_timeout=0.5),
            resolver=FakeResolver({HOST: ["127.0.0.1"]}),
        )
        start = time.monotonic()
        with pytest.raises(FetchTimeout):
            fetcher.get(f"https://{HOST}:{port}/")

    assert time.monotonic() - start < 1.5


@contextmanager
def slow_reader() -> Iterator[int]:
    """A plain TCP server with a tiny receive window that empties it every 100 ms.

    Each send the client makes waits less than its timeout, but the body as a whole
    trickles in slowly.
    """
    stop = threading.Event()
    listener = socket.socket()
    # Before listen(), so the small buffer sets the window advertised in the handshake.
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)

    def serve() -> None:
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        with conn:
            conn.setblocking(False)
            while not stop.wait(0.1):
                try:
                    while conn.recv(1 << 20):
                        pass
                    return
                except BlockingIOError:
                    continue
                except OSError:
                    return

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        yield int(listener.getsockname()[1])
    finally:
        stop.set()
        thread.join()
        listener.close()


def test_a_slow_reader_cannot_stretch_a_request_body_past_the_total_timeout() -> None:
    # Without a deadline on every send, this body takes over three seconds to get through.
    with slow_reader() as port:
        policy = FetchPolicy.cli(allow_http=True, extra_ports=[port])
        fetcher = SafeFetcher(dataclasses.replace(policy, total_timeout=0.5))
        start = time.monotonic()
        with pytest.raises(FetchTimeout):
            fetcher.request("POST", f"http://127.0.0.1:{port}/token", body=b"x" * (32 << 20))
        elapsed = time.monotonic() - start

    assert elapsed < 1.5


def test_the_tls_context_is_strict_and_ignores_sslkeylogfile(
    ca: trustme.CA, ca_bundle: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    keylog = tmp_path / "keys.log"
    with https_server(ca, HOST) as server:
        # Set after the test server's own context exists, which does honour it.
        monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
        context = create_ssl_context()
        local_fetcher(server, ca_bundle).get(f"https://{HOST}:{server.port}/")

    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname
    assert context.minimum_version is ssl.TLSVersion.TLSv1_2
    assert not context.keylog_filename
    assert not keylog.exists()


def test_proxies_from_the_environment_are_ignored(
    ca: trustme.CA, ca_bundle: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Port 9 is the discard port: if the fetcher used this proxy, the request would fail.
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)

    with https_server(ca, HOST) as server:
        response = local_fetcher(server, ca_bundle).get(f"https://{HOST}:{server.port}/")

    assert response.status_code == 200
    assert len(server.requests) == 1


def test_the_hosted_profile_never_connects_to_a_local_server(ca: trustme.CA) -> None:
    with https_server(ca, HOST) as server:
        fetcher = SafeFetcher(FetchPolicy.hosted(), resolver=FakeResolver({HOST: ["127.0.0.1"]}))
        with pytest.raises(AddressRejected):
            fetcher.get(f"https://{HOST}/")

    assert server.requests == []
    assert server.sni_names == []
