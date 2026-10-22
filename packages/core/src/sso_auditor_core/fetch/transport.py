"""The connection layer: httpx's transport over an httpcore pool that enforces the fetch's
total deadline on every socket operation.

httpcore's timeouts apply to one socket read or write at a time. A server that sends a
byte inside each timeout (headers one byte at a time, an endless run of ``100 Continue``
responses, slow chunk framing or trailers) would otherwise keep a fetch open for as long
as it liked, because the fetcher only regains control between body chunks. Here every
connect, TLS handshake, read and send is capped by the time left, and fails once none is.
"""

import socket
import ssl
from collections.abc import Callable, Iterable
from typing import Any

import httpcore
import httpx

type Remaining = Callable[[], float]
"""Seconds left before the fetch's deadline. Zero or less means the deadline has passed."""


def deadline_transport(ssl_context: ssl.SSLContext, remaining: Remaining) -> httpx.BaseTransport:
    """The production transport: one connection, never kept alive, capped by ``remaining``.

    A pooled connection to an IP must not be reused for another hostname, whose SNI and
    certificate were never checked on it, so keep-alive is off.
    """
    transport = httpx.HTTPTransport(
        verify=ssl_context, trust_env=False, http1=True, http2=False, retries=0
    )
    # httpx 0.28 has no parameter for httpcore's network backend, so swap the pool it built
    # for one that uses the deadline backend. test_fetch_tls.py fails if this stops working.
    transport._pool = httpcore.ConnectionPool(
        ssl_context=ssl_context,
        max_connections=1,
        max_keepalive_connections=0,
        http1=True,
        http2=False,
        retries=0,
        network_backend=_DeadlineBackend(remaining),
    )
    return transport


def _capped[E: httpcore.TimeoutException](
    timeout: float | None, remaining: Remaining, error: type[E]
) -> float:
    left = remaining()
    if left <= 0:
        raise error("the fetch's total deadline has passed")
    return left if timeout is None else min(timeout, left)


class _DeadlineStream(httpcore.NetworkStream):
    def __init__(self, stream: httpcore.NetworkStream, remaining: Remaining) -> None:
        self._stream = stream
        self._remaining = remaining

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        capped = _capped(timeout, self._remaining, httpcore.ReadTimeout)
        return self._stream.read(max_bytes, capped)

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        # httpcore's own write loops over partial sends and gives each one the full
        # timeout, so a server that reads slowly could stretch one large write far past
        # the deadline. Send here instead, capping the timeout again before every send.
        sock: socket.socket | None = self._stream.get_extra_info("socket")
        if sock is None:
            self._stream.write(buffer, _capped(timeout, self._remaining, httpcore.WriteTimeout))
            return
        view = memoryview(buffer)
        while view:
            capped = _capped(timeout, self._remaining, httpcore.WriteTimeout)
            try:
                sock.settimeout(capped)
                sent = sock.send(view)
            except TimeoutError as exc:
                raise httpcore.WriteTimeout(str(exc)) from exc
            except OSError as exc:  # including ssl.SSLError
                raise httpcore.WriteError(str(exc)) from exc
            view = view[sent:]

    def close(self) -> None:
        self._stream.close()

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.NetworkStream:
        capped = _capped(timeout, self._remaining, httpcore.ConnectTimeout)
        stream = self._stream.start_tls(ssl_context, server_hostname, capped)
        return _DeadlineStream(stream, self._remaining)

    def get_extra_info(self, info: str) -> Any:
        return self._stream.get_extra_info(info)


class _DeadlineBackend(httpcore.NetworkBackend):
    def __init__(self, remaining: Remaining) -> None:
        self._backend = httpcore.SyncBackend()
        self._remaining = remaining

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.NetworkStream:
        capped = _capped(timeout, self._remaining, httpcore.ConnectTimeout)
        stream = self._backend.connect_tcp(host, port, capped, local_address, socket_options)
        return _DeadlineStream(stream, self._remaining)

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.NetworkStream:
        raise httpcore.ConnectError("the fetcher never connects to Unix sockets")

    def sleep(self, seconds: float) -> None:
        self._backend.sleep(seconds)
