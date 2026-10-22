"""SystemResolver with getaddrinfo() replaced: no DNS traffic."""

import ipaddress
import socket
import threading
import time
from collections.abc import Callable
from typing import Any

import pytest

from sso_auditor_core.fetch import FetchTimeout, ResolutionFailed, resolver
from sso_auditor_core.fetch.addresses import AddressClass, classify
from sso_auditor_core.fetch.resolver import SystemResolver

type GetAddrInfo = Callable[..., list[tuple[Any, ...]]]


def v4(address: str) -> tuple[Any, ...]:
    return (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443))


def v6(address: str, scope_id: int = 0) -> tuple[Any, ...]:
    sockaddr = (address, 443, 0, scope_id)
    return (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)


@pytest.fixture
def slots(monkeypatch: pytest.MonkeyPatch) -> threading.BoundedSemaphore:
    """A private set of two lookup slots, so tests can fill them."""
    semaphore = threading.BoundedSemaphore(2)
    monkeypatch.setattr(resolver, "_SLOTS", semaphore)
    return semaphore


def use(monkeypatch: pytest.MonkeyPatch, getaddrinfo: GetAddrInfo) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


def wait_for_free_slots(slots: threading.BoundedSemaphore, count: int) -> None:
    """Block until every slot is back, proving each lookup thread released its own."""
    for _ in range(count):
        assert slots.acquire(timeout=5)
    for _ in range(count):
        slots.release()


def test_keeps_the_resolver_order_and_drops_duplicates(
    monkeypatch: pytest.MonkeyPatch, slots: threading.BoundedSemaphore
) -> None:
    answer = [v6("2606:4700::1"), v4("93.184.215.14"), v4("93.184.215.14"), v6("2606:4700::1")]
    use(monkeypatch, lambda *args, **kwargs: answer)

    addresses = SystemResolver().resolve("id.example.com", 443, timeout=1.0)

    assert addresses == [
        ipaddress.IPv6Address("2606:4700::1"),
        ipaddress.IPv4Address("93.184.215.14"),
    ]
    wait_for_free_slots(slots, 2)


@pytest.mark.parametrize("answer", [v6("fe80::1%eth0", 2), v6("fe80::1", 2)])
def test_a_link_local_answer_is_blocked_with_or_without_its_zone(
    monkeypatch: pytest.MonkeyPatch, slots: threading.BoundedSemaphore, answer: tuple[Any, ...]
) -> None:
    use(monkeypatch, lambda *args, **kwargs: [answer])

    (address,) = SystemResolver().resolve("id.example.com", 443, timeout=1.0)

    assert classify(address).kind is AddressClass.BLOCKED


@pytest.mark.parametrize(
    "error", [socket.gaierror(socket.EAI_NONAME, "unknown"), UnicodeError("label too long")]
)
def test_lookup_errors_are_resolution_failures(
    monkeypatch: pytest.MonkeyPatch, slots: threading.BoundedSemaphore, error: Exception
) -> None:
    def getaddrinfo(*args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        raise error

    use(monkeypatch, getaddrinfo)

    with pytest.raises(ResolutionFailed, match="could not resolve"):
        SystemResolver().resolve("id.example.com", 443, timeout=1.0)
    wait_for_free_slots(slots, 2)


def test_an_empty_answer_is_a_resolution_failure(
    monkeypatch: pytest.MonkeyPatch, slots: threading.BoundedSemaphore
) -> None:
    use(monkeypatch, lambda *args, **kwargs: [])

    with pytest.raises(ResolutionFailed, match="no addresses"):
        SystemResolver().resolve("id.example.com", 443, timeout=1.0)


def test_a_lookup_that_never_returns_times_out_and_later_frees_its_slot(
    monkeypatch: pytest.MonkeyPatch, slots: threading.BoundedSemaphore
) -> None:
    answer_now = threading.Event()

    def getaddrinfo(*args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        answer_now.wait(timeout=5)
        return [v4("93.184.215.14")]

    use(monkeypatch, getaddrinfo)

    start = time.monotonic()
    with pytest.raises(FetchTimeout, match="timed out"):
        SystemResolver().resolve("id.example.com", 443, timeout=0.2)
    assert time.monotonic() - start < 1.0

    answer_now.set()
    wait_for_free_slots(slots, 2)


def test_new_lookups_fail_at_once_while_every_slot_is_held(
    monkeypatch: pytest.MonkeyPatch, slots: threading.BoundedSemaphore
) -> None:
    answer_now = threading.Event()

    def getaddrinfo(host: str, *args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        if host != "fast.example.com":
            answer_now.wait(timeout=5)
        return [v4("93.184.215.14")]

    use(monkeypatch, getaddrinfo)
    for host in ("slow1.example.com", "slow2.example.com"):
        with pytest.raises(FetchTimeout):
            SystemResolver().resolve(host, 443, timeout=0.05)

    with pytest.raises(ResolutionFailed, match="too many DNS lookups"):
        SystemResolver().resolve("fast.example.com", 443, timeout=1.0)

    answer_now.set()
    wait_for_free_slots(slots, 2)
    assert SystemResolver().resolve("fast.example.com", 443, timeout=1.0)


def test_a_thread_that_cannot_start_gives_its_slot_back(
    monkeypatch: pytest.MonkeyPatch, slots: threading.BoundedSemaphore
) -> None:
    def start(self: threading.Thread) -> None:
        raise RuntimeError("can't start new thread")

    use(monkeypatch, lambda *args, **kwargs: [v4("93.184.215.14")])
    monkeypatch.setattr(threading.Thread, "start", start)

    for _ in range(3):  # more attempts than there are slots
        with pytest.raises(ResolutionFailed, match="can't start new thread"):
            SystemResolver().resolve("id.example.com", 443, timeout=1.0)

    wait_for_free_slots(slots, 2)
