"""DNS resolution for the safe fetcher.

The fetcher resolves each hostname once per hop, validates every address in the answer,
and connects to one of those addresses. It never lets the HTTP client resolve the name
again, which is what defeats DNS rebinding.
"""

import ipaddress
import socket
import threading
from typing import Any, Protocol

from sso_auditor_core.fetch.addresses import IPAddress
from sso_auditor_core.fetch.errors import FetchTimeout, ResolutionFailed


class Resolver(Protocol):
    """Turns a hostname into the addresses to validate and connect to."""

    def resolve(self, host: str, port: int, timeout: float) -> list[IPAddress]:
        """Return every address for ``host``, in the order to try them.

        Raises :class:`ResolutionFailed` or :class:`FetchTimeout`.
        """
        ...


# getaddrinfo() can't be cancelled. Each lookup runs on its own daemon thread and the
# caller stops waiting at its deadline, but the thread lives until the system resolver
# gives up. A slot is held for exactly that long. When every slot is taken, new lookups
# fail at once instead of queueing behind lookups a hostile zone never answers, so a few
# slow names can't make every other lookup time out. Per-client limits on the hosted
# demo (#20) keep one requester from taking all the slots.
MAX_CONCURRENT_LOOKUPS = 64
_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_LOOKUPS)


class SystemResolver:
    """Resolves with the operating system's resolver (``getaddrinfo``)."""

    def resolve(self, host: str, port: int, timeout: float) -> list[IPAddress]:
        if not _SLOTS.acquire(blocking=False):
            raise ResolutionFailed(
                f"could not resolve {host}: too many DNS lookups are in progress"
            )
        lookup = _Lookup(host, port)
        try:
            threading.Thread(target=lookup.run, name="sso-auditor-dns", daemon=True).start()
        except BaseException as exc:
            # The thread never ran, so it can't release the slot it was given.
            _SLOTS.release()
            if isinstance(exc, RuntimeError):  # "can't start new thread"
                raise ResolutionFailed(f"could not resolve {host}: {exc}") from exc
            raise
        if not lookup.done.wait(timeout):
            raise FetchTimeout(f"DNS lookup for {host} timed out")
        if lookup.error is not None:
            if isinstance(lookup.error, OSError | UnicodeError):
                raise ResolutionFailed(f"could not resolve {host}: {lookup.error}")
            raise lookup.error

        addresses: list[IPAddress] = []
        for _family, _type, _proto, _canonname, sockaddr in lookup.infos:
            # A link-local IPv6 answer may carry its zone as "%eth0" in the string or only
            # as the scope id in sockaddr[3]. Either way it classifies as link-local, which
            # is blocked.
            address = ipaddress.ip_address(sockaddr[0])
            if address not in addresses:
                addresses.append(address)
        if not addresses:
            raise ResolutionFailed(f"{host} has no addresses")
        return addresses


class _Lookup:
    """One getaddrinfo() call on a worker thread. Releases its slot when it returns."""

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.done = threading.Event()
        self.infos: list[tuple[Any, ...]] = []
        self.error: BaseException | None = None

    def run(self) -> None:
        try:
            self.infos = socket.getaddrinfo(
                self.host, self.port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
            )
        except BaseException as exc:  # handed to the waiting caller, if it still waits
            self.error = exc
        finally:
            _SLOTS.release()
            self.done.set()
