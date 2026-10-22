"""Classify IP addresses for the fetcher's network policy (ADR-0002).

The ranges are listed explicitly instead of relying only on ``ipaddress``'s
``is_global``/``is_private`` flags, whose tables have changed between Python patch
releases. ``is_global`` is still checked last as a second net.
"""

import enum
import ipaddress
from dataclasses import dataclass

type IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class AddressClass(enum.Enum):
    """How the network policy treats an address."""

    PUBLIC = "public"
    """Globally routable unicast. Allowed by every profile."""

    LOOPBACK = "loopback"
    """``127.0.0.0/8`` and ``::1``. Allowed only by the ``cli`` profile's flags."""

    PRIVATE = "private"
    """RFC 1918, shared address space and unique-local. Allowed only with
    ``--allow-private-network``."""

    BLOCKED = "blocked"
    """Everything else: never allowed, whatever the policy."""


@dataclass(frozen=True)
class Classification:
    """The verdict for one address, with a reason fit for an error message."""

    address: IPAddress
    kind: AddressClass
    reason: str


def _networks(
    entries: list[tuple[str, str]],
) -> list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]]:
    return [(ipaddress.ip_network(cidr), reason) for cidr, reason in entries]


# Never allowed. Checked before the private ranges, so the metadata addresses inside the
# private ranges stay blocked even with --allow-private-network.
_V4_BLOCKED = _networks(
    [
        ("0.0.0.0/8", "'this network' (RFC 791)"),
        ("169.254.0.0/16", "link-local, where cloud metadata services live (RFC 3927)"),
        ("100.100.100.200/32", "cloud metadata service (Alibaba Cloud)"),
        ("192.0.0.0/24", "IETF protocol assignments (RFC 6890)"),
        ("192.0.2.0/24", "documentation (RFC 5737)"),
        ("192.88.99.0/24", "6to4 relay anycast (RFC 7526)"),
        ("198.18.0.0/15", "benchmarking (RFC 2544)"),
        ("198.51.100.0/24", "documentation (RFC 5737)"),
        ("203.0.113.0/24", "documentation (RFC 5737)"),
        ("224.0.0.0/4", "multicast (RFC 5771)"),
        ("240.0.0.0/4", "reserved, including broadcast (RFC 1112)"),
    ]
)
_V4_LOOPBACK = ipaddress.ip_network("127.0.0.0/8")
_V4_PRIVATE = _networks(
    [
        ("10.0.0.0/8", "private (RFC 1918)"),
        ("172.16.0.0/12", "private (RFC 1918)"),
        ("192.168.0.0/16", "private (RFC 1918)"),
        ("100.64.0.0/10", "shared address space, carrier-grade NAT (RFC 6598)"),
    ]
)

_V6_LOOPBACK = ipaddress.ip_address("::1")
_V6_MAPPED = ipaddress.ip_network("::ffff:0:0/96")
_V6_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_V6_6TO4 = ipaddress.ip_network("2002::/16")
_V6_BLOCKED = _networks(
    [
        ("::/128", "unspecified address (RFC 4291)"),
        ("::/96", "IPv4-compatible address, deprecated (RFC 4291)"),
        # Cloud services that answer inside unique-local space. They must stay blocked
        # when --allow-private-network allows the rest of fc00::/7.
        ("fd00:ec2::/32", "AWS instance-local services: metadata, DNS, NTP, EKS Pod Identity"),
        ("fd20:ce::254/128", "cloud metadata service (GCP)"),
        ("fd00:c1::a9fe:a9fe/128", "cloud metadata service (OCI)"),
        ("64:ff9b:1::/48", "local-use NAT64 (RFC 8215)"),
        ("100::/64", "discard-only (RFC 6666)"),
        ("2001::/23", "IETF protocol assignments, including Teredo (RFC 2928)"),
        ("2001:db8::/32", "documentation (RFC 3849)"),
        ("3fff::/20", "documentation (RFC 9637)"),
        ("5f00::/16", "SRv6 segment identifiers (RFC 9602)"),
        ("fe80::/10", "link-local (RFC 4291)"),
        ("fec0::/10", "site-local, deprecated (RFC 3879)"),
        ("ff00::/8", "multicast (RFC 4291)"),
    ]
)
_V6_PRIVATE = ipaddress.ip_network("fc00::/7")
_V6_GLOBAL_UNICAST = ipaddress.ip_network("2000::/3")


def classify(address: IPAddress) -> Classification:
    """Return how the network policy treats ``address``."""
    if isinstance(address, ipaddress.IPv4Address):
        return _classify_v4(address)
    return _classify_v6(address)


def _classify_v4(address: ipaddress.IPv4Address) -> Classification:
    for network, reason in _V4_BLOCKED:
        if address in network:
            return Classification(address, AddressClass.BLOCKED, reason)
    if address in _V4_LOOPBACK:
        return Classification(address, AddressClass.LOOPBACK, "loopback (RFC 1122)")
    for network, reason in _V4_PRIVATE:
        if address in network:
            return Classification(address, AddressClass.PRIVATE, reason)
    if not address.is_global:
        return Classification(address, AddressClass.BLOCKED, "not globally routable")
    return Classification(address, AddressClass.PUBLIC, "public unicast")


def _classify_v6(address: ipaddress.IPv6Address) -> Classification:
    if address.scope_id is not None:
        return Classification(address, AddressClass.BLOCKED, "scoped (zone) address")

    # An IPv4-mapped address reaches the IPv4 address on a dual-stack host, so it is
    # exactly as allowed as that address.
    if address in _V6_MAPPED and address.ipv4_mapped is not None:
        embedded = _classify_v4(address.ipv4_mapped)
        return Classification(address, embedded.kind, f"IPv4-mapped {embedded.reason}")

    # NAT64 and 6to4 addresses are routed to a translator or relay, not to the embedded
    # IPv4 address on this host. Allow them only when the embedded address is public.
    embedded_v4 = _embedded_v4(address)
    if embedded_v4 is not None:
        form, inner = embedded_v4
        verdict = _classify_v4(inner)
        if verdict.kind is AddressClass.PUBLIC:
            return Classification(address, AddressClass.PUBLIC, f"{form} of a public address")
        return Classification(address, AddressClass.BLOCKED, f"{form} of {verdict.reason}")

    if address == _V6_LOOPBACK:
        return Classification(address, AddressClass.LOOPBACK, "loopback (RFC 4291)")
    for network, reason in _V6_BLOCKED:
        if address in network:
            return Classification(address, AddressClass.BLOCKED, reason)
    if address in _V6_PRIVATE:
        return Classification(address, AddressClass.PRIVATE, "unique local (RFC 4193)")
    if address not in _V6_GLOBAL_UNICAST or not address.is_global:
        return Classification(address, AddressClass.BLOCKED, "not globally routable")
    return Classification(address, AddressClass.PUBLIC, "public unicast")


def _embedded_v4(address: ipaddress.IPv6Address) -> tuple[str, ipaddress.IPv4Address] | None:
    if address in _V6_NAT64:
        return "NAT64 form", ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    if address in _V6_6TO4 and address.sixtofour is not None:
        return "6to4 form", address.sixtofour
    return None
