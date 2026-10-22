import ipaddress

import pytest

from sso_auditor_core.fetch import AddressClass, classify

PUBLIC = AddressClass.PUBLIC
LOOPBACK = AddressClass.LOOPBACK
PRIVATE = AddressClass.PRIVATE
BLOCKED = AddressClass.BLOCKED


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        # Public unicast, including embedded forms of public addresses.
        ("8.8.8.8", PUBLIC),
        ("1.1.1.1", PUBLIC),
        ("93.184.215.14", PUBLIC),
        ("172.32.0.1", PUBLIC),  # just outside 172.16.0.0/12
        ("100.128.0.1", PUBLIC),  # just outside 100.64.0.0/10
        ("2606:4700:4700::1111", PUBLIC),
        ("2001:4860:4860::8888", PUBLIC),
        ("::ffff:8.8.8.8", PUBLIC),
        ("64:ff9b::808:808", PUBLIC),  # NAT64 form of 8.8.8.8
        ("2002:808:808::1", PUBLIC),  # 6to4 form of 8.8.8.8
        # Loopback.
        ("127.0.0.1", LOOPBACK),
        ("127.255.255.254", LOOPBACK),
        ("::1", LOOPBACK),
        ("::ffff:127.0.0.1", LOOPBACK),
        # Private, shared and unique-local.
        ("10.0.0.1", PRIVATE),
        ("172.16.0.1", PRIVATE),
        ("172.31.255.255", PRIVATE),
        ("192.168.1.1", PRIVATE),
        ("100.64.0.1", PRIVATE),
        ("fc00::1", PRIVATE),
        ("fd12:3456::1", PRIVATE),
        ("fdaa::3", PRIVATE),  # Fly.io private network
        ("fd20:ce::1", PRIVATE),  # next to GCP's metadata address, but not it
        ("::ffff:10.0.0.1", PRIVATE),
        # Never allowed.
        ("0.0.0.0", BLOCKED),
        ("0.1.2.3", BLOCKED),
        ("169.254.169.254", BLOCKED),  # AWS, GCP, Azure metadata
        ("169.254.170.2", BLOCKED),  # AWS ECS task metadata
        ("100.100.100.200", BLOCKED),  # Alibaba Cloud metadata, inside 100.64.0.0/10
        ("192.0.0.192", BLOCKED),  # Oracle Cloud metadata, inside 192.0.0.0/24
        ("192.0.0.1", BLOCKED),
        ("192.0.2.1", BLOCKED),
        ("192.88.99.1", BLOCKED),
        ("198.18.0.1", BLOCKED),
        ("198.19.255.255", BLOCKED),
        ("198.51.100.1", BLOCKED),
        ("203.0.113.1", BLOCKED),
        ("224.0.0.1", BLOCKED),
        ("239.255.255.250", BLOCKED),
        ("240.0.0.1", BLOCKED),
        ("255.255.255.255", BLOCKED),
        ("::", BLOCKED),
        ("::7f00:1", BLOCKED),  # IPv4-compatible form of 127.0.0.1
        ("::8.8.8.8", BLOCKED),  # IPv4-compatible forms are blocked even when public
        ("fd00:ec2::254", BLOCKED),  # AWS metadata, inside fc00::/7
        ("fd00:ec2::23", BLOCKED),  # AWS EKS Pod Identity
        ("fd00:ec2::253", BLOCKED),  # AWS DNS resolver
        ("fd00:ec2::123", BLOCKED),  # AWS time sync
        ("fd20:ce::254", BLOCKED),  # GCP metadata
        ("fd00:c1::a9fe:a9fe", BLOCKED),  # OCI metadata
        ("fe80::1", BLOCKED),
        ("fec0::1", BLOCKED),
        ("ff02::1", BLOCKED),
        ("2001:db8::1", BLOCKED),
        ("2001::1", BLOCKED),  # Teredo
        ("3fff::1", BLOCKED),
        ("100::1", BLOCKED),
        ("5f00::1", BLOCKED),
        ("64:ff9b:1::1", BLOCKED),
        ("64:ff9b::7f00:1", BLOCKED),  # NAT64 form of 127.0.0.1
        ("64:ff9b::a9fe:a9fe", BLOCKED),  # NAT64 form of 169.254.169.254
        ("64:ff9b::a00:1", BLOCKED),  # NAT64 form of 10.0.0.1
        ("2002:7f00:1::", BLOCKED),  # 6to4 form of 127.0.0.1
        ("2002:a9fe:a9fe::", BLOCKED),  # 6to4 form of 169.254.169.254
        ("::ffff:169.254.169.254", BLOCKED),
        ("::ffff:a9fe:a9fe", BLOCKED),
        ("::ffff:0.0.0.0", BLOCKED),
        ("fe80::1%eth0", BLOCKED),
    ],
)
def test_classify(address: str, expected: AddressClass) -> None:
    verdict = classify(ipaddress.ip_address(address))

    assert verdict.kind is expected, verdict.reason
    assert verdict.reason


def test_mapped_address_reason_names_the_embedded_range() -> None:
    verdict = classify(ipaddress.ip_address("::ffff:169.254.169.254"))

    assert "IPv4-mapped" in verdict.reason
    assert "link-local" in verdict.reason
