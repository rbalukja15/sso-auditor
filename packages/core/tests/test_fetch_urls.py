import ipaddress

import pytest

from sso_auditor_core.fetch import URLRejected, parse_url
from sso_auditor_core.fetch.urls import MAX_URL_LENGTH


def test_parses_a_discovery_url() -> None:
    target = parse_url("https://id.example.com/realms/demo/.well-known/openid-configuration")

    assert target.scheme == "https"
    assert target.host == "id.example.com"
    assert target.ip is None
    assert target.port == 443
    assert target.raw_path == b"/realms/demo/.well-known/openid-configuration"
    assert target.authority == "id.example.com"
    assert target.url == "https://id.example.com/realms/demo/.well-known/openid-configuration"


def test_normalises_case_trailing_dot_and_drops_the_fragment() -> None:
    target = parse_url("HTTPS://ID.Example.COM./x?a=1#section")

    assert target.host == "id.example.com"
    assert target.raw_path == b"/x?a=1"
    assert target.url == "https://id.example.com/x?a=1"


def test_encodes_internationalised_hostnames_with_idna() -> None:
    assert parse_url("https://bücher.example/").host == "xn--bcher-kva.example"


def test_keeps_a_non_default_port_in_the_authority() -> None:
    target = parse_url("https://sso.example.com:8443/realms/x")

    assert target.port == 8443
    assert target.authority == "sso.example.com:8443"


def test_parses_ip_literals() -> None:
    v4 = parse_url("https://8.8.8.8/")
    v6 = parse_url("https://[2606:4700::1]:8443/x")

    assert v4.ip == ipaddress.IPv4Address("8.8.8.8")
    assert v6.ip == ipaddress.IPv6Address("2606:4700::1")
    assert v6.authority == "[2606:4700::1]:8443"
    assert v6.url == "https://[2606:4700::1]:8443/x"


def test_folds_unicode_dots_before_classifying_the_host() -> None:
    # IDNA maps the ideographic full stop to "." (UTS #46), so this is the loopback literal.
    assert parse_url("https://127\u30020\u30020\u30021/").ip == ipaddress.IPv4Address("127.0.0.1")


def test_an_empty_path_becomes_slash() -> None:
    assert parse_url("https://id.example.com").raw_path == b"/"


@pytest.mark.parametrize(
    "url",
    [
        "ftp://id.example.com/",
        "file:///etc/passwd",
        "gopher://id.example.com/",
        "javascript:alert(1)",
        "//id.example.com/",
        "id.example.com",
        "https://user@id.example.com/",
        "https://user:secret@id.example.com/",
        "https://@id.example.com/",
        "https://id.example.com\\@evil.example/",
        "https://exa mple.com/",
        "https://id.example.com/\n",
        "https://id.example.com/\x00",
        " https://id.example.com/",
        "https://2130706433/",
        "https://0x7f.1/",
        "https://0x7f000001/",
        "https://0177.0.0.1/",
        "https://127.1/",
        "https://127.0.1/",
        "https://1.2.3.4./",
        "https://1.2.3.256/",
        "https://010.0.0.1/",
        "https://example.123/",
        "https://%31%32%37.0.0.1/",
        "https://[fe80::1%25eth0]/",
        "https://[fe80::1%\u00fc]/",  # a zone id httpx rejects with ValueError, not InvalidURL
        "https://[::1/",
        "https://a_b.example.com/",
        "https://-bad.example.com/",
        "https://bad-.example.com/",
        "https://" + "a" * 64 + ".example.com/",
        "https:///path",
        "https://id.example.com:0/",
        "https://id.example.com:99999/",
        "https://id.example.com/" + "a" * MAX_URL_LENGTH,
    ],
)
def test_rejects(url: str) -> None:
    with pytest.raises(URLRejected):
        parse_url(url)
