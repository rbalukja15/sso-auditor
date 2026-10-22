import dataclasses
import ipaddress
from pathlib import Path

import pytest

from sso_auditor_core.fetch import AddressRejected, FetchPolicy, URLRejected, parse_url

HOSTED = FetchPolicy.hosted()
CLI = FetchPolicy.cli()
CLI_PRIVATE = FetchPolicy.cli(allow_private_network=True, extra_ports=[8443])
CLI_HTTP = FetchPolicy.cli(allow_http=True, extra_ports=[8080])
CLI_HTTP_PRIVATE = FetchPolicy.cli(allow_http=True, allow_private_network=True, extra_ports=[8080])


def addresses(*values: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    return [ipaddress.ip_address(v) for v in values]


class TestProfiles:
    def test_hosted_is_strict(self) -> None:
        assert HOSTED.profile == "hosted"
        assert not HOSTED.allow_private_network
        assert not HOSTED.allow_http
        assert HOSTED.allowed_ports == {443}
        assert HOSTED.ca_bundle is None
        assert HOSTED.warnings == ()

    def test_cli_defaults_match_hosted(self) -> None:
        assert dataclasses.replace(CLI, profile="hosted") == HOSTED
        assert CLI.warnings == ()

    @pytest.mark.parametrize(
        "relaxation",
        [
            {"allow_private_network": True},
            {"allow_http": True},
            {"allowed_ports": frozenset({443, 8443})},
            {"ca_bundle": Path("ca.pem")},
            {"max_redirects": 10},
            {"total_timeout": 600.0},
            {"read_timeout": 60.0},
            {"max_body_bytes": 100 * 1024 * 1024},
            {"max_json_depth": 1000},
            {"max_json_nodes": 1_000_000},
            {"max_jwks_keys": 10_000},
            {"max_connect_attempts": 100},
        ],
    )
    def test_hosted_cannot_be_relaxed(self, relaxation: dict[str, object]) -> None:
        with pytest.raises(ValueError, match="hosted profile"):
            dataclasses.replace(HOSTED, **relaxation)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="hosted profile"):
            FetchPolicy(profile="hosted", **relaxation)  # type: ignore[arg-type]

    def test_a_mutable_port_set_is_copied_so_it_cannot_relax_the_policy_later(self) -> None:
        ports = {443}
        policy = FetchPolicy(profile="hosted", allowed_ports=ports)  # type: ignore[arg-type]
        ports.add(8443)

        assert policy.allowed_ports == frozenset({443})
        assert isinstance(policy.allowed_ports, frozenset)
        with pytest.raises(URLRejected):
            policy.check_target(parse_url("https://id.example.com:8443/"))

    def test_each_cli_relaxation_has_a_warning(self) -> None:
        private, http, port = (
            FetchPolicy.cli(allow_private_network=True).warnings,
            FetchPolicy.cli(allow_http=True).warnings,
            FetchPolicy.cli(extra_ports=[8443]).warnings,
        )

        assert len(private) == 1
        assert "--allow-private-network" in private[0]
        assert len(http) == 1
        assert "--allow-http" in http[0]
        assert len(port) == 1
        assert "8443" in port[0]
        assert len(FetchPolicy.cli(allow_private_network=True, allow_http=True).warnings) == 2

    @pytest.mark.parametrize(
        "bad",
        [
            {"allowed_ports": frozenset()},
            {"allowed_ports": frozenset({0})},
            {"allowed_ports": frozenset({70000})},
            {"total_timeout": 0.0},
            {"connect_timeout": -1.0},
            {"max_body_bytes": 0},
            {"max_redirects": -1},
            {"max_connect_attempts": 0},
            {"max_json_nodes": 0},
            {"total_timeout": float("nan")},
            {"total_timeout": float("inf")},
            {"read_timeout": float("nan")},
            {"connect_timeout": float("inf")},
        ],
    )
    def test_rejects_invalid_limits(self, bad: dict[str, object]) -> None:
        with pytest.raises(ValueError, match="must be"):
            FetchPolicy(profile="cli", **bad)  # type: ignore[arg-type]


class TestCheckTarget:
    @pytest.mark.parametrize(
        ("policy", "url"),
        [
            (HOSTED, "https://id.example.com/"),
            (CLI, "https://id.example.com/"),
            (CLI_PRIVATE, "https://sso.example.com:8443/"),
            (CLI_PRIVATE, "https://keycloak.internal/"),
            (CLI_PRIVATE, "https://keycloak.local/"),
            (CLI_PRIVATE, "https://router.home.arpa/"),
            (CLI_PRIVATE, "https://home.arpa/"),
            (CLI_PRIVATE, "https://keycloak/"),
            (CLI_PRIVATE, "https://localhost/"),
            (CLI_PRIVATE, "https://keycloak.flycast/"),
            (CLI_PRIVATE, "https://localhost.localdomain/"),
            (CLI_HTTP, "http://localhost:8080/"),
            (CLI_HTTP, "http://kc.localhost:8080/"),
            (CLI_HTTP, "http://127.0.0.1:8080/"),
        ],
    )
    def test_allows(self, policy: FetchPolicy, url: str) -> None:
        policy.check_target(parse_url(url))

    @pytest.mark.parametrize(
        ("policy", "url"),
        [
            (HOSTED, "http://id.example.com/"),
            (HOSTED, "https://id.example.com:8443/"),
            (HOSTED, "https://localhost/"),
            (HOSTED, "https://kc.localhost/"),
            (HOSTED, "https://keycloak.internal/"),
            (HOSTED, "https://printer.local/"),
            (HOSTED, "https://router.home.arpa/"),
            (HOSTED, "https://home.arpa/"),  # the zone's own name, not only its subdomains
            (HOSTED, "https://keycloak/"),
            (HOSTED, "https://metadata.google.internal/"),
            (HOSTED, "https://my-app.flycast/"),
            (HOSTED, "https://localhost.localdomain/"),
            (HOSTED, "https://localhost6.localdomain6/"),
            (CLI, "http://id.example.com/"),
            (CLI, "https://id.example.com:80/"),
            (CLI, "https://localhost/"),
            (CLI_PRIVATE, "https://metadata.google.internal/"),
            (CLI_PRIVATE, "https://metadata/"),
            (CLI_PRIVATE, "https://instance-data.ec2.internal/"),
            (CLI_PRIVATE, "http://localhost/"),  # http still needs --allow-http
            (CLI_HTTP, "https://localhost/"),  # --allow-http covers http only
            (CLI_HTTP, "http://keycloak.internal:8080/"),
            (CLI_HTTP, "http://localhost/"),  # port 80 not allowed
        ],
    )
    def test_rejects(self, policy: FetchPolicy, url: str) -> None:
        with pytest.raises(URLRejected):
            policy.check_target(parse_url(url))


class TestCheckAddresses:
    @pytest.mark.parametrize(
        ("policy", "url", "answer"),
        [
            (HOSTED, "https://id.example.com/", ["93.184.215.14", "2606:2800:21f:cb07::1"]),
            (CLI_PRIVATE, "https://keycloak.internal/", ["10.0.0.5"]),
            (CLI_PRIVATE, "https://keycloak.internal/", ["fd12::5"]),
            (CLI_PRIVATE, "https://localhost/", ["127.0.0.1", "::1"]),
            (CLI_PRIVATE, "https://id.example.com/", ["93.184.215.14", "10.0.0.5"]),
            (CLI_HTTP, "http://localhost:8080/", ["127.0.0.1", "::1"]),
        ],
    )
    def test_allows(self, policy: FetchPolicy, url: str, answer: list[str]) -> None:
        policy.check_addresses(parse_url(url), addresses(*answer))

    @pytest.mark.parametrize(
        ("policy", "url", "answer"),
        [
            (HOSTED, "https://id.example.com/", ["10.0.0.5"]),
            (HOSTED, "https://id.example.com/", ["127.0.0.1"]),
            (HOSTED, "https://id.example.com/", ["93.184.215.14", "10.0.0.5"]),
            (HOSTED, "https://id.example.com/", ["fdaa::3"]),
            (CLI, "https://id.example.com/", ["100.64.0.1"]),
            (CLI_PRIVATE, "https://id.example.com/", ["169.254.169.254"]),
            (CLI_PRIVATE, "https://id.example.com/", ["fd00:ec2::254"]),
            (CLI_PRIVATE, "https://id.example.com/", ["fd00:ec2::23"]),
            (CLI_PRIVATE, "https://id.example.com/", ["fd20:ce::254"]),
            (CLI_PRIVATE, "https://id.example.com/", ["fd00:c1::a9fe:a9fe"]),
            (CLI_PRIVATE, "https://id.example.com/", ["100.100.100.200"]),
            (CLI_PRIVATE, "https://id.example.com/", ["10.0.0.5", "0.0.0.0"]),
            (CLI_HTTP, "http://localhost:8080/", ["127.0.0.1", "93.184.215.14"]),
            (CLI_HTTP, "http://localhost:8080/", ["10.0.0.5"]),
            (CLI_HTTP, "https://id.example.com/", ["127.0.0.1"]),  # https to loopback
            # --allow-private-network doesn't widen --allow-http beyond loopback.
            (CLI_HTTP_PRIVATE, "http://keycloak.internal:8080/", ["10.0.0.5"]),
            (CLI_HTTP_PRIVATE, "http://keycloak.internal:8080/", ["fd12::5"]),
            (CLI_HTTP_PRIVATE, "http://localhost:8080/", ["127.0.0.1", "192.168.1.2"]),
        ],
    )
    def test_rejects(self, policy: FetchPolicy, url: str, answer: list[str]) -> None:
        with pytest.raises(AddressRejected):
            policy.check_addresses(parse_url(url), addresses(*answer))
