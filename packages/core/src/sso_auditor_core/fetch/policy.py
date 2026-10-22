"""Network policy profiles for the safe fetcher (ADR-0002, "Network policy").

There are two profiles:

- ``hosted`` for the public demo. Strict, takes no parameters, and refuses to be built in
  a relaxed form, so no request parameter can loosen it.
- ``cli`` for the command line. Strict by default; ``--allow-private-network``,
  ``--allow-http`` (loopback only) and ``--allow-port`` relax it, and each relaxation
  comes with a warning for the CLI to print.
"""

import dataclasses
import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from sso_auditor_core.fetch.addresses import AddressClass, IPAddress, classify
from sso_auditor_core.fetch.errors import AddressRejected, URLRejected
from sso_auditor_core.fetch.urls import Target

DEFAULT_PORT = 443

# Hostnames that are never fetched. Cloud metadata services answer on these names.
_ALWAYS_REFUSED_HOSTS = frozenset(
    {
        "metadata",
        "metadata.goog",
        "metadata.google.internal",
        "instance-data",
        "instance-data.ec2.internal",
    }
)
# Names that only make sense on a local or private network: RFC 6761, RFC 6762, RFC 8375,
# ICANN's .internal, the common /etc/hosts aliases localhost.localdomain and
# localhost6.localdomain6, and .flycast, Fly.io's private service names (the hosted demo
# runs on Fly.io).
_LOCALHOST_SUFFIX = ".localhost"
_PRIVATE_SUFFIXES = (
    ".local",
    ".internal",
    ".home.arpa",
    ".localdomain",
    ".localdomain6",
    ".flycast",
)


@dataclass(frozen=True, kw_only=True)
class FetchPolicy:
    """What the safe fetcher may connect to, and the limits it enforces.

    Build one with :meth:`hosted` or :meth:`cli` rather than calling the constructor.
    """

    profile: Literal["hosted", "cli"]
    allow_private_network: bool = False
    allow_http: bool = False
    allowed_ports: frozenset[int] = frozenset({DEFAULT_PORT})
    ca_bundle: Path | None = None
    """A PEM file of CA certificates to trust instead of the bundled ones."""

    max_redirects: int = 3
    max_connect_attempts: int = 4
    """How many of a hop's validated addresses are tried, alternating address families.
    Every address in the answer is still validated."""

    connect_timeout: float = 5.0
    read_timeout: float = 10.0
    total_timeout: float = 15.0
    """Deadline for the whole fetch: DNS, every redirect hop, and reading the body."""

    max_body_bytes: int = 1024 * 1024
    """Cap on the response body, both as received and after decompression."""

    max_json_depth: int = 32
    max_json_nodes: int = 20_000
    """Cap on objects, arrays and values in a JSON document. Real discovery documents and
    JWKS have a few hundred to a few thousand."""

    max_jwks_keys: int = 100
    max_rsa_modulus_bits: int = 16384

    def __post_init__(self) -> None:
        # A caller's mutable set would let the policy change after it was checked.
        object.__setattr__(self, "allowed_ports", frozenset(self.allowed_ports))
        if not self.allowed_ports or not all(1 <= p <= 65535 for p in self.allowed_ports):
            raise ValueError("allowed_ports must be a non-empty set of ports in 1-65535")
        limits = (
            self.max_connect_attempts,
            self.connect_timeout,
            self.read_timeout,
            self.total_timeout,
            self.max_body_bytes,
            self.max_json_depth,
            self.max_json_nodes,
            self.max_jwks_keys,
            self.max_rsa_modulus_bits,
        )
        # Written so NaN fails too: every comparison with NaN is false.
        if not self.max_redirects >= 0 or not all(
            math.isfinite(limit) and limit > 0 for limit in limits
        ):
            raise ValueError("limits must be positive and finite, max_redirects non-negative")
        if self.profile == "hosted" and dataclasses.replace(self, profile="cli") != _DEFAULTS:
            # Every field must keep its strict default. This runs on direct construction
            # and on dataclasses.replace(), so neither can relax the hosted profile.
            raise ValueError("the hosted profile is fixed and cannot be relaxed")

    @classmethod
    def hosted(cls) -> "FetchPolicy":
        """The strict profile for the public demo. It takes no parameters on purpose."""
        return cls(profile="hosted")

    @classmethod
    def cli(
        cls,
        *,
        allow_private_network: bool = False,
        allow_http: bool = False,
        extra_ports: Iterable[int] = (),
        ca_bundle: Path | None = None,
    ) -> "FetchPolicy":
        """The command-line profile: strict unless the user passes explicit flags."""
        return cls(
            profile="cli",
            allow_private_network=allow_private_network,
            allow_http=allow_http,
            allowed_ports=frozenset({DEFAULT_PORT, *extra_ports}),
            ca_bundle=ca_bundle,
        )

    @property
    def warnings(self) -> tuple[str, ...]:
        """One message per relaxation, for the CLI to print on every run."""
        messages = []
        if self.allow_private_network:
            messages.append(
                "--allow-private-network: requests may reach private, loopback and "
                "carrier-grade NAT addresses. Link-local and cloud metadata addresses "
                "stay blocked. Use it only for an issuer on a network you trust."
            )
        if self.allow_http:
            messages.append(
                "--allow-http: plain http:// is allowed to loopback addresses only. "
                "That traffic is not encrypted."
            )
        extra = sorted(self.allowed_ports - {DEFAULT_PORT})
        if extra:
            ports = ", ".join(str(p) for p in extra)
            messages.append(f"--allow-port: connections to port {ports} are allowed besides 443.")
        return tuple(messages)

    def check_target(self, target: Target) -> None:
        """Apply the scheme, port and hostname rules. Raises :class:`URLRejected`."""
        if target.scheme == "http" and not self.allow_http:
            raise URLRejected("plain http is not allowed; use https", url=target.url)
        if target.port not in self.allowed_ports:
            allowed = ", ".join(str(p) for p in sorted(self.allowed_ports))
            raise URLRejected(
                f"port {target.port} is not allowed (allowed: {allowed})", url=target.url
            )
        if target.ip is None:
            self._check_hostname(target)

    def _check_hostname(self, target: Target) -> None:
        host = target.host
        if host in _ALWAYS_REFUSED_HOSTS:
            raise URLRejected(f"{host!r} is a cloud metadata hostname", url=target.url)
        if host == "localhost" or host.endswith(_LOCALHOST_SUFFIX):
            if self.allow_private_network or (self.allow_http and target.scheme == "http"):
                return
            raise URLRejected(f"{host!r} is a loopback name", url=target.url)
        # The leading dot makes each suffix match its zone's own name too (home.arpa).
        if "." not in host or f".{host}".endswith(_PRIVATE_SUFFIXES):
            if self.allow_private_network:
                return
            raise URLRejected(
                f"{host!r} is a single-label or private-use name; "
                "public issuers have a fully qualified domain name",
                url=target.url,
            )

    def check_addresses(self, target: Target, addresses: Sequence[IPAddress]) -> None:
        """Check every address the target resolved to. One bad address fails them all,
        so a mixed public and private answer is refused. Raises :class:`AddressRejected`.
        """
        for address in addresses:
            verdict = classify(address)
            if verdict.kind is AddressClass.BLOCKED:
                raise AddressRejected(
                    f"{target.host} resolves to {address}, which is {verdict.reason}",
                    url=target.url,
                )
            if target.scheme == "http":
                # check_target only lets http through when allow_http is set.
                if verdict.kind is not AddressClass.LOOPBACK:
                    raise AddressRejected(
                        f"plain http is allowed only to loopback, and {target.host} "
                        f"resolves to {address}",
                        url=target.url,
                    )
                continue
            if verdict.kind is not AddressClass.PUBLIC and not self.allow_private_network:
                raise AddressRejected(
                    f"{target.host} resolves to {address}, which is {verdict.reason}; "
                    "private and loopback addresses need --allow-private-network",
                    url=target.url,
                )


_DEFAULTS = FetchPolicy(profile="cli")
