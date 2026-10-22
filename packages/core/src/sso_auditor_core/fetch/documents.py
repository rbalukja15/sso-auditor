"""Parse fetched JSON documents within fixed limits.

The body size cap bounds how much JSON there is; these limits bound its shape: nesting
depth, the number of values, and for a JWKS the number of keys and the size of RSA keys,
which later checks would otherwise spend time on. The limits come from the
:class:`~sso_auditor_core.fetch.policy.FetchPolicy`, so they are required arguments here.
"""

import base64
import binascii
import json
import math
import re
from collections.abc import Iterator
from itertools import accumulate
from typing import Any, NoReturn

from sso_auditor_core.fetch.errors import FetchError

# Real RSA public exponents are tiny (almost always 65537); this is generous.
_MAX_RSA_EXPONENT_CHARS = 16

# A JSON string, or an unterminated one running to the end of the body. Possessive, and
# every attempt that starts at a quote matches, so the scan is linear in the body size.
_STRING = re.compile(rb'"(?:[^"\\]++|\\.)*+(?:"|\\?\Z)', re.DOTALL)
_NOT_BRACKETS = bytes(b for b in range(256) if b not in b"[]{}")
_DEPTH_STEP = tuple(1 if b in b"[{" else -1 if b in b"]}" else 0 for b in range(256))


class DocumentError(FetchError):
    """A fetched document can't be used: not JSON, or outside the shape limits."""


class InvalidJSON(DocumentError):
    """The body is not valid UTF-8 JSON (RFC 8259)."""


class JSONTooDeep(DocumentError):
    """Objects and arrays nest deeper than the limit."""


class JSONTooLarge(DocumentError):
    """The document has more objects, arrays and values than the limit."""


class JWKSLimitExceeded(DocumentError):
    """A JWKS has too many keys, or an RSA key outside the size caps."""


def parse_json(data: bytes, *, max_depth: int, max_nodes: int) -> Any:
    """Parse ``data`` as JSON and enforce ``max_depth`` and ``max_nodes``.

    Rejects invalid UTF-8, ``NaN`` and ``Infinity`` (as literals or as numbers too large
    for a float, RFC 8259 §6), and integers too long for Python to parse safely. A
    leading byte-order mark is ignored (RFC 8259 §8.1).
    """
    _check_depth(data, max_depth)
    try:
        text = data.decode("utf-8").removeprefix("﻿")
    except UnicodeDecodeError as exc:
        raise InvalidJSON(f"the body is not valid UTF-8: {exc}") from exc
    try:
        document = json.loads(text, parse_constant=_reject_constant, parse_float=_finite_float)
    except RecursionError as exc:
        raise JSONTooDeep(f"JSON nests deeper than {max_depth} levels") from exc
    except ValueError as exc:
        # JSONDecodeError, plus the int-length limit from sys.set_int_max_str_digits().
        raise InvalidJSON(f"the body is not valid JSON: {exc}") from exc
    _check_shape(document, max_depth, max_nodes)
    return document


def _check_depth(data: bytes, max_depth: int) -> None:
    """Reject nesting deeper than ``max_depth`` before ``json.loads`` sees it.

    ``json.loads`` recurses in C once per level and stops only at CPython's recursion
    limit, which can be deeper than a small thread stack holds: a few kilobytes of
    brackets would crash the process instead of raising. So the depth is measured on the
    raw bytes first, without recursion. String contents are skipped; UTF-8 never uses
    these byte values inside a multi-byte character.
    """
    brackets = _STRING.sub(b"", data).translate(None, _NOT_BRACKETS)
    if max(accumulate(map(_DEPTH_STEP.__getitem__, brackets)), default=0) > max_depth:
        raise JSONTooDeep(f"JSON nests deeper than {max_depth} levels")


def _reject_constant(name: str) -> NoReturn:
    raise ValueError(f"{name} is not valid JSON")


def _finite_float(literal: str) -> float:
    value = float(literal)
    if not math.isfinite(value):
        raise ValueError(f"{literal} is out of range for a float")
    return value


def _check_shape(document: Any, max_depth: int, max_nodes: int) -> None:
    """Walk the document without recursion and enforce the depth and node caps.

    The stack holds one iterator per open container, so the walk's memory grows with the
    nesting depth, not with the size of the document.
    """
    nodes = 0
    stack: list[Iterator[Any]] = []
    node: Any = document
    while True:
        nodes += 1
        if nodes > max_nodes:
            raise JSONTooLarge(f"JSON has more than {max_nodes} values")
        if isinstance(node, dict | list):
            if len(stack) >= max_depth:
                raise JSONTooDeep(f"JSON nests deeper than {max_depth} levels")
            stack.append(iter(node.values() if isinstance(node, dict) else node))
        while stack:
            try:
                node = next(stack[-1])
                break
            except StopIteration:
                stack.pop()
        else:
            return


def check_jwks_limits(jwks: Any, *, max_keys: int, max_rsa_modulus_bits: int) -> None:
    """Enforce the key-count and RSA size caps on a parsed JWKS.

    Only the caps are checked here. Whether the document is a well-formed JWKS is for the
    JWKS client (#7) and the rules (#32) to judge, so malformed members are left alone.
    """
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        return
    keys: list[Any] = jwks["keys"]
    if len(keys) > max_keys:
        raise JWKSLimitExceeded(f"the JWKS has {len(keys)} keys; the limit is {max_keys}")
    for index, key in enumerate(keys):
        if not isinstance(key, dict) or key.get("kty") != "RSA":
            continue
        modulus, exponent = key.get("n"), key.get("e")
        if isinstance(modulus, str):
            bits = _base64url_bits(modulus, max_rsa_modulus_bits)
            if bits is not None and bits > max_rsa_modulus_bits:
                raise JWKSLimitExceeded(
                    f"key {index} has an RSA modulus over {max_rsa_modulus_bits} bits"
                )
        if isinstance(exponent, str) and len(exponent) > _MAX_RSA_EXPONENT_CHARS:
            raise JWKSLimitExceeded(f"key {index} has an oversized RSA exponent")


def _base64url_bits(value: str, max_bits: int) -> int | None:
    """Bit length of a base64url-encoded big-endian integer, or None if it isn't one.

    Strings far longer than ``max_bits`` allows are reported as too large without being
    decoded.
    """
    if len(value) > max_bits // 6 + 4:
        return max_bits + 1
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (binascii.Error, ValueError):
        return None
    return int.from_bytes(raw, "big").bit_length()
