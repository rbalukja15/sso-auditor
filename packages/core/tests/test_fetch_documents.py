import base64
import json
import threading
import time
from typing import Any

import pytest

from sso_auditor_core.fetch import (
    FetchPolicy,
    InvalidJSON,
    JSONTooDeep,
    JSONTooLarge,
    JWKSLimitExceeded,
    check_jwks_limits,
)
from sso_auditor_core.fetch import parse_json as parse_json_with

POLICY = FetchPolicy.hosted()


def parse_json(body: bytes, *, max_depth: int = POLICY.max_json_depth) -> Any:
    return parse_json_with(body, max_depth=max_depth, max_nodes=POLICY.max_json_nodes)


def check_jwks(
    jwks: Any,
    *,
    max_keys: int = POLICY.max_jwks_keys,
    max_rsa_modulus_bits: int = POLICY.max_rsa_modulus_bits,
) -> None:
    check_jwks_limits(jwks, max_keys=max_keys, max_rsa_modulus_bits=max_rsa_modulus_bits)


def b64url_int(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def rsa_key(bits: int, *, e: str = "AQAB") -> dict[str, Any]:
    return {"kty": "RSA", "kid": f"k{bits}", "n": b64url_int((1 << (bits - 1)) | 1), "e": e}


class TestParseJSON:
    def test_parses_an_object(self) -> None:
        assert parse_json(b'{"issuer": "https://id.example.com", "n": [1, 2]}') == {
            "issuer": "https://id.example.com",
            "n": [1, 2],
        }

    def test_ignores_a_byte_order_mark(self) -> None:
        assert parse_json(b'\xef\xbb\xbf{"a": 1}') == {"a": 1}

    def test_accepts_nesting_up_to_the_limit(self) -> None:
        assert parse_json(b"[" * 4 + b"]" * 4, max_depth=4) == [[[[]]]]

    @pytest.mark.parametrize(
        "body",
        [
            b"[" * 33 + b"]" * 33,
            b'{"a":' * 40 + b"1" + b"}" * 40,
            b"[" * 100_000 + b"]" * 100_000,  # past CPython's recursion limit
        ],
    )
    def test_rejects_deep_nesting(self, body: bytes) -> None:
        with pytest.raises(JSONTooDeep):
            parse_json(body)

    def test_brackets_inside_strings_do_not_count_toward_the_depth(self) -> None:
        body = b'{"a": "' + b"[" * 100 + b'", "b": "\\"{{{{", "c": [[1]]}'
        assert parse_json(body) == {"a": "[" * 100, "b": '"{{{{', "c": [[1]]}

    def test_rejects_deep_nesting_on_a_small_thread_stack(self) -> None:
        # json.loads would recurse into this until CPython's recursion limit, which a
        # 1 MiB thread stack (musl's default) can't hold: the process would crash.
        body = b"[" * 10_000 + b"]" * 10_000
        errors: list[BaseException] = []

        def parse() -> None:
            try:
                parse_json(body)
            except BaseException as exc:
                errors.append(exc)

        previous = threading.stack_size(1 << 20)
        try:
            thread = threading.Thread(target=parse)
            thread.start()
        finally:
            threading.stack_size(previous)
        thread.join()

        assert [type(error) for error in errors] == [JSONTooDeep]

    @pytest.mark.parametrize(
        "body",
        [
            b'"\\"' * 300_000,  # a quote, then escaped quotes to the end
            b'"\\' * 500_000,
            b'"' * 1_000_000,
            b'"' + b"[" * 1_000_000,
        ],
    )
    def test_the_depth_scan_is_linear_on_hostile_strings(self, body: bytes) -> None:
        start = time.monotonic()
        with pytest.raises(InvalidJSON):
            parse_json(body)
        assert time.monotonic() - start < 2

    @pytest.mark.parametrize(
        "body",
        [
            b"",
            b"not json",
            b'{"a": 1',
            b"\xff\xfe{}",
            b'{"a": NaN}',
            b'{"a": Infinity}',
            b'{"a": -Infinity}',
            b'{"a": 1e400}',  # overflows a float to inf
            b'{"a": -1E309}',
            b'{"a": ' + b"9" * 5000 + b"}",  # longer than Python's int parsing limit
            b"<html>gateway error</html>",
        ],
    )
    def test_rejects_invalid_json(self, body: bytes) -> None:
        with pytest.raises(InvalidJSON):
            parse_json(body)

    def test_accepts_large_but_finite_numbers(self) -> None:
        assert parse_json(b'{"a": 1.7e308, "b": 1e-400}') == {"a": 1.7e308, "b": 0.0}

    def test_rejects_more_values_than_the_node_cap(self) -> None:
        body = b"[" + b",".join([b"{}"] * POLICY.max_json_nodes) + b"]"
        with pytest.raises(JSONTooLarge, match="more than 20000 values"):
            parse_json(body)

    def test_accepts_a_document_at_the_node_cap(self) -> None:
        body = b"[" + b",".join([b"1"] * (POLICY.max_json_nodes - 1)) + b"]"
        assert len(parse_json(body)) == POLICY.max_json_nodes - 1


class TestJWKSLimits:
    def test_accepts_a_normal_jwks(self) -> None:
        check_jwks({"keys": [rsa_key(2048), rsa_key(4096), {"kty": "EC", "crv": "P-256"}]})

    def test_ignores_documents_that_are_not_a_jwks(self) -> None:
        documents: list[object] = [[], {"keys": "x"}, {"keys": [1, "two", None]}, "text"]
        for document in documents:
            check_jwks(document)

    def test_rejects_too_many_keys(self) -> None:
        with pytest.raises(JWKSLimitExceeded, match="101 keys"):
            check_jwks({"keys": [{"kty": "EC"}] * 101})

    def test_accepts_the_largest_allowed_modulus(self) -> None:
        check_jwks({"keys": [rsa_key(16384)]})

    def test_rejects_an_oversized_modulus(self) -> None:
        with pytest.raises(JWKSLimitExceeded, match="modulus"):
            check_jwks({"keys": [rsa_key(16385)]})

    def test_rejects_a_huge_modulus_without_decoding_it(self) -> None:
        with pytest.raises(JWKSLimitExceeded, match="modulus"):
            check_jwks({"keys": [{"kty": "RSA", "n": "A" * 1_000_000, "e": "AQAB"}]})

    def test_rejects_an_oversized_exponent(self) -> None:
        with pytest.raises(JWKSLimitExceeded, match="exponent"):
            check_jwks({"keys": [rsa_key(2048, e="A" * 64)]})

    def test_limits_are_configurable(self) -> None:
        with pytest.raises(JWKSLimitExceeded):
            check_jwks({"keys": [rsa_key(4096)]}, max_rsa_modulus_bits=2048)
        with pytest.raises(JWKSLimitExceeded):
            check_jwks({"keys": [rsa_key(2048)] * 3}, max_keys=2)

    def test_round_trip_through_parse_json(self) -> None:
        body = json.dumps({"keys": [rsa_key(2048)]}).encode()
        check_jwks(parse_json(body))
