import gzip
import zlib

import pytest

from sso_auditor_core.fetch import InvalidResponse, ResponseTooLarge
from sso_auditor_core.fetch.decoding import BoundedDecoder

BODY = b'{"issuer": "https://id.example.com"}' * 50


def decode_all(encoding: str | None, data: bytes, limit: int, chunk: int = 7) -> bytes:
    decoder = BoundedDecoder(encoding, limit)
    out = b"".join(decoder.decode(data[i : i + chunk]) for i in range(0, len(data), chunk))
    return out + decoder.flush()


def raw_deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


def sync_flushed(data: bytes) -> bytes:
    """A zlib stream flushed but never finished: all the data, no end of stream."""
    compressor = zlib.compressobj()
    return compressor.compress(data) + compressor.flush(zlib.Z_SYNC_FLUSH)


@pytest.mark.parametrize(
    ("encoding", "encoded"),
    [
        (None, BODY),
        ("identity", BODY),
        ("gzip", gzip.compress(BODY)),
        ("x-gzip", gzip.compress(BODY)),
        ("GZIP", gzip.compress(BODY)),
        ("deflate", zlib.compress(BODY)),
        ("deflate", raw_deflate(BODY)),
    ],
)
def test_decodes(encoding: str | None, encoded: bytes) -> None:
    assert decode_all(encoding, encoded, limit=len(BODY)) == BODY


@pytest.mark.parametrize("chunk", [1, 2, 7, 1000])
def test_decodes_concatenated_gzip_members(chunk: int) -> None:
    # Chunks of one or two bytes split the second member's magic number.
    members = gzip.compress(b"abc") + gzip.compress(b"def")
    assert decode_all("gzip", members, limit=6, chunk=chunk) == b"abcdef"


@pytest.mark.parametrize("tail", [b"\x1f", b"\x1f\x8b"])
def test_the_start_of_another_gzip_member_at_the_end_is_truncation(tail: bytes) -> None:
    with pytest.raises(InvalidResponse, match="truncated"):
        decode_all("gzip", gzip.compress(b"abc") + tail, limit=10)


def test_an_empty_compressed_body_is_empty() -> None:
    assert decode_all("gzip", b"", limit=10) == b""


@pytest.mark.parametrize("encoding", [None, "gzip", "deflate"])
def test_stops_one_byte_over_the_limit(encoding: str | None) -> None:
    encoded = {
        None: BODY,
        "gzip": gzip.compress(BODY),
        "deflate": zlib.compress(BODY),
    }[encoding]
    with pytest.raises(ResponseTooLarge):
        decode_all(encoding, encoded, limit=len(BODY) - 1)


def test_stops_a_decompression_bomb_without_inflating_it() -> None:
    bomb = gzip.compress(b"\0" * 50_000_000)  # about 50 KB compressed
    decoder = BoundedDecoder("gzip", 1024 * 1024)

    with pytest.raises(ResponseTooLarge):
        decoder.decode(bomb)


@pytest.mark.parametrize("encoding", ["br", "zstd", "compress", "gzip, gzip", "gzip, br"])
def test_rejects_unsupported_encodings(encoding: str) -> None:
    with pytest.raises(InvalidResponse, match="unsupported"):
        BoundedDecoder(encoding, 100)


@pytest.mark.parametrize(
    ("encoding", "encoded"),
    [
        ("gzip", gzip.compress(BODY)[:-10]),  # truncated
        ("gzip", b"definitely not gzip"),
        ("gzip", gzip.compress(BODY) + b"trailing garbage"),
        ("deflate", b"\x78\x9c" + b"\xff" * 20),
        ("deflate", zlib.compress(BODY)[:-4]),  # the Adler-32 checksum is missing
        ("deflate", zlib.compress(BODY)[:-12]),
        ("deflate", raw_deflate(BODY)[:-5]),
        ("deflate", sync_flushed(BODY)),  # no final block
    ],
)
def test_rejects_corrupt_bodies(encoding: str, encoded: bytes) -> None:
    with pytest.raises(InvalidResponse):
        decode_all(encoding, encoded, limit=10 * len(BODY))
