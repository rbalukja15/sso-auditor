"""Content decoding with a hard cap on the decoded size.

The fetcher reads the raw body from the transport and decodes it here, so a small
compressed response can't expand past the size cap (a decompression bomb).
"""

import zlib

from sso_auditor_core.fetch.errors import InvalidResponse, ResponseTooLarge

# What the fetcher advertises in Accept-Encoding. A server that sends anything else gets
# an InvalidResponse.
ACCEPT_ENCODING = "gzip, deflate"

_GZIP = zlib.MAX_WBITS | 16
_GZIP_MAGIC = b"\x1f\x8b"


class BoundedDecoder:
    """Decodes one response body and raises once the output passes ``limit`` bytes."""

    def __init__(self, content_encoding: str | None, limit: int) -> None:
        encoding = (content_encoding or "identity").strip().lower()
        if encoding == "x-gzip":
            encoding = "gzip"
        if encoding not in {"identity", "gzip", "deflate"}:
            raise InvalidResponse(f"unsupported Content-Encoding {content_encoding!r}")
        self._encoding = encoding
        self._limit = limit
        self._produced = 0
        self._decompressor: zlib._Decompress | None = (
            zlib.decompressobj(_GZIP) if encoding == "gzip" else None
        )
        # Bytes held back until the next chunk: the start of a raw "deflate" body, or the
        # first byte of the next gzip member's magic number.
        self._pending = b""
        self._received = False

    def decode(self, chunk: bytes) -> bytes:
        """Decode the next chunk of the raw body."""
        self._received = self._received or bool(chunk)
        if self._encoding == "identity":
            return self._emit(chunk)
        chunk, self._pending = self._pending + chunk, b""
        if self._decompressor is None:
            # "deflate" should be zlib-wrapped (RFC 9110 §8.4.1.2), but some servers send
            # raw deflate. Pick the format from the first two bytes, as browsers do.
            if len(chunk) < 2:
                self._pending = chunk
                return b""
            wbits = zlib.MAX_WBITS if _is_zlib_header(chunk) else -zlib.MAX_WBITS
            self._decompressor = zlib.decompressobj(wbits)
        return self._inflate(self._decompressor, chunk)

    def flush(self) -> bytes:
        """Finish once the raw body has ended. Raises if the body was cut short."""
        if self._encoding == "identity" or not self._received:
            return b""
        decompressor = self._decompressor
        # A complete gzip member, zlib stream or raw deflate stream always reaches its
        # end; one that doesn't was cut short, and for zlib its checksum was never read.
        if decompressor is None or self._pending or not decompressor.eof:
            raise InvalidResponse("the compressed body is truncated")
        return self._emit(decompressor.flush())

    def _inflate(self, decompressor: "zlib._Decompress", data: bytes) -> bytes:
        out = bytearray()
        while data:
            if decompressor.eof:
                # gzip allows several members back to back; anything else after the end
                # of the stream is garbage. A chunk can end inside the next magic number.
                if self._encoding == "gzip" and _GZIP_MAGIC.startswith(data):
                    self._pending = data
                    break
                if self._encoding != "gzip" or not data.startswith(_GZIP_MAGIC):
                    raise InvalidResponse("unexpected data after the end of the compressed body")
                decompressor = self._decompressor = zlib.decompressobj(_GZIP)
            # Ask for one byte more than the cap allows, so going over is detectable.
            room = self._limit - self._produced - len(out) + 1
            try:
                out += decompressor.decompress(data, room)
            except zlib.error as exc:
                raise InvalidResponse(f"corrupt compressed body: {exc}") from exc
            if self._produced + len(out) > self._limit:
                raise ResponseTooLarge(f"the response body exceeds {self._limit} bytes")
            data = decompressor.unconsumed_tail or decompressor.unused_data
        return self._emit(bytes(out))

    def _emit(self, data: bytes) -> bytes:
        self._produced += len(data)
        if self._produced > self._limit:
            raise ResponseTooLarge(f"the response body exceeds {self._limit} bytes")
        return data


def _is_zlib_header(data: bytes) -> bool:
    cmf, flg = data[0], data[1]
    return cmf & 0x0F == 8 and (cmf << 8 | flg) % 31 == 0
