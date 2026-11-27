"""Bounded streaming HTTP body reader with incremental decompression bomb protection."""

from __future__ import annotations

import zlib
from typing import Final

import httpx

_RAW_CHUNK_SIZE: Final[int] = 16_384
_ALLOWED_ENCODINGS: Final[frozenset[str]] = frozenset(
    {"", "identity", "gzip", "x-gzip", "deflate"}
)


class DecompressionLimitError(ValueError):
    """Raised when an HTTP response violates wire, decompression, or encoding limits."""


class SharedByteBudget:
    """Mutable shared byte counter enforced incrementally across concurrent async streams."""

    __slots__ = ("limit", "used")

    def __init__(self, limit: int) -> None:
        if limit < 0:
            raise ValueError("limit must be non-negative")
        self.limit = limit
        self.used = 0

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    def consume(self, n: int) -> None:
        if n < 0:
            raise ValueError("n must be non-negative")
        if self.used + n > self.limit:
            raise DecompressionLimitError(
                f"Shared session byte budget exceeded ({self.limit} bytes)"
            )
        self.used += n


async def read_bounded_http_body(
    resp: httpx.Response,
    max_body_bytes: int,
    max_wire_bytes: int | None = None,
    session_budget: SharedByteBudget | None = None,
) -> bytes:
    """Read an httpx.Response body with strict caps on wire size and inflated size."""
    if max_body_bytes < 0:
        raise ValueError("max_body_bytes must be non-negative")
    wire_limit = max_body_bytes if max_wire_bytes is None else max_wire_bytes
    if wire_limit < 0:
        raise ValueError("max_wire_bytes must be non-negative")

    encoding = resp.headers.get("content-encoding", "").strip().lower()
    if "," in encoding:
        raise DecompressionLimitError(f"Stacked Content-Encoding not allowed: {encoding}")
    if encoding not in _ALLOWED_ENCODINGS:
        raise DecompressionLimitError(f"Unsupported Content-Encoding: {encoding}")

    # Preserve backward compatibility for pre-buffered httpx.MockTransport responses
    if resp.is_stream_consumed and hasattr(resp, "_content"):
        raw = resp.content[: max_body_bytes + 1]
        if len(raw) > max_body_bytes:
            raise DecompressionLimitError(f"Body exceeded max_body_bytes ({max_body_bytes})")
        if session_budget is not None:
            session_budget.consume(len(raw))
        return raw

    if encoding in ("", "identity"):
        return await _read_identity_stream(resp, max_body_bytes, wire_limit, session_budget)
    return await _read_compressed_stream(
        resp, encoding, max_body_bytes, wire_limit, session_budget
    )


async def _read_identity_stream(
    resp: httpx.Response,
    max_body_bytes: int,
    wire_limit: int,
    session_budget: SharedByteBudget | None = None,
) -> bytes:
    chunks: list[bytes] = []
    wire_bytes = 0
    out_bytes = 0
    async for raw_chunk in resp.aiter_raw(chunk_size=_RAW_CHUNK_SIZE):
        if not raw_chunk:
            continue
        wire_bytes += len(raw_chunk)
        if wire_bytes > wire_limit:
            raise DecompressionLimitError(f"Wire body exceeded {wire_limit} bytes")
        out_bytes += len(raw_chunk)
        if out_bytes > max_body_bytes:
            raise DecompressionLimitError(f"HTTP body exceeded {max_body_bytes} bytes")
        if session_budget is not None:
            session_budget.consume(len(raw_chunk))
        chunks.append(raw_chunk)
    return b"".join(chunks)


async def _read_compressed_stream(
    resp: httpx.Response,
    encoding: str,
    max_body_bytes: int,
    wire_limit: int,
    session_budget: SharedByteBudget | None = None,
) -> bytes:
    is_gzip = encoding in ("gzip", "x-gzip")
    dec = zlib.decompressobj(wbits=(16 + zlib.MAX_WBITS) if is_gzip else zlib.MAX_WBITS)
    tried_raw_deflate = False
    first_chunk = True
    chunks: list[bytes] = []
    wire_bytes = 0
    out_bytes = 0
    charged_budget = 0

    async for raw_chunk in resp.aiter_raw(chunk_size=_RAW_CHUNK_SIZE):
        if not raw_chunk:
            continue
        wire_bytes += len(raw_chunk)
        if wire_bytes > wire_limit:
            raise DecompressionLimitError(f"Compressed wire body exceeded {wire_limit} bytes")
        if session_budget is not None and wire_bytes > charged_budget:
            session_budget.consume(wire_bytes - charged_budget)
            charged_budget = wire_bytes

        pending = raw_chunk
        while pending:
            remaining = max_body_bytes - out_bytes
            if session_budget is not None:
                budget_room = session_budget.remaining + max(0, charged_budget - out_bytes)
                remaining = min(remaining, budget_room)
            try:
                piece = dec.decompress(pending, remaining + 1)
            except zlib.error as exc:
                if first_chunk and not is_gzip and not tried_raw_deflate:
                    tried_raw_deflate = True
                    dec = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
                    try:
                        piece = dec.decompress(pending, remaining + 1)
                    except zlib.error as raw_exc:
                        raise DecompressionLimitError("Malformed deflate HTTP body") from raw_exc
                else:
                    raise DecompressionLimitError(f"Malformed {encoding} HTTP body") from exc

            first_chunk = False
            if len(piece) > remaining or dec.unconsumed_tail:
                raise DecompressionLimitError(f"Decompressed body exceeded {max_body_bytes} bytes")
            if piece:
                next_out = out_bytes + len(piece)
                if session_budget is not None and next_out > charged_budget:
                    session_budget.consume(next_out - charged_budget)
                    charged_budget = next_out
                chunks.append(piece)
                out_bytes = next_out

            if dec.eof:
                pending = dec.unused_data
                if pending:
                    if is_gzip:
                        dec = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
                    else:
                        raise DecompressionLimitError(f"Trailing bytes after {encoding} EOF")
            else:
                pending = b""

    remaining = max_body_bytes - out_bytes
    if session_budget is not None:
        budget_room = session_budget.remaining + max(0, charged_budget - out_bytes)
        remaining = min(remaining, budget_room)
    try:
        tail = dec.flush(4096)
    except zlib.error as exc:
        raise DecompressionLimitError(f"Malformed {encoding} HTTP trailer") from exc
    if len(tail) > remaining:
        raise DecompressionLimitError(f"Decompressed body exceeded {max_body_bytes} bytes")
    if tail:
        next_out = out_bytes + len(tail)
        if session_budget is not None and next_out > charged_budget:
            session_budget.consume(next_out - charged_budget)
            charged_budget = next_out
        chunks.append(tail)
    return b"".join(chunks)
