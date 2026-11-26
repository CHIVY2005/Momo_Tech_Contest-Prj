"""SSRF network target validation, IP-pinned HTTP transport, media hardening, and secret auth."""

from __future__ import annotations

import asyncio
import hmac
import io
import ipaddress
import re
import socket
import warnings
from collections.abc import Iterable
from typing import Any, Final, Literal
from urllib.parse import urlsplit

import av
import httpcore
import httpx
from PIL import Image, UnidentifiedImageError

MAX_DECOMPRESSED_PIXELS: Final[int] = 25_000_000
MAX_DECODED_AUDIO_SAMPLES: Final[int] = 48_000 * 600  # Max 10 minutes at 48kHz
MAX_AUDIO_CHANNELS: Final[int] = 8

_BLOCKED_IPV4_NETS: Final[tuple[ipaddress.IPv4Network, ...]] = (
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("100.64.0.0/10"),  # CGNAT
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),  # Link-local / Cloud IMDS
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.0.0.0/24"),
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("198.18.0.0/15"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("240.0.0.0/4"),
)

_BLOCKED_IPV6_NETS: Final[tuple[ipaddress.IPv6Network, ...]] = (
    ipaddress.IPv6Network("::/128"),
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("64:ff9b::/96"),
    ipaddress.IPv6Network("64:ff9b:1::/48"),
    ipaddress.IPv6Network("100::/64"),
    ipaddress.IPv6Network("2001:db8::/32"),
    ipaddress.IPv6Network("fc00::/7"),
    ipaddress.IPv6Network("fe80::/10"),
    ipaddress.IPv6Network("fec0::/10"),  # Deprecated IPv6 site-local
    ipaddress.IPv6Network("ff00::/8"),
)

_NUMERIC_HOST_LABEL_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:0x[0-9a-f]+|\d+)$",
    re.IGNORECASE,
)


def _is_obfuscated_numeric_ip(hostname: str) -> bool:
    """Return True for shorthand, hex, octal, or integer-encoded IPv4 host literals."""
    labels = hostname.split(".")
    if not (1 <= len(labels) <= 4):
        return False
    if not all(_NUMERIC_HOST_LABEL_RE.fullmatch(lbl) for lbl in labels):
        return False
    if len(labels) != 4:
        return True
    for lbl in labels:
        if lbl.lower().startswith("0x") or (len(lbl) > 1 and lbl.startswith("0")):
            return True
    try:
        ipaddress.IPv4Address(hostname)
    except ValueError:
        return True
    return False


class UploadTooLargeError(ValueError):
    """Raised when uploaded media exceeds configured max_upload_bytes (HTTP 413)."""


class InvalidMediaError(ValueError):
    """Raised when uploaded media is empty, corrupt, or fails container decoding (HTTP 400)."""


class SsrfBlockedError(PermissionError):
    """Raised at socket connect time if a target resolves to any non-public IP."""


def is_public_ip(ip_str: str) -> bool:
    """Return True strictly for routable public IPv4/IPv6 addresses (blocks all ::ffff: mapped IPs)."""
    cleaned = ip_str.strip().strip("[]")
    if not cleaned or "%" in cleaned:
        return False
    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError:
        return False

    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return False
        if addr.sixtofour is not None:
            return is_public_ip(str(addr.sixtofour))
        if addr.teredo is not None:
            client_ip, server_ip = addr.teredo
            return is_public_ip(str(client_ip)) and is_public_ip(str(server_ip))
        if any(addr in net for net in _BLOCKED_IPV6_NETS):
            return False
        return bool(
            addr.is_global
            and not addr.is_private
            and not addr.is_loopback
            and not addr.is_link_local
            and not getattr(addr, "is_site_local", False)
            and not addr.is_multicast
            and not addr.is_reserved
            and not addr.is_unspecified
        )

    if any(addr in net for net in _BLOCKED_IPV4_NETS):
        return False
    return bool(
        addr.is_global
        and not addr.is_private
        and not addr.is_loopback
        and not addr.is_link_local
        and not addr.is_multicast
        and not addr.is_reserved
        and not addr.is_unspecified
    )


def _parse_url_authority(url: str) -> tuple[bool, str | None, str, int, list[str]]:
    raw = url.strip()
    if not raw:
        return False, "Empty URL", "", 0, []
    try:
        parsed = urlsplit(raw)
        scheme = parsed.scheme.lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        hostname = (parsed.hostname or "").strip().rstrip(".").lower()
    except ValueError as exc:
        return False, f"Malformed URL authority: {exc}", "", 0, []

    if scheme not in ("http", "https"):
        return False, f"Disallowed URL scheme: {scheme or 'none'}", "", 0, []
    if parsed.username is not None or parsed.password is not None:
        return False, "Embedded URL credentials are disallowed", "", 0, []
    if not hostname:
        return False, "Missing hostname", "", 0, []
    if hostname == "localhost" or hostname.endswith((".localhost", ".local", ".internal")):
        return False, f"Internal hostname blocked: {hostname}", "", 0, []
    if _is_obfuscated_numeric_ip(hostname):
        return False, f"Obfuscated numeric IP literal blocked: {hostname}", "", 0, []

    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        literal_ip = None

    if literal_ip is not None:
        if not is_public_ip(hostname):
            return False, f"Non-public IP literal blocked: {hostname}", "", 0, []
        return True, None, hostname, port, [str(literal_ip)]

    try:
        ascii_host = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return False, "Invalid internationalized domain name", "", 0, []

    return True, None, ascii_host, port, []


def _check_addrinfo_results(infos: list[Any]) -> tuple[bool, str | None, list[str]]:
    resolved_ips: list[str] = []
    for info in infos:
        ip_candidate = str(info[4][0])
        if not is_public_ip(ip_candidate):
            return False, f"DNS resolved to non-public IP: {ip_candidate}", []
        if ip_candidate not in resolved_ips:
            resolved_ips.append(ip_candidate)
    if not resolved_ips:
        return False, "DNS returned no addresses", []
    return True, None, resolved_ips


def validate_url_target(
    url: str,
    resolve_dns: bool = True,
) -> tuple[bool, str | None, list[str]]:
    """Synchronous URL authority & DNS SSRF validator."""
    ok, reason, ascii_host, port, literal_ips = _parse_url_authority(url)
    if not ok:
        return False, reason, []
    if literal_ips or not resolve_dns:
        return True, None, literal_ips
    try:
        infos = socket.getaddrinfo(ascii_host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        return False, f"DNS resolution failed: {exc}", []
    return _check_addrinfo_results(infos)


async def async_validate_url_target(
    url: str,
    resolve_dns: bool = True,
    timeout_sec: float = 2.5,
) -> tuple[bool, str | None, list[str]]:
    """Non-blocking async URL authority & DNS SSRF validator with bounded deadline."""
    ok, reason, ascii_host, port, literal_ips = _parse_url_authority(url)
    if not ok:
        return False, reason, []
    if literal_ips or not resolve_dns:
        return True, None, literal_ips
    try:
        infos = await asyncio.wait_for(
            asyncio.to_thread(socket.getaddrinfo, ascii_host, port, 0, socket.SOCK_STREAM),
            timeout=timeout_sec,
        )
    except (TimeoutError, OSError) as exc:
        return False, f"DNS resolution failed: {exc}", []
    return _check_addrinfo_results(infos)


class _PinnedPublicNetworkBackend(httpcore.AsyncNetworkBackend):
    """Pins outbound TCP sockets directly to SSRF-validated public IPs (eliminates DNS rebinding)."""

    def __init__(self, dns_timeout: float = 2.5) -> None:
        self._inner = httpcore.AnyIOBackend()
        self._dns_timeout = dns_timeout

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        cleaned_host = host.strip().strip("[]").rstrip(".").lower()
        if is_public_ip(cleaned_host):
            pinned_ip = cleaned_host
        else:
            try:
                infos = await asyncio.wait_for(
                    asyncio.to_thread(
                        socket.getaddrinfo,
                        cleaned_host,
                        port,
                        0,
                        socket.SOCK_STREAM,
                    ),
                    timeout=self._dns_timeout,
                )
            except (TimeoutError, OSError) as exc:
                raise httpx.ConnectError(f"DNS lookup failed for {cleaned_host}: {exc}") from exc
            ok, reason, ips = _check_addrinfo_results(infos)
            if not ok or not ips:
                raise SsrfBlockedError(reason or f"Blocked non-public target {cleaned_host}")
            pinned_ip = ips[0]

        return await self._inner.connect_tcp(
            host=pinned_ip,
            port=port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise SsrfBlockedError("Unix domain sockets are disallowed.")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def build_ssrf_pinned_http_client(timeout_sec: float = 3.5) -> httpx.AsyncClient:
    """Return an AsyncClient whose connection pool pins sockets strictly to validated public IPs."""
    pool = httpcore.AsyncConnectionPool(
        network_backend=_PinnedPublicNetworkBackend(),
        max_connections=16,
        max_keepalive_connections=4,
    )
    transport = httpx.AsyncHTTPTransport()
    transport._pool = pool  # noqa: SLF001
    return httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(timeout_sec, connect=2.5),
        follow_redirects=False,
    )


def _verify_decodable_audio(data: bytes) -> None:
    if len(data) < 12:
        raise InvalidMediaError("Audio payload too short.")
    try:
        with av.open(io.BytesIO(data), mode="r") as container:
            if not container.streams.audio:
                raise InvalidMediaError("Container has no audio streams.")
            stream = container.streams.audio[0]
            channels = int(getattr(stream, "channels", 1) or 1)
            if channels > MAX_AUDIO_CHANNELS:
                raise InvalidMediaError(f"Audio channel count {channels} exceeds limit.")
            total_samples = 0
            for frame in container.decode(audio=0):
                total_samples += int(frame.samples)
                if total_samples > MAX_DECODED_AUDIO_SAMPLES:
                    raise InvalidMediaError("Audio duration exceeds maximum safe decoding budget.")
            if total_samples <= 0:
                raise InvalidMediaError("Audio stream contains zero decodable frames.")
    except InvalidMediaError:
        raise
    except Exception as exc:
        raise InvalidMediaError(f"Corrupt or undecodable audio payload: {exc}") from exc


def validate_upload_bytes(
    data: bytes,
    max_bytes: int,
    kind: Literal["image", "audio"],
) -> None:
    """Enforce upload byte ceiling, non-empty check, full pixel/frame decoding, and bomb cap."""
    if not data:
        raise InvalidMediaError(f"Empty {kind} payload.")
    if len(data) > max_bytes:
        raise UploadTooLargeError(
            f"Upload size {len(data)} bytes exceeds limit of {max_bytes} bytes."
        )

    if kind == "audio":
        _verify_decodable_audio(data)
        return

    if not data.startswith(
        (b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"GIF87a", b"GIF89a", b"RIFF")
    ):
        raise InvalidMediaError("Unsupported image header; expected JPEG, PNG, WEBP, or GIF.")
    if data.startswith(b"RIFF") and data[8:12] != b"WEBP":
        raise InvalidMediaError("RIFF container is not a valid WEBP image.")

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as img:
                width, height = img.size
                if width <= 0 or height <= 0 or (width * height) > MAX_DECOMPRESSED_PIXELS:
                    raise InvalidMediaError(
                        "Image dimensions invalid or exceed pixel-bomb threshold."
                    )
                img.verify()
            # Re-open and force full raster pixel decode to catch truncated JPEG scan streams
            with Image.open(io.BytesIO(data)) as decoded_img:
                decoded_img.load()
    except (
        UnidentifiedImageError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        OSError,
        ValueError,
        SyntaxError,
    ) as exc:
        if isinstance(exc, InvalidMediaError):
            raise
        raise InvalidMediaError(f"Corrupt or unsafe image file: {exc}") from exc


def verify_secret(provided: str | None, expected: str) -> bool:
    """Constant-time comparison for PINs and webhook secret tokens."""
    if not provided or not expected:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))
