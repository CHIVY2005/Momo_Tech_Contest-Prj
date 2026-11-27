"""SSRF network target validation, IP-pinned HTTP transport, media hardening, and secret auth."""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import socket
from collections.abc import Iterable
from typing import Any, Final
from urllib.parse import urlsplit

import httpcore
import httpx

from app.core.media_security import (
    MAX_AUDIO_CHANNELS,
    MAX_DECODED_AUDIO_SAMPLES,
    MAX_DECOMPRESSED_PIXELS,
    MAX_IMAGE_DIMENSION,
    InvalidMediaError,
    UploadTooLargeError,
    decode_audio_to_pcm16k,
    detect_audio_format,
    detect_canonical_image_mime,
    normalize_image_for_downstream,
    validate_upload_bytes,
)
from app.core.url_authority import (
    has_disallowed_url_backslash,
    has_invisible_url_chars,
    is_obfuscated_numeric_ip,
    is_strict_ldh_hostname,
    strip_single_trailing_dot,
)

__all__ = [
    "MAX_AUDIO_CHANNELS",
    "MAX_DECODED_AUDIO_SAMPLES",
    "MAX_DECOMPRESSED_PIXELS",
    "MAX_IMAGE_DIMENSION",
    "InvalidMediaError",
    "SsrfBlockedError",
    "UploadTooLargeError",
    "async_validate_url_target",
    "build_ssrf_pinned_http_client",
    "decode_audio_to_pcm16k",
    "detect_audio_format",
    "detect_canonical_image_mime",
    "is_public_ip",
    "normalize_image_for_downstream",
    "validate_upload_bytes",
    "validate_url_target",
    "verify_secret",
]

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
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in raw):
        return False, "Disallowed control character in URL", "", 0, []
    if has_invisible_url_chars(raw):
        return False, "Disallowed invisible character in URL", "", 0, []
    if has_disallowed_url_backslash(raw):
        return False, "Disallowed backslash in URL authority", "", 0, []
    try:
        parsed = urlsplit(raw)
        scheme = parsed.scheme.lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        raw_host_full = (parsed.hostname or "").lower()
    except ValueError as exc:
        return False, f"Malformed URL authority: {exc}", "", 0, []

    if scheme not in ("http", "https"):
        return False, f"Disallowed URL scheme: {scheme or 'none'}", "", 0, []
    if parsed.username is not None or parsed.password is not None:
        return False, "Embedded URL credentials are disallowed", "", 0, []
    if any(ch.isspace() for ch in raw_host_full):
        return False, "Whitespace in hostname is disallowed", "", 0, []

    had_trailing_dot = raw_host_full.endswith(".")
    hostname = strip_single_trailing_dot(raw_host_full)
    if not hostname or hostname.endswith("."):
        return False, "Missing or malformed hostname", "", 0, []
    if hostname == "localhost" or hostname.endswith((".localhost", ".local", ".internal")):
        return False, f"Internal hostname blocked: {hostname}", "", 0, []
    if is_obfuscated_numeric_ip(hostname):
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
        idna_host = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return False, "Invalid internationalized domain name", "", 0, []
    ascii_host = idna_host if had_trailing_dot else strip_single_trailing_dot(idna_host)

    if (
        not ascii_host
        or ascii_host == "localhost"
        or ascii_host.endswith((".localhost", ".local", ".internal"))
    ):
        return False, f"Internal hostname blocked: {ascii_host}", "", 0, []
    if is_obfuscated_numeric_ip(ascii_host):
        return False, f"Obfuscated numeric IP literal blocked: {ascii_host}", "", 0, []

    try:
        post_ip = ipaddress.ip_address(ascii_host)
    except ValueError:
        post_ip = None

    if post_ip is not None:
        if not is_public_ip(ascii_host):
            return False, f"Non-public IP literal blocked: {ascii_host}", "", 0, []
        return True, None, ascii_host, port, [str(post_ip)]

    if not is_strict_ldh_hostname(ascii_host):
        return False, f"Invalid LDH hostname: {ascii_host}", "", 0, []

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
        cleaned_host = strip_single_trailing_dot(host.strip().strip("[]").lower())
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


def verify_secret(provided: str | None, expected: str) -> bool:
    """Constant-time comparison for PINs and webhook secret tokens."""
    if not provided or not expected:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))
