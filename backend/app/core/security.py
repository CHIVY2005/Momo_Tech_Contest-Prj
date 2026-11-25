"""SSRF network target validation, media upload hardening, and secret comparison."""

from __future__ import annotations

import hmac
import io
import ipaddress
import re
import socket
from typing import Final, Literal
from urllib.parse import urlsplit

from PIL import Image, UnidentifiedImageError

MAX_DECOMPRESSED_PIXELS: Final[int] = 25_000_000

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
    ipaddress.IPv6Network("64:ff9b::/96"),  # NAT64
    ipaddress.IPv6Network("64:ff9b:1::/48"),
    ipaddress.IPv6Network("100::/64"),
    ipaddress.IPv6Network("2001:db8::/32"),
    ipaddress.IPv6Network("fc00::/7"),
    ipaddress.IPv6Network("fe80::/10"),
    ipaddress.IPv6Network("ff00::/8"),
)

_NON_STANDARD_IP_HOST_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:0x[0-9a-f]+|\d+|0[0-7]+(?:\.[0-9a-fx]+)+)$",
    re.IGNORECASE,
)


class UploadTooLargeError(ValueError):
    """Raised when uploaded media exceeds configured max_upload_bytes (HTTP 413)."""


class InvalidMediaError(ValueError):
    """Raised when uploaded media is empty, corrupt, or fails magic-byte checks (HTTP 400)."""


def is_public_ip(ip_str: str) -> bool:
    """Return True strictly for routable public unicast IPv4/IPv6 addresses."""
    cleaned = ip_str.strip().strip("[]")
    if not cleaned or "%" in cleaned:
        return False
    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError:
        return False

    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return is_public_ip(str(addr.ipv4_mapped))
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


def validate_url_target(
    url: str,
    resolve_dns: bool = True,
) -> tuple[bool, str | None, list[str]]:
    """Validate URL scheme, host syntax, and (optionally) all DNS-resolved IPs against SSRF."""
    raw = url.strip()
    if not raw:
        return False, "Empty URL", []

    parsed = urlsplit(raw)
    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Disallowed URL scheme: {parsed.scheme or 'none'}", []
    if parsed.username is not None or parsed.password is not None:
        return False, "Embedded URL credentials are disallowed", []

    hostname = (parsed.hostname or "").strip().rstrip(".").lower()
    if not hostname:
        return False, "Missing hostname", []
    if hostname == "localhost" or hostname.endswith((".localhost", ".local", ".internal")):
        return False, f"Internal hostname blocked: {hostname}", []
    if _NON_STANDARD_IP_HOST_RE.match(hostname):
        return False, f"Obfuscated numeric IP literal blocked: {hostname}", []

    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        literal_ip = None

    if literal_ip is not None:
        if not is_public_ip(str(literal_ip)):
            return False, f"Non-public IP literal blocked: {literal_ip}", []
        return True, None, [str(literal_ip)]

    try:
        ascii_host = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return False, "Invalid internationalized domain name", []

    if not resolve_dns:
        return True, None, []

    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    try:
        infos = socket.getaddrinfo(ascii_host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        return False, f"DNS resolution failed: {exc}", []

    resolved_ips: list[str] = []
    for info in infos:
        sockaddr = info[4]
        ip_candidate = str(sockaddr[0])
        if not is_public_ip(ip_candidate):
            return False, f"DNS resolved to non-public IP: {ip_candidate}", []
        if ip_candidate not in resolved_ips:
            resolved_ips.append(ip_candidate)

    if not resolved_ips:
        return False, "DNS returned no addresses", []
    return True, None, resolved_ips


def _has_valid_audio_magic(data: bytes) -> bool:
    if len(data) < 12:
        return False
    if data.startswith((b"ID3", b"OggS", b"fLaC", b"\x1a\x45\xdf\xa3")):
        return True
    if data.startswith(b"RIFF") and data[8:12] == b"WAVE":
        return True
    if data[4:8] == b"ftyp":
        return True
    # MPEG audio frame sync (MP3 / AAC ADTS)
    return data[0] == 0xFF and (data[1] & 0xE0) == 0xE0


def validate_upload_bytes(
    data: bytes,
    max_bytes: int,
    kind: Literal["image", "audio"],
) -> None:
    """Enforce upload byte ceiling, non-empty check, magic bytes, and pixel-bomb cap."""
    if not data:
        raise InvalidMediaError(f"Empty {kind} payload.")
    if len(data) > max_bytes:
        raise UploadTooLargeError(
            f"Upload size {len(data)} bytes exceeds limit of {max_bytes} bytes."
        )

    if kind == "audio":
        if not _has_valid_audio_magic(data):
            raise InvalidMediaError("Unsupported or corrupt audio container header.")
        return

    if not data.startswith(
        (b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"GIF87a", b"GIF89a", b"RIFF")
    ):
        raise InvalidMediaError("Unsupported image header; expected JPEG, PNG, WEBP, or GIF.")
    if data.startswith(b"RIFF") and data[8:12] != b"WEBP":
        raise InvalidMediaError("RIFF container is not a valid WEBP image.")

    try:
        with Image.open(io.BytesIO(data)) as img:
            width, height = img.size
            if width <= 0 or height <= 0 or (width * height) > MAX_DECOMPRESSED_PIXELS:
                raise InvalidMediaError("Image dimensions invalid or exceed pixel-bomb threshold.")
            img.verify()
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        if isinstance(exc, InvalidMediaError):
            raise
        raise InvalidMediaError(f"Corrupt image file: {exc}") from exc


def verify_secret(provided: str | None, expected: str) -> bool:
    """Constant-time comparison for PINs and webhook secret tokens."""
    if not provided or not expected:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))
