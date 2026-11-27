"""Strict WHATWG-aligned URL authority, backslash, IDNA, and LDH hostname validators."""

from __future__ import annotations

import ipaddress
import re
from typing import Final
from urllib.parse import urlsplit

_SCHEME_BACKSLASH_RE: Final[re.Pattern[str]] = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9+.-]*:[/\\]*\\"
)
_LDH_LABEL_RE: Final[re.Pattern[str]] = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_NUMERIC_HOST_LABEL_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:0x[0-9a-f]+|\d+)$",
    re.IGNORECASE,
)
_INVISIBLE_URL_CHAR_RE: Final[re.Pattern[str]] = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]"
)


def has_invisible_url_chars(raw: str) -> bool:
    """Return True if raw URL contains invisible zero-width or bidi format characters."""
    return _INVISIBLE_URL_CHAR_RE.search(raw) is not None


def has_disallowed_url_chars(raw: str) -> bool:
    """Return True if raw URL contains ASCII control chars or invisible format characters."""
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in raw) or has_invisible_url_chars(raw)


def has_disallowed_url_backslash(url: str) -> bool:
    """Return True if raw URL contains a backslash in its scheme/authority section."""
    raw = url.strip()
    if not raw:
        return False
    if _SCHEME_BACKSLASH_RE.match(raw):
        return True
    if "://" in raw:
        after_scheme = raw.split("://", 1)[1]
    elif raw.startswith("//"):
        after_scheme = raw[2:]
    else:
        after_scheme = raw
    authority = re.split(r"[/?#]", after_scheme, maxsplit=1)[0]
    return "\\" in authority


def strip_single_trailing_dot(host: str) -> str:
    """Strip at most one canonical FQDN trailing dot so multi-dot hosts fail LDH checks."""
    return host[:-1] if host.endswith(".") else host


def is_obfuscated_numeric_ip(hostname: str) -> bool:
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


def is_strict_ldh_hostname(ascii_host: str) -> bool:
    """Return True iff ascii_host is a valid RFC 1035/1123 LDH DNS hostname."""
    if not ascii_host or len(ascii_host) > 253 or not ascii_host.isascii():
        return False
    labels = ascii_host.split(".")
    if any(not lbl for lbl in labels):
        return False
    return all(_LDH_LABEL_RE.fullmatch(lbl) is not None for lbl in labels)


def extract_strict_ascii_host(url: str) -> str | None:
    """Parse URL authority strictly, rejecting control/invisible chars, backslashes, and bad IDNA/LDH."""
    raw = url.strip()
    if not raw or has_disallowed_url_chars(raw) or has_disallowed_url_backslash(raw):
        return None
    try:
        parsed = urlsplit(raw)
        _ = parsed.port
    except ValueError:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    raw_host_full = (parsed.hostname or "").lower()
    if not raw_host_full or any(ch.isspace() for ch in raw_host_full):
        return None
    had_ascii_dot = raw_host_full.endswith(".")
    raw_host = strip_single_trailing_dot(raw_host_full)
    if not raw_host or any(ch.isspace() or ord(ch) < 32 for ch in raw_host):
        return None
    try:
        ipaddress.ip_address(raw_host)
        return raw_host
    except ValueError:
        pass
    try:
        encoded_host = raw_host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    ascii_host = encoded_host if had_ascii_dot else strip_single_trailing_dot(encoded_host)
    if is_obfuscated_numeric_ip(ascii_host):
        return None
    try:
        ipaddress.ip_address(ascii_host)
        return ascii_host
    except ValueError:
        pass
    if not is_strict_ldh_hostname(ascii_host):
        return None
    return ascii_host
