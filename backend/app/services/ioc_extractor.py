"""Vietnamese IOC extraction (phones, bank accounts, URLs, brands), SHA-256, and PII masking."""

from __future__ import annotations

import hashlib
import re
from typing import Final
from urllib.parse import urlsplit

from app.schemas import ExtractedIOCs, IocType

_URL_RE: Final[re.Pattern[str]] = re.compile(
    r"https?://[^\s<>'\"()\[\]{}]+",
    re.IGNORECASE,
)
_TRAILING_PUNCT: Final[str] = ".,!?;:)'\"»]"

_VN_PHONE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<!\d)(?:\+?84[\s.\-]?|0)(?P<body_head>[35789])(?P<body_rest>(?:[\s.\-]?\d){8})(?!\d)"
)

_BANK_CONTEXT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:\bstk\b|số\s*tài\s*khoản|tài\s*khoản(?:\s*nhận|\s*thụ\s*hưởng)?|\btk\b|"
    r"account(?:\s*no|\s*number)?|vietcombank|techcombank|mbbank|mb\s*bank|bidv|"
    r"vietinbank|agribank|acb|vpbank|tpbank|sacombank|vib|shb|hdbank)"
    r"[\s:.\-–—]{0,20}(?P<acct>\d{9,16})(?!\d)",
    re.IGNORECASE,
)

_CURRENCY_AMOUNT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![+\d])[1-9]\d{0,2}(?:[.,]\d{3})+(?:\s*(?:đ|vnđ|vnd|đồng))?(?!\d)",
    re.IGNORECASE,
)

_BRAND_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("Vietcombank", re.compile(r"\b(?:vietcombank|vcb)\b", re.IGNORECASE)),
    ("Techcombank", re.compile(r"\b(?:techcombank|tcb)\b", re.IGNORECASE)),
    ("MB Bank", re.compile(r"\b(?:mb\s*bank|mbbank)\b", re.IGNORECASE)),
    ("BIDV", re.compile(r"\bbidv\b", re.IGNORECASE)),
    ("VietinBank", re.compile(r"\b(?:vietinbank|ctg)\b", re.IGNORECASE)),
    ("Agribank", re.compile(r"\bagribank\b", re.IGNORECASE)),
    ("ACB", re.compile(r"\bacb\b", re.IGNORECASE)),
    ("VPBank", re.compile(r"\bvpbank\b", re.IGNORECASE)),
    ("TPBank", re.compile(r"\btpbank\b", re.IGNORECASE)),
    ("Sacombank", re.compile(r"\bsacombank\b", re.IGNORECASE)),
    ("VIB", re.compile(r"\bvib\b", re.IGNORECASE)),
    ("SHB", re.compile(r"\bshb\b", re.IGNORECASE)),
    ("HDBank", re.compile(r"\bhdbank\b", re.IGNORECASE)),
    ("NAPAS", re.compile(r"\bnapas(?:247)?\b", re.IGNORECASE)),
    ("VNeID", re.compile(r"\bvneid\b", re.IGNORECASE)),
    ("Bộ Công an", re.compile(r"\b(?:bộ\s+công\s+an|cục\s+a05)\b", re.IGNORECASE)),
    ("Cục Thuế", re.compile(r"\b(?:tổng\s+cục\s+thuế|cục\s+thuế|etax)\b", re.IGNORECASE)),
    ("EVN", re.compile(r"\b(?:điện\s+lực|evn)\b", re.IGNORECASE)),
    ("ZaloPay", re.compile(r"\bzalopay\b", re.IGNORECASE)),
    ("VNPay", re.compile(r"\bvnpay\b", re.IGNORECASE)),
    ("Viettel Money", re.compile(r"\bviettel\s*money\b", re.IGNORECASE)),
    ("Shopee", re.compile(r"\bshopee\b", re.IGNORECASE)),
    ("TikTok Shop", re.compile(r"\btiktok\s*shop\b", re.IGNORECASE)),
)


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def normalize_ioc_value(ioc_type: str, value: str) -> str:
    """Canonicalize raw IOC value prior to hashing or masking."""
    cleaned = value.strip()
    if ioc_type == "phone":
        digits = re.sub(r"\D", "", cleaned)
        if digits.startswith("84") and len(digits) == 11:
            return "0" + digits[2:]
        return digits
    if ioc_type == "bank_account":
        return re.sub(r"\D", "", cleaned)
    if ioc_type == "domain":
        host = cleaned.lower().rstrip(".")
        if "://" in host:
            host = (urlsplit(host).hostname or host).lower().rstrip(".")
        return host
    return cleaned.lower()


def hash_ioc(ioc_type: str, value: str) -> str:
    """Compute deterministic SHA-256 hex digest over normalized IOC."""
    canonical = normalize_ioc_value(ioc_type, value)
    payload = f"{ioc_type.strip().lower()}:{canonical}".encode()
    return hashlib.sha256(payload).hexdigest()


def mask_ioc(ioc_type: IocType, value: str) -> str:
    """Mask middle characters of PII (phones, bank accounts, domains) for public display."""
    norm = normalize_ioc_value(ioc_type, value)
    if ioc_type == "phone":
        if len(norm) >= 7:
            return f"{norm[:3]}****{norm[-3:]}"
        return "****"
    if ioc_type == "bank_account":
        if len(norm) >= 8:
            return f"{norm[:4]}****{norm[-4:]}"
        if len(norm) >= 4:
            return f"{norm[:2]}****{norm[-2:]}"
        return "****"
    # domain masking: preserve subdomain prefix + TLD while redacting core label
    parts = norm.split(".")
    if len(parts) >= 2:
        tld = parts[-1]
        core = parts[-2]
        prefix = ".".join(parts[:-2])
        visible_core = core[:2] if len(core) > 2 else core[:1]
        masked_core = f"{visible_core}****"
        return f"{prefix}.{masked_core}.{tld}" if prefix else f"{masked_core}.{tld}"
    return f"{norm[:2]}****"


def extract_iocs(text: str, extra_urls: list[str] | None = None) -> ExtractedIOCs:
    """Extract Vietnamese phones, bank accounts, URLs, domains, and targeted brands."""
    raw_urls = [m.group(0).rstrip(_TRAILING_PUNCT) for m in _URL_RE.finditer(text)]
    if extra_urls:
        for candidate in extra_urls:
            stripped = candidate.strip().rstrip(_TRAILING_PUNCT)
            if stripped:
                raw_urls.append(stripped)
    urls = _dedupe_preserve_order(raw_urls)

    domains: list[str] = []
    for u in urls:
        host = (urlsplit(u).hostname or "").lower().rstrip(".")
        if host:
            domains.append(host)
    domains = _dedupe_preserve_order(domains)

    # Strip URLs first, extract phones (which start with 0 or +84), then strip currency amounts
    scrubbed = _URL_RE.sub(" ", text)

    raw_phones: list[str] = []
    phone_spans: list[tuple[int, int]] = []
    for match in _VN_PHONE_RE.finditer(scrubbed):
        rest_digits = re.sub(r"\D", "", match.group("body_rest"))
        normalized_phone = f"0{match.group('body_head')}{rest_digits}"
        raw_phones.append(normalized_phone)
        phone_spans.append(match.span())

    chars = list(scrubbed)
    for start, end in phone_spans:
        for idx in range(start, end):
            chars[idx] = " "
    scrubbed_no_phones = "".join(chars)
    scrubbed_no_currency = _CURRENCY_AMOUNT_RE.sub(" ", scrubbed_no_phones)

    accounts: list[str] = []
    for match in _BANK_CONTEXT_RE.finditer(scrubbed_no_currency):
        acct = match.group("acct")
        accounts.append(acct)
    accounts = _dedupe_preserve_order(accounts)
    account_set = set(accounts)

    phones = _dedupe_preserve_order([p for p in raw_phones if p not in account_set])

    brands: list[str] = []
    for brand_name, pattern in _BRAND_PATTERNS:
        if pattern.search(text):
            brands.append(brand_name)

    return ExtractedIOCs(
        phones=phones,
        bank_accounts=accounts,
        urls=urls,
        domains=domains,
        brands=brands,
    )
