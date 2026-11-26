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
_SCHEMELESS_TOKEN_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![/@\w])(?:www\.|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})"
    r"(?::\d{1,5})?(?:[/?#][^\s<>'\"()\[\]{}]*)?",
    re.IGNORECASE,
)
_DNS_LABEL_RE: Final[re.Pattern[str]] = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
_NON_DOMAIN_FILE_EXTS: Final[frozenset[str]] = frozenset(
    {
        "apk",
        "pdf",
        "jpg",
        "jpeg",
        "png",
        "webp",
        "wav",
        "mp3",
        "m4a",
        "ogg",
        "json",
        "zip",
        "exe",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "txt",
        "csv",
    }
)
_MULTI_PART_PUBLIC_SUFFIXES: Final[frozenset[str]] = frozenset(
    {"com.vn", "gov.vn", "net.vn", "org.vn", "edu.vn", "int.vn", "ac.vn", "co.uk", "org.uk", "com.sg"}
)
_TRAILING_PUNCT: Final[str] = ".,!?;:)'\"»]"

_VN_PHONE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<!\d)(?:\+?84[\s.\-]?|0)(?P<body_head>[35789])(?P<body_rest>(?:[\s.\-]?\d){8})(?!\d)"
)

_BANK_CONTEXT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:"
    r"\bstk(?:\s*(?:nhận|thụ\s*hưởng|tạm\s*giữ|cá\s*nhân|ngân\s*hàng|đích))?\b|"
    r"số\s*(?:tk|tài\s*khoản)(?:\s*(?:nhận|thụ\s*hưởng|tạm\s*giữ))?|"
    r"tài\s*khoản(?:\s*(?:nhận|thụ\s*hưởng|tạm\s*giữ|đến|đích))?|"
    r"\btk(?:\s*(?:nhận|tạm\s*giữ))?\b|"
    r"account(?:\s*no|\s*number)?|vietcombank|techcombank|mbbank|mb\s*bank|bidv|"
    r"vietinbank|agribank|acb|vpbank|tpbank|sacombank|vib|shb|hdbank"
    r")"
    r"[\s:.\-–—]{0,20}(?P<acct>\d{8,16})(?!\d)",
    re.IGNORECASE,
)

# Only match grouped currency numbers starting with 1-9 (never touches 0-prefixed or +84 phones)
_CURRENCY_AMOUNT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![+\d])[1-9]\d{0,2}(?:[.,]\d{3})+(?:\s*(?:đ|vnđ|vnd|đồng))?(?!\d)",
    re.IGNORECASE,
)

_RAW_DIGIT_ACCOUNT_SCRUB_RE: Final[re.Pattern[str]] = re.compile(r"(?<!\d)\d{8,16}(?!\d)")
_LEGACY_8DIGIT_MASK_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<!\d)(\d{2})\d{2}\*{4}\d{2}(\d{2})(?!\d)"
)
_GROUPED_ACCOUNT_SCRUB_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![+\d.,])\d{3,4}(?:[\s\-–—]\d{3,4}){2,3}(?![\d.,])"
)
_LABELED_GROUPED_ACCOUNT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?P<prefix>(?:\bstk|\btk|số\s*tài\s*khoản|tài\s*khoản)[\s:.\-–—]{1,12})"
    r"(?P<acct>\d{2,4}(?:[.\s\-–—]\d{2,4}){2,4})(?!\d)",
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


def _safe_extract_host(url_or_host: str) -> str:
    candidate = url_or_host if "://" in url_or_host else f"https://{url_or_host}"
    try:
        return (urlsplit(candidate).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


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
        extracted = _safe_extract_host(host)
        return extracted or host
    return cleaned.lower()


def hash_ioc(ioc_type: str, value: str) -> str:
    """Compute deterministic SHA-256 hex digest over normalized IOC."""
    canonical = normalize_ioc_value(ioc_type, value)
    payload = f"{ioc_type.strip().lower()}:{canonical}".encode()
    return hashlib.sha256(payload).hexdigest()


def mask_ioc(ioc_type: IocType, value: str) -> str:
    """Mask middle characters of PII so multiple digits are ALWAYS concealed."""
    norm = normalize_ioc_value(ioc_type, value)
    if ioc_type == "phone":
        if len(norm) >= 9:
            return f"{norm[:3]}****{norm[-3:]}"
        if len(norm) >= 6:
            return f"{norm[:2]}****{norm[-1:]}"
        return "****"
    if ioc_type == "bank_account":
        if len(norm) >= 10:
            return f"{norm[:4]}****{norm[-4:]}"
        if len(norm) >= 6:
            return f"{norm[:2]}****{norm[-2:]}"
        return "****"
    parts = [lbl for lbl in norm.split(".") if lbl]
    if len(parts) >= 2:
        last_two = f"{parts[-2]}.{parts[-1]}"
        if len(parts) >= 3 and last_two in _MULTI_PART_PUBLIC_SUFFIXES:
            suffix = last_two
            core = parts[-3]
            has_subdomain = len(parts) > 3
        else:
            suffix = parts[-1]
            core = parts[-2]
            has_subdomain = len(parts) > 2
        visible_core = core[:2] if len(core) > 2 else core[:1]
        masked_core = f"{visible_core}****"
        return f"*.{masked_core}.{suffix}" if has_subdomain else f"{masked_core}.{suffix}"
    return f"{norm[:2]}****"


def _build_spaced_digits_pattern(digits: str) -> re.Pattern[str] | None:
    only_digits = re.sub(r"\D", "", digits)
    if len(only_digits) < 6:
        return None
    sep = r"[\s.\-–—]?"
    body = sep.join(re.escape(ch) for ch in only_digits)
    return re.compile(rf"(?<!\d){body}(?!\d)")


def scrub_free_text_pii(
    text: str,
    known_phones: list[str] | None = None,
    known_accounts: list[str] | None = None,
) -> str:
    """Redact both exact and space/dot/hyphen-formatted phones and bank accounts in free text."""
    if not text:
        return text
    out = text

    for ph in known_phones or []:
        raw_digits = normalize_ioc_value("phone", ph)
        if raw_digits and "****" not in ph:
            masked_ph = mask_ioc("phone", raw_digits)
            out = out.replace(ph, masked_ph)
            pat = _build_spaced_digits_pattern(raw_digits)
            if pat is not None:
                out = pat.sub(masked_ph, out)

    for acct in known_accounts or []:
        raw_digits = normalize_ioc_value("bank_account", acct)
        if raw_digits and "****" not in acct:
            masked_acct = mask_ioc("bank_account", raw_digits)
            out = out.replace(acct, masked_acct)
            pat = _build_spaced_digits_pattern(raw_digits)
            if pat is not None:
                out = pat.sub(masked_acct, out)

    # Catch any remaining formatted Vietnamese phones or grouped/contiguous account numbers
    def _replace_phone(m: re.Match[str]) -> str:
        rest = re.sub(r"\D", "", m.group("body_rest"))
        return mask_ioc("phone", f"0{m.group('body_head')}{rest}")

    out = _VN_PHONE_RE.sub(_replace_phone, out)
    out = _LABELED_GROUPED_ACCOUNT_RE.sub(
        lambda m: f"{m.group('prefix')}{mask_ioc('bank_account', m.group('acct'))}",
        out,
    )
    out = _GROUPED_ACCOUNT_SCRUB_RE.sub(
        lambda m: mask_ioc("bank_account", m.group(0)),
        out,
    )
    out = _RAW_DIGIT_ACCOUNT_SCRUB_RE.sub(
        lambda m: mask_ioc("bank_account", m.group(0)),
        out,
    )
    out = _LEGACY_8DIGIT_MASK_RE.sub(r"\1****\2", out)
    return out


def extract_candidate_urls(text: str) -> list[str]:
    """Extract both explicit http(s) URLs and scheme-less web links (normalized to https://)."""
    found = [m.group(0).rstrip(_TRAILING_PUNCT) for m in _URL_RE.finditer(text)]
    without_http = _URL_RE.sub(" ", text)
    for sm in _SCHEMELESS_TOKEN_RE.finditer(without_http):
        token = sm.group(0).rstrip(_TRAILING_PUNCT)
        if not token:
            continue
        try:
            parts = urlsplit(f"https://{token}")
            _ = parts.port
        except ValueError:
            continue
        host = (parts.hostname or "").lower().rstrip(".")
        labels = [lbl for lbl in host.split(".") if lbl]
        if len(labels) < 2 or not all(_DNS_LABEL_RE.match(lbl) for lbl in labels):
            continue
        tld = labels[-1]
        if not (tld.isalpha() or tld.startswith("xn--")):
            continue
        has_url_suffix = bool(
            (parts.path and parts.path != "/") or parts.query or parts.fragment or parts.port
        )
        if not has_url_suffix and tld in _NON_DOMAIN_FILE_EXTS and not host.startswith("www."):
            continue
        found.append(f"https://{token}")
    return _dedupe_preserve_order(found)


def extract_iocs(text: str, extra_urls: list[str] | None = None) -> ExtractedIOCs:
    """Extract Vietnamese phones, bank accounts, URLs, domains, and targeted brands."""
    raw_urls = extract_candidate_urls(text)
    if extra_urls:
        for candidate in extra_urls:
            stripped = candidate.strip().rstrip(_TRAILING_PUNCT)
            if stripped:
                raw_urls.append(stripped if "://" in stripped else f"https://{stripped}")
    urls = _dedupe_preserve_order(raw_urls)

    domains: list[str] = []
    for u in urls:
        host = _safe_extract_host(u)
        if host:
            domains.append(host)
    domains = _dedupe_preserve_order(domains)

    scrubbed = _URL_RE.sub(" ", text)
    scrubbed = _SCHEMELESS_TOKEN_RE.sub(" ", scrubbed)

    raw_accounts: list[str] = []
    account_spans: list[tuple[int, int]] = []
    for match in _BANK_CONTEXT_RE.finditer(scrubbed):
        raw_accounts.append(match.group("acct"))
        account_spans.append(match.span("acct"))

    chars = list(scrubbed)
    for start, end in account_spans:
        for idx in range(start, end):
            chars[idx] = " "
    without_accounts = "".join(chars)

    phones: list[str] = []
    for match in _VN_PHONE_RE.finditer(without_accounts):
        rest_digits = re.sub(r"\D", "", match.group("body_rest"))
        phones.append(f"0{match.group('body_head')}{rest_digits}")

    _ = _CURRENCY_AMOUNT_RE

    brands: list[str] = []
    for brand_name, pattern in _BRAND_PATTERNS:
        if pattern.search(text):
            brands.append(brand_name)

    return ExtractedIOCs(
        phones=_dedupe_preserve_order(phones),
        bank_accounts=_dedupe_preserve_order(raw_accounts),
        urls=urls,
        domains=domains,
        brands=brands,
    )
