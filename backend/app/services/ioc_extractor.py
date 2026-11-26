"""Vietnamese IOC extraction (phones, bank accounts, URLs, brands), SHA-256, and PII masking."""

from __future__ import annotations

import hashlib
import hmac
import re
import unicodedata
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
_NON_TLD_FILE_EXTS: Final[frozenset[str]] = frozenset(
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
        "exe",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "txt",
        "csv",
    }
)
_AMBIGUOUS_TLD_FILE_EXTS: Final[frozenset[str]] = frozenset({"zip", "mov"})
_FILENAME_CONTEXT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:tệp(?:\s+tin)?|tập\s+tin|file|ảnh|hình|tài\s+liệu|đính\s+kèm|"
    r"nén|giải\s+nén|archive|attachment|document)[\s:.\-\"'\u00ab]*$",
    re.IGNORECASE,
)
_MULTI_PART_PUBLIC_SUFFIXES: Final[frozenset[str]] = frozenset(
    {"com.vn", "gov.vn", "net.vn", "org.vn", "edu.vn", "int.vn", "ac.vn", "co.uk", "org.uk", "com.sg"}
)
RECOGNIZED_DISPLAY_PUBLIC_SUFFIXES: Final[frozenset[str]] = frozenset(
    {
        "com",
        "net",
        "org",
        "edu",
        "gov",
        "int",
        "mil",
        "info",
        "biz",
        "pro",
        "vn",
        "us",
        "uk",
        "sg",
        "au",
        "ca",
        "de",
        "fr",
        "jp",
        "kr",
        "cn",
        "hk",
        "tw",
        "eu",
        "id",
        "th",
        "my",
        "ph",
        "la",
        "kh",
        "in",
        "nz",
        "nl",
        "ch",
        "top",
        "vip",
        "xyz",
        "site",
        "online",
        "click",
        "shop",
        "store",
        "app",
        "dev",
        "io",
        "ai",
        "co",
        "me",
        "tv",
        "cc",
        "gg",
        "asia",
        "club",
        "live",
        "link",
        "tech",
        "cloud",
        "space",
        "work",
        "fun",
        "icu",
        "buzz",
        "lat",
        "cfd",
        "sbs",
        "quest",
        "cyou",
        "life",
        "world",
        "today",
        "news",
        "media",
        "email",
        "finance",
        "support",
        "services",
        "solutions",
        "center",
        "digital",
        "network",
        "systems",
        "security",
        "banking",
        "pay",
        "zip",
        "mov",
        "example",
        *_MULTI_PART_PUBLIC_SUFFIXES,
    }
)
_TRAILING_PUNCT: Final[str] = ".,!?;:)'\"»]"

_VN_PHONE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<!\d)(?:\+?84[\s.\-]?|0)(?P<body_head>[35789])(?P<body_rest>(?:[\s.\-]?\d){8})(?!\d)"
)
_ALT_VN_PHONE_SCRUB_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<!\d)(?:\(\+?84\)[\s.\-/_]*|(?:\+?84)[\s.\-/_]*\(0\)[\s.\-/_]*|(?:\+?84)[\s.\-/_]?|0)"
    r"(?P<body_head>[35789])(?P<body_rest>(?:[\s.\-/_]?\d){8})(?!\d)"
)

# Only match grouped currency numbers starting with 1-9 (never touches 0-prefixed or +84 phones)
_CURRENCY_AMOUNT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![+\d])[1-9]\d{0,2}(?:[.,]\d{3})+(?:\s*(?:đ|vnđ|vnd|đồng))?(?!\d)",
    re.IGNORECASE,
)
_STRICT_CURRENCY_SYMBOL_AFTER_RE: Final[re.Pattern[str]] = re.compile(
    r"^[ \t]*(?:vn[đd]|[đd])(?!\w)",
    re.IGNORECASE,
)
_BANK_CURRENCY_WORD_AFTER_RE: Final[re.Pattern[str]] = re.compile(
    r"^[ \t]*(?:vn[đd]|[đd](?!\w)|(?:đồng|dong)(?!\w)"
    r"(?![ \t]+(?:phạm|pham|bọn|bon|thời|thoi|ý|y|chí|chi|loạt|loat|"
    r"hành|hanh|tình|tinh|đội|doi|nghiệp|nghiep)\b))",
    re.IGNORECASE,
)

_RAW_DIGIT_ACCOUNT_SCRUB_RE: Final[re.Pattern[str]] = re.compile(r"(?<!\d)\d{8,19}(?!\d)")
_LEGACY_8DIGIT_MASK_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<!\d)(\d{2})\d{2}\*{4}\d{2}(\d{2})(?!\d)"
)
_GROUPED_ACCOUNT_SCRUB_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![+\d.,])\d{3,4}(?:[\s\-–—]\d{2,5}){2,4}(?![\d.]|,\d)"
)
_TWO_GROUP_ACCOUNT_SCRUB_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![+\d.,/:])\d{4,10}[\s\-–—]\d{4,10}(?![\d./:]|,\d)"
)
_DOT_GROUPED_ACCOUNT_SCRUB_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![+\d.,])\d{4}(?:\.\d{2,5}){2,3}(?![\d.]|,\d)"
)
_DATE_LIKE_SPAN_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:\d{1,2}[.\-/]\d{1,2}[.\-/](?:19|20)\d{2}|(?:19|20)\d{2}[.\-/]\d{1,2}[.\-/]\d{1,2})$"
)

# Intra-account separators ONLY: horizontal spaces/tabs or tight single '.'/'-' between digits
# (never bridges clause delimiters such as ' - ', ' — ', or '. ').
_ACCT_SPAN_PAT: Final[str] = r"(?P<acct>\d+(?:(?:[ \t]+|[.\-])\d+)*)(?!\d|[ \t]+\d|[.\-]\d)"
_LABEL_SEP_PAT: Final[str] = r"(?:[ \t:.\-\u2013\u2014]{1,16}|[ \t:.\-\u2013\u2014]{0,12}\r?\n[ \t]{0,12})"

_EXPLICIT_RECIPIENT_LABEL_PAT: Final[str] = (
    r"(?:s[ốo][ \t]*)?(?:\bstk|\btk|t[àa]i[ \t]*kho[ảa]n)[ \t]*"
    r"(?:nh[ậa]n|th[ụu][ \t]*h[ưởu][ởo]ng|[đd][ếe]n|[đd][íi]ch|ng[ườu][ờo]i[ \t]*nh[ậa]n)"
    r"|(?:t[ớo]i|[đd][ếe]n)[ \t]+(?:s[ốo][ \t]*)?(?:stk|tk|t[àa]i[ \t]*kho[ảa]n)"
    r"|\b(?:beneficiary|recipient)[ \t]+account(?:[ \t]*(?:no\.?|number))?"
)
_EXPLICIT_ACCOUNT_LABEL_PAT: Final[str] = (
    rf"(?:{_EXPLICIT_RECIPIENT_LABEL_PAT})"
    r"|(?:s[ốo][ \t]*)?(?:\bstk|\btk|t[àa]i[ \t]*kho[ảa]n)"
    r"(?:[ \t]*(?:t[ạa]m[ \t]*gi[ữ u]|c[áa][ \t]*nh[âa]n|ng[âa]n[ \t]*h[àa]ng))?"
    r"|\baccount(?:[ \t]*no\.?|[ \t]*number)?"
)
_BANK_NAME_LABEL_PAT: Final[str] = (
    r"\b(?:vietcombank(?:digibank)?|techcombank(?:mobile)?|mbbank|mb[ \t]*bank|bidv|vietinbank|"
    r"agribank|acb|vpbank|tpbank|sacombank|vib|shb|hdbank)\b"
)


def fold_vi_ascii(text: str) -> str:
    """Fold Vietnamese diacritics 1-to-1 per NFC character for OCR-tolerant matching."""
    nfc = unicodedata.normalize("NFC", text)
    out: list[str] = []
    for ch in nfc:
        if ch == "đ":
            out.append("d")
        elif ch == "Đ":
            out.append("D")
        elif ord(ch) < 128:
            out.append(ch)
        else:
            decomp = unicodedata.normalize("NFD", ch)
            base = decomp[0] if decomp else ch
            out.append(base if ord(base) < 128 else ch)
    return "".join(out)

EXPLICIT_RECIPIENT_SPAN_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?P<prefix>(?:{_EXPLICIT_RECIPIENT_LABEL_PAT}){_LABEL_SEP_PAT}){_ACCT_SPAN_PAT}",
    re.IGNORECASE,
)

LABELED_ACCOUNT_SPAN_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?P<prefix>(?:(?P<explicit_label>{_EXPLICIT_ACCOUNT_LABEL_PAT})"
    rf"|(?P<bank_label>{_BANK_NAME_LABEL_PAT})){_LABEL_SEP_PAT}){_ACCT_SPAN_PAT}",
    re.IGNORECASE,
)


def is_labeled_account_match(text: str, match: re.Match[str]) -> bool:
    raw_tok = match.group("acct")
    tail = text[match.end("acct") :]
    if match.group("explicit_label") is not None:
        return not _STRICT_CURRENCY_SYMBOL_AFTER_RE.match(tail)
    if _BANK_CURRENCY_WORD_AFTER_RE.match(tail):
        return False
    if _DATE_LIKE_SPAN_RE.fullmatch(raw_tok):
        return False
    return not _CURRENCY_AMOUNT_RE.fullmatch(raw_tok)


_is_labeled_account_match = is_labeled_account_match

_BRAND_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("Vietcombank", re.compile(r"\b(?:vietcombank(?:digibank)?|vcb)\b", re.IGNORECASE)),
    ("Techcombank", re.compile(r"\b(?:techcombank(?:mobile)?|tcb)\b", re.IGNORECASE)),
    ("MB Bank", re.compile(r"\b(?:mb\s*bank|mbbank)\b", re.IGNORECASE)),
    ("BIDV", re.compile(r"\bbidv(?:smartbanking)?\b", re.IGNORECASE)),
    ("VietinBank", re.compile(r"\b(?:vietinbank(?:ipay)?|ctg)\b", re.IGNORECASE)),
    ("Agribank", re.compile(r"\bagribank(?:plus)?\b", re.IGNORECASE)),
    ("ACB", re.compile(r"\bacb(?:one)?\b", re.IGNORECASE)),
    ("VPBank", re.compile(r"\bvpbank(?:neo)?\b", re.IGNORECASE)),
    ("TPBank", re.compile(r"\btpbank\b", re.IGNORECASE)),
    ("Sacombank", re.compile(r"\bsacombank(?:pay)?\b", re.IGNORECASE)),
    ("VIB", re.compile(r"\bvib\b", re.IGNORECASE)),
    ("SHB", re.compile(r"\bshb\b", re.IGNORECASE)),
    ("HDBank", re.compile(r"\bhdbank\b", re.IGNORECASE)),
    ("NAPAS", re.compile(r"\bnapas(?:247)?\b", re.IGNORECASE)),
    ("VNeID", re.compile(r"\bvneid\b", re.IGNORECASE)),
    ("Bộ Công an", re.compile(r"\b(?:bo\s+cong\s+an|cuc\s+a05)\b", re.IGNORECASE)),
    ("Cục Thuế", re.compile(r"\b(?:tong\s+cuc\s+thue|cuc\s+thue|etax)\b", re.IGNORECASE)),
    ("EVN", re.compile(r"\b(?:dien\s+luc|evn)\b", re.IGNORECASE)),
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
        if re.fullmatch(r"[A-Za-z0-9\-_]+", cleaned) and any(ch.isalpha() for ch in cleaned):
            return re.sub(r"[^A-Za-z0-9]", "", cleaned).upper()
        return re.sub(r"\D", "", cleaned)
    if ioc_type == "domain":
        host = cleaned.lower().rstrip(".")
        extracted = _safe_extract_host(host)
        return extracted or host
    return cleaned.lower()


def hash_ioc(ioc_type: str, value: str, *, hmac_key: str | None = None) -> str:
    """Compute keyed HMAC-SHA256 (when hmac_key is provided) or SHA-256 over normalized IOC."""
    canonical = normalize_ioc_value(ioc_type, value)
    payload = f"{ioc_type.strip().lower()}:{canonical}".encode()
    if hmac_key:
        return hmac.new(hmac_key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
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
        if len(norm) >= 6:
            return f"{norm[:2]}****{norm[-2:]}"
        return "****"
    parts = [lbl for lbl in norm.split(".") if lbl]
    if len(parts) >= 2 and all(_DNS_LABEL_RE.match(lbl) for lbl in parts):
        last_two = f"{parts[-2]}.{parts[-1]}"
        if len(parts) >= 3 and last_two in _MULTI_PART_PUBLIC_SUFFIXES:
            suffix = last_two
            core = parts[-3]
            has_subdomain = len(parts) > 3
        else:
            suffix = parts[-1]
            core = parts[-2]
            has_subdomain = len(parts) > 2
        if suffix not in RECOGNIZED_DISPLAY_PUBLIC_SUFFIXES:
            return f"dom_{hash_ioc('domain', value)[:6]}****"
        alnum_head = re.sub(r"[^a-z0-9]", "", core.lower())[:2]
        if not alnum_head or alnum_head.isdigit():
            return f"dom_{hash_ioc('domain', value)[:6]}****"
        if re.search(r"\d{6,}", core) and any(ch.isdigit() for ch in alnum_head):
            return f"dom_{hash_ioc('domain', value)[:6]}****"
        masked_core = f"{alnum_head}****"
        return f"*.{masked_core}.{suffix}" if has_subdomain else f"{masked_core}.{suffix}"
    return f"dom_{hash_ioc('domain', value)[:6]}****"


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

    def _replace_labeled_acct(m: re.Match[str]) -> str:
        if not _is_labeled_account_match(m.string, m):
            return m.group(0)
        digits = re.sub(r"\D", "", m.group("acct"))
        if 6 <= len(digits) <= 24:
            return f"{m.group('prefix')}{mask_ioc('bank_account', digits)}"
        return m.group(0)

    def _replace_grouped_acct(m: re.Match[str]) -> str:
        tok = m.group(0)
        if _DATE_LIKE_SPAN_RE.fullmatch(tok):
            return tok
        digits = re.sub(r"\D", "", tok)
        if 8 <= len(digits) <= 19:
            return mask_ioc("bank_account", digits)
        return tok

    out = _ALT_VN_PHONE_SCRUB_RE.sub(_replace_phone, out)
    out = LABELED_ACCOUNT_SPAN_RE.sub(_replace_labeled_acct, out)
    out = _GROUPED_ACCOUNT_SCRUB_RE.sub(_replace_grouped_acct, out)
    out = _TWO_GROUP_ACCOUNT_SCRUB_RE.sub(_replace_grouped_acct, out)
    out = _DOT_GROUPED_ACCOUNT_SCRUB_RE.sub(_replace_grouped_acct, out)
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
        if not has_url_suffix and not host.startswith("www."):
            if tld in _NON_TLD_FILE_EXTS:
                continue
            if tld in _AMBIGUOUS_TLD_FILE_EXTS:
                prefix_ctx = without_http[max(0, sm.start() - 32) : sm.start()]
                if _FILENAME_CONTEXT_RE.search(prefix_ctx):
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

    folded_text = fold_vi_ascii(text)
    scrubbed = _URL_RE.sub(" ", folded_text)
    scrubbed = _SCHEMELESS_TOKEN_RE.sub(" ", scrubbed)

    raw_accounts: list[str] = []
    chars = list(scrubbed)
    for match in LABELED_ACCOUNT_SPAN_RE.finditer(scrubbed):
        if not _is_labeled_account_match(scrubbed, match):
            continue
        digits = re.sub(r"\D", "", match.group("acct"))
        if 6 <= len(digits) <= 19:
            raw_accounts.append(digits)
            start, end = match.span("acct")
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
        if pattern.search(folded_text):
            brands.append(brand_name)

    return ExtractedIOCs(
        phones=_dedupe_preserve_order(phones),
        bank_accounts=_dedupe_preserve_order(raw_accounts),
        urls=urls,
        domains=domains,
        brands=brands,
    )
