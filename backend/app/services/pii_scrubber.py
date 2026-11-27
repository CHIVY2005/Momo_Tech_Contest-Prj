"""Persisted-text PII scrubber extending free-text phone/account redaction (NV-23)."""

from __future__ import annotations

import re
import secrets
from functools import lru_cache
from typing import Final

from app.services.ioc_extractor import mask_ioc, normalize_ioc_value, scrub_free_text_pii

_HEX_ALPHA: Final[dict[int, int]] = str.maketrans("0123456789abcdef", "ABCDEFGHIJKLMNOP")
_INTERNAL_ID_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(?:vs|drf)_[0-9a-f]{32}\b|\b(?:rule|aud)_[0-9a-f]{10}\b"
)
_INVIS_RE: Final[re.Pattern[str]] = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
_URL_USERINFO_RE: Final[re.Pattern[str]] = re.compile(
    r"((?:https?|ftps?|sftp)://|(?<![:\w/])//)([^\s<>'\"()\[\]{}@/]+)@",
    re.IGNORECASE,
)
_U: Final[str] = r"[^\W_]"
_EMAIL_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?<![\w.%+\-])[\w.%+\-]{{1,64}}@"
    rf"(?:{_U}(?:(?:{_U}|-){{0,61}}{_U})?[\.\u3002\uff0e\uff61])+"
    rf"(?:[^\W\d_]{{2,24}}|xn--[A-Za-z0-9\-]{{2,59}})(?![\w\-])",
    re.IGNORECASE,
)
_OTP_PIN_CVV_RE: Final[re.Pattern[str]] = re.compile(
    r"(?P<prefix>"
    r"(?:(?:m[ãa][ \t]+)?\b(?:otp|smart[ \t]*otp|soft[ \t]*otp|pin|cvv2?|cvc2?|csc)\b"
    r"|\bm[ãa][ \t]+(?:x[áa]c[ \t]*(?:th[ựư]c|nh[ậa]n)|b[ảa]o[ \t]*m[ậa]t)\b"
    r"|\bverification[ \t]+code\b)"
    r"(?:[ \t]+c[ủu]a[ \t]+(?:b[ạa]n|qu[ýy][ \t]+kh[áa]ch))?"
    r"(?:[ \t]*(?::|=|\bl[àa]\b|\bis\b)[ \t]*|[ \t]+))"
    r"(?P<secret>\d(?:[ \t\-]?\d){2,7})(?!\d)",
    re.IGNORECASE,
)
_CRED_LABEL_PAT: Final[str] = (
    r"(?:\bm[ậa]t[ \t]+kh[ẩa]u"
    r"(?:[ \t]+(?:[đd][ăa]ng[ \t]+nh[ậa]p|ng[âa]n[ \t]+h[àa]ng|giao[ \t]+d[ịi]ch))?"
    r"|\b(?:password|passwd|passcode|pass|mk)\b)"
    r"(?:[ \t]+c[ủu]a[ \t]+(?:b[ạa]n|qu[ýy][ \t]+kh[áa]ch))?"
)
_CRED_VAL_PAT: Final[str] = (
    r"(?P<quote>['\"]?)(?P<secret>(?=[^\s,;\"'<>()\[\]{}]*(?:\d|[!@#$%^&*_+=~]))"
    r"[^\s,;\"'<>()\[\]{}]{3,64})(?P=quote)"
)
_CRED_COLON_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?P<prefix>{_CRED_LABEL_PAT}[ \t]*[:=][ \t]*){_CRED_VAL_PAT}",
    re.IGNORECASE,
)
_CRED_WORD_RE: Final[re.Pattern[str]] = re.compile(
    rf"(?P<prefix>{_CRED_LABEL_PAT}[ \t]+(?:l[àa]|is)[ \t]+){_CRED_VAL_PAT}",
    re.IGNORECASE,
)
_CARD_16_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<!\d)(?:\d{4}[\s.\-\u2013\u2014]){3}\d{4}(?!\d)|(?<!\d)\d{16}(?!\d)"
)
_LABELED_CCCD_RE: Final[re.Pattern[str]] = re.compile(
    r"(?P<prefix>(?:s[ốo][ \t]+)?"
    r"(?:\b(?:cccd|cmnd)\b"
    r"|\bc[ăa]n[ \t]+c[ướu][ớo]c(?:[ \t]+c[ôo]ng[ \t]+d[âa]n)?"
    r"|\bch[ứu]ng[ \t]+minh[ \t]+(?:nh[âa]n[ \t]+d[âa]n|th[ưu])"
    r"|\b[đd][ịi]nh[ \t]+danh[ \t]+c[áa][ \t]+nh[âa]n)"
    r"(?:[ \t]*(?::|=|\-|\bl[àa]\b)[ \t]*|[ \t]+))"
    r"(?P<num>\d(?:[ \t.\-\u2013\u2014]?\d){8,11})(?!\d)",
    re.IGNORECASE,
)
_DOT_CCCD_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![+\d.,])0(?:0[1-9]|[1-8]\d|9[0-6])(?:\.\d{3}){3}(?![\d.,])"
)
_URL_ENCODED_NUM_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:%3[0-9]|[0-9])(?:(?:%20|%2[dDeE]|[\-._+])?(?:%3[0-9]|[0-9])){7,}", re.IGNORECASE
)
_SEP_CHAR: Final[str] = r"[\s.\-\u2013\u2014/_]"
_SEP_OPT: Final[str] = f"{_SEP_CHAR}?"
_MAX_SCRUB_KNOWN_ENTITIES: Final[int] = 32


@lru_cache(maxsize=256)
def _compile_digits_pattern(digits: str) -> re.Pattern[str]:
    body = _SEP_OPT.join(re.escape(ch) for ch in digits)
    return re.compile(rf"(?<!\d){body}(?!\d)")


@lru_cache(maxsize=256)
def _compile_vn_intl_phone_pattern(tail_digits: str) -> re.Pattern[str]:
    intl_body = _SEP_OPT.join(re.escape(ch) for ch in tail_digits)
    return re.compile(
        rf"(?<!\d)(?:\(\+?84\)|\+?84)(?:{_SEP_CHAR}{{0,3}}\(0\))?{_SEP_CHAR}{{0,3}}{intl_body}(?!\d)"
    )


@lru_cache(maxsize=256)
def _compile_alnum_account_pattern(alnum: str) -> re.Pattern[str]:
    body = _SEP_OPT.join(re.escape(ch) for ch in alnum)
    return re.compile(rf"(?<![A-Za-z0-9]){body}(?![A-Za-z0-9])", re.IGNORECASE)


def _redact_known_entities(
    text: str,
    known_phones: list[str] | None,
    known_accounts: list[str] | None,
) -> str:
    out = text
    seen_phones: set[str] = set()
    for ph in known_phones or []:
        clean_ph = _INVIS_RE.sub("", ph).strip()
        if not clean_ph or "****" in clean_ph or clean_ph in seen_phones:
            continue
        raw_digits = normalize_ioc_value("phone", clean_ph)
        if len(raw_digits) < 6:
            continue
        seen_phones.add(clean_ph)
        masked_ph = mask_ioc("phone", raw_digits)
        out = out.replace(clean_ph, masked_ph)
        out = _compile_digits_pattern(raw_digits).sub(masked_ph, out)
        if raw_digits.startswith("0") and len(raw_digits) == 10:
            out = _compile_vn_intl_phone_pattern(raw_digits[1:]).sub(masked_ph, out)
        if len(seen_phones) >= _MAX_SCRUB_KNOWN_ENTITIES:
            break

    seen_accounts: set[str] = set()
    for acct in known_accounts or []:
        clean_acct = _INVIS_RE.sub("", acct).strip()
        if not clean_acct or "****" in clean_acct or clean_acct in seen_accounts:
            continue
        if any(ch.isalpha() for ch in clean_acct):
            alnum = re.sub(r"[^A-Za-z0-9]", "", clean_acct).upper()
            if len(alnum) < 6:
                continue
            seen_accounts.add(clean_acct)
            masked_acct = mask_ioc("bank_account", alnum)
            out = _compile_alnum_account_pattern(alnum).sub(masked_acct, out)
        else:
            digits = re.sub(r"\D", "", clean_acct)
            if len(digits) < 6:
                continue
            seen_accounts.add(clean_acct)
            masked_acct = mask_ioc("bank_account", digits)
            out = out.replace(clean_acct, masked_acct)
            out = _compile_digits_pattern(digits).sub(masked_acct, out)
        if len(seen_accounts) >= _MAX_SCRUB_KNOWN_ENTITIES:
            break
    return out


def _replace_labeled_cccd(match: re.Match[str]) -> str:
    digits = re.sub(r"\D", "", match.group("num"))
    return f"{match.group('prefix')}[CCCD_REDACTED]" if 9 <= len(digits) <= 12 else match.group(0)


def _replace_encoded_num(match: re.Match[str]) -> str:
    tok = match.group(0)
    return "[ENCODED_NUM_REDACTED]" if "%3" in tok else tok


def _shield_internal_ids(text: str) -> tuple[str, list[tuple[str, str]]]:
    if not _INTERNAL_ID_RE.search(text):
        return text, []
    tag = "".join(chr(65 + (b % 26)) for b in secrets.token_bytes(6))
    items: list[tuple[str, str]] = []

    def _hold(m: re.Match[str]) -> str:
        key = f"VSIDSHIELD{tag}{f'{len(items):04x}'.translate(_HEX_ALPHA)}END"
        items.append((key, m.group(0)))
        return key

    return _INTERNAL_ID_RE.sub(_hold, text), items


def scrub_persisted_pii(
    text: str,
    known_phones: list[str] | None = None,
    known_accounts: list[str] | None = None,
) -> str:
    """Idempotently redact persisted PII: URL userinfo, accounts, emails, OTPs, cards, CCCDs."""
    if not text:
        return text
    out = _INVIS_RE.sub("", text)
    out, shielded_ids = _shield_internal_ids(out)
    out = _URL_USERINFO_RE.sub(r"\1[CRED_REDACTED]@", out)
    out = _redact_known_entities(out, known_phones=known_phones, known_accounts=known_accounts)
    out = _EMAIL_RE.sub("[EMAIL_REDACTED]", out)
    out = _OTP_PIN_CVV_RE.sub(r"\g<prefix>[OTP_REDACTED]", out)
    out = _CRED_COLON_RE.sub(r"\g<prefix>\g<quote>[OTP_REDACTED]\g<quote>", out)
    out = _CRED_WORD_RE.sub(r"\g<prefix>\g<quote>[OTP_REDACTED]\g<quote>", out)
    out = _CARD_16_RE.sub("[CARD_REDACTED]", out)
    out = _LABELED_CCCD_RE.sub(_replace_labeled_cccd, out)
    out = _DOT_CCCD_RE.sub("[CCCD_REDACTED]", out)
    out = _URL_ENCODED_NUM_RE.sub(_replace_encoded_num, out)
    out = scrub_free_text_pii(out, known_phones=known_phones, known_accounts=known_accounts)
    for key, val in reversed(shielded_ids):
        out = out.replace(key, val)
    return out
