"""Compiled regex patterns and domain/PII sets for VeriShield Assistant vault & egress sanitizer."""

from __future__ import annotations

import re
from typing import Final

from app.services import ioc_extractor as ioc

_R, _I = re.compile, re.IGNORECASE

HEX_ALPHA: Final[dict[int, int]] = str.maketrans("0123456789abcdef", "ABCDEFGHIJKLMNOP")
INVIS_RE: Final[re.Pattern[str]] = _R(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
SREF_RE: Final[re.Pattern[str]] = _R(
    r"\[(?P<k>URL|VIETQR|PHONE|ACCT)_REF_[1-9]\d{0,2} \((?P<p>[A-Za-z0-9*._-]{1,32})\)\]"
)
REF_SHAPES: Final[dict[str, re.Pattern[str]]] = {
    "URL": _R(
        r"(?:(?:\*\.)?[a-z0-9]{1,2}\*{4}\.(?:[a-z]{2,3}\.[a-z]{2}|[a-z]{2,16}|xn--[a-z0-9-]{2,22})"
        r"|(?:ipv6|ip|dom|url)_[0-9a-f]{4,6}\*{3,4})"
    ),
    "VIETQR": _R(r"qr_(?:[A-Za-z0-9]{2}\*{4}[A-Za-z0-9]{2}|[0-9a-f]{4}\*{3}|\*{4})"),
    "PHONE": _R(r"(?:\d{2,3}\*{4}\d{1,3}|ph_[0-9a-f]{4}\*{3}|\*{4})"),
    "ACCT": _R(r"(?:[A-Za-z0-9]{2}\*{4}[A-Za-z0-9]{2}|ac_[0-9a-f]{4}\*{3}|\*{4})"),
}
FAKE_REF_RE: Final[re.Pattern[str]] = _R(
    r"\[(?:URL|VIETQR|PHONE|ACCT)_REF_\d+(?:(?:[^\[\]\n]|\[[^\[\]\n]*\])*\])?", _I
)
FAKE_SEC_RE: Final[re.Pattern[str]] = _R(
    r"\[(?:SYSTEM_CASE_FACTS|GROUNDED_KB_CONTEXT|AVAILABLE_USER_ENTITY_REFS|TOOL_RESULTS|"
    r"QUICK_INTENT|CASE_EVIDENCE_EXCERPTS|CONVERSATION_HISTORY_UNTRUSTED|CURRENT_USER_MESSAGE)\]",
    _I,
)
VQR_RE: Final[re.Pattern[str]] = _R(
    r"(?<!\d)000201(?:\d{4}[\x20-\x7e]{8,1010}?6304[0-9A-Fa-f]{4}(?![0-9A-Za-z])"
    r"|[0-9A-Za-z]{8,1020}A000000727[0-9A-Za-z]{4,1020})"
)

DFG: Final[str] = r"(?:\[\.\]|\(\.\)|\[dot\]|\(dot\))"
DFG_RE: Final[re.Pattern[str]] = _R(DFG, _I)
UDOT: Final[str] = r"[\.\u3002\uff0e\uff61]"
UDOT_RE: Final[re.Pattern[str]] = _R(r"[\u3002\uff0e\uff61]")
TAIL: Final[str] = rf"(?:[^\s<>'\"()\[\]{{}}]|{DFG}|\([^\s<>'\"()\[\]{{}}]*\))*"
_U: Final[str] = r"[^\W_]"
_ULBL: Final[str] = rf"{_U}(?:(?:{_U}|-){{0,61}}{_U})?"
_TLD: Final[str] = r"(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})"
HOST: Final[str] = rf"(?:{_ULBL}(?:\.|{DFG}))+{_TLD}"
_SLBL: Final[str] = rf"{_U}(?:{_U}|-)*"
_STLD: Final[str] = r"(?:[^\W\d_]{2,24}|xn--[a-z0-9-]{2,59})"
_SYNTAX_HOST: Final[str] = rf"(?:{_SLBL}(?:{UDOT}|{DFG}))+{_STLD}"
_IP4: Final[str] = rf"(?:\d{{1,3}}(?:{UDOT}|{DFG})){{3}}\d{{1,3}}"
V6: Final[str] = rf"\[(?:[0-9a-fA-F:.%]|{DFG})*:(?:[0-9a-fA-F:.%]|{DFG})+\]"
UI: Final[str] = r"(?:[^\s<>'\"()\[\]{}@]+@)?"
_UI_REQ: Final[str] = r"[^\s<>'\"()\[\]{}@]+@"

EXPLICIT_URL_RE: Final[re.Pattern[str]] = _R(
    rf"\b(?:h(?:tt|xx)ps?|ftps?|sftp|wss?|file|javascript)(?:\[:\]|:)//"
    rf"{UI}(?:{V6}|(?:[^\s<>'\"()\[\]{{}}]|{DFG})+){TAIL}",
    _I,
)
PROTO_REL_RE: Final[re.Pattern[str]] = _R(
    rf"(?<![:\w/])//{UI}(?:{V6}|{_SYNTAX_HOST}|{_IP4}|\d{{8,12}})"
    rf"(?::\d+)?(?:[/?#]{TAIL})?",
    _I,
)
BARE_IP_RE: Final[re.Pattern[str]] = _R(
    rf"(?:{UI}{V6}|(?<![\d.]){UI}{_IP4})(?::\d+(?:[/?#]{TAIL})?|[/?#]{TAIL})"
    rf"|(?<![\w.%+-]){_UI_REQ}(?:{V6}|{_IP4})(?::\d+)?(?:[/?#]{TAIL})?",
    _I,
)
URL_SYNTAX_RE: Final[re.Pattern[str]] = _R(
    rf"(?<![/@\w.*\u3002\uff0e\uff61])(?:[^\s<>'\"()\[\]{{}}@:]+:[^\s<>'\"()\[\]{{}}@]+@"
    rf"{_SYNTAX_HOST}(?::\d+)?(?:[/?#]{TAIL})?"
    rf"|{UI}{_SYNTAX_HOST}(?::\d+(?:[/?#]{TAIL})?|[/?#]{TAIL}))",
    _I,
)
EMAIL_RE: Final[re.Pattern[str]] = _R(
    rf"(?<![\w.%+-])[\w.%+-]{{1,64}}@{_SYNTAX_HOST}", _I,
)
SCHEMELESS_RE: Final[re.Pattern[str]] = _R(rf"(?<![/@\w.*]){HOST}", _I)
DNS_LBL_RE: Final[re.Pattern[str]] = _R(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", _I)
IP_RADIX_RE: Final[re.Pattern[str]] = _R(
    r"^(?:0x[0-9a-f]+|0[0-7]+|\d+)(?:\.(?:0x[0-9a-f]+|0[0-7]+|\d+)){0,3}$", _I
)
NON_TLD_EXTS: Final[frozenset[str]] = frozenset({
    "apk", "pdf", "jpg", "jpeg", "png", "webp", "wav", "mp3", "m4a",
    "ogg", "json", "exe", "doc", "docx", "xls", "xlsx", "txt", "csv",
})
PUBLIC_SUFFIXES: Final[frozenset[str]] = ioc.RECOGNIZED_DISPLAY_PUBLIC_SUFFIXES | frozenset({
    "ru", "tk", "ml", "ga", "cf", "gq", "pw", "su", "to", "ws", "ly", "website",
    "host", "press", "site", "bid", "win", "loan", "pro", "mobi", "br", "pl", "it", "es",
})

_SEP: Final[str] = (
    r"(?:[ \t]+(?:ng[âa]n\s+h[àa]ng|c[ủu]a\s+(?:t[ôo]i|m[ìi]nh|em|anh|ch[ịi])|[đd][ăa]ng\s+nh[ậa]p)){0,2}"
    r"(?:[ \t:.\-=–—]{1,12}|[ \t]+l[àa][ \t:]{1,4})"
)
OTP_PW_RE: Final[re.Pattern[str]] = _R(
    rf"(?P<p>\b(?:(?:(?:m[ãa]\s+)?(?:smart\s*)?otp|m[ãa]\s+x[áa]c\s+(?:th[ựư]c|nh[ậa]n)|(?:m[ãa]\s+)?pin|"
    rf"cv[vc]2?)\b{_SEP}(?=\d)|\b(?:m[ậa]t\s+kh[ẩa]u|password)\b{_SEP}(?=\S*\d)))"
    r"(?:\d(?:[\s\-]?\d){2,9}(?!\d)|\S{4,40})",
    _I,
)
CARD_LBL_RE: Final[re.Pattern[str]] = _R(
    r"(?P<p>\b(?:s[ốo]\s+th[ẻe]|th[ẻe]\s+(?:t[íi]n\s+d[ụu]ng|thanh\s+to[áa]n|visa|mastercard|atm)|"
    r"card(?:\s+(?:no\.?|number))?)\b[ \t:.\-=–—]{1,10})\d(?:[\s\-]?\d){12,18}(?!\d)",
    _I,
)
CCCD_LBL_RE: Final[re.Pattern[str]] = _R(
    r"(?P<p>\b(?:s[ốo]\s+)?(?:cccd|cmnd|c[ăa]n\s+c[ướu][ớo]c(?:\s+c[ôo]ng\s+d[âa]n)?|"
    r"ch[ứu]ng\s+minh\s+(?:nh[âa]n\s+d[âa]n|th[ưu])|s[ốo]\s+[đd][ịi]nh\s+danh)\b"
    r"[ \t:.\-=–—]{1,10})(?:\d(?:[\s.\-]?\d){11}|\d(?:[\s.\-]?\d){8})(?!\d)",
    _I,
)
CARD16_RE: Final[re.Pattern[str]] = _R(
    r"(?<![+\d.,])\d{4}(?:[\s\-]\d{4}){3}(?![\d.]|,\d)|(?<!\d)\d{16}(?!\d)"
)
VN_CCCD_RE: Final[re.Pattern[str]] = _R(r"(?<!\d)0(?:0[1-9]|[1-8]\d|9[0-6])\d{9}(?!\d)")
VN_PHONE_RE: Final[re.Pattern[str]] = _R(
    r"(?<!\d)(?:\(\+?84\)[\s.\-/_]*|(?:\+?84)[\s.\-/_]*\(0\)[\s.\-/_]*|(?:\+?84)[\s.\-/_]?|0)"
    r"(?P<h>[35789])(?P<r>(?:[\s.\-/_]?\d){8})(?!\d)"
)
BARE_ACCT_RE: Final[re.Pattern[str]] = _R(
    r"(?<![+\d.,])\d{3,4}(?:[\s\-–—]\d{2,5}){2,4}(?![\d.]|,\d)"
    r"|(?<![+\d.,/:])\d{4,10}[\s\-–—]\d{4,10}(?![\d./:]|,\d)"
    r"|(?<![+\d.,])\d{4}(?:\.\d{2,5}){2,3}(?![\d.]|,\d)|(?<!\d)\d{8,19}(?!\d)"
)
DATE_RE: Final[re.Pattern[str]] = _R(
    r"^(?:\d{1,2}[./-]\d{1,2}[./-](?:19|20)\d{2}|(?:19|20)\d{2}[./-]\d{1,2}[./-]\d{1,2})$"
)
ACCT_PRE_RE: Final[re.Pattern[str]] = _R(
    r"(?:s[ốo][ \t]*)?(?:\bstk|\btk|t[àa]i[ \t]*kho[ảa]n|\baccount(?:[ \t]*(?:no\.?|number))?)"
    r"(?:[ \t]*(?:nh[ậa]n|th[ụu][ \t]*h[ưởu][ởo]ng|t[ạa]m[ \t]*gi[ữ u]|ng[âa]n[ \t]*h[àa]ng))?"
    r"[ \t:.\-–—]{1,12}$",
    _I,
)
NAPAS_BIN_RE: Final[re.Pattern[str]] = _R(r"\bBIN[ \t:.\-]{1,4}\d{6}\b", _I)
FALLBACK_DOMS: Final[frozenset[str]] = frozenset({
    "canhbao.khonggianmang.vn",
    "congthongtin.bocongan.gov.vn",
})
TRAIL_PUNCT: Final[str] = ".,!?;:'\"»)"
