"""Tier-1 deterministic text guardrails: safety-advisory filter & prompt-injection trap."""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Sequence
from functools import lru_cache
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from app.core.url_authority import extract_strict_ascii_host, has_disallowed_url_backslash
from app.schemas import EvidenceItem
from app.services.ioc_extractor import extract_candidate_urls, extract_iocs

_INVISIBLE_CHARS_RE: Final[re.Pattern[str]] = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]"
)

XML_BREAKOUT_TAG_RE: Final[re.Pattern[str]] = re.compile(
    r"<\s*/?\s*(?:untrusted_user_content|system_case_facts|grounded_kb_context|"
    r"available_user_entity_refs|case_evidence_excerpts|conversation_history_untrusted|"
    r"current_user_message|tool_results|quick_intent|system|developer)(?:\b[^>]*)?>",
    re.IGNORECASE,
)

_PROMPT_INJECTION_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("xml_tag_breakout", XML_BREAKOUT_TAG_RE),
    ("en_ignore_instructions", re.compile(
        r"\b(?:ignore|disregard|forget|override)\b.{0,45}\b(?:previous|prior|above|all|system)\b"
        r".{0,35}\b(?:instruction|rule|prompt|guideline)s?\b", re.IGNORECASE | re.DOTALL,
    )),
    ("en_force_safe_verdict", re.compile(
        r"\b(?:system\s+override|developer\s+(?:mode|note)|output|return|set)\b.{0,70}"
        r"(?:(?:ai_)?risk_score\s*[:=]\s*0|\bverdict\s*[:=]?\s*['\"]?safe\b)",
        re.IGNORECASE | re.DOTALL,
    )),
    ("vi_ignore_rules", re.compile(
        r"(?:bỏ\s+qua|phớt\s+lờ|xóa\s+bỏ|ghi\s+đè).{0,45}"
        r"(?:mọi\s+|toàn\s+bộ\s+)?(?:quy\s+tắc|hướng\s+dẫn|chỉ\s+thị|lệnh)\s*(?:trước\s+đó|hệ\s+thống)?",
        re.IGNORECASE | re.DOTALL,
    )),
    ("vi_force_safe_score", re.compile(
        r"(?:hệ\s+thống\s+(?:chú\s+ý|lưu\s+ý)|lệnh\s+hệ\s+thống|chấm\s+điểm|trả\s+về|đánh\s+giá)"
        r".{0,60}(?:risk_score\s*=\s*0|0\s*điểm|an\s+toàn\s+tuyệt\s+đối|\bsafe\b)",
        re.IGNORECASE | re.DOTALL,
    )),
)

_ADVISORY_HEADER_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(
        r"(?:cảnh\s+báo(?:\s+an\s+toàn|\s+lừa\s+đảo|\s+bảo\s+mật)?|thông\s+báo\s+(?:cảnh\s+báo|bảo\s+mật)|"
        r"khuyến\s+cáo(?:\s+an\s+toàn|\s+bảo\s+mật|\s+bộ\s+công\s+an|\s+phòng\s+chống\s+lừa\s+đảo)?|"
        r"cẩm\s+nang\s+an\s+toàn)", re.IGNORECASE,
    ),
    re.compile(
        r"(?:ngân\s+hàng|napas|cơ\s+quan\s+công\s+an|bộ\s+công\s+an|viện\s+kiểm\s+sát).{0,45}"
        r"không(?:\s+bao\s+giờ)?\s+(?:yêu\s+cầu|làm\s+việc\s+qua\s+điện\s+thoại)",
        re.IGNORECASE | re.DOTALL,
    ),
)

_ADVISORY_PROTECTIVE_CLAUSES: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(
        r"(?:tuyệt\s+đối\s+)?không(?:\s+bao\s+giờ)?\s+(?:cung\s+cấp|chia\s+sẻ|đưa|nhập).{0,40}"
        r"(?:mã\s+otp|otp|mật\s+khẩu)", re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"không(?:\s+bao\s+giờ)?\s+gửi\s+(?:đường\s+(?:link|dẫn)|link).{0,45}(?:otp|mật\s+khẩu)",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"không\s+(?:bấm\s+vào\s+(?:đường\s+)?link\s+lạ|nhấn\s+vào\s+đường\s+link\s+lạ|"
        r"(?:tải|cài(?:\s+đặt)?).{0,40}\.apk|quét\s+mã\s+(?:qr|vietqr)\s+do\s+người\s+lạ)",
        re.IGNORECASE | re.DOTALL,
    ),
)

_BASE_OFFICIAL_SUFFIXES: Final[tuple[str, ...]] = (
    ".gov.vn", "chinhphu.vn", "vietcombank.com.vn", "techcombank.com.vn",
    "napas.com.vn", "mbbank.com.vn", "bidv.com.vn", "vietinbank.vn",
    "agribank.com.vn", "acb.com.vn", "vpbank.com.vn", "tpb.vn",
)

_ACTIONABLE_SCAM_DEMAND_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:(?:chuyển|nộp|gửi)\s+(?:ngay|gấp|tiền|khoản)?\s*(?:\d|vào\s+(?:số\s+)?(?:stk|tài\s+khoản))|"
    r"vào\s+(?:số\s+)?(?:stk|tài\s+khoản)|"
    r"stk\s+tạm\s+giữ|"
    r"giữ\s+bí\s+mật(?:\s+tuyệt\s+đối)?\s+cuộc\s+gọi|"
    r"(?:lệnh\s+)?(?:khởi\s+tố|bắt\s+tạm\s+giam)|"
    r"nếu\s+không\s+sẽ\s+(?:bị\s+)?(?:khóa|bắt|khởi\s+tố|truy\s+tố)|"
    r"bấm\s+ngay\s+vào|truy\s+cập\s+ngay\s+(?:http|www\.)|"
    r"gửi\s+mã\s+otp\s+của\s+bạn|"
    r"liên\s+hệ\s+zalo\s+\d)",
    re.IGNORECASE,
)


class GuardrailResult(BaseModel):
    """Deterministic guardrail screening output."""

    safety_advisory_detected: bool = False
    advisory_vetoed: bool = False
    prompt_injection_detected: bool = False
    normalized_text: str = ""
    matched_patterns: list[str] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)


@lru_cache(maxsize=1)
def _load_official_advisory_suffixes() -> tuple[str, ...]:
    suffixes = list(_BASE_OFFICIAL_SUFFIXES)
    kb_path = Path(__file__).resolve().parent.parent / "data" / "vn_scam_kb.json"
    if kb_path.exists():
        data = json.loads(kb_path.read_text(encoding="utf-8"))
        for entry in data.get("official_brands", []):
            for dom in entry.get("official_domains", []):
                clean_dom = str(dom).strip().lower()
                if clean_dom and clean_dom not in suffixes:
                    suffixes.append(clean_dom)
    return tuple(suffixes)


def normalize_guardrail_text(text: str) -> tuple[str, bool]:
    """Normalize Unicode to NFC and strip hidden zero-width/bidi characters."""
    had_invisible = bool(_INVISIBLE_CHARS_RE.search(text))
    stripped = _INVISIBLE_CHARS_RE.sub("", text)
    normalized = unicodedata.normalize("NFC", stripped).strip()
    return normalized, had_invisible


def strip_xml_breakout_tags(text: str) -> str:
    """Normalize text and neutralize XML-like prompt delimiter breakouts."""
    cleaned, _ = normalize_guardrail_text(text)
    return XML_BREAKOUT_TAG_RE.sub("[STRIPPED_TAG]", cleaned)


def untrusted_user_content(text: str) -> str:
    """Wrap sanitized untrusted payload inside a single <UNTRUSTED_USER_CONTENT> block."""
    return f"<UNTRUSTED_USER_CONTENT>\n{strip_xml_breakout_tags(text)}\n</UNTRUSTED_USER_CONTENT>"


def detect_prompt_injection(normalized_text: str, had_invisible: bool = False) -> tuple[bool, list[str]]:
    """Detect English/Vietnamese adversarial prompt-injection attempts."""
    matches: list[str] = []
    for name, pattern in _PROMPT_INJECTION_PATTERNS:
        if pattern.search(normalized_text):
            matches.append(name)
    if matches and had_invisible:
        matches.append("zero_width_obfuscation")
    return bool(matches), matches


_SCHEME_BS_URL_RE: Final[re.Pattern[str]] = re.compile(
    r"\bhttps?:[/\\]*\\[^\s<>'\"()\[\]{}]*", re.IGNORECASE
)


def _has_non_official_url(text: str, extra_urls: Sequence[str] | None = None) -> bool:
    if _SCHEME_BS_URL_RE.search(text):
        return True
    candidates = list(extract_candidate_urls(text))
    for raw in extra_urls or ():
        stripped = raw.strip()
        if not stripped:
            continue
        if has_disallowed_url_backslash(stripped):
            return True
        candidates.append(stripped if "://" in stripped else f"https://{stripped}")
    official_suffixes = _load_official_advisory_suffixes()
    for raw_url in candidates:
        host = extract_strict_ascii_host(raw_url)
        if host is None:
            return True
        try:
            parts = urlsplit(raw_url)
            port = parts.port
        except ValueError:
            return True
        if (
            parts.scheme.lower() not in ("http", "https")
            or ".." in (parts.hostname or "")
            or (port is not None and port not in (80, 443))
        ):
            return True
        if not any(
            host == sfx.lstrip(".") or host.endswith(sfx if sfx.startswith(".") else f".{sfx}")
            for sfx in official_suffixes
        ):
            return True
    return False


def detect_safety_advisory(
    normalized_text: str,
    has_suspicious_url: bool = False,
    extra_urls: Sequence[str] | None = None,
) -> tuple[bool, bool, list[str]]:
    """Identify genuine security advisories and explicit scam/URL/PII vetoes."""
    if not normalized_text:
        return False, False, []
    extracted_iocs = extract_iocs(normalized_text)
    if (
        has_suspicious_url
        or _has_non_official_url(normalized_text, extra_urls=extra_urls)
        or bool(_ACTIONABLE_SCAM_DEMAND_RE.search(normalized_text))
        or bool(extracted_iocs.phones)
        or bool(extracted_iocs.bank_accounts)
    ):
        return False, True, []
    matched = [
        f"advisory_header_{idx + 1}"
        for idx, pat in enumerate(_ADVISORY_HEADER_PATTERNS)
        if pat.search(normalized_text)
    ]
    matched.extend(
        f"protective_clause_{idx + 1}"
        for idx, pat in enumerate(_ADVISORY_PROTECTIVE_CLAUSES)
        if pat.search(normalized_text)
    )
    is_advisory = len(matched) >= 2 or "advisory_header_2" in matched
    return is_advisory, False, matched if is_advisory else []


def evaluate_guardrails(
    text: str,
    has_suspicious_url: bool = False,
    extra_urls: Sequence[str] | None = None,
) -> GuardrailResult:
    """Run prompt-injection trap and official safety-advisory filter on raw input text."""
    normalized, had_invisible = normalize_guardrail_text(text)
    inj_detected, inj_patterns = detect_prompt_injection(normalized, had_invisible=had_invisible)
    evidence: list[EvidenceItem] = []
    matched_patterns = list(inj_patterns)
    if inj_detected:
        evidence.append(
            EvidenceItem(
                source="guardrails",
                severity="CRITICAL",
                title="Phát hiện nội dung tìm cách thao túng kết quả kiểm tra",
                detail=(
                    "Nội dung chứa chỉ thị bất thường nhằm thay đổi đánh giá của hệ thống hoặc "
                    "chèn ký tự ẩn gây nhiễu."
                ),
                snippet=normalized[:180],
            )
        )
        return GuardrailResult(
            safety_advisory_detected=False, advisory_vetoed=True, prompt_injection_detected=True,
            normalized_text=normalized, matched_patterns=matched_patterns, evidence=evidence,
        )
    adv_detected, adv_vetoed, adv_patterns = detect_safety_advisory(
        normalized, has_suspicious_url=has_suspicious_url, extra_urls=extra_urls,
    )
    if adv_detected:
        matched_patterns.extend(adv_patterns)
        evidence.append(
            EvidenceItem(
                source="guardrails",
                severity="INFO",
                title="Nhận diện thông báo khuyến cáo an toàn thông thường",
                detail=(
                    "Nội dung mang đặc điểm thông báo nhắc nhở phòng tránh lừa đảo (nhắc không "
                    "chia sẻ mã OTP hoặc không cài tệp .apk lạ) và không chứa yêu cầu chuyển tiền "
                    "hay đường dẫn đáng ngờ."
                ),
            )
        )
    return GuardrailResult(
        safety_advisory_detected=adv_detected, advisory_vetoed=adv_vetoed,
        prompt_injection_detected=False, normalized_text=normalized,
        matched_patterns=matched_patterns, evidence=evidence,
    )
