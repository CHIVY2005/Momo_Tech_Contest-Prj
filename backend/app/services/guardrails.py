"""Tier-1 deterministic text guardrails: safety-advisory filter & prompt-injection trap."""

from __future__ import annotations

import re
import unicodedata
from typing import Final

from pydantic import BaseModel, Field

from app.schemas import EvidenceItem

_INVISIBLE_CHARS_RE: Final[re.Pattern[str]] = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]"
)

_PROMPT_INJECTION_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "xml_tag_breakout",
        re.compile(r"</?\s*untrusted_user_content\s*>", re.IGNORECASE),
    ),
    (
        "en_ignore_instructions",
        re.compile(
            r"\b(?:ignore|disregard|forget|override)\b.{0,45}\b(?:previous|prior|above|all|system)\b"
            r".{0,35}\b(?:instruction|rule|prompt|guideline)s?\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "en_force_safe_verdict",
        re.compile(
            r"\b(?:system\s+override|developer\s+mode|output|return|set)\b.{0,50}"
            r"\b(?:risk_score\s*[:=]\s*0|verdict\s*[:=]?\s*['\"]?safe)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "vi_ignore_rules",
        re.compile(
            r"(?:bỏ\s+qua|phớt\s+lờ|xóa\s+bỏ|ghi\s+đè).{0,45}"
            r"(?:mọi\s+)?(?:quy\s+tắc|hướng\s+dẫn|chỉ\s+thị|lệnh)\s*(?:trước\s+đó|hệ\s+thống)?",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "vi_force_safe_score",
        re.compile(
            r"(?:hệ\s+thống\s+(?:chú\s+ý|lưu\s+ý)|lệnh\s+hệ\s+thống|chấm\s+điểm|trả\s+về|đánh\s+giá)"
            r".{0,60}(?:risk_score\s*=\s*0|0\s*điểm|an\s+toàn\s+tuyệt\s+đối|\bsafe\b)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
)

_ADVISORY_HEADER_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(
        r"(?:cảnh\s+báo(?:\s+an\s+toàn|\s+lừa\s+đảo|\s+bảo\s+mật)?|thông\s+báo\s+cảnh\s+báo|"
        r"khuyến\s+cáo(?:\s+an\s+toàn|\s+bảo\s+mật)?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:ngân\s+hàng|napas|cơ\s+quan\s+công\s+an|bộ\s+công\s+an).{0,40}"
        r"không\s+bao\s+giờ\s+yêu\s+cầu",
        re.IGNORECASE | re.DOTALL,
    ),
)

_ADVISORY_PROTECTIVE_CLAUSES: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(
        r"(?:tuyệt\s+đối\s+)?không(?:\s+bao\s+giờ)?\s+(?:cung\s+cấp|chia\s+sẻ|đưa).{0,35}"
        r"(?:mã\s+otp|otp|mật\s+khẩu)",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"không\s+(?:bấm\s+vào\s+(?:đường\s+)?link\s+lạ|"
        r"(?:tải|cài(?:\s+đặt)?)\s+(?:file\s+|ứng\s+dụng\s+)?\.apk)",
        re.IGNORECASE,
    ),
)

_ACTIONABLE_SCAM_DEMAND_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:chuyển\s+(?:ngay|gấp|tiền|khoản)\s+(?:\d|vào\s+stk)|"
    r"stk\s+tạm\s+giữ|"
    r"bấm\s+ngay\s+vào|truy\s+cập\s+ngay\s+http|"
    r"gửi\s+mã\s+otp\s+của\s+bạn|"
    r"liên\s+hệ\s+zalo\s+\d)",
    re.IGNORECASE,
)


class GuardrailResult(BaseModel):
    """Deterministic guardrail screening output."""

    safety_advisory_detected: bool = False
    prompt_injection_detected: bool = False
    normalized_text: str = ""
    matched_patterns: list[str] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)


def normalize_guardrail_text(text: str) -> tuple[str, bool]:
    """Normalize Unicode to NFC and strip hidden zero-width/bidi characters."""
    had_invisible = bool(_INVISIBLE_CHARS_RE.search(text))
    stripped = _INVISIBLE_CHARS_RE.sub("", text)
    normalized = unicodedata.normalize("NFC", stripped).strip()
    return normalized, had_invisible


def detect_prompt_injection(normalized_text: str, had_invisible: bool = False) -> tuple[bool, list[str]]:
    """Detect English/Vietnamese adversarial prompt-injection attempts."""
    matches: list[str] = []
    for name, pattern in _PROMPT_INJECTION_PATTERNS:
        if pattern.search(normalized_text):
            matches.append(name)
    if matches and had_invisible:
        matches.append("zero_width_obfuscation")
    return bool(matches), matches


def detect_safety_advisory(
    normalized_text: str,
    has_suspicious_url: bool = False,
) -> tuple[bool, list[str]]:
    """Identify genuine security advisories that must not trigger false positives."""
    if not normalized_text or has_suspicious_url:
        return False, []
    if re.search(r"https?://", normalized_text, re.IGNORECASE):
        return False, []
    if _ACTIONABLE_SCAM_DEMAND_RE.search(normalized_text):
        return False, []

    matched: list[str] = []
    for idx, pat in enumerate(_ADVISORY_HEADER_PATTERNS):
        if pat.search(normalized_text):
            matched.append(f"advisory_header_{idx + 1}")
    for idx, pat in enumerate(_ADVISORY_PROTECTIVE_CLAUSES):
        if pat.search(normalized_text):
            matched.append(f"protective_clause_{idx + 1}")

    is_advisory = len(matched) >= 2 or "advisory_header_2" in matched
    return is_advisory, matched if is_advisory else []


def evaluate_guardrails(text: str, has_suspicious_url: bool = False) -> GuardrailResult:
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
                title="Phát hiện tấn công Adversarial Prompt Injection",
                detail=(
                    "Nội dung chứa chỉ thị giả mạo nhằm ghi đè quy tắc hệ thống AI hoặc che giấu "
                    f"bằng ký tự ẩn ({', '.join(inj_patterns)})."
                ),
                snippet=normalized[:180],
            )
        )
        return GuardrailResult(
            safety_advisory_detected=False,
            prompt_injection_detected=True,
            normalized_text=normalized,
            matched_patterns=matched_patterns,
            evidence=evidence,
        )

    adv_detected, adv_patterns = detect_safety_advisory(
        normalized,
        has_suspicious_url=has_suspicious_url,
    )
    if adv_detected:
        matched_patterns.extend(adv_patterns)
        evidence.append(
            EvidenceItem(
                source="guardrails",
                severity="INFO",
                title="Nhận diện khuyến cáo an toàn chính thống",
                detail=(
                    "Văn bản mang cấu trúc thông báo phòng chống lừa đảo (nhắc không chia sẻ OTP / "
                    "không cài .apk lạ) và không chứa yêu cầu chuyển tiền hay liên kết đáng ngờ."
                ),
            )
        )

    return GuardrailResult(
        safety_advisory_detected=adv_detected,
        prompt_injection_detected=False,
        normalized_text=normalized,
        matched_patterns=matched_patterns,
        evidence=evidence,
    )
