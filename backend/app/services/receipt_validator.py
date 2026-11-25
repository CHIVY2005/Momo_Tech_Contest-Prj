"""Layer-3 & Layer-4 Vietnamese bank transfer receipt business-logic & geometry validator."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone
from typing import Final

import numpy as np

from app.schemas import ReceiptLogicResult, ReceiptVerificationStatus
from app.services.local_ocr import OcrBox

VN_TZ: Final[timezone] = timezone(timedelta(hours=7))

_RECEIPT_KEYWORD_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:chuyển\s+(?:tiền|khoản)\s+thành\s+công|giao\s+dịch\s+thành\s+công|"
    r"mã\s*(?:gd|giao\s*dịch)|số\s*tham\s*chiếu|biên\s*lai\s*chuyển\s*tiền)",
    re.IGNORECASE,
)

_MIXED_AMOUNT_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(
    r"\b\d{1,3}(?:,\d{3}\.\d{3}|\.\d{3},\d{3})\b"
)

_REF_CODE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:mã\s*(?:gd|giao\s*dịch)|số\s*tham\s*chiếu|ref(?:\s*no)?)[\s:.\-]{1,6}([A-Z0-9]{4,24})",
    re.IGNORECASE,
)

_STANDALONE_FT_RE: Final[re.Pattern[str]] = re.compile(r"\b(FT\d{8,18}[A-Z0-9]*)\b")

_DATE_TIME_PATTERNS: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    (
        re.compile(r"\b(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}(?::\d{2})?)\b"),
        "%d/%m/%Y %H:%M",
    ),
    (
        re.compile(r"\b(\d{2}:\d{2}(?::\d{2})?\s+\d{2}/\d{2}/\d{4})\b"),
        "%H:%M %d/%m/%Y",
    ),
)

_RECIPIENT_ACCT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:stk\s*(?:nhận|thụ\s*hưởng)?|tài\s*khoản\s*(?:nhận|thụ\s*hưởng|đến))[\s:.\-]{1,12}(\d{8,16})",
    re.IGNORECASE,
)

_KNOWN_BANKS: Final[tuple[str, ...]] = (
    "Vietcombank",
    "Techcombank",
    "MB Bank",
    "BIDV",
    "VietinBank",
    "Agribank",
    "ACB",
    "VPBank",
    "TPBank",
    "Sacombank",
    "VIB",
    "SHB",
    "HDBank",
)


def _detect_bank_name(text: str) -> str | None:
    lower = text.lower()
    for name in _KNOWN_BANKS:
        if name.lower().replace(" ", "") in lower.replace(" ", ""):
            return name
    return None


def _parse_vn_timestamp(text: str) -> datetime | None:
    for regex, base_fmt in _DATE_TIME_PATTERNS:
        match = regex.search(text)
        if not match:
            continue
        raw_ts = match.group(1).strip()
        fmt = base_fmt.replace("%H:%M", "%H:%M:%S") if raw_ts.count(":") == 2 else base_fmt
        try:
            naive = datetime.strptime(raw_ts, fmt)
            return naive.replace(tzinfo=VN_TZ)
        except ValueError:
            continue
    return None


def _check_box_geometry_anomaly(ocr_boxes: list[OcrBox] | None) -> bool:
    if not ocr_boxes or len(ocr_boxes) < 4:
        return False
    heights = np.asarray([b.height for b in ocr_boxes if b.height > 2.0], dtype=np.float32)
    if len(heights) < 4:
        return False
    median_h = float(np.median(heights))
    max_h = float(np.max(heights))
    return median_h > 0 and (max_h / median_h) >= 2.15


def validate_receipt_logic(
    ocr_text: str,
    ocr_boxes: list[OcrBox] | None = None,
    reference_now: datetime | None = None,
    expected_merchant_account: str | None = None,
    is_replayed_hash: bool = False,
) -> ReceiptLogicResult:
    """Validate Vietnamese banking receipt logic and enforce the Merchant Honesty Guardrail."""
    cleaned = ocr_text.strip()
    is_candidate = bool(_RECEIPT_KEYWORD_RE.search(cleaned))
    if not is_candidate:
        return ReceiptLogicResult(
            is_receipt_candidate=False,
            verification_status="NOT_APPLICABLE",
        )

    bank_detected = _detect_bank_name(cleaned)
    reasons: list[str] = []
    risk = 0

    if is_replayed_hash:
        risk += 85
        reasons.append(
            "Ảnh biên lai hoặc mã tham chiếu trùng với giao dịch cũ đã gửi trước đó (Bill Replay)."
        )

    amount_anomaly = bool(_MIXED_AMOUNT_SEPARATOR_RE.search(cleaned))
    if amount_anomaly:
        risk += 30
        reasons.append(
            "Định dạng số tiền trộn lẫn dấu chấm và dấu phẩy hàng nghìn bất thường (dấu hiệu sửa tay)."
        )

    ref_code: str | None = None
    ref_valid = True
    ft_match = _STANDALONE_FT_RE.search(cleaned)
    ref_match = _REF_CODE_RE.search(cleaned)
    if ft_match:
        ref_code = ft_match.group(1).upper()
    elif ref_match:
        ref_code = ref_match.group(1).upper()

    if ref_code is not None and (len(ref_code) < 8 or "FAKE" in ref_code or ref_code.isalpha()):
        ref_valid = False
        risk += 25
        reasons.append(
            f"Mã tham chiếu giao dịch '{ref_code}' không đúng chuẩn độ dài/cấu trúc ngân hàng VN."
        )

    now_vn = (reference_now or datetime.now(UTC)).astimezone(VN_TZ)
    parsed_ts = _parse_vn_timestamp(cleaned)
    ts_anomaly = False
    if parsed_ts is not None:
        delta_minutes = (parsed_ts - now_vn).total_seconds() / 60.0
        if delta_minutes > 10.0:
            ts_anomaly = True
            risk += 35
            reasons.append(
                f"Thời gian trên biên lai ({parsed_ts.strftime('%d/%m/%Y %H:%M')}) nằm ở tương lai "
                f"so với thời điểm kiểm tra ({now_vn.strftime('%d/%m/%Y %H:%M')} GMT+7)."
            )
        elif delta_minutes < -(7 * 24 * 60):
            ts_anomaly = True
            risk += 25
            reasons.append(
                f"Biên lai ghi nhận từ hơn 7 ngày trước ({parsed_ts.strftime('%d/%m/%Y %H:%M')}) — "
                "nghi vấn tái sử dụng ảnh biên lai cũ."
            )

    beneficiary_mismatch = False
    if expected_merchant_account:
        exp_digits = re.sub(r"\D", "", expected_merchant_account)
        acct_match = _RECIPIENT_ACCT_RE.search(cleaned)
        if exp_digits and acct_match:
            found_digits = re.sub(r"\D", "", acct_match.group(1))
            if found_digits and found_digits != exp_digits:
                beneficiary_mismatch = True
                risk += 75
                reasons.append(
                    f"Số tài khoản nhận trên biên lai ({found_digits[:4]}****) không khớp với "
                    "tài khoản của cửa hàng."
                )

    geometry_anomaly = _check_box_geometry_anomaly(ocr_boxes)
    if geometry_anomaly:
        risk += 25
        reasons.append(
            " Tọa độ khung chữ OCR phát hiện dòng văn bản có chiều cao lệch chuẩn (>2.15x trung vị)."
        )

    status: ReceiptVerificationStatus
    if is_replayed_hash:
        status = "REPLAYED_RECEIPT"
    elif beneficiary_mismatch:
        status = "BENEFICIARY_MISMATCH"
    elif risk > 0:
        status = "TAMPER_OR_LOGIC_ANOMALY"
    else:
        status = "UNVERIFIED_SCREENSHOT"

    return ReceiptLogicResult(
        is_receipt_candidate=True,
        bank_detected=bank_detected,
        reference_code=ref_code,
        reference_valid=ref_valid,
        timestamp_anomaly=ts_anomaly,
        amount_format_anomaly=amount_anomaly,
        geometry_anomaly=geometry_anomaly,
        beneficiary_mismatch=beneficiary_mismatch,
        is_replayed=is_replayed_hash,
        verification_status=status,
        logic_risk_points=min(100, risk),
        reasons=[r.strip() for r in reasons],
    )
