"""Layer-3 & Layer-4 Vietnamese bank transfer receipt business-logic & geometry validator."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone
from typing import Final

import numpy as np

from app.schemas import AnalyzeMode, ReceiptLogicResult, ReceiptVerificationStatus
from app.services.ioc_extractor import (
    EXPLICIT_RECIPIENT_SPAN_RE,
    LABELED_ACCOUNT_SPAN_RE,
    fold_vi_ascii,
    is_labeled_account_match,
    mask_ioc,
)
from app.services.local_ocr import OcrBox

VN_TZ: Final[timezone] = timezone(timedelta(hours=7))

_FALSE_SETTLEMENT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<!không\s)(?<!chưa\s)(?:"
    r"tiền\s+đã\s+(?:vào|về|chuyển\s+vào)|"
    r"đã\s+(?:nhận\s+(?:được\s+|đủ\s+)?tiền|ghi\s+có|thanh\s+toán\s+xong|hoàn\s+tất\s+thanh\s+toán)|"
    r"số\s+dư\s+đã\s+(?:được\s+)?(?:ghi\s+có|cập\s+nhật|tăng)|"
    r"có\s+thể\s+giao\s+hàng|"
    r"giao\s+hàng\s+ngay|"
    r"giao\s+dịch\s+đã\s+hoàn\s+tất\s+an\s+toàn"
    r")",
    re.IGNORECASE,
)


def build_trusted_merchant_summary(
    raw_summary: str,
    mode: AnalyzeMode,
    receipt_status: ReceiptVerificationStatus,
    has_qr_beneficiary_mismatch: bool = False,
    has_ocr_beneficiary_mismatch: bool = False,
    ocr_incomplete: bool = False,
) -> str:
    """Generate merchant receipt settlement conclusions strictly from trusted forensic status."""
    cleaned = raw_summary.strip()
    if receipt_status == "UNVERIFIED_SCREENSHOT":
        if ocr_incomplete:
            return (
                "Không thể đọc được đầy đủ nội dung văn bản từ ảnh chụp biên lai nên chưa thể "
                "kết luận an toàn. Chỉ giao hàng sau khi kiểm tra trực tiếp biến động số dư "
                "trên ứng dụng ngân hàng hoặc loa thông báo nhận tiền."
            )
        return (
            "Ảnh chụp biên lai chưa ghi nhận dấu hiệu chỉnh sửa, nhưng hệ thống không thể xác nhận "
            "tiền đã vào tài khoản chỉ từ ảnh chụp. Chỉ giao hàng sau khi kiểm tra trực tiếp biến động "
            "số dư trên ứng dụng ngân hàng hoặc loa thông báo nhận tiền."
        )
    if receipt_status == "REPLAYED_RECEIPT":
        return (
            "Cảnh báo rủi ro rất cao: Ảnh biên lai hoặc mã giao dịch này trùng khớp với một biên lai "
            "đã từng xuất hiện trước đó. Không giao hàng và hãy kiểm tra trực tiếp biến động số dư "
            "trên ứng dụng ngân hàng."
        )
    if receipt_status == "BENEFICIARY_MISMATCH":
        if has_qr_beneficiary_mismatch and not has_ocr_beneficiary_mismatch:
            return (
                "Cảnh báo rủi ro rất cao: Mã VietQR trỏ sang số tài khoản khác với tài khoản nhận tiền "
                "của cửa hàng. Hãy dừng giao hàng và kiểm tra trực tiếp biến động số dư."
            )
        if has_qr_beneficiary_mismatch and has_ocr_beneficiary_mismatch:
            return (
                "Cảnh báo rủi ro rất cao: Cả mã VietQR và thông tin trên biên lai đều trỏ sang số tài "
                "khoản khác với tài khoản của cửa hàng. Hãy dừng giao hàng và đối chiếu biến động số dư."
            )
        return (
            "Cảnh báo rủi ro rất cao: Số tài khoản nhận trên biên lai không khớp với tài khoản của "
            "cửa hàng. Hãy dừng giao hàng và kiểm tra trực tiếp biến động số dư."
        )
    if receipt_status == "TAMPER_OR_LOGIC_ANOMALY":
        return (
            "Cảnh báo rủi ro cao: Phát hiện dấu hiệu chỉnh sửa hình ảnh hoặc sai lệch thông tin trên "
            "biên lai. Không giao hàng trước khi kiểm tra trực tiếp biến động số dư trên ứng dụng "
            "ngân hàng hoặc loa thông báo nhận tiền."
        )
    if mode == "merchant" and _FALSE_SETTLEMENT_RE.search(cleaned):
        return (
            "Chưa thể xác nhận tiền đã vào tài khoản từ ảnh chụp — hãy kiểm tra trực tiếp biến động "
            "số dư trên ứng dụng ngân hàng hoặc loa thông báo nhận tiền trước khi giao hàng."
        )
    return cleaned

_RECEIPT_KEYWORD_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:chuyen\s*(?:tien|khoan)\s*thanh\s*cong|giao\s*dich\s*thanh\s*cong|"
    r"ma\s*(?:gd|giao\s*dich)|so\s*tham\s*chieu|bien\s*lai\s*chuyen\s*tien|"
    r"stk\s*nhan\s*:?\s*\d{6,19}|"
    r"transfer\s+successful|transaction\s+successful|"
    r"transaction\s+(?:id|no\.?|ref)|beneficiary\s+account|"
    r"reference\s+(?:no\.?|number|code)|remittance\s+advice)",
    re.IGNORECASE,
)

_MIXED_AMOUNT_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(
    r"\b\d{1,3}(?:,\d{3}\.\d{3}|\.\d{3},\d{3})\b"
)
_AMOUNT_CANDIDATE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:"
    r"(?:s[o06]\s*tien|thanh\s*tien|tong\s*tien|tien\s*chuyen|amount|total)"
    r"[\s:.\-\u2013\u2014]{1,12}(?P<labeled_amt>\d[\d.,]{2,18})"
    r"|(?P<suffixed_amt>\b\d{1,3}(?:[.,]\d{3})+|\b\d{4,15})\s*(?:vnd|dong|d)(?!\w)"
    r"|(?:vnd)\s*(?P<prefixed_amt>\d[\d.,]{2,18})"
    r")",
    re.IGNORECASE,
)

MAX_REF_CODE_LEN: Final[int] = 24

_REF_CODE_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:ma\s*(?:gd|giao\s*dich)|so\s*tham\s*chieu|ref(?:\s*no)?)"
    r"[\s:.\-]{1,6}([A-Z0-9#]{4,}(?:[-/_][A-Z0-9#]+)*)(?![A-Z0-9#]|[-/_][A-Z0-9#])",
    re.IGNORECASE,
)

_STANDALONE_FT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?<![A-Z0-9#])(FT\d{8,18}[A-Z0-9]*(?:[-/_][A-Z0-9#]+)*)(?![A-Z0-9#]|[-/_][A-Z0-9#])"
)

_RECIPIENT_CURRENCY_TAIL_RE: Final[re.Pattern[str]] = re.compile(
    r"[ \t]*(?:vn[đd]|[đd]|đồng|dong)(?!\w)"
    r"(?![ \t]+(?:phạm|pham|bọn|bon|thời|thoi|ý|y|chí|chi|loạt|loat|"
    r"hành|hanh|tình|tinh|đội|doi|nghiệp|nghiep)\b)",
    re.IGNORECASE,
)
_COMMA_DIGIT_AT_RE: Final[re.Pattern[str]] = re.compile(r",\d")

_DATE_TIME_PATTERNS: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    (
        re.compile(r"\b(\d{2}/\d{2}/\d{4})\s*(\d{2}:\d{2}(?::\d{2})?)\b"),
        "%d/%m/%Y %H:%M",
    ),
    (
        re.compile(r"\b(\d{2}:\d{2}(?::\d{2})?)\s*(\d{2}/\d{2}/\d{4})\b"),
        "%H:%M %d/%m/%Y",
    ),
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


def _parse_vn_timestamp(text: str) -> tuple[datetime | None, bool]:
    """Return (parsed_dt, malformed_date_detected)."""
    for regex, base_fmt in _DATE_TIME_PATTERNS:
        match = regex.search(text)
        if not match:
            continue
        raw_ts = f"{match.group(1).strip()} {match.group(2).strip()}"
        fmt = base_fmt.replace("%H:%M", "%H:%M:%S") if raw_ts.count(":") == 2 else base_fmt
        try:
            naive = datetime.strptime(raw_ts, fmt)
            return naive.replace(tzinfo=VN_TZ), False
        except ValueError:
            return None, True
    return None, False


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
    replay_checked: bool = False,
) -> ReceiptLogicResult:
    """Validate Vietnamese banking receipt logic and enforce the Merchant Honesty Guardrail."""
    cleaned = fold_vi_ascii(ocr_text.strip())
    bank_detected = _detect_bank_name(cleaned)
    has_structural_receipt = bool(
        bank_detected
        and (
            _STANDALONE_FT_RE.search(cleaned)
            or _REF_CODE_RE.search(cleaned)
            or (
                _AMOUNT_CANDIDATE_RE.search(cleaned)
                and (
                    _parse_vn_timestamp(cleaned)[0] is not None
                    or EXPLICIT_RECIPIENT_SPAN_RE.search(cleaned) is not None
                )
            )
        )
    )
    is_candidate = bool(_RECEIPT_KEYWORD_RE.search(cleaned)) or has_structural_receipt or is_replayed_hash
    if not is_candidate:
        return ReceiptLogicResult(
            is_receipt_candidate=False,
            verification_status="NOT_APPLICABLE",
        )

    reasons: list[str] = []
    risk = 0

    if is_replayed_hash:
        risk += 85
        reasons.append(
            "Ảnh biên lai hoặc mã giao dịch trùng với một biên lai đã từng xuất hiện trước đó."
        )

    amount_chars = list(cleaned)
    for span_m in LABELED_ACCOUNT_SPAN_RE.finditer(cleaned):
        s_idx, e_idx = span_m.span("acct")
        digits = re.sub(r"\D", "", span_m.group("acct"))
        if (
            len(digits) >= 6
            and _COMMA_DIGIT_AT_RE.match(cleaned, e_idx) is None
            and is_labeled_account_match(cleaned, span_m)
        ):
            for idx in range(s_idx, e_idx):
                amount_chars[idx] = " "
    for span_m in EXPLICIT_RECIPIENT_SPAN_RE.finditer(cleaned):
        s_idx, e_idx = span_m.span("acct")
        digits = re.sub(r"\D", "", span_m.group("acct"))
        if (
            len(digits) >= 6
            and _COMMA_DIGIT_AT_RE.match(cleaned, e_idx) is None
            and _RECIPIENT_CURRENCY_TAIL_RE.match(cleaned, e_idx) is None
        ):
            for idx in range(s_idx, e_idx):
                amount_chars[idx] = " "
    for pat in (_REF_CODE_RE, _STANDALONE_FT_RE):
        for span_m in pat.finditer(cleaned):
            s_idx, e_idx = span_m.span(1)
            for idx in range(s_idx, e_idx):
                amount_chars[idx] = " "
    amount_scan_text = "".join(amount_chars)

    amount_tokens = [
        m.group("labeled_amt") or m.group("suffixed_amt") or m.group("prefixed_amt") or ""
        for m in _AMOUNT_CANDIDATE_RE.finditer(amount_scan_text)
    ]
    amount_checked = bool(amount_tokens)
    amount_anomaly = any(bool(_MIXED_AMOUNT_SEPARATOR_RE.search(tok)) for tok in amount_tokens)
    if amount_anomaly:
        risk += 30
        reasons.append(
            "Định dạng số tiền trộn lẫn dấu chấm và dấu phẩy bất thường, có dấu hiệu bị chỉnh sửa."
        )

    ref_code: str | None = None
    ref_valid = True
    ft_match = _STANDALONE_FT_RE.search(cleaned)
    ref_match = _REF_CODE_RE.search(cleaned)
    raw_ref: str | None = None
    if ft_match:
        raw_ref = ft_match.group(1).upper()
    elif ref_match:
        raw_ref = ref_match.group(1).upper()

    if raw_ref is not None:
        if len(raw_ref) > MAX_REF_CODE_LEN:
            ref_valid = False
            risk += 25
            reasons.append(
                f"Mã giao dịch vượt quá độ dài thông thường (trên {MAX_REF_CODE_LEN} ký tự) "
                "nên không hợp lệ để đối chiếu."
            )
        else:
            ref_code = raw_ref
            if (
                len(ref_code) < 8
                or "FAKE" in ref_code
                or "#" in ref_code
                or not any(ch.isdigit() for ch in ref_code)
            ):
                ref_valid = False
                risk += 25
                reasons.append(
                    f"Mã giao dịch '{ref_code}' không khớp với cấu trúc phổ biến của ngân hàng Việt Nam."
                )

    now_vn = (reference_now or datetime.now(UTC)).astimezone(VN_TZ)
    parsed_ts, malformed_ts = _parse_vn_timestamp(cleaned)
    timestamp_checked = malformed_ts or (parsed_ts is not None)
    ts_anomaly = False
    if malformed_ts:
        ts_anomaly = True
        risk += 35
        reasons.append("Ngày giờ trên biên lai không hợp lệ, có dấu hiệu bị chỉnh sửa.")
    elif parsed_ts is not None:
        delta_minutes = (parsed_ts - now_vn).total_seconds() / 60.0
        if delta_minutes > 10.0:
            ts_anomaly = True
            risk += 35
            reasons.append(
                f"Thời gian trên biên lai ({parsed_ts.strftime('%d/%m/%Y %H:%M')}) lớn hơn "
                f"thời điểm kiểm tra hiện tại ({now_vn.strftime('%d/%m/%Y %H:%M')})."
            )
        elif delta_minutes < -(7 * 24 * 60):
            ts_anomaly = True
            risk += 25
            ts_str = parsed_ts.strftime("%d/%m/%Y %H:%M")
            reasons.append(
                f"Biên lai ghi nhận thời điểm từ hơn 7 ngày trước ({ts_str}), "
                "cần kiểm tra nguy cơ dùng lại ảnh cũ."
            )

    beneficiary_checked = False
    beneficiary_mismatch = False
    extracted_recipient_account: str | None = None
    first_mismatched_account: str | None = None
    mismatch_risk_added = False
    seen_mismatch_accounts: set[str] = set()
    exp_digits = re.sub(r"\D", "", expected_merchant_account) if expected_merchant_account else ""

    for acct_match in EXPLICIT_RECIPIENT_SPAN_RE.finditer(cleaned):
        if _RECIPIENT_CURRENCY_TAIL_RE.match(cleaned, acct_match.end()):
            continue
        candidate_digits = re.sub(r"\D", "", acct_match.group("acct"))
        if len(candidate_digits) < 6:
            continue
        if extracted_recipient_account is None and len(candidate_digits) <= 19:
            extracted_recipient_account = candidate_digits
        if exp_digits:
            beneficiary_checked = True
            if candidate_digits != exp_digits:
                beneficiary_mismatch = True
                if first_mismatched_account is None and len(candidate_digits) <= 19:
                    first_mismatched_account = candidate_digits
                if not mismatch_risk_added:
                    risk += 75
                    mismatch_risk_added = True
                if candidate_digits not in seen_mismatch_accounts:
                    seen_mismatch_accounts.add(candidate_digits)
                    reasons.append(
                        f"Số tài khoản nhận trên biên lai "
                        f"({mask_ioc('bank_account', candidate_digits)}) "
                        "không khớp với tài khoản của cửa hàng."
                    )
    if first_mismatched_account is not None:
        extracted_recipient_account = first_mismatched_account

    geometry_checked = bool(ocr_boxes and sum(1 for b in ocr_boxes if b.height > 2.0) >= 4)
    geometry_anomaly = _check_box_geometry_anomaly(ocr_boxes)
    if geometry_anomaly:
        risk += 25
        reasons.append(
            "Kích thước chữ giữa các dòng trên biên lai chênh lệch bất thường, có dấu hiệu chèn đè số tiền."
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
        timestamp_checked=timestamp_checked,
        timestamp_anomaly=ts_anomaly,
        amount_checked=amount_checked,
        amount_format_anomaly=amount_anomaly,
        geometry_checked=geometry_checked,
        geometry_anomaly=geometry_anomaly,
        beneficiary_checked=beneficiary_checked,
        beneficiary_mismatch=beneficiary_mismatch,
        extracted_recipient_account=extracted_recipient_account,
        replay_checked=replay_checked or is_replayed_hash,
        is_replayed=is_replayed_hash,
        verification_status=status,
        logic_risk_points=min(100, risk),
        reasons=[r.strip() for r in reasons],
    )
