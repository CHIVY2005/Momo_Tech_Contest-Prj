"""EMVCo Merchant-Presented VietQR (QĐ 1928/QĐ-NHNN) TLV & CRC-16/CCITT-FALSE parser."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Final

from app.schemas import EvidenceItem, VietQRInfo

NAPAS_GUID: Final[str] = "A000000727"

_RECEIVE_SCAM_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:quét\s+(?:mã\s+)?(?:qr\s+)?(?:này\s+)?để\s+(?:nhận|hoàn|lấy)|"
    r"nhận\s+(?:tiền\s+hoàn|khoản\s+hoàn|tiền\s+thưởng|lại\s+tiền)|"
    r"hoàn\s+tiền\s+(?:đơn\s+hàng|vào\s+tài\s+khoản)|"
    r"hủy\s+gói\s+(?:hội\s+viên|bảo\s+hiểm|cước))",
    re.IGNORECASE,
)


@lru_cache(maxsize=1)
def _load_bin_map() -> dict[str, str]:
    kb_path = Path(__file__).resolve().parent.parent / "data" / "vn_scam_kb.json"
    with kb_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    bins: dict[str, str] = data.get("napas_bins", {})
    return bins


def crc16_ccitt_false(payload: bytes) -> str:
    """Compute EMVCo standard CRC-16/CCITT-FALSE (poly=0x1021, init=0xFFFF, no reflection)."""
    crc = 0xFFFF
    for byte in payload:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return f"{crc:04X}"


def read_tlv(raw: str) -> tuple[dict[str, str], bool]:
    """Parse sequential 2-digit Tag + 2-digit Length + Value pairs; return (fields, ok)."""
    idx = 0
    total = len(raw)
    fields: dict[str, str] = {}
    while idx < total:
        if idx + 4 > total:
            return fields, False
        tag = raw[idx : idx + 2]
        len_str = raw[idx + 2 : idx + 4]
        if not (tag.isdigit() and len_str.isdigit()):
            return fields, False
        length = int(len_str)
        val_start = idx + 4
        val_end = val_start + length
        if val_end > total:
            return fields, False
        fields[tag] = raw[val_start:val_end]
        idx = val_end
    return fields, True


def _tlv_field(tag: str, value: str) -> str:
    return f"{tag}{len(value):02d}{value}"


def build_vietqr_test_payload(
    bin_code: str,
    account: str,
    amount: str | None = None,
    note: str | None = None,
    service_code: str = "QRIBFTTA",
) -> str:
    """Construct a standards-compliant EMVCo NAPAS VietQR payload with valid CRC-16."""
    beneficiary = _tlv_field("00", bin_code) + _tlv_field("01", account)
    tag38_val = (
        _tlv_field("00", NAPAS_GUID)
        + _tlv_field("01", beneficiary)
        + _tlv_field("02", service_code)
    )
    parts = [
        _tlv_field("00", "01"),
        _tlv_field("01", "12" if amount else "11"),
        _tlv_field("38", tag38_val),
        _tlv_field("53", "704"),
    ]
    if amount:
        parts.append(_tlv_field("54", amount))
    parts.append(_tlv_field("58", "VN"))
    if note:
        parts.append(_tlv_field("62", _tlv_field("08", note[:25])))
    body_with_crc_header = "".join(parts) + "6304"
    checksum = crc16_ccitt_false(body_with_crc_header.encode("ascii"))
    return body_with_crc_header + checksum


def parse_qr_payload(
    raw_qr: str,
    accompanying_text: str = "",
    expected_merchant_account: str | None = None,
) -> tuple[VietQRInfo, list[EvidenceItem]]:
    """Decode a QR payload into VietQRInfo and emit deterministic security EvidenceItems."""
    cleaned = raw_qr.strip()
    evidence: list[EvidenceItem] = []

    if re.match(r"^https?://", cleaned, re.IGNORECASE):
        return VietQRInfo(raw=cleaned, kind="URL_QR", crc_valid=True), evidence

    if not cleaned.startswith("000201"):
        return VietQRInfo(raw=cleaned, kind="TEXT_QR", crc_valid=True), evidence

    # Verify ASCII printable + Tag 63 CRC-16/CCITT-FALSE at end of payload
    if len(cleaned) < 16 or not cleaned.isascii() or cleaned[-8:-4] != "6304":
        evidence.append(
            EvidenceItem(
                source="vietqr_parser",
                severity="HIGH",
                title="Mã VietQR sai cấu trúc EMVCo",
                detail="Chuỗi bắt đầu bằng 000201 nhưng thiếu trường kiểm tra toàn vẹn 6304.",
                snippet=cleaned[:80],
            )
        )
        return VietQRInfo(raw=cleaned, kind="INVALID_CRC_VIETQR", crc_valid=False), evidence

    declared_crc = cleaned[-4:].upper()
    computed_crc = crc16_ccitt_false(cleaned[:-4].encode("ascii"))
    top_fields, tlv_ok = read_tlv(cleaned)

    if declared_crc != computed_crc or not tlv_ok:
        evidence.append(
            EvidenceItem(
                source="vietqr_parser",
                severity="HIGH",
                title="Mã kiểm tra CRC-16 VietQR không hợp lệ",
                detail=(
                    f"Chữ ký CRC-16 trong mã ({declared_crc}) lệch với giá trị toán học "
                    f"({computed_crc}) — dấu hiệu chuỗi QR bị chỉnh sửa thủ công."
                ),
                snippet=cleaned[:80],
            )
        )
        return VietQRInfo(raw=cleaned, kind="INVALID_CRC_VIETQR", crc_valid=False), evidence

    bank_bin: str | None = None
    bank_name: str | None = None
    account_number: str | None = None
    service_code: str | None = None

    if "38" in top_fields:
        sub38, ok38 = read_tlv(top_fields["38"])
        if ok38 and sub38.get("00") == NAPAS_GUID:
            service_code = sub38.get("02", "QRIBFTTA")
            if "01" in sub38:
                acct_tlv, ok_acct = read_tlv(sub38["01"])
                if ok_acct:
                    bank_bin = acct_tlv.get("00")
                    account_number = acct_tlv.get("01")
                    if bank_bin:
                        bank_name = _load_bin_map().get(bank_bin, f"BIN {bank_bin}")

    note: str | None = None
    if "62" in top_fields:
        sub62, ok62 = read_tlv(top_fields["62"])
        if ok62:
            note = sub62.get("08")

    amount = top_fields.get("54")
    is_dynamic = top_fields.get("01") == "12" or amount is not None

    receive_scam = bool(accompanying_text and _RECEIVE_SCAM_RE.search(accompanying_text))
    if receive_scam:
        evidence.append(
            EvidenceItem(
                source="vietqr_parser",
                severity="CRITICAL",
                title="Bẫy lừa quét mã VietQR để 'nhận tiền'",
                detail=(
                    f"Mã QR là lệnh CHUYỂN TIỀN ĐI ({service_code or 'QRIBFTTA'})"
                    f"{f' số tiền {amount} VND' if amount else ''} tới {bank_name or 'ngân hàng'} "
                    "nhưng tin nhắn lại dụ quét mã để nhận tiền hoàn/nhận thưởng."
                ),
            )
        )

    beneficiary_mismatch = False
    if expected_merchant_account and account_number:
        exp_digits = re.sub(r"\D", "", expected_merchant_account)
        act_digits = re.sub(r"\D", "", account_number)
        if exp_digits and act_digits and exp_digits != act_digits:
            beneficiary_mismatch = True
            evidence.append(
                EvidenceItem(
                    source="vietqr_parser",
                    severity="CRITICAL",
                    title="Mã VietQR trỏ sai tài khoản thụ hưởng của cửa hàng",
                    detail=(
                        "Tài khoản giải mã bên trong mã VietQR không khớp với số tài khoản "
                        "đăng ký của cửa hàng — nghi vấn bị dán đè hoặc tráo mã QR."
                    ),
                )
            )

    return (
        VietQRInfo(
            raw=cleaned,
            kind="VALID_VIETQR",
            crc_valid=True,
            bank_bin=bank_bin,
            bank_name=bank_name,
            account_number=account_number,
            service_code=service_code,
            is_dynamic=is_dynamic,
            amount=amount,
            note=note,
            receive_scam_detected=receive_scam,
            beneficiary_mismatch=beneficiary_mismatch,
        ),
        evidence,
    )
