"""EMVCo Merchant-Presented VietQR (QĐ 1928/QĐ-NHNN) TLV & CRC-16/CCITT-FALSE parser."""

from __future__ import annotations

import hashlib
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Final

from app.schemas import EvidenceItem, VietQRInfo

NAPAS_GUID: Final[str] = "A000000727"
SUPPORTED_NAPAS_SERVICES: Final[frozenset[str]] = frozenset({"QRIBFTTA", "QRIBFTTC"})

VALID_VIETQR_AMOUNT_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:0(?:\.\d{1,2})?|[1-9]\d{0,12}(?:\.\d{1,2})?)$"
)

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
    """Parse sequential 2-digit Tag + 2-digit Length + Value pairs; reject duplicate tags."""
    idx = 0
    total = len(raw)
    fields: dict[str, str] = {}
    while idx < total:
        if idx + 4 > total:
            return fields, False
        tag = raw[idx : idx + 2]
        len_str = raw[idx + 2 : idx + 4]
        if not (tag.isascii() and tag.isdigit() and len_str.isascii() and len_str.isdigit()):
            return fields, False
        if tag in fields:
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

    frame_tag = (
        f"[VIETQR_INVALID_FRAME:sha256="
        f"{hashlib.sha256(cleaned.encode('utf-8')).hexdigest()[:10]}:len={len(cleaned)}]"
    )

    if len(cleaned) < 16 or not cleaned.isascii() or cleaned[-8:-4] != "6304":
        evidence.append(
            EvidenceItem(
                source="vietqr_parser",
                severity="HIGH",
                title="Mã VietQR không đúng cấu trúc chuẩn",
                detail="Mã QR có phần đầu giống VietQR nhưng thiếu mã kiểm tra tính toàn vẹn.",
                snippet=frame_tag,
            )
        )
        return (
            VietQRInfo(raw=frame_tag, kind="INVALID_CRC_VIETQR", crc_valid=False, tlv_valid=False),
            evidence,
        )

    declared_crc = cleaned[-4:].upper()
    computed_crc = crc16_ccitt_false(cleaned[:-4].encode("ascii"))
    crc_ok = declared_crc == computed_crc
    top_fields, tlv_ok = read_tlv(cleaned)
    last_key = next(reversed(top_fields.keys()), "") if top_fields else ""
    struct_ok = tlv_ok and last_key == "63" and len(top_fields.get("63", "")) == 4

    if not crc_ok:
        evidence.append(
            EvidenceItem(
                source="vietqr_parser",
                severity="HIGH",
                title="Mã kiểm tra toàn vẹn của mã VietQR không hợp lệ",
                detail="Mã kiểm tra tính toàn vẹn không khớp — có dấu hiệu chuỗi QR đã bị chỉnh sửa.",
                snippet=frame_tag,
            )
        )
        return (
            VietQRInfo(
                raw=frame_tag,
                kind="INVALID_CRC_VIETQR",
                crc_valid=False,
                tlv_valid=struct_ok,
            ),
            evidence,
        )

    if not struct_ok:
        evidence.append(
            EvidenceItem(
                source="vietqr_parser",
                severity="HIGH",
                title="Cấu trúc dữ liệu của mã VietQR không hợp lệ",
                detail=(
                    "Các trường dữ liệu trong mã VietQR bị trùng lặp hoặc sai độ dài "
                    "— có dấu hiệu mã QR bị chỉnh sửa cấu trúc."
                ),
                snippet=frame_tag,
            )
        )
        return (
            VietQRInfo(
                raw=frame_tag,
                kind="INVALID_CRC_VIETQR",
                crc_valid=True,
                tlv_valid=False,
            ),
            evidence,
        )

    if "38" not in top_fields:
        return VietQRInfo(raw=frame_tag, kind="TEXT_QR", crc_valid=True), evidence

    sub38, ok38 = read_tlv(top_fields["38"])
    if not ok38:
        evidence.append(
            EvidenceItem(
                source="vietqr_parser",
                severity="HIGH",
                title="Thông tin ngân hàng trong mã VietQR bị lỗi",
                detail="Cấu trúc thông tin tài khoản bên trong mã VietQR không hợp lệ.",
                snippet=frame_tag,
            )
        )
        return (
            VietQRInfo(raw=frame_tag, kind="INVALID_CRC_VIETQR", crc_valid=True, tlv_valid=False),
            evidence,
        )

    if sub38.get("00") != NAPAS_GUID or "01" not in sub38:
        return VietQRInfo(raw=frame_tag, kind="TEXT_QR", crc_valid=True), evidence

    service_code = sub38.get("02")
    acct_tlv, ok_acct = read_tlv(sub38["01"])
    if not ok_acct:
        evidence.append(
            EvidenceItem(
                source="vietqr_parser",
                severity="HIGH",
                title="Thông tin tài khoản nhận trong mã VietQR bị lỗi hoặc trùng lặp",
                detail=(
                    "Cấu trúc tài khoản nhận bên trong mã VietQR không hợp lệ "
                    "— có dấu hiệu chèn trùng thông tin người nhận."
                ),
                snippet=frame_tag,
            )
        )
        return (
            VietQRInfo(raw=frame_tag, kind="INVALID_CRC_VIETQR", crc_valid=True, tlv_valid=False),
            evidence,
        )

    bank_bin = acct_tlv.get("00")
    account_number = acct_tlv.get("01")

    if (
        not bank_bin
        or not (bank_bin.isdigit() and len(bank_bin) == 6)
        or not account_number
        or service_code not in SUPPORTED_NAPAS_SERVICES
    ):
        return VietQRInfo(raw=frame_tag, kind="TEXT_QR", crc_valid=True), evidence

    if service_code == "QRIBFTTA":
        if (
            not re.fullmatch(r"[A-Za-z0-9]{6,19}", account_number)
            or sum(ch.isdigit() for ch in account_number) < 4
        ):
            return VietQRInfo(raw=frame_tag, kind="TEXT_QR", crc_valid=True), evidence
    elif not (account_number.isascii() and account_number.isdigit() and 12 <= len(account_number) <= 19):
        return VietQRInfo(raw=frame_tag, kind="TEXT_QR", crc_valid=True), evidence

    amount = top_fields.get("54")
    if amount is not None and not VALID_VIETQR_AMOUNT_RE.fullmatch(amount):
        evidence.append(
            EvidenceItem(
                source="vietqr_parser",
                severity="HIGH",
                title="Trường số tiền trong mã VietQR không đúng định dạng",
                detail=(
                    "Giá trị số tiền trong mã VietQR không đúng quy chuẩn "
                    "— có dấu hiệu mã QR bị chỉnh sửa cấu trúc."
                ),
                snippet=frame_tag,
            )
        )
        return (
            VietQRInfo(raw=frame_tag, kind="INVALID_CRC_VIETQR", crc_valid=True, tlv_valid=False),
            evidence,
        )

    bank_name = _load_bin_map().get(bank_bin, f"BIN {bank_bin}")
    currency_code = top_fields.get("53", "704")
    currency_label = "VND" if currency_code == "704" else f"ISO-{currency_code}"

    note: str | None = None
    if "62" in top_fields:
        sub62, ok62 = read_tlv(top_fields["62"])
        if ok62:
            note = sub62.get("08")

    is_dynamic = top_fields.get("01") == "12" or amount is not None

    receive_scam = bool(accompanying_text and _RECEIVE_SCAM_RE.search(accompanying_text))
    if receive_scam:
        evidence.append(
            EvidenceItem(
                source="vietqr_parser",
                severity="CRITICAL",
                title="Bẫy lừa quét mã VietQR để nhận tiền",
                detail=(
                    f"Mã QR này thực chất là lệnh chuyển tiền đi"
                    f"{f' số tiền {amount} {currency_label}' if amount else ''} tới {bank_name}, "
                    "nhưng tin nhắn lại hướng dẫn quét mã để nhận tiền hoàn hoặc nhận thưởng."
                ),
            )
        )

    beneficiary_mismatch = False
    if expected_merchant_account:
        act_norm = re.sub(r"[^A-Za-z0-9]", "", account_number).upper()
        exp_norm = re.sub(r"[^A-Za-z0-9]", "", expected_merchant_account).upper()
        if exp_norm and exp_norm != act_norm:
            beneficiary_mismatch = True
            evidence.append(
                EvidenceItem(
                    source="vietqr_parser",
                    severity="CRITICAL",
                    title="Mã VietQR không khớp với tài khoản nhận của cửa hàng",
                    detail=(
                        "Số tài khoản bên trong mã VietQR không khớp với tài khoản đăng ký của "
                        "cửa hàng — cần kiểm tra nguy cơ bị dán đè hoặc tráo mã QR."
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
