from datetime import UTC, datetime

from app.services.local_ocr import OcrBox
from app.services.receipt_validator import validate_receipt_logic


def test_detects_zalo_recompressed_fake_bill_logic_and_both_timestamp_orders_with_seconds() -> None:
    # Order 1: DD/MM/YYYY HH:MM:SS in the future
    ocr_text_dmy = (
        "Giao dịch thành công\n"
        "Số tiền: 5,000.000 VND\n"
        "STK nhận: 190399998888\n"
        "Mã GD: FAKE12\n"
        "Thời gian: 26/11/2026 23:59:45"
    )
    now = datetime(2026, 11, 26, 8, 0, tzinfo=UTC)  # 15:00 ICT
    res = validate_receipt_logic(
        ocr_text_dmy,
        reference_now=now,
        expected_merchant_account="190311112222",
        is_replayed_hash=False,
    )
    assert res.is_receipt_candidate is True
    assert res.timestamp_anomaly is True
    assert res.amount_format_anomaly is True
    assert res.beneficiary_mismatch is True
    assert res.verification_status == "BENEFICIARY_MISMATCH"
    assert res.logic_risk_points >= 65

    # Order 2: HH:MM:SS DD/MM/YYYY in the future
    ocr_text_hms_first = (
        "Vietcombank\nChuyển tiền thành công\n"
        "500.000 VND\nMã GD: FT26330123456789\n23:45:12 26/11/2026"
    )
    res_hms = validate_receipt_logic(ocr_text_hms_first, reference_now=now)
    assert res_hms.timestamp_anomaly is True
    assert res_hms.verification_status == "TAMPER_OR_LOGIC_ANOMALY"


def test_detects_replayed_receipt_and_ocr_geometry_anomaly() -> None:
    ocr_text = (
        "Techcombank\nChuyển khoản thành công\n"
        "50.000.000 VND\nMã GD: FT26330987654321\n26/11/2026 14:10"
    )
    now = datetime(2026, 11, 26, 7, 25, tzinfo=UTC)
    replayed = validate_receipt_logic(ocr_text, reference_now=now, is_replayed_hash=True)
    assert replayed.is_replayed is True
    assert replayed.verification_status == "REPLAYED_RECEIPT"
    assert replayed.logic_risk_points >= 80

    spliced_boxes = [
        OcrBox(text="Mã GD: FT26330987654321", confidence=0.95, x=20, y=100, width=220, height=18),
        OcrBox(text="STK nhận: 190311112222", confidence=0.95, x=20, y=130, width=210, height=18),
        OcrBox(text="Thời gian: 26/11/2026 14:10", confidence=0.95, x=20, y=160, width=230, height=19),
        OcrBox(text="Nội dung: thanh toan don", confidence=0.90, x=20, y=190, width=210, height=46),
    ]
    geom_res = validate_receipt_logic(ocr_text, ocr_boxes=spliced_boxes, reference_now=now)
    assert geom_res.geometry_anomaly is True
    assert geom_res.verification_status == "TAMPER_OR_LOGIC_ANOMALY"


def test_clean_unedited_receipt_sets_unverified_screenshot_status() -> None:
    ocr_text = (
        "Vietcombank\nChuyển tiền thành công\n"
        "250.000 VND\nMã GD: FT26330123456789\n26/11/2026 14:20"
    )
    now = datetime(2026, 11, 26, 7, 25, tzinfo=UTC)  # 14:25 ICT (UTC+7)
    res = validate_receipt_logic(ocr_text, reference_now=now)
    assert res.is_receipt_candidate is True
    assert res.logic_risk_points == 0
    assert res.verification_status == "UNVERIFIED_SCREENSHOT"
