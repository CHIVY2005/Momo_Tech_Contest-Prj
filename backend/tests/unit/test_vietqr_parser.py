from app.services.vietqr_parser import (
    build_vietqr_test_payload,
    crc16_ccitt_false,
    parse_qr_payload,
)


def test_crc16_ccitt_false_standard_vector_and_valid_napas_vietqr() -> None:
    assert crc16_ccitt_false(b"123456789") == "29B1"
    qr = build_vietqr_test_payload(
        bin_code="970436",
        account="0011001234567",
        amount="500000",
        note="THANH TOAN DON 12",
    )
    info, ev = parse_qr_payload(qr, accompanying_text="Quét mã để thanh toán đơn hàng")
    assert info.kind == "VALID_VIETQR"
    assert info.crc_valid is True
    assert info.bank_bin == "970436"
    assert info.bank_name == "Vietcombank"
    assert info.account_number == "0011001234567"
    assert info.amount == "500000"
    assert info.is_dynamic is True
    assert info.receive_scam_detected is False
    assert info.beneficiary_mismatch is False
    assert len(ev) == 0


def test_flags_vietqr_receive_money_scam_beneficiary_mismatch_and_bad_crc() -> None:
    qr = build_vietqr_test_payload(
        bin_code="970422",
        account="0988776655",
        amount="1500000",
        note="HOAN TIEN",
    )
    info, ev = parse_qr_payload(
        qr,
        accompanying_text="Anh chị quét mã QR này để nhận tiền hoàn 1.500.000đ từ sàn nhé",
    )
    assert info.receive_scam_detected is True
    assert any(item.severity == "CRITICAL" for item in ev)

    mismatch_info, mismatch_ev = parse_qr_payload(
        qr,
        expected_merchant_account="190311112222",
    )
    assert mismatch_info.beneficiary_mismatch is True
    assert any(item.severity in ("HIGH", "CRITICAL") for item in mismatch_ev)

    tampered = qr[:-4] + ("0000" if qr[-4:] != "0000" else "FFFF")
    bad_info, bad_ev = parse_qr_payload(tampered)
    assert bad_info.kind == "INVALID_CRC_VIETQR"
    assert bad_info.crc_valid is False
    assert len(bad_ev) >= 1


def test_non_napas_emv_payload_is_not_classified_as_valid_vietqr() -> None:
    # EMVCo 000201 payload WITHOUT Tag 38 NAPAS GUID
    body = "00020101021153037045802VN6304"
    non_napas = body + crc16_ccitt_false(body.encode("ascii"))
    info, ev = parse_qr_payload(
        non_napas,
        accompanying_text="Quét mã QR này để nhận tiền thưởng",
    )
    assert info.kind == "TEXT_QR"
    assert info.receive_scam_detected is False
    assert len(ev) == 0

    url_info, _ = parse_qr_payload("https://vneid-capnhat.vip/download.apk")
    assert url_info.kind == "URL_QR"
