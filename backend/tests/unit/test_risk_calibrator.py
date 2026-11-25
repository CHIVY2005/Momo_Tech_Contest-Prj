from app.schemas import (
    ActionBundle,
    AnalysisReport,
    ImageForensicsResult,
    PreTransferIntervention,
    ReceiptLogicResult,
    ScamClassifierOutput,
    VietQRInfo,
)
from app.services.guardrails import GuardrailResult
from app.services.risk_calibrator import calibrate_risk


def test_enforces_block_rule_advisory_cap_injection_floor_and_vietqr_floor() -> None:
    empty_guard = GuardrailResult()

    # 1. Active Block Rule >= 95 even if advisory flag was somehow set
    adv_guard = GuardrailResult(safety_advisory_detected=True, matched_patterns=["header"])
    assert (
        calibrate_risk(
            mode="wallet_transfer",
            tier1_score=10,
            classifier=None,
            ai_score=10,
            guardrails=adv_guard,
            url_findings=[],
            vietqr_findings=[],
            sandbox=None,
            image_forensics=None,
            receipt_logic=None,
            active_block_rule_hit=True,
            in_active_call=False,
        ).final_score
        >= 95
    )

    # 2. Official Safety Advisory <= 20 when no threat artifacts exist
    assert (
        calibrate_risk(
            mode="personal",
            tier1_score=5,
            classifier=None,
            ai_score=75,
            guardrails=adv_guard,
            url_findings=[],
            vietqr_findings=[],
            sandbox=None,
            image_forensics=None,
            receipt_logic=None,
            active_block_rule_hit=False,
            in_active_call=False,
        ).final_score
        <= 20
    )

    # 3. Prompt Injection >= 75 even if LLM tricked into returning 0
    inj_guard = GuardrailResult(prompt_injection_detected=True, matched_patterns=["ignore"])
    assert (
        calibrate_risk(
            mode="personal",
            tier1_score=25,
            classifier=None,
            ai_score=0,
            guardrails=inj_guard,
            url_findings=[],
            vietqr_findings=[],
            sandbox=None,
            image_forensics=None,
            receipt_logic=None,
            active_block_rule_hit=False,
            in_active_call=False,
        ).final_score
        >= 75
    )

    # 4. VietQR receive-money scam >= 80
    vqr = VietQRInfo(
        raw="000201",
        kind="VALID_VIETQR",
        crc_valid=True,
        bank_bin="970422",
        account_number="123456789",
        receive_scam_detected=True,
    )
    assert (
        calibrate_risk(
            mode="personal",
            tier1_score=20,
            classifier=None,
            ai_score=30,
            guardrails=empty_guard,
            url_findings=[],
            vietqr_findings=[vqr],
            sandbox=None,
            image_forensics=None,
            receipt_logic=None,
            active_block_rule_hit=False,
            in_active_call=False,
        ).final_score
        >= 80
    )


def test_merchant_clean_screenshot_and_degraded_fusion() -> None:
    clean_receipt = ReceiptLogicResult(
        is_receipt_candidate=True,
        bank_detected="Vietcombank",
        reference_code="FT26330123456",
        verification_status="UNVERIFIED_SCREENSHOT",
        logic_risk_points=0,
    )
    img_res = ImageForensicsResult(
        filename="bill.jpg",
        format="JPEG",
        width=400,
        height=600,
        dhash_hex="0011223344556677",
        tamper_score=0,
    )
    cal = calibrate_risk(
        mode="merchant",
        tier1_score=0,
        classifier=None,
        ai_score=10,
        guardrails=GuardrailResult(),
        url_findings=[],
        vietqr_findings=[],
        sandbox=None,
        image_forensics=img_res,
        receipt_logic=clean_receipt,
        active_block_rule_hit=False,
        in_active_call=False,
    )
    assert cal.verdict == "SAFE" and cal.final_score <= 24
    assert cal.receipt_verification_status == "UNVERIFIED_SCREENSHOT"

    # Degraded mode (ai_score=None) with strong ONNX classifier + active call boost
    clf = ScamClassifierOutput(
        available=True,
        predicted_label="SCAM_IMPERSONATION",
        scam_probability=0.92,
        latency_ms=11,
    )
    deg = calibrate_risk(
        mode="wallet_transfer",
        tier1_score=60,
        classifier=clf,
        ai_score=None,
        guardrails=GuardrailResult(),
        url_findings=[],
        vietqr_findings=[],
        sandbox=None,
        image_forensics=None,
        receipt_logic=None,
        active_block_rule_hit=False,
        in_active_call=True,
    )
    assert deg.final_score >= 80
    assert deg.verdict == "CRITICAL_SCAM"


def test_minor_receipt_anomaly_with_zero_ai_score_never_contradicts_merchant_invariant() -> None:
    anomaly_receipt = ReceiptLogicResult(
        is_receipt_candidate=True,
        bank_detected="Vietcombank",
        reference_code="BAD!",
        reference_valid=False,
        verification_status="TAMPER_OR_LOGIC_ANOMALY",
        logic_risk_points=25,
        reasons=["Mã tham chiếu giao dịch không khớp định dạng chuẩn."],
    )
    img_res = ImageForensicsResult(
        filename="bill.jpg",
        format="JPEG",
        width=400,
        height=600,
        dhash_hex="0011223344556677",
        tamper_score=10,
    )
    cal = calibrate_risk(
        mode="merchant",
        tier1_score=25,
        classifier=None,
        ai_score=0,
        guardrails=GuardrailResult(),
        url_findings=[],
        vietqr_findings=[],
        sandbox=None,
        image_forensics=img_res,
        receipt_logic=anomaly_receipt,
        active_block_rule_hit=False,
        in_active_call=False,
    )
    assert cal.final_score >= 25
    assert cal.verdict != "SAFE"
    assert cal.receipt_verification_status == "TAMPER_OR_LOGIC_ANOMALY"

    # Must validate cleanly against AnalysisReport merchant receipt invariant
    report = AnalysisReport(
        case_id="vs_cal_test01",
        created_at="2026-11-26T00:00:00+00:00",
        mode="merchant",
        risk_score=cal.final_score,
        verdict=cal.verdict,
        confidence=cal.confidence,
        receipt_verification_status=cal.receipt_verification_status,
        summary_vi="Phát hiện mã tham chiếu biên lai bất thường.",
        image_forensics=img_res,
        receipt_logic=anomaly_receipt,
        actions=ActionBundle(
            merchant_balance_warning="Kiểm tra số dư thực tế hoặc Loa thông báo trước khi giao hàng.",
            pre_transfer=PreTransferIntervention(should_hold_transfer=False),
        ),
    )
    assert report.verdict == cal.verdict
