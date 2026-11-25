import pytest
from pydantic import ValidationError

from app.config import Settings
from app.schemas import (
    SCAM_LABELS,
    ActionBundle,
    AnalysisReport,
    CreateBlockRuleRequest,
    EmergingCampaign,
    PreTransferIntervention,
    ReceiptLogicResult,
    ResetBlockRulesRequest,
    score_to_verdict,
)


def _make_base_actions(merchant_warning: str | None = None) -> ActionBundle:
    return ActionBundle(
        counter_replies=[],
        family_shield_message="",
        urgent_steps=["Kiểm tra biến động số dư trước khi giao hàng."],
        merchant_balance_warning=merchant_warning,
        pre_transfer=PreTransferIntervention(
            should_hold_transfer=False,
            cooling_off_seconds=0,
            triggered_by_active_call=False,
            blocked_by_ops_rule=False,
            warning_headline="",
            verification_questions=[],
        ),
    )


def test_score_to_verdict_exact_boundaries() -> None:
    assert score_to_verdict(0) == "SAFE"
    assert score_to_verdict(24) == "SAFE"
    assert score_to_verdict(25) == "SUSPICIOUS"
    assert score_to_verdict(54) == "SUSPICIOUS"
    assert score_to_verdict(55) == "HIGH_RISK"
    assert score_to_verdict(79) == "HIGH_RISK"
    assert score_to_verdict(80) == "CRITICAL_SCAM"
    assert score_to_verdict(100) == "CRITICAL_SCAM"
    assert len(SCAM_LABELS) == 7


def test_score_to_verdict_rejects_out_of_range_values() -> None:
    with pytest.raises(ValueError, match="0..100"):
        score_to_verdict(-1)
    with pytest.raises(ValueError, match="0..100"):
        score_to_verdict(101)


def test_settings_defaults_isolated_and_upload_ceiling_enforced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for env_name in ("MAX_UPLOAD_BYTES", "BLOCK_RULE_TTL_MINUTES", "ANALYST_PIN"):
        monkeypatch.delenv(env_name, raising=False)

    cfg = Settings(_env_file=None)
    assert cfg.max_upload_bytes == 10 * 1024 * 1024
    assert cfg.block_rule_ttl_minutes == 30
    assert cfg.analyst_pin == "2026"

    exact_cap = Settings(_env_file=None, max_upload_bytes=10 * 1024 * 1024)
    assert exact_cap.max_upload_bytes == 10 * 1024 * 1024
    with pytest.raises(ValidationError):
        Settings(_env_file=None, max_upload_bytes=10 * 1024 * 1024 + 1)


def test_radar_mutations_require_explicit_pin_and_no_raw_ioc_in_campaign() -> None:
    with pytest.raises(ValidationError):
        CreateBlockRuleRequest(ioc_type="domain", value="evil.top", reason="phishing")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        ResetBlockRulesRequest()  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        CreateBlockRuleRequest(
            ioc_type="invalid_type",  # type: ignore[arg-type]
            value="123",
            reason="test",
            analyst_pin="2026",
        )
    with pytest.raises(ValidationError):
        CreateBlockRuleRequest(ioc_type="domain", reason="missing target", analyst_pin="2026")

    by_hash = CreateBlockRuleRequest(
        ioc_type="bank_account",
        ioc_hash="a" * 64,
        masked_value="1903****6201",
        reason="Confirmed mule campaign",
        analyst_pin="2026",
    )
    assert by_hash.ioc_hash == "a" * 64

    campaign = EmergingCampaign(
        campaign_id="camp_01",
        title_vi="Mạo danh SMS NAPAS",
        playbook_id="scam_napas_sms",
        case_count=4,
        primary_ioc_type="domain",
        primary_ioc_masked="napas-****.top",
        primary_ioc_hash="b" * 64,
        recommended_action="Chặn tên miền trên toàn hệ thống",
    )
    assert "sample_raw_for_demo_block" not in campaign.model_dump()


def test_analysis_report_enforces_verdict_consistency_and_merchant_honesty() -> None:
    clean_receipt = ReceiptLogicResult(
        is_receipt_candidate=True,
        bank_detected="Vietcombank",
        reference_code="FT26330123456",
        verification_status="UNVERIFIED_SCREENSHOT",
    )

    # Valid merchant receipt report
    valid_report = AnalysisReport(
        case_id="case_test_001",
        created_at="2026-11-26T00:00:00Z",
        mode="merchant",
        risk_score=18,
        verdict="SAFE",
        confidence=0.91,
        receipt_verification_status="UNVERIFIED_SCREENSHOT",
        summary_vi="Chưa phát hiện dấu hiệu chỉnh sửa kỹ thuật trên ảnh biên lai.",
        receipt_logic=clean_receipt,
        actions=_make_base_actions("Ảnh biên lai không chứng minh tiền đã vào tài khoản."),
    )
    restored = AnalysisReport.model_validate_json(valid_report.model_dump_json())
    assert restored.receipt_verification_status == "UNVERIFIED_SCREENSHOT"

    # Rejects mismatched score vs verdict
    with pytest.raises(ValidationError, match="verdict"):
        AnalysisReport(
            case_id="case_bad_verdict",
            created_at="2026-11-26T00:00:00Z",
            mode="personal",
            risk_score=95,
            verdict="SAFE",
            confidence=0.9,
            summary_vi="Mâu thuẫn điểm và phán quyết.",
            actions=_make_base_actions(),
        )

    # Rejects SAFE merchant receipt missing UNVERIFIED_SCREENSHOT or balance warning
    with pytest.raises(ValidationError, match="UNVERIFIED_SCREENSHOT"):
        AnalysisReport(
            case_id="case_missing_status",
            created_at="2026-11-26T00:00:00Z",
            mode="merchant",
            risk_score=15,
            verdict="SAFE",
            confidence=0.9,
            receipt_verification_status="NOT_APPLICABLE",
            summary_vi="Thiếu trạng thái biên lai.",
            receipt_logic=clean_receipt,
            actions=_make_base_actions("Kiểm tra số dư."),
        )

    with pytest.raises(ValidationError, match="merchant_balance_warning"):
        AnalysisReport(
            case_id="case_missing_warning",
            created_at="2026-11-26T00:00:00Z",
            mode="merchant",
            risk_score=15,
            verdict="SAFE",
            confidence=0.9,
            receipt_verification_status="UNVERIFIED_SCREENSHOT",
            summary_vi="Thiếu cảnh báo kiểm tra số dư.",
            receipt_logic=clean_receipt,
            actions=_make_base_actions(None),
        )
