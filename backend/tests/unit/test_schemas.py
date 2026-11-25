import pytest
from pydantic import ValidationError

from app.config import Settings
from app.schemas import (
    SCAM_LABELS,
    ActionBundle,
    AnalysisReport,
    CreateBlockRuleRequest,
    ExtractedIOCs,
    PreTransferIntervention,
    score_to_verdict,
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


def test_settings_defaults_and_strict_block_rule_request() -> None:
    cfg = Settings(_env_file=None)
    assert cfg.max_upload_bytes == 10 * 1024 * 1024
    assert cfg.block_rule_ttl_minutes == 30
    assert cfg.analyst_pin == "2026"
    with pytest.raises(ValidationError):
        CreateBlockRuleRequest(ioc_type="invalid_type", value="123", reason="test")  # type: ignore[arg-type]


def test_analysis_report_roundtrip_serialization() -> None:
    report = AnalysisReport(
        case_id="case_test_001",
        created_at="2026-11-26T00:00:00Z",
        mode="merchant",
        in_active_call=False,
        risk_score=18,
        verdict="SAFE",
        confidence=0.91,
        degraded_mode=False,
        safety_advisory_detected=False,
        prompt_injection_detected=False,
        active_block_rule_hit=False,
        receipt_verification_status="UNVERIFIED_SCREENSHOT",
        summary_vi="Chưa phát hiện dấu hiệu chỉnh sửa kỹ thuật trên ảnh biên lai.",
        transcript=None,
        classifier=None,
        matched_playbooks=[],
        manipulation_tactics=[],
        highlighted_phrases=[],
        iocs=ExtractedIOCs(),
        vietqr_findings=[],
        url_findings=[],
        sandbox=None,
        image_forensics=None,
        receipt_logic=None,
        evidence=[],
        actions=ActionBundle(
            counter_replies=[],
            family_shield_message="",
            urgent_steps=["Kiểm tra biến động số dư trước khi giao hàng."],
            merchant_balance_warning="Ảnh biên lai không chứng minh tiền đã vào tài khoản.",
            pre_transfer=PreTransferIntervention(
                should_hold_transfer=False,
                cooling_off_seconds=0,
                triggered_by_active_call=False,
                blocked_by_ops_rule=False,
                warning_headline="",
                verification_questions=[],
            ),
        ),
        trace=[],
        community_hits=0,
    )
    restored = AnalysisReport.model_validate_json(report.model_dump_json())
    assert restored.receipt_verification_status == "UNVERIFIED_SCREENSHOT"
    assert restored.verdict == "SAFE"
