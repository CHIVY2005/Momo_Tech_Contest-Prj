from app.services.action_copilot import build_action_bundle
from app.services.ai_orchestrator import LLMReasoningResult


def test_cooling_off_triggers_on_active_call_and_merchant_always_warns_balance() -> None:
    llm = LLMReasoningResult(
        degraded_mode=False,
        ai_score=45,
        summary_vi="Có dấu hiệu bất thường trong cuộc gọi.",
    )

    # Risk score 42 (< 55) WITH in_active_call=True triggers 30s Cooling-Off Lock!
    wallet_bundle = build_action_bundle(
        mode="wallet_transfer",
        verdict="SUSPICIOUS",
        risk_score=42,
        in_active_call=True,
        active_block_rule_hit=False,
        receipt_status="NOT_APPLICABLE",
        matched_playbooks=[],
        llm_result=llm,
    )
    assert wallet_bundle.pre_transfer.should_hold_transfer is True
    assert wallet_bundle.pre_transfer.cooling_off_seconds == 30
    assert wallet_bundle.pre_transfer.triggered_by_active_call is True

    # Merchant mode with clean SAFE screenshot still populates mandatory balance warning
    merchant_bundle = build_action_bundle(
        mode="merchant",
        verdict="SAFE",
        risk_score=12,
        in_active_call=False,
        active_block_rule_hit=False,
        receipt_status="UNVERIFIED_SCREENSHOT",
        matched_playbooks=[],
        llm_result=llm,
    )
    assert merchant_bundle.merchant_balance_warning is not None
    assert "biến động số dư" in merchant_bundle.merchant_balance_warning.lower()
