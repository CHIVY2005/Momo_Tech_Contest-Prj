"""Tier-3 Action Copilot: 30s psychological cooling-off, counter-replies, and merchant warnings."""

from __future__ import annotations

from typing import Any, Final

from app.schemas import (
    ActionBundle,
    AnalyzeMode,
    PreTransferIntervention,
    ReceiptVerificationStatus,
    VerdictLevel,
)
from app.services.ai_orchestrator import LLMReasoningResult

MERCHANT_HONESTY_BANNER: Final[str] = (
    "Lưu ý bắt buộc cho người bán: Ảnh chụp màn hình biên lai không phải bằng chứng tiền đã vào "
    "tài khoản. Chỉ giao hàng sau khi kiểm tra trực tiếp biến động số dư trên ứng dụng ngân hàng "
    "hoặc loa thông báo nhận tiền."
)


def build_action_bundle(
    mode: AnalyzeMode,
    verdict: VerdictLevel,
    risk_score: int,
    in_active_call: bool,
    active_block_rule_hit: bool,
    receipt_status: ReceiptVerificationStatus,
    matched_playbooks: list[dict[str, Any]],
    llm_result: LLMReasoningResult,
) -> ActionBundle:
    """Construct protective interventions tailored to personal, merchant, and wallet modes."""
    hold_for_block = active_block_rule_hit
    hold_for_score = risk_score >= 55
    hold_for_call = in_active_call and risk_score >= 35
    should_hold = hold_for_block or hold_for_score or hold_for_call

    if hold_for_block:
        headline = (
            "Khuyến nghị dừng chuyển tiền — số tài khoản hoặc tên miền đang nằm trong danh sách "
            "cảnh báo của hệ thống"
        )
    elif hold_for_call:
        headline = (
            "Tạm dừng để kiểm tra 30 giây — hãy bình tĩnh xác minh lại khi đang nghe cuộc gọi "
            "thúc ép chuyển tiền"
        )
    elif hold_for_score:
        headline = (
            "Tạm dừng để kiểm tra 30 giây — phát hiện nhiều dấu hiệu rủi ro trước khi chuyển tiền"
        )
    else:
        headline = ""

    questions: list[str] = []
    if should_hold:
        questions = [
            "Người yêu cầu chuyển tiền có đang giục gấp hoặc yêu cầu bạn giữ bí mật cuộc gọi không?",
            "Bạn đã gọi lại bằng số di động thông thường (ngoài Zalo hoặc Messenger) để xác nhận chưa?",
            "Họ có tự xưng công an, ngân hàng, NAPAS hoặc hứa trả hoa hồng khi làm nhiệm vụ không?",
        ]

    replies: list[str] = list(llm_result.counter_replies)
    urgent_steps: list[str] = []
    for pb in matched_playbooks[:2]:
        for r in pb.get("counter_replies", []):
            if r not in replies:
                replies.append(r)
        for step in pb.get("urgent_steps", []):
            if step not in urgent_steps:
                urgent_steps.append(step)

    if not replies and verdict in ("HIGH_RISK", "CRITICAL_SCAM"):
        replies.append(
            "Tôi cần xác minh lại thông tin qua tổng đài chính thức trước khi thực hiện giao dịch này."
        )

    if not urgent_steps:
        if verdict in ("HIGH_RISK", "CRITICAL_SCAM"):
            urgent_steps = [
                "Dừng ngay thao tác chuyển tiền và không cung cấp mã OTP hoặc xác thực sinh trắc học.",
                (
                    "Tải báo cáo bằng chứng PDF để lưu lại thông tin khi cần trình báo "
                    "cơ quan công an."
                ),
            ]
        else:
            urgent_steps = [
                "Luôn tự xác minh thông tin người nhận qua kênh chính thức trước khi chuyển tiền."
            ]

    family_msg = (llm_result.family_alert or "").strip()
    if not family_msg and verdict in ("SUSPICIOUS", "HIGH_RISK", "CRITICAL_SCAM"):
        pb_title = (
            matched_playbooks[0]["name_vi"]
            if matched_playbooks
            else "thủ đoạn lừa đảo trực tuyến mới"
        )
        family_msg = (
            f"[Cảnh báo từ VeriShield AI] Cả nhà cẩn thận với {pb_title} "
            f"(mức rủi ro {risk_score}/100). Không chuyển tiền gấp khi đang nghe điện thoại lạ."
        )

    merchant_warning: str | None = None
    if mode == "merchant" or receipt_status != "NOT_APPLICABLE":
        merchant_warning = MERCHANT_HONESTY_BANNER

    return ActionBundle(
        counter_replies=replies[:3],
        family_shield_message=family_msg,
        urgent_steps=urgent_steps[:4],
        merchant_balance_warning=merchant_warning,
        pre_transfer=PreTransferIntervention(
            should_hold_transfer=should_hold,
            cooling_off_seconds=30 if should_hold else 0,
            triggered_by_active_call=hold_for_call,
            blocked_by_ops_rule=hold_for_block,
            warning_headline=headline,
            verification_questions=questions,
        ),
    )
