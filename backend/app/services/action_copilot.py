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
    "LƯU Ý BẮT BUỘC CHO TIỂU THƯƠNG: Ảnh chụp màn hình biên lai KHÔNG phải bằng chứng tiền đã vào "
    "tài khoản. Chỉ giao hàng sau khi trực tiếp kiểm tra ứng dụng ngân hàng hoặc Loa thông báo "
    "ghi nhận biến động số dư."
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
        headline = "CHẶN KHẨN CẤP — TÀI KHOẢN / TÊN MIỀN ĐANG NẰM TRONG DANH SÁCH ĐEN FRAUD OPS"
    elif hold_for_call:
        headline = "TẠM KHÓA LÀM NGUỘI 30 GIÂY — BẠN ĐANG TRONG CUỘC GỌI CÓ DẤU HIỆU THAO TÚNG"
    elif hold_for_score:
        headline = "TẠM KHÓA LÀM NGUỘI 30 GIÂY — PHÁT HIỆN NGUY CƠ LỪA ĐẢO CAO ('KIỂM TRƯỚC TIN SAU')"
    else:
        headline = ""

    questions: list[str] = []
    if should_hold:
        questions = [
            "Người yêu cầu chuyển tiền có đang giục gấp hoặc bắt bạn giữ bí mật cuộc gọi không?",
            "Bạn đã gọi lại bằng số di động thông thường (ngoài Zalo/Messenger) để xác nhận chưa?",
            "Họ có tự xưng Công an, Ngân hàng, NAPAS hoặc hứa trả hoa hồng nhiệm vụ không?",
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
                "Dừng ngay thao tác chuyển tiền và không cung cấp mã OTP / sinh trắc học.",
                "Tải xuống Hồ sơ Tố giác PDF bên dưới để lưu bằng chứng trình báo cơ quan chức năng.",
            ]
        else:
            urgent_steps = [
                "Luôn thực hành nguyên tắc 'Kiểm trước tin sau' trước mọi yêu cầu chuyển khoản."
            ]

    family_msg = (llm_result.family_alert or "").strip()
    if not family_msg and verdict in ("SUSPICIOUS", "HIGH_RISK", "CRITICAL_SCAM"):
        pb_title = (
            matched_playbooks[0]["name_vi"]
            if matched_playbooks
            else "thủ đoạn lừa đảo trực tuyến mới"
        )
        family_msg = (
            f"[Cảnh báo Gia đình - VeriShield AI] Cả nhà cảnh giác với {pb_title} "
            f"(mức rủi ro {risk_score}/100). Tuyệt đối không chuyển tiền gấp khi đang nghe điện thoại lạ!"
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
