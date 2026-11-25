"""Telegram 1-Tap Forward Bot webhook handler with secret-token verification."""

from __future__ import annotations

import logging
from typing import Any

from app.config import Settings
from app.core.security import build_ssrf_pinned_http_client
from app.schemas import AnalysisReport
from app.services.pipeline import AnalysisPipeline

logger = logging.getLogger(__name__)


def format_telegram_verdict_reply(report: AnalysisReport) -> str:
    """Format concise Vietnamese safety verdict & counter-reply for Telegram chat."""
    badge_map = {
        "SAFE": "🟢 ÍT RỦI RO",
        "SUSPICIOUS": "🟡 NGHI VẤN — CẦN KIỂM CHỨNG",
        "HIGH_RISK": "🟠 RỦI RO CAO — TẠM DỪNG GIAO DỊCH",
        "CRITICAL_SCAM": "🔴 CẢNH BÁO ĐỎ — DẤU HIỆU LỪA ĐẢO RÕ RỆT",
    }
    lines = [
        f"🛡 VeriShield AI | {badge_map[report.verdict]} ({report.risk_score}/100)",
        f"📌 Tóm tắt: {report.summary_vi}",
    ]
    if report.matched_playbooks:
        lines.append(f"🎯 Kịch bản khớp: {', '.join(report.matched_playbooks[:2])}")
    if report.actions.merchant_balance_warning:
        lines.append(f"⚠️ {report.actions.merchant_balance_warning}")
    if report.actions.counter_replies:
        lines.append(f"💬 Gợi ý phản hồi: \"{report.actions.counter_replies[0]}\"")
    if report.actions.urgent_steps:
        lines.append(f"✅ Việc cần làm ngay: {report.actions.urgent_steps[0]}")
    lines.append(f"🆔 Mã hồ sơ: {report.case_id}")
    return "\n\n".join(lines)


async def handle_telegram_update(
    update: dict[str, Any],
    pipeline: AnalysisPipeline,
    settings: Settings,
) -> dict[str, Any]:
    """Process incoming Telegram message/forwarded message and optionally reply via Bot API."""
    msg = update.get("message") or update.get("edited_message") or {}
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    raw_text = str(msg.get("text") or msg.get("caption") or "").strip()

    if not raw_text:
        reply_text = (
            "🛡 VeriShield AI: Hãy chuyển tiếp (Forward) tin nhắn đáng ngờ, đường link "
            "hoặc mô tả giao dịch vào đây để kiểm tra tức thì!"
        )
        return {"ok": True, "chat_id": chat_id, "reply_text": reply_text}

    report = await pipeline.run(mode="personal", text=raw_text)
    reply_text = format_telegram_verdict_reply(report)

    if settings.telegram_bot_token.strip() and chat_id is not None:
        api_url = f"https://api.telegram.org/bot{settings.telegram_bot_token.strip()}/sendMessage"
        client = build_ssrf_pinned_http_client(timeout_sec=4.0)
        try:
            await client.post(
                api_url,
                json={"chat_id": chat_id, "text": reply_text},
            )
        except Exception as exc:
            logger.warning("Telegram sendMessage failed (%s).", type(exc).__name__)
        finally:
            await client.aclose()

    return {
        "ok": True,
        "chat_id": chat_id,
        "case_id": report.case_id,
        "verdict": report.verdict,
        "risk_score": report.risk_score,
        "reply_text": reply_text,
    }
