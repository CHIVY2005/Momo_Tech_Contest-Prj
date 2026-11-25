"""Telegram 1-Tap Forward Bot webhook handler with verified Bot API delivery."""

from __future__ import annotations

import logging
from typing import Any

from app.config import Settings
from app.core.security import build_ssrf_pinned_http_client
from app.schemas import AnalysisReport
from app.services.pipeline import AnalysisPipeline

logger = logging.getLogger(__name__)


class TelegramDeliveryError(RuntimeError):
    """Raised when sending a reply through Telegram Bot API fails or is rejected."""


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


async def _deliver_telegram_message(bot_token: str, chat_id: int | str, text: str) -> None:
    api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    client = build_ssrf_pinned_http_client(timeout_sec=4.0)
    try:
        resp = await client.post(
            api_url,
            json={"chat_id": chat_id, "text": text},
        )
    except Exception as exc:
        logger.warning("Telegram sendMessage transport failure (%s).", type(exc).__name__)
        raise TelegramDeliveryError("Telegram Bot API transport failure.") from exc
    finally:
        await client.aclose()

    if not resp.is_success:
        logger.warning("Telegram sendMessage rejected with HTTP %s.", resp.status_code)
        raise TelegramDeliveryError(f"Telegram Bot API returned HTTP {resp.status_code}.")

    try:
        payload = resp.json()
    except ValueError as exc:
        raise TelegramDeliveryError("Telegram Bot API returned invalid JSON.") from exc

    if not isinstance(payload, dict) or payload.get("ok") is not True:
        raise TelegramDeliveryError("Telegram Bot API reported ok=false.")


async def handle_telegram_update(
    update: dict[str, Any],
    pipeline: AnalysisPipeline,
    settings: Settings,
) -> dict[str, Any]:
    """Process incoming Telegram message/forwarded message and deliver reply reliably."""
    msg = update.get("message") or update.get("edited_message") or {}
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    raw_text = str(msg.get("text") or msg.get("caption") or "").strip()

    report: AnalysisReport | None = None
    if not raw_text:
        reply_text = (
            "🛡 VeriShield AI: Hãy chuyển tiếp (Forward) tin nhắn đáng ngờ, đường link "
            "hoặc mô tả giao dịch vào đây để kiểm tra tức thì!"
        )
    else:
        report = await pipeline.run(mode="personal", text=raw_text)
        reply_text = format_telegram_verdict_reply(report)

    token = settings.telegram_bot_token.strip()
    delivered = False
    if chat_id is not None and token:
        await _deliver_telegram_message(token, chat_id, reply_text)
        delivered = True

    response: dict[str, Any] = {
        "ok": True,
        "delivered": delivered,
        "chat_id": chat_id,
        "reply_text": reply_text,
    }
    if chat_id is not None and not token:
        # Valid Telegram webhook-method fallback when outbound Bot API token is not set
        response["method"] = "sendMessage"
        response["text"] = reply_text

    if report is not None:
        response["case_id"] = report.case_id
        response["verdict"] = report.verdict
        response["risk_score"] = report.risk_score

    return response
