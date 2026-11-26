"""Telegram 1-Tap Forward Bot webhook handler with verified Bot API delivery & idempotency."""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from app.config import Settings
from app.core.security import build_ssrf_pinned_http_client
from app.schemas import AnalysisReport
from app.services.pipeline import AnalysisPipeline

logger = logging.getLogger(__name__)


class TelegramDeliveryError(RuntimeError):
    """Raised when sending a reply through Telegram Bot API fails or is rejected."""


class InvalidTelegramPayloadError(ValueError):
    """Raised when an authenticated Telegram webhook body violates expected object structure."""


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
    """Process incoming Telegram message/forwarded message with strict schema & update_id idempotency."""
    if not isinstance(update, dict):
        raise InvalidTelegramPayloadError("Telegram update must be a JSON object.")

    raw_update_id = update.get("update_id")
    if raw_update_id is not None and (
        isinstance(raw_update_id, bool) or not isinstance(raw_update_id, int)
    ):
        raise InvalidTelegramPayloadError("Telegram update_id must be an integer.")
    update_id: int | None = raw_update_id

    for field_name in ("message", "edited_message"):
        if (
            field_name in update
            and update[field_name] is not None
            and not isinstance(update[field_name], dict)
        ):
            raise InvalidTelegramPayloadError(f"Telegram field '{field_name}' must be a JSON object.")

    msg = update.get("message") or update.get("edited_message")
    if msg is None:
        return {"ok": True, "delivered": False, "ignored": True}

    chat = msg.get("chat")
    if chat is not None and not isinstance(chat, dict):
        raise InvalidTelegramPayloadError("Telegram message.chat must be a JSON object.")
    chat_id = chat.get("id") if isinstance(chat, dict) else None
    if chat_id is not None and (isinstance(chat_id, bool) or not isinstance(chat_id, (int, str))):
        raise InvalidTelegramPayloadError("Telegram chat.id must be an integer or string.")

    raw_text_field = msg.get("text") if msg.get("text") is not None else msg.get("caption")
    if raw_text_field is not None and not isinstance(raw_text_field, str):
        raise InvalidTelegramPayloadError("Telegram text/caption must be a string.")
    raw_text = (raw_text_field or "").strip()

    report: AnalysisReport | None = None
    claim_state = "untracked"
    cached_case_id: str | None = None
    reply_text = ""
    owner_id = uuid.uuid4().hex

    if update_id is not None:
        claim_state, cached_case_id, cached_reply = pipeline.repo.claim_telegram_update(
            update_id,
            owner_id=owner_id,
            lease_seconds=180,
        )
        if claim_state == "in_progress":
            return {"ok": True, "delivered": False, "duplicate_in_progress": True}
        if claim_state == "cached" and cached_reply is not None:
            reply_text = cached_reply
            if cached_case_id:
                report = pipeline.repo.get_report(cached_case_id)

    if claim_state != "cached":
        renew_task: asyncio.Task[None] | None = None
        if update_id is not None:
            uid_for_renew = update_id

            async def _heartbeat() -> None:
                while True:
                    await asyncio.sleep(30.0)
                    pipeline.repo.renew_telegram_update_lease(
                        uid_for_renew,
                        owner_id=owner_id,
                        lease_seconds=180,
                    )

            renew_task = asyncio.create_task(_heartbeat())
        try:
            if not raw_text:
                reply_text = (
                    "🛡 VeriShield AI: Hãy chuyển tiếp (Forward) tin nhắn đáng ngờ, đường link "
                    "hoặc mô tả giao dịch vào đây để kiểm tra tức thì!"
                )
                if update_id is not None:
                    pipeline.repo.save_telegram_update_cache(
                        update_id,
                        None,
                        reply_text,
                        owner_id=owner_id,
                    )
            else:
                report = await pipeline.run(
                    mode="personal",
                    text=raw_text,
                    case_id_override=cached_case_id,
                )
                reply_text = format_telegram_verdict_reply(report)
                if update_id is not None:
                    pipeline.repo.save_telegram_update_cache(
                        update_id,
                        report.case_id,
                        reply_text,
                        owner_id=owner_id,
                    )
        except Exception:
            if update_id is not None:
                pipeline.repo.release_telegram_update_claim(update_id, owner_id=owner_id)
            raise
        finally:
            if renew_task is not None:
                renew_task.cancel()

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
        response["method"] = "sendMessage"
        response["text"] = reply_text

    if report is not None:
        response["case_id"] = report.case_id
        response["verdict"] = report.verdict
        response["risk_score"] = report.risk_score

    return response
