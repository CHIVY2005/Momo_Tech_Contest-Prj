"""Telegram 1-Tap Multimodal Bot webhook handler with verified delivery & idempotency."""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from app.config import Settings
from app.core.security import InvalidMediaError, build_ssrf_pinned_http_client
from app.schemas import AnalysisReport
from app.services.pipeline import AnalysisPipeline
from app.services.telegram_formatting import (
    build_verdict_inline_keyboard,
    format_telegram_verdict_reply,
    parse_telegram_command,
    truncate_telegram_text,
    validate_telegram_update_envelope,
)
from app.services.telegram_media import (
    TelegramAttachment,
    TelegramMediaFetchError,
    TelegramMediaTooLargeError,
    download_telegram_file,
    extract_telegram_attachment,
    send_telegram_typing_action,
)

logger = logging.getLogger(__name__)

_OVERSIZE_REPLY = (
    "⚠️ Tệp gửi lên vượt quá giới hạn an toàn 10 MB. "
    "Vui lòng gửi ảnh/ghi âm nhỏ hơn để kiểm tra."
)
_EMPTY_GUIDANCE_REPLY = (
    "🛡 VeriShield AI: Hãy chuyển tiếp (Forward) tin nhắn đáng ngờ, đường link, "
    "ảnh biên lai/VietQR hoặc tin nhắn thoại vào đây để kiểm tra tức thì! "
    "(Gõ /help để xem hướng dẫn)"
)

__all__ = [
    "InvalidTelegramPayloadError",
    "TelegramDeliveryError",
    "format_telegram_verdict_reply",
    "handle_telegram_update",
]


class TelegramDeliveryError(RuntimeError):
    """Raised when sending a reply through Telegram Bot API fails or is rejected."""


class InvalidTelegramPayloadError(ValueError):
    """Raised when an authenticated Telegram webhook body violates expected object structure."""


async def _deliver_telegram_message(
    bot_token: str,
    chat_id: int | str,
    text: str,
    reply_markup: dict[str, Any] | None = None,
) -> None:
    api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    body: dict[str, Any] = {"chat_id": chat_id, "text": truncate_telegram_text(text)}
    if reply_markup is not None:
        body["reply_markup"] = reply_markup

    client = build_ssrf_pinned_http_client(timeout_sec=10.0)
    try:
        resp = await client.post(api_url, json=body)
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


async def _analyze_telegram_payload(
    *,
    pipeline: AnalysisPipeline,
    settings: Settings,
    token: str,
    chat_id: int | str | None,
    raw_text: str,
    attachment: TelegramAttachment | None,
    cached_case_id: str | None,
) -> tuple[AnalysisReport | None, str]:
    direct_reply, mode, expected_stk, analysis_text = parse_telegram_command(
        raw_text, has_attachment=attachment is not None
    )
    if direct_reply is not None:
        return None, direct_reply

    if not analysis_text and (attachment is None or not token):
        return None, _EMPTY_GUIDANCE_REPLY

    if chat_id is not None and token:
        await send_telegram_typing_action(token, chat_id)

    image_bytes: bytes | None = None
    image_filename = "telegram_photo.jpg"
    image_mime = "image/jpeg"
    audio_bytes: bytes | None = None
    audio_filename = "telegram_voice.ogg"
    audio_mime = "audio/ogg"
    media_note = ""

    if attachment is not None and token:
        if attachment.file_size is not None and attachment.file_size > settings.max_upload_bytes:
            return None, _OVERSIZE_REPLY
        try:
            media_bytes, resolved_name = await download_telegram_file(
                token, attachment.file_id, settings.max_upload_bytes
            )
            if attachment.kind == "image":
                image_bytes = media_bytes
                image_filename = attachment.filename or resolved_name
                image_mime = attachment.mime_type
            else:
                audio_bytes = media_bytes
                audio_filename = attachment.filename or resolved_name
                audio_mime = attachment.mime_type
        except TelegramMediaTooLargeError:
            return None, _OVERSIZE_REPLY
        except TelegramMediaFetchError:
            if not analysis_text:
                return (
                    None,
                    "⚠️ Không thể tải tệp đính kèm từ Telegram lúc này. "
                    "Vui lòng gửi lại ảnh/ghi âm hoặc dán nội dung tin nhắn.",
                )
            media_note = (
                "ℹ️ Không tải được tệp đính kèm từ Telegram — "
                "kết quả bên dưới chỉ dựa trên phần văn bản.\n\n"
            )

    try:
        report = await pipeline.run(
            mode=mode,
            text=analysis_text,
            image_bytes=image_bytes,
            image_filename=image_filename,
            image_mime=image_mime,
            audio_bytes=audio_bytes,
            audio_filename=audio_filename,
            audio_mime=audio_mime,
            expected_merchant_account=expected_stk,
            case_id_override=cached_case_id,
        )
    except InvalidMediaError:
        return (
            None,
            "⚠️ Tệp hình ảnh/âm thanh bị lỗi định dạng hoặc không đọc được. "
            "Vui lòng gửi lại ảnh JPG/PNG/WebP hoặc ghi âm WAV/MP3/OGG/M4A hợp lệ.",
        )

    return report, truncate_telegram_text(media_note + format_telegram_verdict_reply(report))


async def handle_telegram_update(
    update: dict[str, Any],
    pipeline: AnalysisPipeline,
    settings: Settings,
) -> dict[str, Any]:
    """Process incoming Telegram message/media with strict schema & update_id idempotency."""
    try:
        update_id, msg, chat_id, raw_text = validate_telegram_update_envelope(update)
    except ValueError as exc:
        raise InvalidTelegramPayloadError(str(exc)) from exc

    if msg is None:
        return {"ok": True, "delivered": False, "ignored": True}

    attachment = extract_telegram_attachment(msg, max_bytes=settings.max_upload_bytes)

    report: AnalysisReport | None = None
    claim_state = "untracked"
    cached_case_id: str | None = None
    reply_text = ""
    owner_id = uuid.uuid4().hex
    token = settings.telegram_bot_token.strip()

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
            report, reply_text = await _analyze_telegram_payload(
                pipeline=pipeline,
                settings=settings,
                token=token,
                chat_id=chat_id,
                raw_text=raw_text,
                attachment=attachment,
                cached_case_id=cached_case_id,
            )
            if update_id is not None:
                pipeline.repo.save_telegram_update_cache(
                    update_id,
                    report.case_id if report is not None else None,
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

    reply_markup = (
        build_verdict_inline_keyboard(report.case_id, settings.public_base_url)
        if report is not None
        else None
    )

    delivered = False
    if chat_id is not None and token:
        if reply_markup is not None:
            await _deliver_telegram_message(token, chat_id, reply_text, reply_markup=reply_markup)
        else:
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
        if reply_markup is not None:
            response["reply_markup"] = reply_markup

    if report is not None:
        response["case_id"] = report.case_id
        response["verdict"] = report.verdict
        response["risk_score"] = report.risk_score

    return response
