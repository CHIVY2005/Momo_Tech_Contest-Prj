"""Telegram 1-Tap Multimodal Bot webhook handler with verified delivery & idempotency."""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from typing import Any

from app.config import Settings
from app.core.security import InvalidMediaError, build_ssrf_pinned_http_client
from app.schemas import AnalysisReport
from app.services.pipeline import AnalysisPipeline
from app.services.telegram_formatting import (
    build_demo_inline_keyboard,
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
    answer_telegram_callback_query,
    download_telegram_file,
    extract_telegram_attachment,
    telegram_typing_scope,
)

logger = logging.getLogger(__name__)

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_OVERSIZE_REPLY = (
    "⚠️ Tệp gửi lên vượt quá dung lượng tối đa 10 MB. "
    "Vui lòng gửi ảnh hoặc tệp ghi âm nhỏ hơn để kiểm tra."
)
_EMPTY_GUIDANCE_REPLY = (
    "🛡 <b>VeriShield AI:</b> Hãy gửi hoặc chuyển tiếp tin nhắn đáng ngờ, đường dẫn, "
    "ảnh biên lai, mã VietQR hoặc tin nhắn thoại vào đây để kiểm tra ngay.\n"
    "(Gõ /demo để thử tình huống mẫu hoặc /help để xem hướng dẫn)"
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


def _resolve_demo_id(pipeline: AnalysisPipeline, selector: str) -> str | None:
    demos = pipeline.list_demos()
    cleaned = selector.strip()
    if cleaned.isdigit():
        idx = int(cleaned) - 1
        if 0 <= idx < len(demos):
            return demos[idx].demo_id
        return None
    for demo in demos:
        if demo.demo_id == cleaned:
            return demo.demo_id
    return None


async def _deliver_telegram_message(
    bot_token: str,
    chat_id: int | str,
    text: str,
    reply_markup: dict[str, Any] | None = None,
    parse_mode: str | None = "HTML",
) -> None:
    api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    body: dict[str, Any] = {"chat_id": chat_id, "text": truncate_telegram_text(text)}
    if parse_mode:
        body["parse_mode"] = parse_mode
    if reply_markup is not None:
        body["reply_markup"] = reply_markup

    client = build_ssrf_pinned_http_client(timeout_sec=10.0)
    try:
        try:
            resp = await client.post(api_url, json=body)
        except Exception as exc:
            logger.warning("Telegram sendMessage transport failure (%s).", type(exc).__name__)
            raise TelegramDeliveryError("Telegram Bot API transport failure.") from exc

        # Belt-and-suspenders: if Telegram rejects HTML entities (HTTP 400), retry as plain text
        if resp.status_code == 400 and parse_mode == "HTML" and "parse entities" in resp.text.lower():
            plain_body = {k: v for k, v in body.items() if k != "parse_mode"}
            plain_body["text"] = truncate_telegram_text(_HTML_TAG_RE.sub("", text))
            try:
                resp = await client.post(api_url, json=plain_body)
            except Exception as exc:
                raise TelegramDeliveryError("Telegram fallback sendMessage failure.") from exc
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
    callback_data: str | None,
    cached_case_id: str | None,
) -> tuple[AnalysisReport | None, str, dict[str, Any] | None]:
    demo_selector: str | None = None
    if callback_data and callback_data.startswith("demo:"):
        demo_selector = callback_data.split(":", 1)[1].strip()

    if demo_selector is not None:
        demo_id = _resolve_demo_id(pipeline, demo_selector)
        if not demo_id:
            return (
                None,
                "⚠️ Không tìm thấy tình huống mẫu. Hãy chọn <code>/demo 1</code> đến "
                "<code>/demo 5</code> hoặc bấm một nút bên dưới:",
                build_demo_inline_keyboard(pipeline.list_demos()),
            )
        async with telegram_typing_scope(token, chat_id):
            report = await pipeline.run(demo_id=demo_id, case_id_override=cached_case_id)
        return report, format_telegram_verdict_reply(report), None

    parsed = parse_telegram_command(raw_text, has_attachment=attachment is not None)
    if parsed.demo_selector is not None:
        demo_id = _resolve_demo_id(pipeline, parsed.demo_selector)
        if not demo_id:
            return (
                None,
                "⚠️ Hiện có 5 tình huống mẫu từ <code>/demo 1</code> đến <code>/demo 5</code>. "
                "Hoặc chọn nhanh bên dưới:",
                build_demo_inline_keyboard(pipeline.list_demos()),
            )
        async with telegram_typing_scope(token, chat_id):
            report = await pipeline.run(demo_id=demo_id, case_id_override=cached_case_id)
        return report, format_telegram_verdict_reply(report), None

    if parsed.direct_reply is not None:
        kb = build_demo_inline_keyboard(pipeline.list_demos()) if parsed.attach_demo_keyboard else None
        return None, parsed.direct_reply, kb

    analysis_text = parsed.cleaned_text
    if not analysis_text and (attachment is None or not token):
        return None, _EMPTY_GUIDANCE_REPLY, None

    image_bytes: bytes | None = None
    image_filename = "telegram_photo.jpg"
    image_mime = "image/jpeg"
    audio_bytes: bytes | None = None
    audio_filename = "telegram_voice.ogg"
    audio_mime = "audio/ogg"
    media_note = ""

    async with telegram_typing_scope(token, chat_id):
        if attachment is not None and token:
            if attachment.file_size is not None and attachment.file_size > settings.max_upload_bytes:
                return None, _OVERSIZE_REPLY, None
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
                return None, _OVERSIZE_REPLY, None
            except TelegramMediaFetchError:
                if not analysis_text:
                    return (
                        None,
                        "⚠️ Không thể tải tệp đính kèm từ Telegram lúc này. "
                        "Vui lòng gửi lại ảnh/ghi âm hoặc dán nội dung tin nhắn.",
                        None,
                    )
                media_note = (
                    "ℹ️ <i>Không tải được tệp đính kèm — kết quả bên dưới chỉ dựa trên văn bản.</i>\n\n"
                )

        try:
            report = await pipeline.run(
                mode=parsed.mode,
                text=analysis_text,
                image_bytes=image_bytes,
                image_filename=image_filename,
                image_mime=image_mime,
                audio_bytes=audio_bytes,
                audio_filename=audio_filename,
                audio_mime=audio_mime,
                in_active_call=parsed.in_active_call,
                expected_merchant_account=parsed.expected_stk,
                case_id_override=cached_case_id,
            )
        except InvalidMediaError:
            return (
                None,
                "⚠️ Tệp hình ảnh hoặc ghi âm bị lỗi định dạng nên không thể đọc được. "
                "Vui lòng gửi lại ảnh JPG, PNG, WebP hoặc tệp âm thanh WAV, MP3, OGG, M4A hợp lệ.",
                None,
            )

    return report, truncate_telegram_text(media_note + format_telegram_verdict_reply(report)), None


async def handle_telegram_update(
    update: dict[str, Any],
    pipeline: AnalysisPipeline,
    settings: Settings,
) -> dict[str, Any]:
    """Process incoming Telegram message/callback with strict schema & update_id idempotency."""
    try:
        env = validate_telegram_update_envelope(update)
    except ValueError as exc:
        raise InvalidTelegramPayloadError(str(exc)) from exc

    if env.msg is None and env.callback_data is None:
        return {"ok": True, "delivered": False, "ignored": True}

    token = settings.telegram_bot_token.strip()
    if env.callback_query_id and token:
        await answer_telegram_callback_query(
            token, env.callback_query_id, "⏳ VeriShield AI đang kiểm tra…"
        )

    attachment = (
        extract_telegram_attachment(env.msg, max_bytes=settings.max_upload_bytes)
        if env.msg is not None and not env.callback_data
        else None
    )

    report: AnalysisReport | None = None
    custom_markup: dict[str, Any] | None = None
    claim_state = "untracked"
    cached_case_id: str | None = None
    reply_text = ""
    owner_id = uuid.uuid4().hex

    if env.update_id is not None:
        claim_state, cached_case_id, cached_reply = pipeline.repo.claim_telegram_update(
            env.update_id, owner_id=owner_id, lease_seconds=180
        )
        if claim_state == "in_progress":
            return {"ok": True, "delivered": False, "duplicate_in_progress": True}
        if claim_state == "cached" and cached_reply is not None:
            reply_text = cached_reply
            if cached_case_id:
                report = pipeline.repo.get_report(cached_case_id)

    if claim_state != "cached":
        renew_task: asyncio.Task[None] | None = None
        if env.update_id is not None:
            uid_for_renew = env.update_id

            async def _heartbeat() -> None:
                while True:
                    await asyncio.sleep(30.0)
                    pipeline.repo.renew_telegram_update_lease(
                        uid_for_renew, owner_id=owner_id, lease_seconds=180
                    )

            renew_task = asyncio.create_task(_heartbeat())
        try:
            report, reply_text, custom_markup = await _analyze_telegram_payload(
                pipeline=pipeline,
                settings=settings,
                token=token,
                chat_id=env.chat_id,
                raw_text=env.raw_text,
                attachment=attachment,
                callback_data=env.callback_data,
                cached_case_id=cached_case_id,
            )
            if env.update_id is not None:
                pipeline.repo.save_telegram_update_cache(
                    env.update_id,
                    report.case_id if report is not None else None,
                    reply_text,
                    owner_id=owner_id,
                )
        except Exception:
            if env.update_id is not None:
                pipeline.repo.release_telegram_update_claim(env.update_id, owner_id=owner_id)
            raise
        finally:
            if renew_task is not None:
                renew_task.cancel()

    reply_markup = (
        build_verdict_inline_keyboard(report.case_id, settings.public_base_url)
        if report is not None
        else custom_markup
    )

    delivered = False
    if env.chat_id is not None and token:
        if reply_markup is not None:
            await _deliver_telegram_message(token, env.chat_id, reply_text, reply_markup=reply_markup)
        else:
            await _deliver_telegram_message(token, env.chat_id, reply_text)
        delivered = True

    response: dict[str, Any] = {
        "ok": True,
        "delivered": delivered,
        "chat_id": env.chat_id,
        "reply_text": reply_text,
    }
    if env.chat_id is not None and not token:
        response["method"] = "sendMessage"
        response["text"] = reply_text
        if reply_markup is not None:
            response["reply_markup"] = reply_markup
    if report is not None:
        response["case_id"] = report.case_id
        response["verdict"] = report.verdict
        response["risk_score"] = report.risk_score
    return response
