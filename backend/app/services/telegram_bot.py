"""Telegram 1-Tap Multimodal Bot webhook handler with verified delivery & idempotency."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import logging
import re
import uuid
from typing import Any

from app.config import Settings
from app.core.case_tokens import CaseOwnerChannel, hash_telegram_private_owner
from app.core.media_executors import MediaExecutorBusyError, run_pdf_bounded
from app.core.security import InvalidMediaError, build_ssrf_pinned_http_client
from app.schemas import AnalysisReport
from app.services.pipeline import AnalysisPipeline
from app.services.report_pdf import generate_incident_pdf
from app.services.telegram_formatting import (
    TelegramEnvelope,
    build_demo_inline_keyboard,
    build_verdict_inline_keyboard,
    format_telegram_verdict_reply,
    parse_telegram_command,
    truncate_telegram_text,
    validate_telegram_update_envelope,
)
from app.services.telegram_limits import (
    TelegramQuotaGuard,
    TelegramRateLimitedError,
    get_telegram_quota_guard,
)
from app.services.telegram_media import (
    TelegramAttachment,
    TelegramMediaFetchError,
    TelegramMediaTooLargeError,
    answer_telegram_callback_query,
    download_telegram_file,
    extract_telegram_attachment,
    send_telegram_document,
    telegram_typing_scope,
)

logger = logging.getLogger(__name__)

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_MAX_DELIVERY_ATTEMPTS = 3
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
    "TelegramPermanentDeliveryError",
    "format_telegram_verdict_reply",
    "handle_telegram_update",
]


class TelegramDeliveryError(RuntimeError):
    """Raised when sending a reply through Telegram Bot API fails or is rejected."""


class TelegramPermanentDeliveryError(TelegramDeliveryError):
    """Raised when Telegram Bot API permanently rejects delivery (HTTP 400/403/404)."""


class InvalidTelegramPayloadError(ValueError):
    """Raised when an authenticated Telegram webhook body violates expected object structure."""


def _resolve_demo_id(pipeline: AnalysisPipeline, selector: str) -> str | None:
    demos = pipeline.list_demos()
    cleaned = selector.strip()
    if cleaned.isascii() and cleaned.isdigit() and len(cleaned) <= 3:
        idx = int(cleaned) - 1
        if 0 <= idx < len(demos):
            return demos[idx].demo_id
        return None
    for demo in demos:
        if demo.demo_id == cleaned:
            return demo.demo_id
    return None


async def _cancel_task(task: asyncio.Task[None] | None) -> None:
    if task is not None and not task.done():
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


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
        if resp.status_code in (400, 403, 404):
            raise TelegramPermanentDeliveryError(
                f"Telegram Bot API permanently rejected request with HTTP {resp.status_code}."
            )
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
    quota: TelegramQuotaGuard,
    token: str,
    chat_id: int | str | None,
    sender_user_id: int | str | None,
    raw_text: str,
    attachment: TelegramAttachment | None,
    callback_data: str | None,
    cached_case_id: str | None,
    owner_channel: CaseOwnerChannel,
    owner_chat_hash: str | None,
    allow_pdf_callback: bool,
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
        if not quota.allow_heavy(chat_id=chat_id, sender_user_id=sender_user_id):
            raise TelegramRateLimitedError("Telegram heavy analysis quota exceeded.")
        async with quota.analysis_slot(), telegram_typing_scope(token, chat_id):
            report = await pipeline.run(
                demo_id=demo_id,
                case_id_override=cached_case_id,
                owner_channel=owner_channel,
                owner_chat_hash=owner_chat_hash,
            )
        return (
            report,
            format_telegram_verdict_reply(report, include_group_pdf_note=not allow_pdf_callback),
            None,
        )

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
        if not quota.allow_heavy(chat_id=chat_id, sender_user_id=sender_user_id):
            raise TelegramRateLimitedError("Telegram heavy analysis quota exceeded.")
        async with quota.analysis_slot(), telegram_typing_scope(token, chat_id):
            report = await pipeline.run(
                demo_id=demo_id,
                case_id_override=cached_case_id,
                owner_channel=owner_channel,
                owner_chat_hash=owner_chat_hash,
            )
        return (
            report,
            format_telegram_verdict_reply(report, include_group_pdf_note=not allow_pdf_callback),
            None,
        )

    if parsed.direct_reply is not None:
        kb = build_demo_inline_keyboard(pipeline.list_demos()) if parsed.attach_demo_keyboard else None
        return None, parsed.direct_reply, kb

    analysis_text = parsed.cleaned_text
    if not analysis_text and (attachment is None or not token):
        return None, _EMPTY_GUIDANCE_REPLY, None

    if (
        attachment is not None
        and token
        and attachment.file_size is not None
        and attachment.file_size > settings.max_upload_bytes
    ):
        return None, _OVERSIZE_REPLY, None

    if not quota.allow_heavy(chat_id=chat_id, sender_user_id=sender_user_id):
        raise TelegramRateLimitedError("Telegram heavy analysis quota exceeded.")

    image_bytes: bytes | None = None
    image_filename = "telegram_photo.jpg"
    image_mime = "image/jpeg"
    audio_bytes: bytes | None = None
    audio_filename = "telegram_voice.ogg"
    audio_mime = "audio/ogg"
    media_note = ""

    async with quota.analysis_slot(), telegram_typing_scope(token, chat_id):
        if attachment is not None and token:
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
                owner_channel=owner_channel,
                owner_chat_hash=owner_chat_hash,
            )
        except InvalidMediaError:
            return (
                None,
                "⚠️ Tệp hình ảnh hoặc ghi âm bị lỗi định dạng nên không thể đọc được. "
                "Vui lòng gửi lại ảnh JPG, PNG, WebP hoặc tệp âm thanh WAV, MP3, OGG, M4A hợp lệ.",
                None,
            )

    verdict_html = format_telegram_verdict_reply(
        report,
        include_group_pdf_note=not allow_pdf_callback,
    )
    return report, truncate_telegram_text(media_note + verdict_html), None


async def _handle_telegram_pdf_callback(
    *,
    env: TelegramEnvelope,
    pipeline: AnalysisPipeline,
    token: str,
    secret: str,
) -> dict[str, Any]:
    """Handle private-chat-only `pdf:{case_id}` callbacks before any generic ack or sendMessage."""
    owner_id = uuid.uuid4().hex
    if env.update_id is not None:
        claim_state, _cached_cid, cached_reply = pipeline.repo.claim_telegram_update(
            env.update_id,
            owner_id=owner_id,
            lease_seconds=60,
            chat_id=env.chat_id,
            sender_user_id=env.sender_user_id,
            chat_type=env.chat_type,
            update_kind="pdf_callback",
        )
        if claim_state == "mismatch":
            return {"ok": True, "delivered": False, "pdf_sent": False, "ignored": True}
        if claim_state == "quarantined":
            return {"ok": True, "delivered": False, "pdf_sent": False, "quarantined": True}
        if claim_state == "in_progress":
            return {"ok": True, "delivered": False, "pdf_sent": False, "duplicate_in_progress": True}
        if claim_state == "cached":
            if env.callback_query_id and token:
                if cached_reply == "pdf_denied":
                    await answer_telegram_callback_query(
                        token,
                        env.callback_query_id,
                        "Không thể xác thực quyền tải báo cáo PDF cho hồ sơ này.",
                        show_alert=True,
                    )
                else:
                    await answer_telegram_callback_query(
                        token,
                        env.callback_query_id,
                        "Báo cáo PDF đã được gửi trước đó.",
                    )
            return {
                "ok": True,
                "delivered": False,
                "pdf_sent": False,
                "duplicate": True,
                "denied": cached_reply == "pdf_denied",
            }

    quota = get_telegram_quota_guard(pipeline)
    if not quota.allow_message(chat_id=env.chat_id, sender_user_id=env.sender_user_id):
        if env.update_id is not None:
            pipeline.repo.release_telegram_update_claim(env.update_id, owner_id=owner_id)
        return {"ok": True, "delivered": False, "pdf_sent": False, "rate_limited": True}

    async def _deny(message: str) -> dict[str, Any]:
        if env.callback_query_id and token:
            await answer_telegram_callback_query(token, env.callback_query_id, message, show_alert=True)
        if env.update_id is not None:
            pipeline.repo.save_telegram_update_cache(
                env.update_id, None, "pdf_denied", owner_id=owner_id
            )
        return {"ok": True, "delivered": False, "pdf_sent": False, "denied": True}

    try:
        case_id = (env.callback_data or "")[4:].strip()
        if env.chat_type != "private":
            return await _deny("Tải báo cáo PDF chỉ được hỗ trợ trong đoạn chat riêng (1-1) với bot.")
        if env.chat_id is None or env.sender_user_id is None or not case_id:
            return await _deny("Không thể xác thực quyền tải báo cáo PDF cho hồ sơ này.")

        record = pipeline.repo.get_report_with_owner(case_id)
        expected_hash = hash_telegram_private_owner(env.chat_id, env.sender_user_id, secret)
        if (
            record is None
            or record.owner_channel != "telegram_private"
            or not record.owner_chat_hash
            or not hmac.compare_digest(record.owner_chat_hash, expected_hash)
        ):
            return await _deny("Không thể xác thực quyền tải báo cáo PDF cho hồ sơ này.")

        if not token:
            if env.update_id is not None:
                pipeline.repo.release_telegram_update_claim(env.update_id, owner_id=owner_id)
            return {
                "ok": True,
                "delivered": False,
                "pdf_sent": False,
                "case_id": record.report.case_id,
                "chat_id": env.chat_id,
            }

        if not quota.allow_heavy(chat_id=env.chat_id, sender_user_id=env.sender_user_id):
            if env.update_id is not None:
                pipeline.repo.release_telegram_update_claim(env.update_id, owner_id=owner_id)
            if env.callback_query_id:
                await answer_telegram_callback_query(
                    token,
                    env.callback_query_id,
                    "Bạn thao tác quá nhanh. Vui lòng thử lại sau ít giây.",
                    show_alert=True,
                )
            return {"ok": True, "delivered": False, "pdf_sent": False, "rate_limited": True}

        try:
            async with quota.analysis_slot():
                pdf_bytes = await run_pdf_bounded(
                    generate_incident_pdf,
                    record.report,
                    already_redacted=True,
                    timeout_sec=15.0,
                )
        except TelegramRateLimitedError:
            if env.update_id is not None:
                pipeline.repo.release_telegram_update_claim(env.update_id, owner_id=owner_id)
            if env.callback_query_id:
                await answer_telegram_callback_query(
                    token,
                    env.callback_query_id,
                    "Hệ thống đang bận xử lý. Vui lòng thử lại sau ít giây.",
                    show_alert=True,
                )
            return {"ok": True, "delivered": False, "pdf_sent": False, "rate_limited": True}
        except (MediaExecutorBusyError, TimeoutError):
            if env.update_id is not None:
                pipeline.repo.release_telegram_update_claim(env.update_id, owner_id=owner_id)
            if env.callback_query_id:
                await answer_telegram_callback_query(
                    token,
                    env.callback_query_id,
                    "Hệ thống tạo báo cáo PDF đang bận. Vui lòng thử lại sau ít giây.",
                    show_alert=True,
                )
            return {
                "ok": True,
                "delivered": False,
                "pdf_sent": False,
                "case_id": record.report.case_id,
                "chat_id": env.chat_id,
            }

        safe_case = (
            "".join(ch for ch in record.report.case_id if ch.isalnum() or ch in ("_", "-"))
            or "report"
        )
        caption = f"📄 Báo cáo bằng chứng VeriShield AI — Mã hồ sơ: {record.report.case_id}"
        sent = await send_telegram_document(
            token,
            env.chat_id,
            f"verishield-{safe_case}.pdf",
            pdf_bytes,
            caption=caption,
        )
        if not sent:
            if env.update_id is not None:
                pipeline.repo.release_telegram_update_claim(env.update_id, owner_id=owner_id)
            if env.callback_query_id:
                await answer_telegram_callback_query(
                    token,
                    env.callback_query_id,
                    "Không thể gửi báo cáo PDF lúc này. Vui lòng thử lại sau.",
                    show_alert=True,
                )
            return {
                "ok": True,
                "delivered": False,
                "pdf_sent": False,
                "case_id": record.report.case_id,
                "chat_id": env.chat_id,
            }

        if env.update_id is not None:
            pipeline.repo.save_telegram_update_cache(
                env.update_id, record.report.case_id, "pdf_sent", owner_id=owner_id
            )
        if env.callback_query_id:
            await answer_telegram_callback_query(token, env.callback_query_id, "Đã gửi báo cáo PDF.")
        return {
            "ok": True,
            "delivered": True,
            "pdf_sent": True,
            "case_id": record.report.case_id,
            "chat_id": env.chat_id,
        }
    except Exception:
        if env.update_id is not None:
            _attempts, quarantined = pipeline.repo.record_telegram_delivery_failure(
                env.update_id,
                permanent=False,
                max_attempts=_MAX_DELIVERY_ATTEMPTS,
                owner_id=owner_id,
            )
            if quarantined:
                return {"ok": True, "delivered": False, "pdf_sent": False, "quarantined": True}
        raise


async def handle_telegram_update(
    update: dict[str, Any],
    pipeline: AnalysisPipeline,
    settings: Settings,
    case_token_secret: str | None = None,
) -> dict[str, Any]:
    """Process incoming Telegram message/callback with strict schema & update_id idempotency."""
    try:
        env = validate_telegram_update_envelope(update)
    except ValueError as exc:
        raise InvalidTelegramPayloadError(str(exc)) from exc

    if env.msg is None and env.callback_data is None:
        return {"ok": True, "delivered": False, "ignored": True}

    token = settings.telegram_bot_token.strip()
    secret = (
        case_token_secret.strip()
        if case_token_secret and case_token_secret.strip()
        else pipeline.case_token_secret
    )

    if env.callback_data and env.callback_data.lower().startswith("pdf:"):
        return await _handle_telegram_pdf_callback(
            env=env,
            pipeline=pipeline,
            token=token,
            secret=secret,
        )

    is_private_owner = (
        env.chat_type == "private" and env.chat_id is not None and env.sender_user_id is not None
    )
    owner_channel: CaseOwnerChannel = (
        "telegram_private" if is_private_owner else "telegram_group_locked"
    )
    owner_chat_hash: str | None = (
        hash_telegram_private_owner(env.chat_id, env.sender_user_id, secret)
        if (is_private_owner and env.chat_id is not None and env.sender_user_id is not None)
        else None
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
    update_kind = "callback" if env.callback_data else "message"

    if env.update_id is not None:
        claim_state, cached_case_id, cached_reply = pipeline.repo.claim_telegram_update(
            env.update_id,
            owner_id=owner_id,
            lease_seconds=180,
            chat_id=env.chat_id,
            sender_user_id=env.sender_user_id,
            chat_type=env.chat_type,
            update_kind=update_kind,
        )
        if claim_state == "mismatch":
            return {"ok": True, "delivered": False, "ignored": True}
        if claim_state == "quarantined":
            return {"ok": True, "delivered": False, "quarantined": True}
        if claim_state == "in_progress":
            return {"ok": True, "delivered": False, "duplicate_in_progress": True}
        if claim_state == "cached":
            if env.chat_id is None or cached_reply is None:
                return {"ok": True, "delivered": False, "ignored": True}
            if cached_case_id:
                record = pipeline.repo.get_report_with_owner(cached_case_id)
                if record is None or record.owner_channel != owner_channel:
                    return {"ok": True, "delivered": False, "ignored": True}
                if owner_channel == "telegram_private" and (
                    not record.owner_chat_hash
                    or not owner_chat_hash
                    or not hmac.compare_digest(record.owner_chat_hash, owner_chat_hash)
                ):
                    return {"ok": True, "delivered": False, "ignored": True}
                report = record.report
            reply_text = cached_reply

    quota = get_telegram_quota_guard(pipeline)
    if claim_state != "cached" and not quota.allow_message(
        chat_id=env.chat_id, sender_user_id=env.sender_user_id
    ):
        if env.update_id is not None:
            pipeline.repo.release_telegram_update_claim(env.update_id, owner_id=owner_id)
        return {"ok": True, "delivered": False, "rate_limited": True}

    if env.callback_query_id and token:
        await answer_telegram_callback_query(
            token, env.callback_query_id, "⏳ VeriShield AI đang kiểm tra…"
        )

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
                quota=quota,
                token=token,
                chat_id=env.chat_id,
                sender_user_id=env.sender_user_id,
                raw_text=env.raw_text,
                attachment=attachment,
                callback_data=env.callback_data,
                cached_case_id=cached_case_id,
                owner_channel=owner_channel,
                owner_chat_hash=owner_chat_hash,
                allow_pdf_callback=is_private_owner,
            )
            if env.update_id is not None:
                pipeline.repo.save_telegram_update_cache(
                    env.update_id,
                    report.case_id if report is not None else None,
                    reply_text,
                    owner_id=owner_id,
                    update_kind=update_kind,
                )
        except TelegramRateLimitedError:
            await _cancel_task(renew_task)
            if env.update_id is not None:
                pipeline.repo.release_telegram_update_claim(env.update_id, owner_id=owner_id)
            return {"ok": True, "delivered": False, "rate_limited": True}
        except Exception:
            await _cancel_task(renew_task)
            if env.update_id is not None:
                _attempts, quarantined = pipeline.repo.record_telegram_delivery_failure(
                    env.update_id,
                    permanent=False,
                    max_attempts=_MAX_DELIVERY_ATTEMPTS,
                    owner_id=owner_id,
                )
                if quarantined:
                    return {"ok": True, "delivered": False, "quarantined": True}
            raise
        finally:
            await _cancel_task(renew_task)

    reply_markup = (
        build_verdict_inline_keyboard(
            report.case_id,
            settings.public_base_url,
            allow_pdf_callback=is_private_owner,
        )
        if report is not None
        else custom_markup
    )

    delivered = False
    if env.chat_id is not None and token:
        try:
            if reply_markup is not None:
                await _deliver_telegram_message(
                    token, env.chat_id, reply_text, reply_markup=reply_markup
                )
            else:
                await _deliver_telegram_message(token, env.chat_id, reply_text)
        except TelegramPermanentDeliveryError:
            if env.update_id is not None:
                pipeline.repo.record_telegram_delivery_failure(
                    env.update_id,
                    permanent=True,
                    owner_id=owner_id,
                )
            return {"ok": True, "delivered": False, "permanent_error": True}
        except TelegramDeliveryError:
            if env.update_id is not None:
                _attempts, quarantined = pipeline.repo.record_telegram_delivery_failure(
                    env.update_id,
                    permanent=False,
                    max_attempts=_MAX_DELIVERY_ATTEMPTS,
                    owner_id=owner_id,
                )
                if quarantined:
                    return {"ok": True, "delivered": False, "quarantined": True}
            raise
        delivered = True

    response: dict[str, Any] = {
        "ok": True,
        "delivered": delivered,
        "chat_id": env.chat_id,
    }
    if env.chat_id is not None and not token:
        response["reply_text"] = reply_text
        response["method"] = "sendMessage"
        response["text"] = reply_text
        if reply_markup is not None:
            response["reply_markup"] = reply_markup
    if report is not None and env.chat_id is not None:
        response["case_id"] = report.case_id
        response["verdict"] = report.verdict
        response["risk_score"] = report.risk_score
    return response
