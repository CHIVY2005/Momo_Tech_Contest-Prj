"""Telegram Bot API media extraction, bounded SSRF-safe download, typing & callback ack."""

from __future__ import annotations

import asyncio
import logging
import mimetypes
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal

from app.core.security import build_ssrf_pinned_http_client
from app.services.telegram_formatting import (
    TELEGRAM_MAX_TEXT_LEN,
    build_verdict_inline_keyboard,
    truncate_telegram_text,
)

logger = logging.getLogger(__name__)

_IMAGE_EXTS: Final[frozenset[str]] = frozenset({".jpg", ".jpeg", ".png", ".webp"})
_AUDIO_EXTS: Final[frozenset[str]] = frozenset(
    {".wav", ".mp3", ".m4a", ".ogg", ".oga", ".flac", ".webm"}
)

__all__ = [
    "TELEGRAM_MAX_TEXT_LEN",
    "TelegramAttachment",
    "TelegramMediaFetchError",
    "TelegramMediaTooLargeError",
    "answer_telegram_callback_query",
    "build_verdict_inline_keyboard",
    "download_telegram_file",
    "extract_telegram_attachment",
    "send_telegram_typing_action",
    "telegram_typing_scope",
    "truncate_telegram_text",
]


class TelegramMediaTooLargeError(ValueError):
    """Raised when a Telegram attachment exceeds the configured max_upload_bytes ceiling."""


class TelegramMediaFetchError(RuntimeError):
    """Raised when retrieving file metadata or bytes from Telegram Bot API fails."""


@dataclass(frozen=True, slots=True)
class TelegramAttachment:
    """Normalized image or audio attachment descriptor extracted from a Telegram message."""

    kind: Literal["image", "audio"]
    file_id: str
    filename: str
    mime_type: str
    file_size: int | None = None


def _parse_optional_int(raw: object) -> int | None:
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        return None
    return raw


def _extract_photo(msg: dict[str, Any], max_bytes: int) -> TelegramAttachment | None:
    photos = msg.get("photo")
    if not isinstance(photos, list) or not photos:
        return None
    candidates = [
        item
        for item in photos
        if isinstance(item, dict)
        and isinstance(item.get("file_id"), str)
        and item["file_id"].strip()
    ]
    if not candidates:
        return None

    within_limit = [
        item
        for item in candidates
        if (sz := _parse_optional_int(item.get("file_size"))) is None or sz <= max_bytes
    ]
    chosen = within_limit[-1] if within_limit else candidates[-1]
    return TelegramAttachment(
        kind="image",
        file_id=str(chosen["file_id"]).strip(),
        filename="telegram_photo.jpg",
        mime_type="image/jpeg",
        file_size=_parse_optional_int(chosen.get("file_size")),
    )


def _extract_voice_or_audio(msg: dict[str, Any]) -> TelegramAttachment | None:
    voice = msg.get("voice")
    if (
        isinstance(voice, dict)
        and isinstance(voice.get("file_id"), str)
        and voice["file_id"].strip()
    ):
        mime = str(voice.get("mime_type") or "audio/ogg").strip().lower()
        return TelegramAttachment(
            kind="audio",
            file_id=voice["file_id"].strip(),
            filename="telegram_voice.ogg",
            mime_type=mime if mime.startswith("audio/") else "audio/ogg",
            file_size=_parse_optional_int(voice.get("file_size")),
        )

    audio = msg.get("audio")
    if (
        isinstance(audio, dict)
        and isinstance(audio.get("file_id"), str)
        and audio["file_id"].strip()
    ):
        mime = str(audio.get("mime_type") or "audio/mpeg").strip().lower()
        raw_name = str(audio.get("file_name") or "").strip()
        ext = Path(raw_name).suffix.lower() if raw_name else (mimetypes.guess_extension(mime) or ".mp3")
        safe_name = Path(raw_name).name if raw_name else f"telegram_audio{ext}"
        return TelegramAttachment(
            kind="audio",
            file_id=audio["file_id"].strip(),
            filename=safe_name,
            mime_type=mime if mime.startswith("audio/") else "audio/mpeg",
            file_size=_parse_optional_int(audio.get("file_size")),
        )
    return None


def _extract_media_document(msg: dict[str, Any]) -> TelegramAttachment | None:
    doc = msg.get("document")
    if not isinstance(doc, dict) or not isinstance(doc.get("file_id"), str) or not doc["file_id"].strip():
        return None
    mime = str(doc.get("mime_type") or "").strip().lower()
    raw_name = str(doc.get("file_name") or "").strip()
    safe_name = Path(raw_name).name if raw_name else ""
    ext = Path(safe_name).suffix.lower()

    if mime.startswith("image/") or ext in _IMAGE_EXTS:
        guessed_img = mimetypes.guess_type(safe_name)[0] or "image/jpeg"
        resolved_mime = mime if mime.startswith("image/") else guessed_img
        return TelegramAttachment(
            kind="image",
            file_id=doc["file_id"].strip(),
            filename=safe_name or "telegram_image.jpg",
            mime_type=resolved_mime,
            file_size=_parse_optional_int(doc.get("file_size")),
        )

    if mime.startswith("audio/") or ext in _AUDIO_EXTS:
        guessed_aud = mimetypes.guess_type(safe_name)[0] or "audio/mpeg"
        resolved_mime = mime if mime.startswith("audio/") else guessed_aud
        return TelegramAttachment(
            kind="audio",
            file_id=doc["file_id"].strip(),
            filename=safe_name or "telegram_audio.mp3",
            mime_type=resolved_mime,
            file_size=_parse_optional_int(doc.get("file_size")),
        )
    return None


def extract_telegram_attachment(msg: dict[str, Any], max_bytes: int) -> TelegramAttachment | None:
    """Extract the highest-priority supported image or audio attachment from a Telegram message."""
    return (
        _extract_photo(msg, max_bytes=max_bytes)
        or _extract_voice_or_audio(msg)
        or _extract_media_document(msg)
    )


def _validate_telegram_file_path(raw_path: object) -> str:
    if not isinstance(raw_path, str):
        raise TelegramMediaFetchError("Telegram getFile returned missing file_path.")
    cleaned = raw_path.strip()
    if (
        not cleaned
        or cleaned.startswith("/")
        or "\\" in cleaned
        or "://" in cleaned
        or ".." in cleaned.split("/")
    ):
        raise TelegramMediaFetchError("Telegram getFile returned unsafe file_path.")
    return cleaned


async def download_telegram_file(
    bot_token: str,
    file_id: str,
    max_bytes: int,
) -> tuple[bytes, str]:
    """Resolve file_id via Telegram getFile and stream file bytes within max_bytes ceiling."""
    get_file_url = f"https://api.telegram.org/bot{bot_token}/getFile"
    client = build_ssrf_pinned_http_client(timeout_sec=10.0)
    try:
        try:
            meta_resp = await client.get(get_file_url, params={"file_id": file_id})
        except Exception as exc:
            logger.warning("Telegram getFile transport failure (%s).", type(exc).__name__)
            raise TelegramMediaFetchError("Telegram getFile transport failure.") from exc

        if not meta_resp.is_success:
            raise TelegramMediaFetchError(f"Telegram getFile rejected with HTTP {meta_resp.status_code}.")

        try:
            meta_json = meta_resp.json()
        except ValueError as exc:
            raise TelegramMediaFetchError("Telegram getFile returned invalid JSON.") from exc

        if not isinstance(meta_json, dict) or meta_json.get("ok") is not True:
            raise TelegramMediaFetchError("Telegram getFile reported ok=false.")

        result = meta_json.get("result")
        if not isinstance(result, dict):
            raise TelegramMediaFetchError("Telegram getFile result missing.")

        declared_size = _parse_optional_int(result.get("file_size"))
        if declared_size is not None and declared_size > max_bytes:
            raise TelegramMediaTooLargeError(
                f"Telegram attachment declared size {declared_size} exceeds {max_bytes} bytes."
            )

        file_path = _validate_telegram_file_path(result.get("file_path"))
        download_url = f"https://api.telegram.org/file/bot{bot_token}/{file_path}"

        chunks = bytearray()
        try:
            async with client.stream("GET", download_url) as stream_resp:
                if not stream_resp.is_success:
                    raise TelegramMediaFetchError(
                        f"Telegram file download rejected with HTTP {stream_resp.status_code}."
                    )
                async for chunk in stream_resp.aiter_bytes():
                    chunks.extend(chunk)
                    if len(chunks) > max_bytes:
                        raise TelegramMediaTooLargeError(
                            f"Telegram attachment stream exceeded {max_bytes} bytes."
                        )
        except (TelegramMediaTooLargeError, TelegramMediaFetchError):
            raise
        except Exception as exc:
            logger.warning("Telegram file download transport failure (%s).", type(exc).__name__)
            raise TelegramMediaFetchError("Telegram file download transport failure.") from exc

        if not chunks:
            raise TelegramMediaFetchError("Telegram attachment downloaded 0 bytes.")
        return bytes(chunks), Path(file_path).name
    finally:
        await client.aclose()


async def send_telegram_typing_action(bot_token: str, chat_id: int | str) -> None:
    """Best-effort typing indicator so Telegram users see live progress while AI runs."""
    api_url = f"https://api.telegram.org/bot{bot_token}/sendChatAction"
    client = build_ssrf_pinned_http_client(timeout_sec=2.5)
    try:
        await client.post(api_url, json={"chat_id": chat_id, "action": "typing"})
    except Exception:
        return
    finally:
        await client.aclose()


async def answer_telegram_callback_query(
    bot_token: str,
    callback_query_id: str,
    text: str = "",
) -> None:
    """Best-effort acknowledgement to stop the spinner on an inline keyboard button."""
    api_url = f"https://api.telegram.org/bot{bot_token}/answerCallbackQuery"
    body: dict[str, Any] = {"callback_query_id": callback_query_id}
    if text:
        body["text"] = text[:180]
    client = build_ssrf_pinned_http_client(timeout_sec=3.0)
    try:
        await client.post(api_url, json=body)
    except Exception:
        return
    finally:
        await client.aclose()


@asynccontextmanager
async def telegram_typing_scope(
    bot_token: str,
    chat_id: int | str | None,
    interval_sec: float = 4.5,
) -> AsyncIterator[None]:
    """Keep Telegram's 5-second typing indicator alive throughout long multimodal analysis."""
    if not bot_token or chat_id is None:
        yield
        return

    async def _loop() -> None:
        while True:
            await send_telegram_typing_action(bot_token, chat_id)
            await asyncio.sleep(interval_sec)

    task = asyncio.create_task(_loop())
    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
