"""Dual-protocol LLM transport (OpenAI-compatible CLIProxyAPI + Official Google GenAI)."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import math
import re
import time
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any, Final, Literal
from urllib.parse import urlsplit

import httpx
from google import genai
from google.genai import types
from pydantic import BaseModel, Field, ValidationError, field_validator

from app.config import Settings
from app.core.media_security import (
    InvalidMediaError,
    detect_audio_format,
    normalize_image_for_downstream,
)
from app.services.llm_resilience import (
    MAX_INTERACTIVE_RETRY_WAIT_SEC as MAX_INTERACTIVE_RETRY_WAIT_SEC,
)
from app.services.llm_resilience import (
    MAX_JSON_PARSE_RETRIES,
    acquire_llm_slot,
    circuit_record_outcome,
    circuit_release_probe,
    circuit_try_acquire,
    compute_overall_deadline,
    jittered_retry_delay,
    should_failover_backup_key,
)

logger = logging.getLogger(__name__)

RETRYABLE_HTTP_STATUSES: frozenset[int] = frozenset({408, 429, 500, 502, 503, 504})
MAX_LLM_AUDIO_BYTES: Final[int] = 10 * 1024 * 1024
MAX_LLM_IMAGES: Final[int] = 4
_AUDIO_AV_TO_OPENAI_FORMAT: Final[dict[str, str]] = {
    "wav": "wav",
    "mp3": "mp3",
    "ogg": "ogg",
    "flac": "flac",
    "matroska": "webm",
    "mp4": "mp4",
}
_SAFETY_FINISH_TOKENS: Final[frozenset[str]] = frozenset(
    {"SAFETY", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "IMAGE_SAFETY"}
)

STRUCTURED_SYSTEM_INSTRUCTION: str = (
    "Bạn là trợ lý phân tích bằng chứng số và cảnh báo rủi ro lừa đảo của VeriShield AI. "
    "Viết tiếng Việt tự nhiên, ngắn gọn, viết hoa đầu câu (sentence case), dễ hiểu với người dùng "
    "phổ thông; không dùng thuật ngữ kỹ thuật chuyên sâu, không nêu mã trạng thái nội bộ và không "
    "cam kết giao dịch an toàn tuyệt đối. "
    "CHỈ TRẢ VỀ DUY NHẤT MỘT ĐỐI TƯỢNG JSON HỢP LỆ (không kèm văn bản giải thích ngoài JSON) "
    "theo đúng cấu trúc:\n"
    "{\n"
    '  "ai_risk_score": <số nguyên 0..100>,\n'
    '  "summary_vi": "<nhận định tiếng Việt tự nhiên; '
    'không khẳng định tiền đã vào tài khoản chỉ qua ảnh>",\n'
    '  "transcript": "<lời thoại âm thanh nếu có hoặc null>",\n'
    '  "manipulation_tactics": ["<dấu hiệu gây áp lực tâm lý bằng tiếng Việt tự nhiên>"],\n'
    '  "highlighted_phrases": ["<cụm từ đáng ngờ>"],\n'
    '  "counter_replies": ["<gợi ý câu trả lời an toàn để từ chối chuyển tiền>"],\n'
    '  "family_alert": "<tin nhắn cảnh báo ngắn cho người thân hoặc null>",\n'
    '  "bill_visual_anomalies": ["<điểm bất thường trên ảnh biên lai nếu có>"]\n'
    "}"
)


class GeminiStructuredSchema(BaseModel):
    """Validated JSON schema shared across OpenAI-compatible CPA and Google GenAI."""

    ai_risk_score: int = Field(ge=0, le=100)
    summary_vi: str
    transcript: str | None = None
    manipulation_tactics: list[str] = Field(default_factory=list)
    highlighted_phrases: list[str] = Field(default_factory=list)
    counter_replies: list[str] = Field(default_factory=list)
    family_alert: str | None = None
    bill_visual_anomalies: list[str] = Field(default_factory=list)

    @field_validator("ai_risk_score", mode="before")
    @classmethod
    def _coerce_score(cls, val: object) -> int:
        if isinstance(val, bool):
            raise ValueError("Boolean is not a valid ai_risk_score")
        if isinstance(val, (int, float)):
            num = float(val)
        elif isinstance(val, str) and val.strip():
            num = float(val.strip())
        else:
            raise ValueError("Invalid ai_risk_score")
        if not math.isfinite(num) or num < 0.0 or num > 100.0:
            raise ValueError(f"ai_risk_score out of range 0..100: {num}")
        return round(num)

    @field_validator(
        "manipulation_tactics",
        "highlighted_phrases",
        "counter_replies",
        "bill_visual_anomalies",
        mode="before",
    )
    @classmethod
    def _null_list_to_empty(cls, val: object) -> list[str]:
        if val is None:
            return []
        if isinstance(val, list):
            return [str(item).strip() for item in val if str(item).strip()]
        return []


class LLMCallOutcome(BaseModel):
    """Rich, secret-free telemetry for live API calls and benchmark auditing."""

    parsed: GeminiStructuredSchema | None = None
    provider: Literal["openai_compatible", "google_genai", "none"] = "none"
    configured_model: str = ""
    actual_model: str | None = None
    latency_ms: int = 0
    attempts: int = 0
    used_backup_key: bool = False
    error_code: str | None = None


def normalize_openai_chat_url(base_url: str) -> str:
    """Normalize CPA / OpenAI base URL; require HTTPS for all non-loopback hosts."""
    cleaned = base_url.strip().rstrip("/")
    if not cleaned:
        raise ValueError("GEMINI_BASE_URL is empty for openai_compatible provider.")
    parts = urlsplit(cleaned)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").strip().lower()
    if parts.username is not None or parts.password is not None:
        raise ValueError("GEMINI_BASE_URL must not contain embedded credentials.")
    if scheme not in ("http", "https") or not host:
        raise ValueError("Invalid GEMINI_BASE_URL scheme or host.")
    if scheme == "http" and host not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("Remote GEMINI_BASE_URL must use HTTPS to protect bearer API keys.")
    if cleaned.endswith("/chat/completions"):
        return cleaned
    if parts.path in ("", "/"):
        return f"{cleaned}/v1/chat/completions"
    return f"{cleaned}/chat/completions"


def _extract_first_json_object(text: str) -> str:
    start = text.find("{")
    if start == -1:
        raise ValueError("No JSON object opening brace found in LLM output.")
    depth = 0
    in_str = False
    escaped = False
    for idx in range(start, len(text)):
        ch = text[idx]
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : idx + 1]
    raise ValueError("Unbalanced JSON braces in LLM output.")


def parse_structured_llm_json(raw_content: Any) -> GeminiStructuredSchema:
    """Extract and validate GeminiStructuredSchema from raw JSON, fenced blocks, or thinking output."""
    if isinstance(raw_content, dict):
        return GeminiStructuredSchema.model_validate(raw_content)

    text_chunks: list[str] = []
    if isinstance(raw_content, str):
        text_chunks.append(raw_content)
    elif isinstance(raw_content, list):
        for part in raw_content:
            if isinstance(part, dict) and part.get("type") in ("text", "output_text", None):
                txt = part.get("text")
                if isinstance(txt, str):
                    text_chunks.append(txt)

    combined = "\n".join(text_chunks).strip()
    combined = re.sub(r"<think>.*?</think>", "", combined, flags=re.DOTALL | re.IGNORECASE).strip()

    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", combined, flags=re.DOTALL | re.IGNORECASE)
    candidate = fenced.group(1).strip() if fenced else _extract_first_json_object(combined)
    loaded = json.loads(candidate)
    return GeminiStructuredSchema.model_validate(loaded)


def _parse_retry_after_sec(retry_after_header: str | None) -> float | None:
    """Parse numeric or HTTP-date Retry-After header into seconds, or None if absent/invalid."""
    if not retry_after_header:
        return None
    raw_hdr = retry_after_header.strip()
    parsed_sec: float | None = None
    try:
        parsed_sec = float(raw_hdr)
    except ValueError:
        try:
            dt = parsedate_to_datetime(raw_hdr)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            parsed_sec = max(0.0, (dt - datetime.now(UTC)).total_seconds())
        except (TypeError, ValueError):
            parsed_sec = None
    if parsed_sec is not None and math.isfinite(parsed_sec):
        return max(0.0, parsed_sec)
    return None


def _compute_backoff_sec(
    retry_idx: int,
    retry_after_header: str | None,
    remaining_sec: float | None = None,
) -> float | None:
    """Compute jittered retry delay; return None when Retry-After or deadline budget is exceeded."""
    parsed_sec = _parse_retry_after_sec(retry_after_header)
    return jittered_retry_delay(retry_idx, parsed_sec, remaining_sec)


def _remaining_sec(deadline: float | None) -> float | None:
    if deadline is None:
        return None
    return max(0.0, deadline - asyncio.get_running_loop().time())


def _slice_attempt_timeout(timeout_sec: float, deadline: float | None) -> float | None:
    if deadline is None:
        return max(0.05, timeout_sec)
    remaining = deadline - asyncio.get_running_loop().time()
    if remaining <= 0.05:
        return None
    return min(timeout_sec, remaining)


def _normalize_media_pairs(
    single_bytes: bytes | None,
    single_mime: str,
    multi_items: list[tuple[bytes, str]] | None,
    max_items: int,
) -> list[tuple[bytes, str]]:
    if multi_items:
        return [(b, m) for b, m in multi_items if b][:max_items]
    if single_bytes:
        return [(single_bytes, single_mime)]
    return []


def _canonicalize_image_pairs(pairs: list[tuple[bytes, str]]) -> list[tuple[bytes, str]]:
    """Strip EXIF/polyglot tails and derive canonical MIME strictly from decoded image bytes."""
    normalized: list[tuple[bytes, str]] = []
    for raw_bytes, _declared_mime in pairs:
        try:
            clean_bytes, clean_mime = normalize_image_for_downstream(raw_bytes)
            normalized.append((clean_bytes, clean_mime))
        except InvalidMediaError:
            logger.warning("Dropped invalid or animated image before LLM egress.")
    return normalized


def _canonicalize_audio_pairs(pairs: list[tuple[bytes, str]]) -> list[tuple[bytes, str, str]]:
    """Derive canonical audio MIME & OpenAI format strictly from magic headers (never octet-stream)."""
    normalized: list[tuple[bytes, str, str]] = []
    aud_total = 0
    for raw_bytes, _declared_mime in pairs:
        if aud_total + len(raw_bytes) > MAX_LLM_AUDIO_BYTES:
            continue
        detected = detect_audio_format(raw_bytes)
        if detected is None:
            logger.warning("Dropped unrecognized audio payload before LLM egress.")
            continue
        av_fmt, canonical_mime = detected
        openai_fmt = _AUDIO_AV_TO_OPENAI_FORMAT.get(av_fmt)
        if not openai_fmt:
            continue
        normalized.append((raw_bytes, canonical_mime, openai_fmt))
        aud_total += len(raw_bytes)
    return normalized


def _build_openai_user_content(
    prompt: str,
    image_bytes: bytes | None,
    image_mime: str,
    audio_bytes: bytes | None,
    audio_mime: str,
    include_audio: bool = True,
    images: list[tuple[bytes, str]] | None = None,
    audios: list[tuple[bytes, str]] | None = None,
    *,
    canonical_images: list[tuple[bytes, str]] | None = None,
    canonical_audios: list[tuple[bytes, str, str]] | None = None,
) -> str | list[dict[str, Any]]:
    img_list = (
        canonical_images
        if canonical_images is not None
        else _canonicalize_image_pairs(
            _normalize_media_pairs(image_bytes, image_mime, images, MAX_LLM_IMAGES)
        )
    )
    if not include_audio:
        bounded_auds: list[tuple[bytes, str, str]] = []
    elif canonical_audios is not None:
        bounded_auds = canonical_audios
    else:
        bounded_auds = _canonicalize_audio_pairs(
            _normalize_media_pairs(audio_bytes, audio_mime, audios, 1)
        )

    if not img_list and not bounded_auds:
        return prompt

    parts: list[dict[str, Any]] = [{"type": "text", "text": prompt}]
    for ib, im in img_list:
        b64_img = base64.b64encode(ib).decode("ascii")
        parts.append({"type": "image_url", "image_url": {"url": f"data:{im};base64,{b64_img}"}})
    for ab, _am, fmt in bounded_auds:
        b64_aud = base64.b64encode(ab).decode("ascii")
        parts.append({"type": "input_audio", "input_audio": {"data": b64_aud, "format": fmt}})
    return parts


def _compose_openai_user_content(
    prompt: str,
    image_parts: list[dict[str, Any]],
    audio_parts: list[dict[str, Any]],
    *,
    include_audio: bool,
) -> str | list[dict[str, Any]]:
    active_audio = audio_parts if include_audio else []
    if not image_parts and not active_audio:
        return prompt
    return [{"type": "text", "text": prompt}, *image_parts, *active_audio]


async def _post_openai_bounded(
    client: httpx.AsyncClient,
    endpoint: str,
    api_key: str,
    payload: dict[str, Any],
    attempt_timeout: float,
) -> httpx.Response:
    req_timeout = httpx.Timeout(attempt_timeout, connect=min(8.0, attempt_timeout))
    async with asyncio.timeout(attempt_timeout):
        return await client.post(
            endpoint,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=req_timeout,
        )


async def _call_openai_key(
    endpoint: str,
    api_key: str,
    model_name: str,
    prompt: str,
    timeout_sec: float,
    max_retries: int,
    image_bytes: bytes | None,
    image_mime: str,
    audio_bytes: bytes | None,
    audio_mime: str,
    has_non_audio_evidence: bool = True,
    failover_cooldown_out: list[float] | None = None,
    images: list[tuple[bytes, str]] | None = None,
    audios: list[tuple[bytes, str]] | None = None,
    deadline: float | None = None,
) -> tuple[GeminiStructuredSchema | None, str | None, int, str | None]:
    attempts = 0
    use_json_format = True
    include_audio = True
    json_parse_retries = 0
    canon_images = await asyncio.to_thread(
        _canonicalize_image_pairs,
        _normalize_media_pairs(image_bytes, image_mime, images, MAX_LLM_IMAGES),
    )
    canon_audios = _canonicalize_audio_pairs(
        _normalize_media_pairs(audio_bytes, audio_mime, audios, 1)
    )
    has_any_audio = bool(canon_audios)
    encoded_image_parts: list[dict[str, Any]] = [
        {
            "type": "image_url",
            "image_url": {"url": f"data:{im};base64,{base64.b64encode(ib).decode('ascii')}"},
        }
        for ib, im in canon_images
    ]
    encoded_audio_parts: list[dict[str, Any]] = [
        {
            "type": "input_audio",
            "input_audio": {"data": base64.b64encode(ab).decode("ascii"), "format": fmt},
        }
        for ab, _am, fmt in canon_audios
    ]
    last_err = "UNKNOWN_OPENAI_ERROR"

    base_timeout = httpx.Timeout(timeout_sec, connect=min(8.0, timeout_sec))
    async with httpx.AsyncClient(timeout=base_timeout) as client:
        for retry_idx in range(max_retries + 1):
            attempt_timeout = _slice_attempt_timeout(timeout_sec, deadline)
            if attempt_timeout is None:
                return None, None, attempts, "TIMEOUT"

            attempts += 1
            user_content = _compose_openai_user_content(
                prompt,
                encoded_image_parts,
                encoded_audio_parts,
                include_audio=include_audio,
            )
            payload: dict[str, Any] = {
                "model": model_name,
                "temperature": 0.1,
                "messages": [
                    {"role": "system", "content": STRUCTURED_SYSTEM_INSTRUCTION},
                    {"role": "user", "content": user_content},
                ],
            }
            if use_json_format:
                payload["response_format"] = {"type": "json_object"}

            try:
                resp = await _post_openai_bounded(
                    client, endpoint, api_key, payload, attempt_timeout
                )
            except (TimeoutError, httpx.TimeoutException):
                last_err = "TIMEOUT"
                if retry_idx < max_retries:
                    delay = jittered_retry_delay(retry_idx, None, _remaining_sec(deadline))
                    if delay is not None:
                        await asyncio.sleep(delay)
                        continue
                return None, None, attempts, last_err
            except httpx.HTTPError:
                last_err = "NETWORK_TRANSPORT_ERROR"
                if retry_idx < max_retries:
                    delay = jittered_retry_delay(retry_idx, None, _remaining_sec(deadline))
                    if delay is not None:
                        await asyncio.sleep(delay)
                        continue
                return None, None, attempts, last_err

            # Step 1 compat: drop response_format FIRST while preserving audio attachment
            if resp.status_code in (400, 422) and use_json_format:
                use_json_format = False
                compat_timeout = _slice_attempt_timeout(timeout_sec, deadline)
                if compat_timeout is None:
                    return None, None, attempts, "TIMEOUT"
                attempts += 1
                no_fmt_payload = {
                    "model": model_name,
                    "temperature": 0.1,
                    "messages": [
                        {"role": "system", "content": STRUCTURED_SYSTEM_INSTRUCTION},
                        {"role": "user", "content": user_content},
                    ],
                }
                try:
                    resp = await _post_openai_bounded(
                        client, endpoint, api_key, no_fmt_payload, compat_timeout
                    )
                except (TimeoutError, httpx.TimeoutException):
                    return None, None, attempts, "TIMEOUT"
                except httpx.HTTPError:
                    return None, None, attempts, "NETWORK_TRANSPORT_ERROR"

            # Step 2 compat: if audio is rejected, only drop when non-audio evidence exists
            if resp.status_code in (400, 422) and has_any_audio and include_audio:
                if not has_non_audio_evidence:
                    return None, None, attempts, "UNSUPPORTED_AUDIO_INPUT"
                include_audio = False
                audio_compat_timeout = _slice_attempt_timeout(timeout_sec, deadline)
                if audio_compat_timeout is None:
                    return None, None, attempts, "TIMEOUT"
                attempts += 1
                no_audio_content = _compose_openai_user_content(
                    prompt,
                    encoded_image_parts,
                    encoded_audio_parts,
                    include_audio=False,
                )
                no_audio_payload = {
                    "model": model_name,
                    "temperature": 0.1,
                    "messages": [
                        {"role": "system", "content": STRUCTURED_SYSTEM_INSTRUCTION},
                        {"role": "user", "content": no_audio_content},
                    ],
                }
                try:
                    resp = await _post_openai_bounded(
                        client, endpoint, api_key, no_audio_payload, audio_compat_timeout
                    )
                except (TimeoutError, httpx.TimeoutException):
                    return None, None, attempts, "TIMEOUT"
                except httpx.HTTPError:
                    return None, None, attempts, "NETWORK_TRANSPORT_ERROR"

            if resp.status_code in (401, 403):
                return None, None, attempts, f"HTTP_{resp.status_code}"

            if resp.status_code in RETRYABLE_HTTP_STATUSES:
                last_err = f"HTTP_{resp.status_code}"
                ra_sec = _parse_retry_after_sec(resp.headers.get("Retry-After"))
                if ra_sec is not None and ra_sec > MAX_INTERACTIVE_RETRY_WAIT_SEC:
                    return None, None, attempts, f"{last_err}_RETRY_AFTER_EXCEEDED"
                if retry_idx < max_retries:
                    delay = jittered_retry_delay(retry_idx, ra_sec, _remaining_sec(deadline))
                    if delay is not None:
                        await asyncio.sleep(delay)
                        continue
                    return None, None, attempts, last_err
                if ra_sec is not None and ra_sec > 0 and failover_cooldown_out is not None:
                    failover_cooldown_out.append(ra_sec)
                return None, None, attempts, last_err

            if not resp.is_success:
                return None, None, attempts, f"HTTP_{resp.status_code}"

            try:
                body = resp.json()
                actual_model = str(body.get("model") or model_name)
                choices = body.get("choices") or []
                first_choice = choices[0] if choices else {}
                finish_reason = str(first_choice.get("finish_reason") or "").upper()
                if finish_reason in ("CONTENT_FILTER", "SAFETY"):
                    return None, actual_model, attempts, "SAFETY_BLOCKED"
                first_msg = first_choice.get("message", {}) if isinstance(first_choice, dict) else {}
                raw_content = first_msg.get("content")
                if raw_content is None:
                    last_err = "EMPTY_COMPLETION_CONTENT"
                    if retry_idx < max_retries:
                        delay = jittered_retry_delay(retry_idx, None, _remaining_sec(deadline))
                        if delay is not None:
                            await asyncio.sleep(delay)
                            continue
                    return None, actual_model, attempts, last_err
                parsed = parse_structured_llm_json(raw_content)
                return parsed, actual_model, attempts, None
            except Exception as exc:
                logger.warning("Failed to parse structured JSON from CPA (%s).", type(exc).__name__)
                last_err = "INVALID_STRUCTURED_JSON"
                if retry_idx < max_retries and json_parse_retries < MAX_JSON_PARSE_RETRIES:
                    json_parse_retries += 1
                    delay = jittered_retry_delay(retry_idx, None, _remaining_sec(deadline))
                    if delay is not None:
                        await asyncio.sleep(delay)
                        continue
                return None, None, attempts, last_err

    return None, None, attempts, last_err


def _is_google_safety_blocked(resp: Any) -> bool:
    prompt_fb = getattr(resp, "prompt_feedback", None)
    if prompt_fb is not None:
        block_reason = getattr(prompt_fb, "block_reason", None)
        if block_reason and str(block_reason).split(".")[-1].upper() not in (
            "",
            "NONE",
            "BLOCK_REASON_UNSPECIFIED",
        ):
            return True
    candidates = getattr(resp, "candidates", None) or []
    for cand in candidates:
        fin = getattr(cand, "finish_reason", None)
        if fin and str(fin).split(".")[-1].upper() in _SAFETY_FINISH_TOKENS:
            return True
    return False


def _extract_google_api_error_info(exc: Exception) -> tuple[int | None, str | None]:
    """Extract HTTP status code and optional Retry-After header from google-genai APIError."""
    raw_code = getattr(exc, "code", None)
    if raw_code is None:
        raw_code = getattr(exc, "status_code", None)
    status_code: int | None = None
    if isinstance(raw_code, int) and 100 <= raw_code <= 599:
        status_code = raw_code
    retry_after: str | None = None
    resp = getattr(exc, "response", None)
    headers = getattr(resp, "headers", None)
    if headers is not None and hasattr(headers, "get"):
        hdr = headers.get("Retry-After") or headers.get("retry-after")
        if isinstance(hdr, str):
            retry_after = hdr
    return status_code, retry_after


async def _call_google_genai_key(
    api_key: str,
    model_name: str,
    prompt: str,
    timeout_sec: float,
    max_retries: int,
    image_bytes: bytes | None,
    image_mime: str,
    audio_bytes: bytes | None,
    audio_mime: str,
    failover_cooldown_out: list[float] | None = None,
    images: list[tuple[bytes, str]] | None = None,
    audios: list[tuple[bytes, str]] | None = None,
    deadline: float | None = None,
) -> tuple[GeminiStructuredSchema | None, str | None, int, str | None]:
    canon_images = await asyncio.to_thread(
        _canonicalize_image_pairs,
        _normalize_media_pairs(image_bytes, image_mime, images, MAX_LLM_IMAGES),
    )
    canon_audios = _canonicalize_audio_pairs(
        _normalize_media_pairs(audio_bytes, audio_mime, audios, 2)
    )
    media_parts: list[types.Part] = [
        types.Part.from_bytes(data=ib, mime_type=im) for ib, im in canon_images
    ]
    for ab, am, _fmt in canon_audios:
        media_parts.append(types.Part.from_bytes(data=ab, mime_type=am))

    safety = [
        types.SafetySetting(category=cat, threshold=types.HarmBlockThreshold.BLOCK_ONLY_HIGH)
        for cat in (
            types.HarmCategory.HARM_CATEGORY_HARASSMENT,
            types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
            types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
            types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
        )
    ]
    config = types.GenerateContentConfig(
        system_instruction=STRUCTURED_SYSTEM_INSTRUCTION,
        temperature=0.1,
        response_mime_type="application/json",
        response_schema=GeminiStructuredSchema,
        safety_settings=safety,
    )

    contents: list[Any] = [*media_parts, prompt]
    attempts = 0
    json_parse_retries = 0
    last_err = "GOOGLE_GENAI_ERROR"
    try:
        client = genai.Client(api_key=api_key)
    except Exception as exc:
        return None, None, 0, f"CLIENT_INIT_{type(exc).__name__.upper()}"

    try:
        for retry_idx in range(max_retries + 1):
            attempt_timeout = _slice_attempt_timeout(timeout_sec, deadline)
            if attempt_timeout is None:
                return None, None, attempts, "TIMEOUT"

            attempts += 1
            retry_after_hdr: str | None = None
            try:
                resp = await asyncio.wait_for(
                    client.aio.models.generate_content(
                        model=model_name,
                        contents=contents,
                        config=config,
                    ),
                    timeout=attempt_timeout,
                )
                actual_model = str(getattr(resp, "model_version", None) or model_name)
                if _is_google_safety_blocked(resp):
                    return None, actual_model, attempts, "SAFETY_BLOCKED"
                try:
                    if isinstance(resp.parsed, GeminiStructuredSchema):
                        return resp.parsed, actual_model, attempts, None
                    if isinstance(resp.parsed, dict):
                        return (
                            GeminiStructuredSchema.model_validate(resp.parsed),
                            actual_model,
                            attempts,
                            None,
                        )
                    if getattr(resp, "text", None):
                        return parse_structured_llm_json(resp.text), actual_model, attempts, None
                    last_err = "EMPTY_COMPLETION_CONTENT"
                except (ValidationError, ValueError, json.JSONDecodeError) as exc:
                    logger.warning(
                        "Failed to parse structured JSON from Google GenAI (%s).",
                        type(exc).__name__,
                    )
                    last_err = "INVALID_STRUCTURED_JSON"
                    if json_parse_retries >= MAX_JSON_PARSE_RETRIES:
                        return None, actual_model, attempts, last_err
                    json_parse_retries += 1
            except (TimeoutError, httpx.TimeoutException):
                last_err = "TIMEOUT"
            except asyncio.CancelledError:
                raise
            except httpx.TransportError:
                last_err = "NETWORK_TRANSPORT_ERROR"
            except Exception as exc:
                status_code, retry_after_hdr = _extract_google_api_error_info(exc)
                if status_code is not None:
                    last_err = f"HTTP_{status_code}"
                    if status_code not in RETRYABLE_HTTP_STATUSES:
                        return None, None, attempts, last_err
                    ra_sec = _parse_retry_after_sec(retry_after_hdr)
                    if ra_sec is not None and ra_sec > MAX_INTERACTIVE_RETRY_WAIT_SEC:
                        return None, None, attempts, f"{last_err}_RETRY_AFTER_EXCEEDED"
                    if (
                        retry_idx >= max_retries
                        and ra_sec is not None
                        and ra_sec > 0
                        and failover_cooldown_out is not None
                    ):
                        failover_cooldown_out.append(ra_sec)
                else:
                    last_err = type(exc).__name__.upper()
            if retry_idx < max_retries:
                ra_sec = _parse_retry_after_sec(retry_after_hdr)
                delay = jittered_retry_delay(retry_idx, ra_sec, _remaining_sec(deadline))
                if delay is not None:
                    await asyncio.sleep(delay)
                else:
                    if ra_sec is not None and ra_sec > MAX_INTERACTIVE_RETRY_WAIT_SEC:
                        return None, None, attempts, f"{last_err}_RETRY_AFTER_EXCEEDED"
                    return None, None, attempts, last_err
        return None, None, attempts, last_err
    finally:
        aclose_fn = getattr(client.aio, "aclose", None)
        if callable(aclose_fn):
            try:
                await aclose_fn()
            except Exception:
                logger.debug("Ignored Google GenAI client aclose error.")


async def execute_llm_call(
    settings: Settings,
    prompt: str,
    image_bytes: bytes | None = None,
    image_mime: str = "image/jpeg",
    audio_bytes: bytes | None = None,
    audio_mime: str = "audio/wav",
    has_non_audio_evidence: bool = True,
    images: list[tuple[bytes, str]] | None = None,
    audios: list[tuple[bytes, str]] | None = None,
) -> LLMCallOutcome:
    """Execute structured scam reasoning across configured provider with retry & backup failover."""
    keys = [k.strip() for k in (settings.gemini_api_key, settings.gemini_backup_api_key) if k.strip()]
    provider = settings.resolved_llm_provider
    if not keys:
        return LLMCallOutcome(
            provider=provider,
            configured_model=settings.gemini_model,
            error_code="NO_API_KEY",
        )

    endpoint = ""
    if provider == "openai_compatible":
        try:
            endpoint = normalize_openai_chat_url(settings.gemini_base_url)
        except ValueError:
            return LLMCallOutcome(
                provider=provider,
                configured_model=settings.gemini_model,
                error_code="INVALID_BASE_URL",
            )
        endpoint_key = endpoint
    else:
        endpoint_key = "google_genai"

    allowed, is_half_open_probe = circuit_try_acquire(endpoint_key)
    if not allowed:
        return LLMCallOutcome(
            provider=provider,
            configured_model=settings.gemini_model,
            error_code="CIRCUIT_BREAKER_OPEN",
        )

    try:
        sem = await acquire_llm_slot()
    except BaseException:
        if is_half_open_probe:
            circuit_release_probe(endpoint_key)
        raise
    if sem is None:
        if is_half_open_probe:
            circuit_release_probe(endpoint_key)
        return LLMCallOutcome(
            provider=provider,
            configured_model=settings.gemini_model,
            error_code="LLM_CONCURRENCY_LIMITED",
        )

    t_start = time.perf_counter()
    deadline = compute_overall_deadline(settings.llm_timeout_sec)
    total_attempts = 0
    last_error = "LLM_UNAVAILABLE"
    recorded_outcome = False

    try:
        pending_cooldown: list[float] = []
        for key_idx, key in enumerate(keys):
            if key_idx > 0:
                rem = _remaining_sec(deadline)
                if rem is not None and rem <= 0.1:
                    break
                if pending_cooldown:
                    wait_sec = pending_cooldown.pop()
                    pending_cooldown.clear()
                    delay = jittered_retry_delay(0, wait_sec, rem)
                    if delay is None:
                        break
                    await asyncio.sleep(delay)

            if provider == "openai_compatible":
                parsed, actual_model, used_attempts, err = await _call_openai_key(
                    endpoint=endpoint,
                    api_key=key,
                    model_name=settings.gemini_model,
                    prompt=prompt,
                    timeout_sec=settings.llm_timeout_sec,
                    max_retries=settings.llm_max_retries,
                    image_bytes=image_bytes,
                    image_mime=image_mime,
                    audio_bytes=audio_bytes,
                    audio_mime=audio_mime,
                    has_non_audio_evidence=has_non_audio_evidence,
                    failover_cooldown_out=pending_cooldown,
                    images=images,
                    audios=audios,
                    deadline=deadline,
                )
            else:
                parsed, actual_model, used_attempts, err = await _call_google_genai_key(
                    api_key=key,
                    model_name=settings.gemini_model,
                    prompt=prompt,
                    timeout_sec=settings.llm_timeout_sec,
                    max_retries=settings.llm_max_retries,
                    image_bytes=image_bytes,
                    image_mime=image_mime,
                    audio_bytes=audio_bytes,
                    audio_mime=audio_mime,
                    failover_cooldown_out=pending_cooldown,
                    images=images,
                    audios=audios,
                    deadline=deadline,
                )
            total_attempts += used_attempts
            if parsed is not None:
                circuit_record_outcome(
                    endpoint_key, None, is_half_open_probe=is_half_open_probe
                )
                recorded_outcome = True
                return LLMCallOutcome(
                    parsed=parsed,
                    provider=provider,
                    configured_model=settings.gemini_model,
                    actual_model=actual_model or settings.gemini_model,
                    latency_ms=int((time.perf_counter() - t_start) * 1000),
                    attempts=total_attempts,
                    used_backup_key=(key_idx > 0),
                )
            if err:
                last_error = err
                if not should_failover_backup_key(err):
                    break

        circuit_record_outcome(
            endpoint_key, last_error, is_half_open_probe=is_half_open_probe
        )
        recorded_outcome = True
        return LLMCallOutcome(
            parsed=None,
            provider=provider,
            configured_model=settings.gemini_model,
            latency_ms=int((time.perf_counter() - t_start) * 1000),
            attempts=total_attempts,
            error_code=last_error,
        )
    finally:
        if not recorded_outcome and is_half_open_probe:
            circuit_release_probe(endpoint_key)
        sem.release()
