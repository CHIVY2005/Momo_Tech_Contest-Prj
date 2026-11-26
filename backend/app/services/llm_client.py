"""Dual-protocol LLM transport (OpenAI-compatible CLIProxyAPI + Official Google GenAI)."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import math
import random
import re
import time
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
from google import genai
from google.genai import types
from pydantic import BaseModel, Field, field_validator

from app.config import Settings

logger = logging.getLogger(__name__)

RETRYABLE_HTTP_STATUSES: frozenset[int] = frozenset({408, 429, 500, 502, 503, 504})
STRUCTURED_SYSTEM_INSTRUCTION: str = (
    "Bạn là bộ suy luận pháp y chống lừa đảo VeriShield AI. "
    "CHỈ TRẢ VỀ DUY NHẤT MỘT ĐỐI TƯỢNG JSON HỢP LỆ (không kèm văn bản giải thích ngoài JSON) "
    "theo đúng cấu trúc:\n"
    "{\n"
    '  "ai_risk_score": <số nguyên 0..100>,\n'
    '  "summary_vi": "<nhận định tiếng Việt ngắn gọn, súc tích>",\n'
    '  "transcript": "<lời thoại âm thanh nếu có hoặc null>",\n'
    '  "manipulation_tactics": ["<đòn tâm lý>"],\n'
    '  "highlighted_phrases": ["<cụm từ đáng ngờ>"],\n'
    '  "counter_replies": ["<câu trả lời an toàn để cắt đuôi kẻ gian>"],\n'
    '  "family_alert": "<cảnh báo gửi người thân hoặc null>",\n'
    '  "bill_visual_anomalies": ["<bất thường thị giác trên biên lai nếu có>"]\n'
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
    """Normalize CPA / OpenAI base URL into a full /chat/completions endpoint."""
    cleaned = base_url.strip().rstrip("/")
    if not cleaned:
        raise ValueError("GEMINI_BASE_URL is empty for openai_compatible provider.")
    parts = urlsplit(cleaned)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError(f"Invalid GEMINI_BASE_URL scheme or host: {base_url!r}")
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


def _compute_backoff_sec(retry_idx: int, retry_after_header: str | None) -> float:
    if retry_after_header:
        try:
            parsed_sec = float(retry_after_header.strip())
            if parsed_sec >= 0:
                return min(6.0, max(0.02, parsed_sec))
        except ValueError:
            pass
    base_delay: float = min(5.0, 0.5 * (2**retry_idx))
    jitter: float = random.uniform(0.01, 0.15)  # noqa: S311
    return base_delay + jitter


def _build_openai_user_content(
    prompt: str,
    image_bytes: bytes | None,
    image_mime: str,
    audio_bytes: bytes | None,
    audio_mime: str,
    include_audio: bool = True,
) -> str | list[dict[str, Any]]:
    if not image_bytes and not (audio_bytes and include_audio):
        return prompt

    parts: list[dict[str, Any]] = [{"type": "text", "text": prompt}]
    if image_bytes:
        b64_img = base64.b64encode(image_bytes).decode("ascii")
        parts.append({"type": "image_url", "image_url": {"url": f"data:{image_mime};base64,{b64_img}"}})
    if audio_bytes and include_audio:
        b64_aud = base64.b64encode(audio_bytes).decode("ascii")
        fmt = audio_mime.split("/")[-1].lower().replace("mpeg", "mp3").replace("x-wav", "wav")
        parts.append({"type": "input_audio", "input_audio": {"data": b64_aud, "format": fmt}})
    return parts


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
) -> tuple[GeminiStructuredSchema | None, str | None, int, str | None]:
    attempts = 0
    use_json_format = True
    include_audio = True
    last_err = "UNKNOWN_OPENAI_ERROR"

    timeout = httpx.Timeout(timeout_sec, connect=min(8.0, timeout_sec))
    async with httpx.AsyncClient(timeout=timeout) as client:
        for retry_idx in range(max_retries + 1):
            attempts += 1
            user_content = _build_openai_user_content(
                prompt, image_bytes, image_mime, audio_bytes, audio_mime, include_audio=include_audio
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
                resp = await client.post(
                    endpoint,
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
            except httpx.TimeoutException:
                last_err = "TIMEOUT"
                if retry_idx < max_retries:
                    await asyncio.sleep(_compute_backoff_sec(retry_idx, None))
                    continue
                return None, None, attempts, last_err
            except httpx.HTTPError:
                last_err = "NETWORK_TRANSPORT_ERROR"
                if retry_idx < max_retries:
                    await asyncio.sleep(_compute_backoff_sec(retry_idx, None))
                    continue
                return None, None, attempts, last_err

            if resp.status_code in (400, 422) and (use_json_format or (audio_bytes and include_audio)):
                # Compatibility retry for CPA models that reject response_format or input_audio
                use_json_format = False
                include_audio = False
                attempts += 1
                compat_payload = {
                    "model": model_name,
                    "temperature": 0.1,
                    "messages": [
                        {"role": "system", "content": STRUCTURED_SYSTEM_INSTRUCTION},
                        {
                            "role": "user",
                            "content": _build_openai_user_content(
                                prompt, image_bytes, image_mime, None, audio_mime, include_audio=False
                            ),
                        },
                    ],
                }
                try:
                    resp = await client.post(
                        endpoint,
                        headers={
                            "Authorization": f"Bearer {api_key}",
                            "Content-Type": "application/json",
                        },
                        json=compat_payload,
                    )
                except httpx.TimeoutException:
                    return None, None, attempts, "TIMEOUT"
                except httpx.HTTPError:
                    return None, None, attempts, "NETWORK_TRANSPORT_ERROR"

            if resp.status_code in (401, 403):
                return None, None, attempts, f"HTTP_{resp.status_code}"

            if resp.status_code in RETRYABLE_HTTP_STATUSES:
                last_err = f"HTTP_{resp.status_code}"
                if retry_idx < max_retries:
                    await asyncio.sleep(
                        _compute_backoff_sec(retry_idx, resp.headers.get("Retry-After"))
                    )
                    continue
                return None, None, attempts, last_err

            if not resp.is_success:
                return None, None, attempts, f"HTTP_{resp.status_code}"

            try:
                body = resp.json()
                actual_model = str(body.get("model") or model_name)
                choices = body.get("choices") or []
                first_msg = choices[0].get("message", {}) if choices else {}
                raw_content = first_msg.get("content")
                if raw_content is None:
                    last_err = "EMPTY_COMPLETION_CONTENT"
                    if retry_idx < max_retries:
                        await asyncio.sleep(_compute_backoff_sec(retry_idx, None))
                        continue
                    return None, actual_model, attempts, last_err
                parsed = parse_structured_llm_json(raw_content)
                return parsed, actual_model, attempts, None
            except Exception as exc:
                logger.warning("Failed to parse structured JSON from CPA (%s).", type(exc).__name__)
                last_err = "INVALID_STRUCTURED_JSON"
                if retry_idx < max_retries:
                    await asyncio.sleep(_compute_backoff_sec(retry_idx, None))
                    continue
                return None, None, attempts, last_err

    return None, None, attempts, last_err


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
) -> tuple[GeminiStructuredSchema | None, str | None, int, str | None]:
    media_parts: list[types.Part] = []
    if image_bytes:
        media_parts.append(types.Part.from_bytes(data=image_bytes, mime_type=image_mime))
    if audio_bytes:
        media_parts.append(types.Part.from_bytes(data=audio_bytes, mime_type=audio_mime))

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
        temperature=0.1,
        response_mime_type="application/json",
        response_schema=GeminiStructuredSchema,
        safety_settings=safety,
    )

    contents: list[Any] = [*media_parts, prompt]
    attempts = 0
    last_err = "GOOGLE_GENAI_ERROR"
    client = genai.Client(api_key=api_key)
    try:
        for retry_idx in range(max_retries + 1):
            attempts += 1
            try:
                resp = await asyncio.wait_for(
                    client.aio.models.generate_content(
                        model=model_name,
                        contents=contents,
                        config=config,
                    ),
                    timeout=timeout_sec,
                )
                actual_model = str(getattr(resp, "model_version", None) or model_name)
                if isinstance(resp.parsed, GeminiStructuredSchema):
                    return resp.parsed, actual_model, attempts, None
                if isinstance(resp.parsed, dict):
                    return GeminiStructuredSchema.model_validate(resp.parsed), actual_model, attempts, None
                if getattr(resp, "text", None):
                    return parse_structured_llm_json(resp.text), actual_model, attempts, None
                return None, actual_model, attempts, "SAFETY_OR_EMPTY_RESPONSE"
            except TimeoutError:
                last_err = "TIMEOUT"
            except Exception as exc:
                last_err = type(exc).__name__.upper()
            if retry_idx < max_retries:
                await asyncio.sleep(_compute_backoff_sec(retry_idx, None))
        return None, None, attempts, last_err
    finally:
        aclose_fn = getattr(client.aio, "aclose", None)
        if callable(aclose_fn):
            await aclose_fn()


async def execute_llm_call(
    settings: Settings,
    prompt: str,
    image_bytes: bytes | None = None,
    image_mime: str = "image/jpeg",
    audio_bytes: bytes | None = None,
    audio_mime: str = "audio/wav",
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

    t_start = time.perf_counter()
    total_attempts = 0
    last_error = "LLM_UNAVAILABLE"

    if provider == "openai_compatible":
        try:
            endpoint = normalize_openai_chat_url(settings.gemini_base_url)
        except ValueError:
            return LLMCallOutcome(
                provider=provider,
                configured_model=settings.gemini_model,
                error_code="INVALID_BASE_URL",
            )

        for key_idx, key in enumerate(keys):
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
            )
            total_attempts += used_attempts
            if parsed is not None:
                return LLMCallOutcome(
                    parsed=parsed,
                    provider="openai_compatible",
                    configured_model=settings.gemini_model,
                    actual_model=actual_model or settings.gemini_model,
                    latency_ms=int((time.perf_counter() - t_start) * 1000),
                    attempts=total_attempts,
                    used_backup_key=(key_idx > 0),
                )
            if err:
                last_error = err
    else:
        for key_idx, key in enumerate(keys):
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
            )
            total_attempts += used_attempts
            if parsed is not None:
                return LLMCallOutcome(
                    parsed=parsed,
                    provider="google_genai",
                    configured_model=settings.gemini_model,
                    actual_model=actual_model or settings.gemini_model,
                    latency_ms=int((time.perf_counter() - t_start) * 1000),
                    attempts=total_attempts,
                    used_backup_key=(key_idx > 0),
                )
            if err:
                last_error = err

    return LLMCallOutcome(
        parsed=None,
        provider=provider,
        configured_model=settings.gemini_model,
        latency_ms=int((time.perf_counter() - t_start) * 1000),
        attempts=total_attempts,
        error_code=last_error,
    )
