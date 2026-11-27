"""Dual-protocol streaming LLM adapter with mandatory wire-egress chokepoint & <think> filter."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import logging
import re
from collections.abc import AsyncGenerator, AsyncIterator
from typing import Any, Final

import httpx
from google import genai
from google.genai import types

from app.config import Settings
from app.services.assistant_guardrails import ThinkStreamFilter
from app.services.assistant_vault import sanitize_llm_egress_text
from app.services.guardrails import strip_xml_breakout_tags, untrusted_user_content
from app.services.llm_client import _is_google_safety_blocked, normalize_openai_chat_url

logger = logging.getLogger(__name__)
_OPEN_TAG: Final[str] = "<UNTRUSTED_USER_CONTENT>"
_CLOSE_TAG: Final[str] = "</UNTRUSTED_USER_CONTENT>"
_OPEN_ANY_RE: Final[re.Pattern[str]] = re.compile(r"<\s*untrusted_user_content\b[^>]*>", re.I)
_CLOSE_ANY_RE: Final[re.Pattern[str]] = re.compile(r"<\s*/\s*untrusted_user_content\s*>", re.I)
_OPENAI_SAFETY_FINISH: Final[frozenset[str]] = frozenset({"CONTENT_FILTER", "SAFETY"})
_SENTINEL: Final[object] = object()
_HC = types.HarmCategory
_SAFETY_CATS: Final[tuple[types.HarmCategory, ...]] = (
    _HC.HARM_CATEGORY_HARASSMENT, _HC.HARM_CATEGORY_HATE_SPEECH,
    _HC.HARM_CATEGORY_DANGEROUS_CONTENT, _HC.HARM_CATEGORY_SEXUALLY_EXPLICIT,
)


class AssistantLlmUnavailableError(RuntimeError):
    """Raised when streaming LLM fails, times out, is unconfigured, or hits safety block."""

    def __init__(self, error_code: str = "LLM_UNAVAILABLE") -> None:
        self.error_code = error_code
        super().__init__(error_code)


class _StreamAttemptError(RuntimeError):
    def __init__(self, error_code: str, *, retryable: bool = True) -> None:
        self.error_code, self.retryable = error_code, retryable
        super().__init__(error_code)


def apply_final_wire_egress_chokepoint(user_prompt: str) -> str:
    """Scrub outbound prompt before wire send; keep official bare domains only in trusted prefix."""
    if not user_prompt:
        return ""
    scrub, s, e = sanitize_llm_egress_text, user_prompt.find(_OPEN_TAG), user_prompt.find(_CLOSE_TAG)
    suffix = user_prompt[e + len(_CLOSE_TAG) :] if e != -1 else ""
    if (
        len(_OPEN_ANY_RE.findall(user_prompt)) != 1 or len(_CLOSE_ANY_RE.findall(user_prompt)) != 1
        or s == -1 or e <= s or suffix.strip()
    ):
        return untrusted_user_content(
            scrub(user_prompt, preserve_official_bare_domains=False, preserve_strict_vault_refs=False)
        )
    pre = strip_xml_breakout_tags(
        scrub(user_prompt[:s], preserve_official_bare_domains=True, preserve_strict_vault_refs=True)
    )
    raw_inner = user_prompt[s + len(_OPEN_TAG) : e]
    inner = strip_xml_breakout_tags(
        scrub(raw_inner, preserve_official_bare_domains=False, preserve_strict_vault_refs=True)
    )
    return f"{pre}\n\n{_OPEN_TAG}\n{inner}\n{_CLOSE_TAG}" if pre else f"{_OPEN_TAG}\n{inner}\n{_CLOSE_TAG}"


def _extract_openai_delta_text(delta: Any) -> str:
    content = delta.get("content") if isinstance(delta, dict) else None
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            t for p in content if isinstance(p, dict) and p.get("type") in ("text", "output_text", None)
            and isinstance((t := p.get("text")), str)
        )
    return ""


async def _filter_think_stream(raw_iter: AsyncIterator[str]) -> AsyncIterator[str]:
    filt, emitted = ThinkStreamFilter(), False
    async for raw_text in raw_iter:
        if raw_text and (clean := filt.feed(raw_text)):
            emitted = True
            yield clean
    if tail := filt.flush():
        emitted = True
        yield tail
    if not emitted:
        raise _StreamAttemptError("EMPTY_COMPLETION_CONTENT")


async def _raw_openai_stream(
    endpoint: str, api_key: str, model_name: str, *, system_instruction: str,
    safe_prompt: str, max_output_tokens: int, timeout_sec: float,
) -> AsyncGenerator[str, None]:
    msgs = [{"role": "system", "content": system_instruction}, {"role": "user", "content": safe_prompt}]
    payload: dict[str, Any] = {
        "model": model_name, "temperature": 0.2, "max_tokens": max_output_tokens,
        "stream": True, "messages": msgs,
    }
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "text/event-stream"}
    timeout = httpx.Timeout(timeout_sec, connect=min(8.0, timeout_sec))
    try:
        async with (
            asyncio.timeout(timeout_sec),
            httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client,
            client.stream("POST", endpoint, headers=headers, json=payload) as resp,
        ):
            if not resp.is_success:
                raise _StreamAttemptError(f"HTTP_{resp.status_code}")
            async for raw_line in resp.aiter_lines():
                if not (line := raw_line.strip()).startswith("data:"):
                    continue
                if (data_str := line[5:].strip()) == "[DONE]":
                    break
                try:
                    obj = json.loads(data_str)
                except ValueError:
                    continue
                choices = obj.get("choices") if isinstance(obj, dict) else None
                if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
                    continue
                if str(choices[0].get("finish_reason") or "").upper() in _OPENAI_SAFETY_FINISH:
                    raise _StreamAttemptError("SAFETY_BLOCKED", retryable=False)
                if raw_text := _extract_openai_delta_text(choices[0].get("delta")):
                    yield raw_text
    except _StreamAttemptError:
        raise
    except (TimeoutError, httpx.TimeoutException) as exc:
        raise _StreamAttemptError("TIMEOUT") from exc
    except httpx.HTTPError as exc:
        raise _StreamAttemptError("NETWORK_TRANSPORT_ERROR") from exc


async def _iter_google_chunks(
    client: Any, model: str, prompt: str, config: types.GenerateContentConfig
) -> AsyncIterator[Any]:
    aio_models = getattr(getattr(client, "aio", None), "models", None)
    if callable(aio_fn := getattr(aio_models, "generate_content_stream", None)):
        stream = aio_fn(model=model, contents=prompt, config=config)
        stream = await stream if inspect.isawaitable(stream) else stream
        async for chunk in stream:
            yield chunk
        return
    it = await asyncio.to_thread(
        client.models.generate_content_stream, model=model, contents=prompt, config=config
    )
    while (chunk := await asyncio.to_thread(next, it, _SENTINEL)) is not _SENTINEL:
        yield chunk


async def _raw_google_stream(
    api_key: str, model_name: str, *, system_instruction: str,
    safe_prompt: str, max_output_tokens: int, timeout_sec: float,
) -> AsyncGenerator[str, None]:
    config = types.GenerateContentConfig(
        system_instruction=system_instruction, temperature=0.2, max_output_tokens=max_output_tokens,
        safety_settings=[
            types.SafetySetting(category=c, threshold=types.HarmBlockThreshold.BLOCK_ONLY_HIGH)
            for c in _SAFETY_CATS
        ],
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
    )
    try:
        client = genai.Client(api_key=api_key)
    except Exception as exc:
        raise _StreamAttemptError(f"CLIENT_INIT_{type(exc).__name__.upper()}") from exc
    try:
        async with asyncio.timeout(timeout_sec):
            async for chunk in _iter_google_chunks(client, model_name, safe_prompt, config):
                if _is_google_safety_blocked(chunk):
                    raise _StreamAttemptError("SAFETY_BLOCKED", retryable=False)
                try:
                    txt = getattr(chunk, "text", None)
                except Exception:
                    txt = None
                if isinstance(txt, str) and txt:
                    yield txt
    except (_StreamAttemptError, asyncio.CancelledError):
        raise
    except TimeoutError as exc:
        raise _StreamAttemptError("TIMEOUT") from exc
    except Exception as exc:
        raise _StreamAttemptError(type(exc).__name__.upper()) from exc
    finally:
        if callable(aclose_fn := getattr(getattr(client, "aio", None), "aclose", None)):
            try:
                if inspect.isawaitable(res := aclose_fn()):
                    async with asyncio.timeout(2.0):
                        await res
            except TimeoutError:
                logger.debug("Timed out closing Google GenAI stream client.")
            except Exception:
                logger.debug("Ignored Google GenAI stream client aclose error.")


async def stream_assistant_llm(
    settings: Settings, *, system_instruction: str, user_prompt: str,
    max_output_tokens: int = 700, timeout_sec: float = 25.0,
) -> AsyncGenerator[str, None]:
    """Stream text chunks from configured provider after wire-egress scrub and <think> filtering."""
    safe_sys = sanitize_llm_egress_text(
        system_instruction, preserve_official_bare_domains=True, preserve_strict_vault_refs=False
    )
    safe_prompt = apply_final_wire_egress_chokepoint(user_prompt)
    keys = [k.strip() for k in (settings.gemini_api_key, settings.gemini_backup_api_key) if k.strip()]
    if not keys:
        raise AssistantLlmUnavailableError("NO_API_KEY")
    provider, endpoint = settings.resolved_llm_provider, ""
    if provider == "openai_compatible":
        try:
            endpoint = normalize_openai_chat_url(settings.gemini_base_url)
        except ValueError as exc:
            raise AssistantLlmUnavailableError("INVALID_BASE_URL") from exc
    last_error = "LLM_UNAVAILABLE"
    kw: dict[str, Any] = {
        "system_instruction": safe_sys, "safe_prompt": safe_prompt,
        "max_output_tokens": max_output_tokens, "timeout_sec": timeout_sec,
    }
    for key in keys:
        emitted = False
        raw = (
            _raw_openai_stream(endpoint, key, settings.gemini_model, **kw)
            if provider == "openai_compatible"
            else _raw_google_stream(key, settings.gemini_model, **kw)
        )
        try:
            async with contextlib.aclosing(raw):
                async for piece in _filter_think_stream(raw):
                    emitted = True
                    yield piece
            return
        except _StreamAttemptError as exc:
            last_error = exc.error_code
            if emitted or not exc.retryable:
                raise AssistantLlmUnavailableError(last_error) from exc
    raise AssistantLlmUnavailableError(last_error)
