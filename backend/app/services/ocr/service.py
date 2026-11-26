"""Bounded-concurrency OCR orchestrator with timeout and selective Gemini fallback."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Final

from app.config import Settings
from app.services.ocr.base import OcrProvider, OcrResult
from app.services.ocr.gemini_provider import extract_ocr_via_gemini
from app.services.ocr.mineru_provider import MinerUBasicOnnxProvider
from app.services.ocr.rapidocr_provider import RapidOcrOnnxProvider

logger = logging.getLogger(__name__)

LOW_CONFIDENCE_FALLBACK_THRESHOLD: Final[float] = 0.45
DEFAULT_MAX_GEMINI_FALLBACKS_PER_BATCH: Final[int] = 2

GeminiOcrFn = Callable[[Settings, bytes, str, float], Awaitable[OcrResult]]


def _resolve_allow_ocr_download(settings: Settings) -> bool:
    raw = os.getenv("VERISHIELD_ALLOW_OCR_DOWNLOAD")
    if raw is not None and raw.strip() != "":
        return raw.strip() == "1"
    return settings.app_env != "production"


def build_primary_ocr_provider(settings: Settings) -> OcrProvider | None:
    """Instantiate configured local OCR provider obeying production offline-cache rules."""
    if not settings.enable_local_ocr or settings.ocr_provider == "disabled":
        return None
    if settings.ocr_provider == "mineru_basic_onnx":
        return MinerUBasicOnnxProvider()
    variant = "ppocrv4" if settings.ocr_provider == "rapidocr_v4" else "ppocrv5_latin"
    cache_dir = Path(settings.ocr_model_dir) if settings.ocr_model_dir.strip() else None
    return RapidOcrOnnxProvider(
        variant=variant,
        model_root_dir=cache_dir,
        allow_download=_resolve_allow_ocr_download(settings),
    )


class OcrOrchestrator:
    """Coordinates local OCR concurrency, per-image timeout, and privacy-bounded Gemini fallback."""

    def __init__(
        self,
        settings: Settings,
        primary_provider: OcrProvider | None = None,
        gemini_fallback_fn: GeminiOcrFn | None = None,
    ) -> None:
        self._settings = settings
        self._primary: OcrProvider | None = (
            primary_provider
            if primary_provider is not None
            else build_primary_ocr_provider(settings)
        )
        self._gemini_fallback_fn: GeminiOcrFn = gemini_fallback_fn or extract_ocr_via_gemini
        self._semaphore = asyncio.Semaphore(max(1, settings.ocr_max_concurrency))

    @property
    def primary_name(self) -> str:
        if self._primary is None:
            return "disabled"
        return self._primary.name

    def is_local_ready(self) -> bool:
        """Return True when local OCR is enabled and weights/runtime are ready."""
        if not self._settings.enable_local_ocr or self._primary is None:
            return False
        if isinstance(self._primary, RapidOcrOnnxProvider):
            return self._primary.has_local_weights() or self._primary.is_available()
        return self._primary.is_available()

    def _should_trigger_gemini_fallback(
        self,
        primary_res: OcrResult,
        *,
        allow_empty_fallback: bool,
    ) -> bool:
        if not self._settings.enable_gemini_ocr_fallback:
            return False
        has_key = bool(
            self._settings.gemini_api_key.strip() or self._settings.gemini_backup_api_key.strip()
        )
        if not has_key:
            return False
        if primary_res.status in ("timeout", "unavailable", "error"):
            return True
        if primary_res.status == "ok" and primary_res.mean_confidence < LOW_CONFIDENCE_FALLBACK_THRESHOLD:
            return True
        return primary_res.status == "empty" and allow_empty_fallback

    async def extract(
        self,
        image_bytes: bytes,
        *,
        mime_type: str = "image/jpeg",
        allow_gemini_fallback: bool = True,
        allow_empty_fallback: bool = False,
    ) -> OcrResult:
        """Extract OCR text for a single image under semaphore & timeout guards."""
        if not self._settings.enable_local_ocr or self._primary is None:
            return OcrResult(available=False, status="skipped", provider="disabled")

        t0 = time.perf_counter()
        async with self._semaphore:
            try:
                primary_res = await asyncio.wait_for(
                    asyncio.to_thread(self._primary.extract, image_bytes, mime_type=mime_type),
                    timeout=self._settings.ocr_timeout_sec,
                )
            except TimeoutError:
                logger.warning(
                    "Local OCR provider '%s' timed out after %.1fs.",
                    self._primary.name,
                    self._settings.ocr_timeout_sec,
                )
                primary_res = OcrResult(
                    available=False,
                    status="timeout",
                    provider=self._primary.name,
                    model_id=self._primary.model_id,
                    latency_ms=int((time.perf_counter() - t0) * 1000),
                    error_code="OCR_TIMEOUT",
                )
            except Exception as exc:
                logger.warning(
                    "Local OCR provider '%s' raised %s.",
                    self._primary.name,
                    type(exc).__name__,
                )
                primary_res = OcrResult(
                    available=False,
                    status="error",
                    provider=self._primary.name,
                    model_id=self._primary.model_id,
                    latency_ms=int((time.perf_counter() - t0) * 1000),
                    error_code=f"OCR_{type(exc).__name__.upper()}",
                )

        if allow_gemini_fallback and self._should_trigger_gemini_fallback(
            primary_res, allow_empty_fallback=allow_empty_fallback
        ):
            fb_res = await self._gemini_fallback_fn(
                self._settings,
                image_bytes,
                mime_type,
                self._settings.ocr_timeout_sec,
            )
            if fb_res.status == "ok" and fb_res.full_text.strip():
                logger.info(
                    "OCR fallback succeeded via '%s' (latency=%dms).",
                    fb_res.provider,
                    fb_res.latency_ms,
                )
                return fb_res
            if primary_res.status == "ok":
                return primary_res
        return primary_res

    async def extract_batch(
        self,
        items: list[tuple[bytes, str]],
        *,
        allow_empty_fallback: bool = False,
        max_gemini_fallbacks: int = DEFAULT_MAX_GEMINI_FALLBACKS_PER_BATCH,
    ) -> list[OcrResult]:
        """Extract OCR across multiple images with concurrency bounds and a fallback budget cap."""
        if not items:
            return []
        raw_results = await asyncio.gather(
            *(
                self.extract(
                    img_bytes,
                    mime_type=img_mime,
                    allow_gemini_fallback=False,
                    allow_empty_fallback=False,
                )
                for img_bytes, img_mime in items
            )
        )
        results = list(raw_results)
        fallbacks_used = 0
        for idx, ((img_bytes, img_mime), cur_res) in enumerate(zip(items, results, strict=True)):
            if fallbacks_used >= max_gemini_fallbacks:
                break
            if self._should_trigger_gemini_fallback(
                cur_res, allow_empty_fallback=allow_empty_fallback
            ):
                fallbacks_used += 1
                fb_res = await self._gemini_fallback_fn(
                    self._settings,
                    img_bytes,
                    img_mime,
                    self._settings.ocr_timeout_sec,
                )
                if fb_res.status == "ok" and fb_res.full_text.strip():
                    results[idx] = fb_res
        return results
