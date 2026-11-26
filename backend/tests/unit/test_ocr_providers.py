"""Unit tests for modular OCR provider interface, ONNX hardening, timeout/concurrency, and fallback."""

from __future__ import annotations

import asyncio
import io
import logging
import time
from pathlib import Path

import pytest
from PIL import Image, ImageDraw

from app.config import Settings
from app.services.ocr.base import OcrBox, OcrProvider, OcrResult
from app.services.ocr.mineru_provider import MinerUBasicOnnxProvider
from app.services.ocr.rapidocr_provider import (
    RapidOcrOnnxProvider,
    ensure_rapidocr_memory_safe_session,
)
from app.services.ocr.service import OcrOrchestrator


def _sample_png_bytes(text: str = "Chuyển khoản 500.000 VND") -> bytes:
    img = Image.new("RGB", (420, 100), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((20, 35), text, fill=(0, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_rapidocr_session_options_enforce_arena_and_mem_pattern_disabled() -> None:
    from omegaconf import OmegaConf
    from rapidocr.inference_engine.onnxruntime.main import OrtInferSession

    ensure_rapidocr_memory_safe_session()
    cfg = OmegaConf.create(
        {
            "enable_cpu_mem_arena": True,
            "intra_op_num_threads": 2,
            "inter_op_num_threads": 1,
        }
    )
    opts = OrtInferSession._init_sess_opts(cfg)  # noqa: SLF001
    assert opts.enable_cpu_mem_arena is False
    assert opts.enable_mem_pattern is False


def test_rapidocr_offline_guard_blocks_runtime_download_when_cache_missing(
    tmp_path: Path,
) -> None:
    empty_cache = tmp_path / "empty_ocr_cache"
    empty_cache.mkdir()
    provider = RapidOcrOnnxProvider(
        model_root_dir=empty_cache,
        allow_download=False,
        fallback_package_models=False,
    )
    assert isinstance(provider, OcrProvider)
    assert provider.is_available() is False
    res = provider.extract(_sample_png_bytes())
    assert res.available is False
    assert res.status == "unavailable"
    assert res.error_code == "OCR_MODEL_CACHE_MISSING"
    assert list(empty_cache.iterdir()) == []


def test_rapidocr_ppocrv5_latin_extracts_vietnamese_receipt_and_geometry() -> None:
    demo_img = (
        Path(__file__).resolve().parents[2]
        / "app"
        / "data"
        / "demo_media"
        / "fake_bill_zalo.jpg"
    )
    provider = RapidOcrOnnxProvider(allow_download=True)
    assert provider.license_name == "Apache-2.0"
    res = provider.extract(demo_img.read_bytes(), mime_type="image/jpeg")
    assert res.available is True
    assert res.status == "ok"
    assert res.provider == "rapidocr_v5_latin"
    assert "FAKE12" in res.full_text
    assert "190399998888" in res.full_text
    assert res.mean_confidence >= 0.80
    assert len(res.boxes) >= 5
    assert all(b.width >= 0 and b.height >= 0 for b in res.boxes)


def test_mineru_provider_unavailable_by_default_without_production_install(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib.util

    monkeypatch.setattr(importlib.util, "find_spec", lambda name: None)
    provider = MinerUBasicOnnxProvider()
    assert isinstance(provider, OcrProvider)
    assert provider.is_available() is False
    res = provider.extract(_sample_png_bytes())
    assert res.available is False
    assert res.status == "unavailable"
    assert res.error_code == "MINERU_NOT_INSTALLED"


class _StubProvider:
    def __init__(
        self,
        result: OcrResult,
        delay_sec: float = 0.0,
        name: str = "stub_ocr",
    ) -> None:
        self.name = name
        self.model_id = "stub-v1"
        self.license_name = "MIT"
        self._result = result
        self._delay_sec = delay_sec
        self.calls = 0
        self.active = 0
        self.max_active = 0

    def is_available(self) -> bool:
        return True

    def extract(self, image_bytes: bytes, *, mime_type: str = "image/jpeg") -> OcrResult:
        _ = (image_bytes, mime_type)
        self.calls += 1
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            if self._delay_sec > 0:
                time.sleep(self._delay_sec)
            return self._result
        finally:
            self.active -= 1


@pytest.mark.asyncio
async def test_orchestrator_enforces_timeout_concurrency_and_selective_gemini_fallback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    cfg = Settings(
        _env_file=None,
        gemini_api_key="test-key",
        ocr_timeout_sec=1.0,
        ocr_max_concurrency=1,
        enable_gemini_ocr_fallback=True,
    )

    # 1. Timeout triggers Gemini fallback and resets status to ok when fallback succeeds
    slow_primary = _StubProvider(
        OcrResult(available=True, status="ok", provider="stub", model_id="m", full_text="late"),
        delay_sec=1.4,
    )
    fallback_calls = 0

    async def _fake_gemini_ocr(
        _settings: Settings,
        _img: bytes,
        _mime: str,
        _timeout: float,
    ) -> OcrResult:
        nonlocal fallback_calls
        fallback_calls += 1
        return OcrResult(
            available=True,
            status="ok",
            provider="gemini_multimodal",
            model_id="gemini-2.5-flash",
            full_text="Chuyển khoản tới STK 190399998888 SĐT 0912345678",
            boxes=[],
            mean_confidence=0.92,
            height_cv=0.0,
            latency_ms=120,
        )

    orch = OcrOrchestrator(
        settings=cfg,
        primary_provider=slow_primary,
        gemini_fallback_fn=_fake_gemini_ocr,
    )
    with caplog.at_level(logging.DEBUG, logger="app.services.ocr"):
        res = await orch.extract(
            _sample_png_bytes(),
            mime_type="image/png",
            allow_empty_fallback=False,
        )
    assert res.status == "ok"
    assert res.provider == "gemini_multimodal"
    assert fallback_calls == 1
    # Verify NO raw PII from OCR text leaked into logs
    log_blob = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "190399998888" not in log_blob
    assert "0912345678" not in log_blob

    # 2. Clean empty OCR on non-image-only request MUST NOT burn a Gemini fallback call
    empty_primary = _StubProvider(
        OcrResult(available=True, status="empty", provider="stub", model_id="m", full_text="")
    )
    fallback_calls_2 = 0

    async def _counting_gemini(
        _settings: Settings,
        _img: bytes,
        _mime: str,
        _timeout: float,
    ) -> OcrResult:
        nonlocal fallback_calls_2
        fallback_calls_2 += 1
        return OcrResult(
            available=True,
            status="ok",
            provider="gemini_multimodal",
            model_id="gemini-2.5-flash",
            full_text="recovered",
            mean_confidence=0.9,
        )

    orch2 = OcrOrchestrator(
        settings=cfg,
        primary_provider=empty_primary,
        gemini_fallback_fn=_counting_gemini,
    )
    res_empty = await orch2.extract(
        _sample_png_bytes(),
        mime_type="image/png",
        allow_empty_fallback=False,
    )
    assert res_empty.status == "empty"
    assert fallback_calls_2 == 0

    # Image-only request with empty OCR DOES allow Gemini fallback
    res_img_only = await orch2.extract(
        _sample_png_bytes(),
        mime_type="image/png",
        allow_empty_fallback=True,
    )
    assert res_img_only.status == "ok"
    assert res_img_only.provider == "gemini_multimodal"
    assert fallback_calls_2 == 1

    # 3. Concurrency semaphore caps in-flight local OCR executions to 1
    conc_primary = _StubProvider(
        OcrResult(
            available=True,
            status="ok",
            provider="stub",
            model_id="m",
            full_text="OK",
            boxes=[OcrBox(text="OK", confidence=0.95, x=0, y=0, width=20, height=10)],
            mean_confidence=0.95,
        ),
        delay_sec=0.12,
    )
    orch_conc = OcrOrchestrator(settings=cfg, primary_provider=conc_primary)
    results = await asyncio.gather(
        orch_conc.extract(_sample_png_bytes()),
        orch_conc.extract(_sample_png_bytes()),
        orch_conc.extract(_sample_png_bytes()),
    )
    assert len(results) == 3
    assert conc_primary.max_active == 1


@pytest.mark.asyncio
async def test_orchestrator_caps_gemini_fallback_calls_per_batch() -> None:
    cfg = Settings(
        _env_file=None,
        gemini_api_key="test-key",
        ocr_timeout_sec=2.0,
        ocr_max_concurrency=2,
        enable_gemini_ocr_fallback=True,
    )
    failing_primary = _StubProvider(
        OcrResult(
            available=False,
            status="error",
            provider="stub",
            model_id="m",
            error_code="ENGINE_ERR",
        )
    )
    fb_count = 0

    async def _fb(
        _settings: Settings,
        _img: bytes,
        _mime: str,
        _timeout: float,
    ) -> OcrResult:
        nonlocal fb_count
        fb_count += 1
        return OcrResult(
            available=True,
            status="ok",
            provider="gemini_multimodal",
            model_id="gemini-2.5-flash",
            full_text=f"img-{fb_count}",
            mean_confidence=0.9,
        )

    orch = OcrOrchestrator(
        settings=cfg,
        primary_provider=failing_primary,
        gemini_fallback_fn=_fb,
    )
    batch = await orch.extract_batch(
        [(_sample_png_bytes(), "image/png") for _ in range(4)],
        allow_empty_fallback=False,
        max_gemini_fallbacks=2,
    )
    assert len(batch) == 4
    assert fb_count == 2
    assert sum(1 for r in batch if r.provider == "gemini_multimodal") == 2
    assert sum(1 for r in batch if r.status == "error") == 2
