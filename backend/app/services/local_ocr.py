"""Backward-compatible local OCR facade delegating to the modular RapidOCR PP-OCRv5 Latin provider."""

from __future__ import annotations

import time
from functools import lru_cache
from typing import Any

from pydantic import BaseModel, Field

from app.services.ocr.base import OcrBox, OcrStatus, build_box_from_quad, compute_height_cv
from app.services.ocr.rapidocr_provider import RapidOcrOnnxProvider

__all__ = ["LocalOcrResult", "OcrBox", "run_local_ocr"]


class LocalOcrResult(BaseModel):
    """Aggregated local ONNX OCR output and line-height dispersion metric."""

    available: bool
    status: OcrStatus = "skipped"
    provider: str = "rapidocr_v5_latin"
    full_text: str = ""
    boxes: list[OcrBox] = Field(default_factory=list)
    mean_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    height_cv: float = Field(default=0.0, ge=0.0)
    latency_ms: int = Field(default=0, ge=0)
    error_code: str | None = None


@lru_cache(maxsize=1)
def _get_rapid_ocr() -> Any:
    """Return cached RapidOCR PP-OCRv5 Latin provider (monkeypatch-friendly for unit tests)."""
    return RapidOcrOnnxProvider(variant="ppocrv5_latin", allow_download=True)


def run_local_ocr(image_bytes: bytes, enabled: bool = True) -> LocalOcrResult:
    """Extract text lines and bounding boxes locally on CPU without cloud dependencies."""
    if not enabled or not image_bytes:
        return LocalOcrResult(available=False, status="skipped")

    t0 = time.perf_counter()
    try:
        engine = _get_rapid_ocr()
        if isinstance(engine, RapidOcrOnnxProvider):
            res = engine.extract(image_bytes)
            return LocalOcrResult(
                available=res.available,
                status=res.status,
                provider=res.provider,
                full_text=res.full_text,
                boxes=res.boxes,
                mean_confidence=res.mean_confidence,
                height_cv=res.height_cv,
                latency_ms=res.latency_ms,
                error_code=res.error_code,
            )
        # Support legacy callable mocks returning (raw_items, elapse) in existing unit tests
        raw_items, _ = engine(image_bytes)
    except Exception as exc:
        return LocalOcrResult(
            available=False,
            status="error",
            latency_ms=int((time.perf_counter() - t0) * 1000),
            error_code=type(exc).__name__.upper(),
        )

    latency_ms = int((time.perf_counter() - t0) * 1000)
    if not raw_items:
        return LocalOcrResult(
            available=True,
            status="empty",
            full_text="",
            boxes=[],
            latency_ms=latency_ms,
        )

    boxes: list[OcrBox] = []
    lines: list[str] = []
    confs: list[float] = []
    for entry in raw_items:
        quad, text_val, conf_val = entry[0], str(entry[1]).strip(), float(entry[2])
        if not text_val:
            continue
        box = build_box_from_quad(quad, text_val, conf_val)
        boxes.append(box)
        lines.append(text_val)
        confs.append(box.confidence)

    mean_conf = round(float(sum(confs) / len(confs)), 4) if confs else 0.0
    return LocalOcrResult(
        available=True,
        status="ok" if lines else "empty",
        full_text="\n".join(lines),
        boxes=boxes,
        mean_confidence=mean_conf,
        height_cv=compute_height_cv(boxes),
        latency_ms=latency_ms,
    )
