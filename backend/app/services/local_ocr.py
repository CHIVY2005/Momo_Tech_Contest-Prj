"""Local Vietnamese/Latin OCR & bounding-box geometry extraction via RapidOCR ONNX."""

from __future__ import annotations

import time
from functools import lru_cache
from typing import Any

import numpy as np
from pydantic import BaseModel, Field


class OcrBox(BaseModel):
    """Single detected text line with bounding-box dimensions in pixels."""

    text: str
    confidence: float = Field(ge=0.0, le=1.0)
    x: float
    y: float
    width: float = Field(ge=0.0)
    height: float = Field(ge=0.0)


class LocalOcrResult(BaseModel):
    """Aggregated local ONNX OCR output and line-height dispersion metric."""

    available: bool
    full_text: str = ""
    boxes: list[OcrBox] = Field(default_factory=list)
    height_cv: float = Field(default=0.0, ge=0.0)
    latency_ms: int = Field(default=0, ge=0)


@lru_cache(maxsize=1)
def _get_rapid_ocr() -> Any:
    from rapidocr_onnxruntime import RapidOCR

    return RapidOCR(intra_op_num_threads=2, inter_op_num_threads=1)


def run_local_ocr(image_bytes: bytes, enabled: bool = True) -> LocalOcrResult:
    """Extract text lines and bounding boxes locally on CPU without cloud dependencies."""
    if not enabled or not image_bytes:
        return LocalOcrResult(available=False)

    t0 = time.perf_counter()
    try:
        engine = _get_rapid_ocr()
        raw_items, _ = engine(image_bytes)
    except Exception:
        return LocalOcrResult(available=False)

    latency_ms = int((time.perf_counter() - t0) * 1000)
    if not raw_items:
        return LocalOcrResult(available=True, full_text="", boxes=[], latency_ms=latency_ms)

    boxes: list[OcrBox] = []
    lines: list[str] = []
    heights: list[float] = []

    for entry in raw_items:
        quad, text_val, conf_val = entry[0], str(entry[1]).strip(), float(entry[2])
        if not text_val:
            continue
        pts = np.asarray(quad, dtype=np.float32)
        min_x = float(np.min(pts[:, 0]))
        max_x = float(np.max(pts[:, 0]))
        min_y = float(np.min(pts[:, 1]))
        max_y = float(np.max(pts[:, 1]))
        width = max(0.0, max_x - min_x)
        height = max(0.0, max_y - min_y)
        boxes.append(
            OcrBox(
                text=text_val,
                confidence=min(1.0, max(0.0, conf_val)),
                x=min_x,
                y=min_y,
                width=width,
                height=height,
            )
        )
        lines.append(text_val)
        if height > 2.0:
            heights.append(height)

    height_cv = 0.0
    if len(heights) >= 3:
        arr = np.asarray(heights, dtype=np.float32)
        mean_h = float(np.mean(arr))
        if mean_h > 0:
            height_cv = round(float(np.std(arr) / mean_h), 4)

    return LocalOcrResult(
        available=True,
        full_text="\n".join(lines),
        boxes=boxes,
        height_cv=height_cv,
        latency_ms=latency_ms,
    )
