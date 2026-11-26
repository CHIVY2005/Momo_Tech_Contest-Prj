"""Shared OCR Provider Protocol and normalized OCR data contracts."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

import numpy as np
from pydantic import BaseModel, Field

from app.schemas.common import OcrStatus as OcrStatus


class OcrBox(BaseModel):
    """Single detected text line with pixel bounding box and optional polygon."""

    text: str
    confidence: float = Field(ge=0.0, le=1.0)
    x: float
    y: float
    width: float = Field(ge=0.0)
    height: float = Field(ge=0.0)
    polygon: list[list[float]] | None = None


class OcrResult(BaseModel):
    """Normalized OCR extraction output shared across all providers."""

    available: bool
    status: OcrStatus = "skipped"
    provider: str = "none"
    model_id: str = ""
    full_text: str = ""
    boxes: list[OcrBox] = Field(default_factory=list)
    mean_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    height_cv: float = Field(default=0.0, ge=0.0)
    latency_ms: int = Field(default=0, ge=0)
    error_code: str | None = None


@runtime_checkable
class OcrProvider(Protocol):
    """Pluggable OCR engine contract supporting local ONNX, document parsers, and multimodal fallback."""

    name: str
    model_id: str
    license_name: str

    def is_available(self) -> bool:
        """Return True if this provider's runtime and local weights are ready."""
        ...

    def extract(self, image_bytes: bytes, *, mime_type: str = "image/jpeg") -> OcrResult:
        """Extract text lines, bounding boxes, and confidence scores from raw image bytes."""
        ...


def compute_height_cv(boxes: list[OcrBox]) -> float:
    """Compute line-height coefficient of variation (CV) for receipt font-tampering forensics."""
    heights = [b.height for b in boxes if b.height > 2.0]
    if len(heights) < 3:
        return 0.0
    arr = np.asarray(heights, dtype=np.float32)
    mean_h = float(np.mean(arr))
    if mean_h <= 0.0:
        return 0.0
    return round(float(np.std(arr) / mean_h), 4)


def build_box_from_quad(quad: object, text: str, confidence: float) -> OcrBox:
    """Construct an OcrBox from a 4-point polygon array."""
    pts = np.asarray(quad, dtype=np.float32)
    min_x = float(np.min(pts[:, 0]))
    max_x = float(np.max(pts[:, 0]))
    min_y = float(np.min(pts[:, 1]))
    max_y = float(np.max(pts[:, 1]))
    polygon = [[round(float(p[0]), 2), round(float(p[1]), 2)] for p in pts.tolist()]
    return OcrBox(
        text=text,
        confidence=min(1.0, max(0.0, float(confidence))),
        x=min_x,
        y=min_y,
        width=max(0.0, max_x - min_x),
        height=max(0.0, max_y - min_y),
        polygon=polygon,
    )
