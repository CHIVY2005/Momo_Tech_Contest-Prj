"""Modular OCR provider interfaces, local ONNX engines, and orchestrator."""

from app.services.ocr.base import OcrBox, OcrProvider, OcrResult, OcrStatus
from app.services.ocr.gemini_provider import extract_ocr_via_gemini
from app.services.ocr.mineru_provider import MinerUBasicOnnxProvider
from app.services.ocr.rapidocr_provider import (
    RapidOcrOnnxProvider,
    ensure_rapidocr_memory_safe_session,
)
from app.services.ocr.service import OcrOrchestrator, build_primary_ocr_provider

__all__ = [
    "MinerUBasicOnnxProvider",
    "OcrBox",
    "OcrOrchestrator",
    "OcrProvider",
    "OcrResult",
    "OcrStatus",
    "RapidOcrOnnxProvider",
    "build_primary_ocr_provider",
    "ensure_rapidocr_memory_safe_session",
    "extract_ocr_via_gemini",
]
