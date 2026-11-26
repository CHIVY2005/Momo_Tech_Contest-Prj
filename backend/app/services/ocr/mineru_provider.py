"""Optional MinerU Basic ONNX provider adapter (NOT installed in production requirements.txt)."""

from __future__ import annotations

import importlib.util
import logging
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any

from app.services.ocr.base import OcrResult

logger = logging.getLogger(__name__)
_MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\([^)]*\)")


class MinerUBasicOnnxProvider:
    """Optional adapter for MinerU v4+ Basic ONNX tier for complex layouts / offline benchmarks."""

    name: str = "mineru_basic_onnx"
    model_id: str = "mineru-v4-basic-onnx"
    license_name: str = "LicenseRef-MinerU-Open-Source-License"

    def is_available(self) -> bool:
        """Return True strictly when optional 'mineru' package is installed in the current venv."""
        return importlib.util.find_spec("mineru") is not None

    def extract(self, image_bytes: bytes, *, mime_type: str = "image/jpeg") -> OcrResult:
        """Run local CPU-only MinerU Basic ONNX parsing inside a strictly cleaned temp directory."""
        if not image_bytes:
            return OcrResult(
                available=False,
                status="error",
                provider=self.name,
                model_id=self.model_id,
                error_code="EMPTY_IMAGE_BYTES",
            )
        if not self.is_available():
            return OcrResult(
                available=False,
                status="unavailable",
                provider=self.name,
                model_id=self.model_id,
                error_code="MINERU_NOT_INSTALLED",
            )

        ext = ".png" if "png" in mime_type.lower() else ".jpg"
        t0 = time.perf_counter()
        prev_device = os.environ.get("MINERU_MODEL_ONNX_DEVICE")
        os.environ["MINERU_MODEL_ONNX_DEVICE"] = "cpu"
        try:
            with tempfile.TemporaryDirectory(prefix="vs_mineru_") as tmp_dir:
                tmp_path = Path(tmp_dir)
                in_file = tmp_path / f"input{ext}"
                out_dir = tmp_path / "out"
                out_dir.mkdir(parents=True, exist_ok=True)
                in_file.write_bytes(image_bytes)

                extracted_text = _MD_IMAGE_RE.sub("", self._invoke_mineru_basic(in_file, out_dir))
                latency_ms = int((time.perf_counter() - t0) * 1000)
                cleaned = extracted_text.strip()
                if not cleaned:
                    return OcrResult(
                        available=True,
                        status="empty",
                        provider=self.name,
                        model_id=self.model_id,
                        latency_ms=latency_ms,
                    )
                return OcrResult(
                    available=True,
                    status="ok",
                    provider=self.name,
                    model_id=self.model_id,
                    full_text=cleaned,
                    boxes=[],
                    mean_confidence=0.85,
                    height_cv=0.0,
                    latency_ms=latency_ms,
                )
        except Exception as exc:
            logger.warning("MinerU Basic ONNX extraction failed (%s).", type(exc).__name__)
            return OcrResult(
                available=False,
                status="error",
                provider=self.name,
                model_id=self.model_id,
                latency_ms=int((time.perf_counter() - t0) * 1000),
                error_code=f"MINERU_{type(exc).__name__.upper()}",
            )
        finally:
            if prev_device is None:
                os.environ.pop("MINERU_MODEL_ONNX_DEVICE", None)
            else:
                os.environ["MINERU_MODEL_ONNX_DEVICE"] = prev_device

    @staticmethod
    def _invoke_mineru_basic(input_file: Path, output_dir: Path) -> str:
        """Invoke MinerU v4+ Python SDK in local basic ONNX mode (no cloud upload)."""
        import mineru

        parse_fn: Any = getattr(mineru, "parse", None)
        if callable(parse_fn):
            result = parse_fn(
                str(input_file),
                tier="basic",
                ocr_mode="ocr",
                image_analysis=False,
            )
            if isinstance(result, str):
                return result
            md_attr = getattr(result, "markdown", None)
            if callable(md_attr):
                md_val = md_attr()
                if isinstance(md_val, str):
                    return md_val
            elif isinstance(md_attr, str):
                return md_attr
            text_attr = getattr(result, "text", None)
            if isinstance(text_attr, str):
                return text_attr

        md_files = sorted(output_dir.rglob("*.md"))
        if md_files:
            return "\n".join(f.read_text(encoding="utf-8", errors="ignore") for f in md_files)
        raise RuntimeError("MinerU SDK returned no markdown output")
