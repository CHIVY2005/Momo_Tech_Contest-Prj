"""RapidOCR v3 ONNX Runtime CPU provider with PP-OCRv5 Latin mobile Vietnamese recognition."""

from __future__ import annotations

import contextlib
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Final

import cv2
import numpy as np

from app.core.media_security import InvalidMediaError, decode_image_to_rgb_array
from app.services.ocr.base import OcrBox, OcrResult, build_box_from_quad, compute_height_cv

logger = logging.getLogger(__name__)

PPOCRV5_DET_FILENAME: Final[str] = "ch_PP-OCRv5_det_mobile.onnx"
PPOCRV5_LATIN_REC_FILENAME: Final[str] = "latin_PP-OCRv5_rec_mobile.onnx"
PPOCRV4_DET_FILENAME: Final[str] = "ch_PP-OCRv4_det_mobile.onnx"
PPOCRV4_CH_REC_FILENAME: Final[str] = "ch_PP-OCRv4_rec_mobile.onnx"
MAX_OCR_DIMENSION: Final[int] = 2048

_PATCH_LOCK = threading.Lock()


def ensure_rapidocr_memory_safe_session() -> None:
    """Patch RapidOCR OrtInferSession so CPU arena & mem_pattern stay disabled (AGENTS.md Rule 4)."""
    from rapidocr.inference_engine.onnxruntime.main import OrtInferSession

    with _PATCH_LOCK:
        if getattr(OrtInferSession, "_verishield_mem_pattern_patched", False):
            return
        orig_init_opts = OrtInferSession._init_sess_opts  # noqa: SLF001

        def _safe_init_sess_opts(cfg: Any) -> Any:
            sess_opt = orig_init_opts(cfg)
            sess_opt.enable_cpu_mem_arena = False
            sess_opt.enable_mem_pattern = False
            return sess_opt

        ort_cls: Any = OrtInferSession
        ort_cls._init_sess_opts = staticmethod(_safe_init_sess_opts)  # noqa: SLF001
        ort_cls._verishield_mem_pattern_patched = True  # noqa: SLF001


def _default_ocr_cache_dir() -> Path:
    env_dir = os.getenv("OCR_MODEL_DIR", "").strip()
    if env_dir:
        return Path(env_dir)
    return Path(__file__).resolve().parents[3] / ".ocr_cache"


def _package_models_dir() -> Path | None:
    try:
        import rapidocr

        return Path(rapidocr.__file__).resolve().parent / "models"
    except Exception:
        return None


class RapidOcrOnnxProvider:
    """CPU-only ONNX RapidOCR provider (default: PP-OCRv5 mobile det + Latin mobile rec for VI)."""

    license_name: str = "Apache-2.0"

    def __init__(
        self,
        *,
        variant: str = "ppocrv5_latin",
        model_root_dir: Path | str | None = None,
        allow_download: bool = True,
        fallback_package_models: bool = True,
        use_cls: bool = False,
        intra_op_num_threads: int = 2,
    ) -> None:
        self._variant = variant
        self.name = "rapidocr_v5_latin" if variant == "ppocrv5_latin" else "rapidocr_v4"
        self.model_id = (
            f"{PPOCRV5_DET_FILENAME}+{PPOCRV5_LATIN_REC_FILENAME}"
            if variant == "ppocrv5_latin"
            else f"{PPOCRV4_DET_FILENAME}+{PPOCRV4_CH_REC_FILENAME}"
        )
        self._model_root_dir = (
            Path(model_root_dir) if model_root_dir is not None else _default_ocr_cache_dir()
        )
        self._allow_download = allow_download
        self._fallback_package_models = fallback_package_models
        self._use_cls = use_cls
        self._intra_threads = max(1, intra_op_num_threads)
        self._engine: Any | None = None
        self._init_lock = threading.Lock()

    def _expected_filenames(self) -> tuple[str, str]:
        if self._variant == "ppocrv5_latin":
            return PPOCRV5_DET_FILENAME, PPOCRV5_LATIN_REC_FILENAME
        return PPOCRV4_DET_FILENAME, PPOCRV4_CH_REC_FILENAME

    def _resolve_cached_paths(self) -> tuple[Path | None, Path | None]:
        det_name, rec_name = self._expected_filenames()
        search_dirs: list[Path] = [self._model_root_dir]
        if self._fallback_package_models:
            pkg_dir = _package_models_dir()
            if pkg_dir is not None and pkg_dir not in search_dirs:
                search_dirs.append(pkg_dir)

        det_path: Path | None = None
        rec_path: Path | None = None
        for root in search_dirs:
            if det_path is None:
                cand = root / det_name
                if cand.is_file() and cand.stat().st_size > 1024:
                    det_path = cand
            if rec_path is None:
                cand = root / rec_name
                if cand.is_file() and cand.stat().st_size > 1024:
                    rec_path = cand
        return det_path, rec_path

    def is_available(self) -> bool:
        """Return True when runtime is installed and either cached weights exist or download allowed."""
        try:
            import rapidocr  # noqa: F401
        except ImportError:
            return False
        det_path, rec_path = self._resolve_cached_paths()
        if det_path is not None and rec_path is not None:
            return True
        return self._allow_download

    def has_local_weights(self) -> bool:
        """Return True strictly when required ONNX weight files exist locally on disk."""
        det_path, rec_path = self._resolve_cached_paths()
        return det_path is not None and rec_path is not None

    def _get_engine(self) -> Any:
        if self._engine is not None:
            return self._engine
        with self._init_lock:
            if self._engine is not None:
                return self._engine
            from rapidocr import EngineType, LangRec, ModelType, OCRVersion, RapidOCR

            ensure_rapidocr_memory_safe_session()
            det_path, rec_path = self._resolve_cached_paths()
            if (det_path is None or rec_path is None) and not self._allow_download:
                raise FileNotFoundError("OCR_MODEL_CACHE_MISSING")

            self._model_root_dir.mkdir(parents=True, exist_ok=True)
            is_v5 = self._variant == "ppocrv5_latin"
            params: dict[str, Any] = {
                "Global.use_det": True,
                "Global.use_cls": self._use_cls,
                "Global.use_rec": True,
                "Global.log_level": "warning",
                "Global.model_root_dir": str(self._model_root_dir),
                "Det.engine_type": EngineType.ONNXRUNTIME,
                "Det.ocr_version": OCRVersion.PPOCRV5 if is_v5 else OCRVersion.PPOCRV4,
                "Det.model_type": ModelType.MOBILE,
                "Rec.engine_type": EngineType.ONNXRUNTIME,
                "Rec.ocr_version": OCRVersion.PPOCRV5 if is_v5 else OCRVersion.PPOCRV4,
                "Rec.lang_type": LangRec.LATIN if is_v5 else LangRec.CH,
                "Rec.model_type": ModelType.MOBILE,
                "EngineConfig.onnxruntime.enable_cpu_mem_arena": False,
                "EngineConfig.onnxruntime.intra_op_num_threads": self._intra_threads,
                "EngineConfig.onnxruntime.inter_op_num_threads": 1,
            }
            if det_path is not None:
                params["Det.model_path"] = str(det_path)
            if rec_path is not None:
                params["Rec.model_path"] = str(rec_path)

            self._engine = RapidOCR(params=params)
            return self._engine

    def extract(self, image_bytes: bytes, *, mime_type: str = "image/jpeg") -> OcrResult:
        """Decode image in-memory and extract Vietnamese/Latin text lines and geometry."""
        _ = mime_type
        if not image_bytes:
            return OcrResult(
                available=False, status="error", provider=self.name, model_id=self.model_id,
                error_code="EMPTY_IMAGE_BYTES",
            )

        t0 = time.perf_counter()
        try:
            arr = np.frombuffer(image_bytes, dtype=np.uint8)
            bgr = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            if bgr is None:
                with contextlib.suppress(InvalidMediaError):
                    bgr = cv2.cvtColor(decode_image_to_rgb_array(image_bytes), cv2.COLOR_RGB2BGR)
            if bgr is None:
                return OcrResult(
                    available=False, status="error", provider=self.name, model_id=self.model_id,
                    error_code="IMAGE_DECODE_FAILED",
                )
            h, w = bgr.shape[:2]
            if max(h, w) > MAX_OCR_DIMENSION:
                scale = MAX_OCR_DIMENSION / float(max(h, w))
                new_w = min(MAX_OCR_DIMENSION, max(1, round(w * scale)))
                new_h = min(MAX_OCR_DIMENSION, max(1, round(h * scale)))
                bgr = cv2.resize(bgr, (new_w, new_h), interpolation=cv2.INTER_AREA)
            engine = self._get_engine()
            raw_out = engine(bgr)
        except FileNotFoundError:
            return OcrResult(
                available=False, status="unavailable", provider=self.name, model_id=self.model_id,
                latency_ms=int((time.perf_counter() - t0) * 1000),
                error_code="OCR_MODEL_CACHE_MISSING",
            )
        except Exception as exc:
            logger.warning("RapidOCR extraction failed (%s).", type(exc).__name__)
            return OcrResult(
                available=False, status="error", provider=self.name, model_id=self.model_id,
                latency_ms=int((time.perf_counter() - t0) * 1000),
                error_code=f"RAPIDOCR_{type(exc).__name__.upper()}",
            )

        latency_ms = int((time.perf_counter() - t0) * 1000)
        raw_boxes = getattr(raw_out, "boxes", None)
        raw_txts = getattr(raw_out, "txts", None)
        raw_scores = getattr(raw_out, "scores", None)

        if raw_txts is None or len(raw_txts) == 0:
            return OcrResult(
                available=True, status="empty", provider=self.name, model_id=self.model_id,
                latency_ms=latency_ms,
            )

        boxes: list[OcrBox] = []
        lines: list[str] = []
        confidences: list[float] = []

        count = len(raw_txts)
        for idx in range(count):
            text_val = str(raw_txts[idx]).strip()
            if not text_val:
                continue
            conf_val = float(raw_scores[idx]) if raw_scores is not None and idx < len(raw_scores) else 0.0
            conf_clamped = min(1.0, max(0.0, conf_val))
            if raw_boxes is not None and idx < len(raw_boxes):
                boxes.append(build_box_from_quad(raw_boxes[idx], text_val, conf_clamped))
            lines.append(text_val)
            confidences.append(conf_clamped)

        if not lines:
            return OcrResult(
                available=True,
                status="empty",
                provider=self.name,
                model_id=self.model_id,
                latency_ms=latency_ms,
            )

        mean_conf = round(float(sum(confidences) / len(confidences)), 4) if confidences else 0.0
        return OcrResult(
            available=True,
            status="ok",
            provider=self.name,
            model_id=self.model_id,
            full_text="\n".join(lines),
            boxes=boxes,
            mean_confidence=mean_conf,
            height_cv=compute_height_cv(boxes),
            latency_ms=latency_ms,
        )
