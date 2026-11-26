"""Local INT8 Vietnamese speech-to-text fallback using faster-whisper."""

from __future__ import annotations

import contextlib
import os
import tempfile
import time
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class LocalSttResult(BaseModel):
    """Result from local CPU speech transcription."""

    available: bool
    transcript: str = ""
    latency_ms: int = Field(default=0, ge=0)


def _configured_whisper_model() -> str:
    return os.getenv("VERISHIELD_WHISPER_MODEL", "base").strip() or "base"


def is_local_stt_ready(enabled: bool = True) -> bool:
    """Return True only when local STT is enabled AND Whisper weights exist locally on disk."""
    if not enabled:
        return False
    try:
        from faster_whisper import download_model

        cache_dir = os.getenv("HF_HUB_CACHE") or None
        model_path = download_model(
            _configured_whisper_model(),
            local_files_only=True,
            cache_dir=cache_dir,
        )
        return bool(model_path and Path(model_path).exists())
    except Exception:
        return False


@lru_cache(maxsize=1)
def _get_whisper_model(model_size: str | None = None) -> Any:
    from faster_whisper import WhisperModel

    resolved_size = model_size or _configured_whisper_model()
    local_only = os.getenv("VERISHIELD_ALLOW_WHISPER_DOWNLOAD", "0") != "1"
    download_root = os.getenv("HF_HUB_CACHE") or None
    return WhisperModel(
        resolved_size,
        device="cpu",
        compute_type="int8",
        cpu_threads=4,
        download_root=download_root,
        local_files_only=local_only,
    )


def run_local_stt(
    audio_bytes: bytes,
    filename: str,
    enabled: bool = True,
) -> LocalSttResult:
    """Transcribe Vietnamese call audio locally when model cache is available."""
    if not enabled or not audio_bytes:
        return LocalSttResult(available=False)

    t0 = time.perf_counter()
    suffix = Path(filename).suffix or ".mp3"
    tmp_path: str | None = None
    try:
        model = _get_whisper_model()
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp_path = tmp.name
            tmp.write(audio_bytes)

        segments, _ = model.transcribe(
            tmp_path,
            language="vi",
            beam_size=1,
            vad_filter=True,
        )
        text = " ".join(seg.text.strip() for seg in segments if seg.text.strip()).strip()
        latency_ms = int((time.perf_counter() - t0) * 1000)
        return LocalSttResult(available=True, transcript=text, latency_ms=latency_ms)
    except Exception:
        return LocalSttResult(available=False)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            with contextlib.suppress(OSError):
                os.remove(tmp_path)
