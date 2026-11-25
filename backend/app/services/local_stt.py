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


@lru_cache(maxsize=1)
def _get_whisper_model(model_size: str = "base") -> Any:
    from faster_whisper import WhisperModel

    local_only = os.getenv("VERISHIELD_ALLOW_WHISPER_DOWNLOAD", "0") != "1"
    return WhisperModel(
        model_size,
        device="cpu",
        compute_type="int8",
        cpu_threads=4,
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
            tmp.write(audio_bytes)
            tmp_path = tmp.name

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
