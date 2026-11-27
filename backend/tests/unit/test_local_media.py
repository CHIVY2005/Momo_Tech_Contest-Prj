import io
import math
import struct
import tempfile
import wave
from typing import Any

import numpy as np
import pytest
from PIL import Image, ImageDraw

from app.core.onnx_session import build_cpu_session_options
from app.services import local_ocr, local_stt
from app.services.local_ocr import run_local_ocr
from app.services.local_stt import run_local_stt


def _make_valid_wav_bytes(duration_ms: int = 80, sample_rate: int = 16000) -> bytes:
    buf = io.BytesIO()
    n_samples = int(sample_rate * duration_ms / 1000)
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        frames = bytearray()
        for i in range(n_samples):
            sample = int(12000 * math.sin(2 * math.pi * 440 * i / sample_rate))
            frames.extend(struct.pack("<h", sample))
        wf.writeframes(bytes(frames))
    return buf.getvalue()


def test_onnx_session_options_disable_cpu_arena_and_mem_pattern() -> None:
    opts = build_cpu_session_options(intra_threads=4)
    assert opts.enable_cpu_mem_arena is False
    assert opts.enable_mem_pattern is False
    assert opts.intra_op_num_threads == 4
    assert opts.inter_op_num_threads == 1


def test_local_ocr_and_stt_deterministic_enabled_and_in_memory_decode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    img = Image.new("RGB", (320, 90), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((20, 30), "FT26330998877 500.000 VND", fill=(0, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    png_bytes = buf.getvalue()

    assert run_local_ocr(png_bytes, enabled=False).available is False
    disabled_stt = run_local_stt(b"ID3\x04\x00\x00\x00\x00\x00\x00test", "call.mp3", enabled=False)
    assert disabled_stt.available is False
    assert disabled_stt.status == "disabled"

    # Deterministic enabled OCR check via injected engine
    def _fake_rapid_ocr() -> Any:
        def _engine(_bytes: bytes) -> tuple[list[list[Any]], Any]:
            return (
                [
                    [[[10, 10], [120, 10], [120, 30], [10, 30]], "FT26330998877", 0.99],
                    [[[10, 40], [140, 40], [140, 60], [10, 60]], "500.000 VND", 0.98],
                ],
                None,
            )

        return _engine

    monkeypatch.setattr(local_ocr, "_get_rapid_ocr", _fake_rapid_ocr)
    ocr_res = run_local_ocr(png_bytes, enabled=True)
    assert ocr_res.available is True
    assert "FT26330998877" in ocr_res.full_text
    assert len(ocr_res.boxes) == 2

    # Deterministic enabled STT check: strictly in-memory np.float32 PCM, zero temp files
    received_inputs: list[Any] = []

    def _forbid_tempfile(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("run_local_stt must decode audio in memory without NamedTemporaryFile")

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", _forbid_tempfile)

    class _Seg:
        def __init__(self, text: str) -> None:
            self.text = text

    class _FakeWhisper:
        def transcribe(self, audio: Any, **_kwargs: Any) -> tuple[list[_Seg], None]:
            received_inputs.append(audio)
            assert isinstance(audio, np.ndarray)
            assert audio.ndim == 1
            assert audio.dtype == np.float32
            assert audio.size > 0
            assert float(np.max(np.abs(audio))) <= 1.0
            return ([_Seg("Yêu cầu giữ bí mật cuộc gọi")], None)

    monkeypatch.setattr(local_stt, "_get_whisper_model", lambda: _FakeWhisper())
    stt_res = run_local_stt(_make_valid_wav_bytes(), "../../evil.m3u8", enabled=True)
    assert stt_res.available is True
    assert stt_res.status == "ok"
    assert "giữ bí mật" in stt_res.transcript
    assert len(received_inputs) == 1
