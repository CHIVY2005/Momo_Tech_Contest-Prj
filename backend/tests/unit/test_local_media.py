import io
import os
from typing import Any

import pytest
from PIL import Image, ImageDraw

from app.core.onnx_session import build_cpu_session_options
from app.services import local_ocr, local_stt
from app.services.local_ocr import run_local_ocr
from app.services.local_stt import run_local_stt


def test_onnx_session_options_disable_cpu_arena_and_mem_pattern() -> None:
    opts = build_cpu_session_options(intra_threads=4)
    assert opts.enable_cpu_mem_arena is False
    assert opts.enable_mem_pattern is False
    assert opts.intra_op_num_threads == 4
    assert opts.inter_op_num_threads == 1


def test_local_ocr_and_stt_deterministic_enabled_and_temp_cleanup(
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

    # Deterministic enabled STT check + temp file cleanup verification
    created_paths: list[str] = []

    class _Seg:
        def __init__(self, text: str) -> None:
            self.text = text

    class _FakeWhisper:
        def transcribe(self, path: str, **_kwargs: Any) -> tuple[list[_Seg], None]:
            created_paths.append(path)
            assert os.path.exists(path)
            return ([_Seg("Yêu cầu giữ bí mật cuộc gọi")], None)

    monkeypatch.setattr(local_stt, "_get_whisper_model", lambda: _FakeWhisper())
    stt_res = run_local_stt(b"RIFF\x24\x00\x00\x00WAVEfmt ", "call.wav", enabled=True)
    assert stt_res.available is True
    assert "giữ bí mật" in stt_res.transcript
    assert len(created_paths) == 1
    assert not os.path.exists(created_paths[0])
