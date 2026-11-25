import io

from PIL import Image, ImageDraw

from app.core.onnx_session import build_cpu_session_options
from app.services.local_ocr import run_local_ocr
from app.services.local_stt import run_local_stt


def test_onnx_session_options_disable_cpu_arena_and_mem_pattern() -> None:
    opts = build_cpu_session_options(intra_threads=4)
    assert opts.enable_cpu_mem_arena is False
    assert opts.enable_mem_pattern is False
    assert opts.intra_op_num_threads == 4
    assert opts.inter_op_num_threads == 1


def test_local_ocr_and_stt_graceful_disabled_and_synthetic_ocr() -> None:
    img = Image.new("RGB", (320, 90), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((20, 30), "FT26330998877 500.000 VND", fill=(0, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    png_bytes = buf.getvalue()

    disabled_ocr = run_local_ocr(png_bytes, enabled=False)
    assert disabled_ocr.available is False

    live_ocr = run_local_ocr(png_bytes, enabled=True)
    assert isinstance(live_ocr.full_text, str)
    if live_ocr.available:
        assert len(live_ocr.boxes) >= 1

    disabled_stt = run_local_stt(b"ID3\x04\x00\x00\x00\x00\x00\x00test", "call.mp3", enabled=False)
    assert disabled_stt.available is False
