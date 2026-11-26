"""Integration tests for multi-image/multi-audio upload, strict limits, PII scrubbing, and SSE."""

from __future__ import annotations

import io
import wave
from pathlib import Path

from fastapi.testclient import TestClient
from PIL import Image

from app.config import Settings
from app.main import create_app


def _make_png(color: tuple[int, int, int] = (230, 235, 240), size: tuple[int, int] = (220, 140)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color=color).save(buf, format="PNG")
    return buf.getvalue()


def _make_wav(duration_ms: int = 80) -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(8000)
        wf.writeframes(b"\x00\x00" * int(8000 * (duration_ms / 1000.0)))
    return buf.getvalue()


def _make_client(tmp_path: Path, max_upload_bytes: int = 10 * 1024 * 1024) -> TestClient:
    cfg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "mm_api.db"),
        gemini_api_key="",
        gemini_backup_api_key="",
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
        enable_local_ocr=False,
        enable_local_stt=False,
        max_upload_bytes=max_upload_bytes,
        rate_limit_per_minute=200,
    )
    return TestClient(create_app(cfg))


def test_multi_image_and_multi_audio_multipart_upload_and_health_metadata(tmp_path: Path) -> None:
    client = _make_client(tmp_path)

    health = client.get("/api/v1/health").json()
    assert "local_ocr_ready" in health
    assert "ocr_provider" in health

    resp = client.post(
        "/api/v1/analyze",
        data={"mode": "personal", "text": "Chuyển gấp vào STK 190384756201 SĐT 0912345678"},
        files=[
            ("images", ("shot1.png", _make_png((220, 220, 220)), "image/png")),
            ("images", ("shot2.png", _make_png((200, 210, 220)), "image/png")),
            ("audios", ("call1.wav", _make_wav(), "audio/wav")),
            ("audios", ("call2.wav", _make_wav(), "audio/wav")),
        ],
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["image_forensics"] is not None
    assert len(body["image_forensics_list"]) == 2
    # PII masked across report
    assert "190384756201" not in resp.text
    assert "0912345678" not in resp.text

    # SSE stream also accepts plural images
    sse = client.post(
        "/api/v1/analyze/stream",
        data={"mode": "personal", "text": "Kiểm tra nhiều ảnh qua SSE"},
        files=[
            ("images", ("a.png", _make_png((180, 190, 200)), "image/png")),
            ("images", ("b.png", _make_png((170, 180, 190)), "image/png")),
        ],
    )
    assert sse.status_code == 200
    assert "event: result" in sse.text


def test_multimodal_upload_rejects_excess_count_mime_spoof_dimension_bomb_and_total_cap(
    tmp_path: Path,
) -> None:
    client = _make_client(tmp_path)

    # 1. More than 4 images -> HTTP 400
    too_many_imgs = client.post(
        "/api/v1/analyze",
        data={"mode": "personal", "text": "test"},
        files=[("images", (f"i{i}.png", _make_png(), "image/png")) for i in range(5)],
    )
    assert too_many_imgs.status_code == 400

    # 2. More than 2 audio files -> HTTP 400
    too_many_auds = client.post(
        "/api/v1/analyze",
        data={"mode": "personal", "text": "test"},
        files=[("audios", (f"a{i}.wav", _make_wav(), "audio/wav")) for i in range(3)],
    )
    assert too_many_auds.status_code == 400

    # 3. MIME mismatch (SVG / HTML masquerading as image upload) -> HTTP 400
    svg_spoof = client.post(
        "/api/v1/analyze",
        data={"mode": "personal"},
        files=[("images", ("evil.svg", _make_png(), "image/svg+xml"))],
    )
    assert svg_spoof.status_code == 400

    html_spoof = client.post(
        "/api/v1/analyze",
        data={"mode": "personal"},
        files=[("images", ("evil.html", _make_png(), "text/html"))],
    )
    assert html_spoof.status_code == 400

    # 4. Excessive single dimension (> 10,000 px wide) -> HTTP 400
    huge_dim = _make_png(size=(10050, 8))
    dim_bomb = client.post(
        "/api/v1/analyze",
        data={"mode": "personal"},
        files=[("images", ("wide.png", huge_dim, "image/png"))],
    )
    assert dim_bomb.status_code == 400

    # 5. Total bytes across multiple valid files exceeding 2 * max_upload_bytes -> HTTP 413
    small_client = _make_client(tmp_path / "cap", max_upload_bytes=4096)
    uncompressed_buf = io.BytesIO()
    Image.new("RGB", (34, 32), color=(120, 160, 200)).save(
        uncompressed_buf, format="PNG", compress_level=0
    )
    img_3k = uncompressed_buf.getvalue()
    assert 2800 <= len(img_3k) <= 4096
    # 3 valid PNG files (~3.3 KB each -> ~10 KB > 2 * 4096 = 8192 bytes) -> 413
    total_cap = small_client.post(
        "/api/v1/analyze",
        data={"mode": "personal"},
        files=[("images", (f"f{i}.png", img_3k, "image/png")) for i in range(3)],
    )
    assert total_cap.status_code == 413
