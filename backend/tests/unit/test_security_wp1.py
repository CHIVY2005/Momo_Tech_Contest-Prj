"""Comprehensive unit tests for WP-1 security remediations (NV-01, NV-03, NV-05, NV-06, NV-24)."""

from __future__ import annotations

import base64
import io
import json
import math
import struct
import tempfile
import wave
from types import SimpleNamespace
from typing import Any

import av
import av.audio.frame
import httpx
import numpy as np
import pytest
import respx
from PIL import Image

from app.config import Settings
from app.core import media_security, security
from app.core.security import (
    InvalidMediaError,
    _parse_url_authority,
    async_validate_url_target,
    decode_audio_to_pcm16k,
    detect_audio_format,
    detect_canonical_image_mime,
    normalize_image_for_downstream,
    validate_upload_bytes,
    validate_url_target,
)
from app.core.url_authority import extract_strict_ascii_host
from app.services import local_stt
from app.services.llm_client import (
    _build_openai_user_content,
    _call_google_genai_key,
    _call_openai_key,
)
from app.services.local_stt import run_local_stt
from app.services.ocr.gemini_provider import extract_ocr_via_gemini
from app.services.ocr.rapidocr_provider import RapidOcrOnnxProvider
from app.services.url_inspector import inspect_url


def _make_wav(
    duration_ms: int = 80,
    sample_rate: int = 16000,
    channels: int = 1,
) -> bytes:
    buf = io.BytesIO()
    n_samples = int(sample_rate * duration_ms / 1000)
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(channels)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        frames = bytearray()
        for i in range(n_samples):
            val = int(10000 * math.sin(2 * math.pi * 440 * i / sample_rate))
            for _ in range(channels):
                frames.extend(struct.pack("<h", val))
        wf.writeframes(bytes(frames))
    return buf.getvalue()


def _make_pyav_audio(fmt: str, codec: str, rate: int = 16000) -> bytes:
    buf = io.BytesIO()
    with av.open(buf, mode="w", format=fmt) as container:
        stream = container.add_stream(codec, rate=rate)
        frame = av.AudioFrame.from_ndarray(
            np.zeros((1, 1024), dtype=np.int16),
            format="s16",
            layout="mono",
        )
        frame.sample_rate = rate
        for pkt in stream.encode(frame):
            container.mux(pkt)
        for pkt in stream.encode(None):
            container.mux(pkt)
    return buf.getvalue()


def _make_mp4_with_video_and_audio() -> bytes:
    buf = io.BytesIO()
    with av.open(buf, mode="w", format="mp4") as container:
        vstream = container.add_stream("mpeg4", rate=24)
        vstream.width = 32
        vstream.height = 32
        vstream.pix_fmt = "yuv420p"
        astream = container.add_stream("aac", rate=16000)

        vframe = av.VideoFrame.from_ndarray(np.zeros((32, 32, 3), dtype=np.uint8), format="rgb24")
        for pkt in vstream.encode(vframe):
            container.mux(pkt)
        for pkt in vstream.encode(None):
            container.mux(pkt)

        aframe = av.AudioFrame.from_ndarray(
            np.zeros((1, 1024), dtype=np.int16), format="s16", layout="mono"
        )
        aframe.sample_rate = 16000
        for pkt in astream.encode(aframe):
            container.mux(pkt)
        for pkt in astream.encode(None):
            container.mux(pkt)
    return buf.getvalue()


def _make_image_bytes(fmt: str, size: tuple[int, int] = (32, 24)) -> bytes:
    buf = io.BytesIO()
    img = Image.new("RGB", size, color=(20, 80, 160))
    img.save(buf, format=fmt)
    return buf.getvalue()


def _make_animated_bytes(fmt: str) -> bytes:
    buf = io.BytesIO()
    f1 = Image.new("RGB", (16, 16), color=(255, 0, 0))
    f2 = Image.new("RGB", (16, 16), color=(0, 255, 0))
    f1.save(buf, format=fmt, save_all=True, append_images=[f2], duration=50, loop=0)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# NV-01: IDNA post-normalization SSRF, backslash, multi-dot, LDH, public IPv6
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nv01_blocks_idna_fullwidth_multidot_non_ldh_and_backslash_urls() -> None:
    blocked_urls = [
        "http://\uff4c\uff4f\uff43\uff41\uff4c\uff48\uff4f\uff53\uff54/",  # fullwidth localhost
        "http://\uff11\uff12\uff17\uff0e\uff10\uff0e\uff10\uff0e\uff11/",  # fullwidth 127.0.0.1
        "http://\uff10\uff58\uff17\uff46\uff0e\uff11/",  # fullwidth 0x7f.1
        "http://\uff11\uff12\uff17\uff0e\uff11/",  # fullwidth 127.1
        "http://foo\u3002local/path",
        "http://foo\u3002localhost/path",
        "http://foo\u3002internal/path",
        "http://localhost\u3002/",
        "http://127\u30020\u30020\u30021/",
        "http://127.0.0.1../",
        "http://example.com../",
        "http://example.com\u3002\u3002/",
        "http://example.com\u3002./",
        "http://bad_host.example/",
        "http://-bad.example/",
        "http://vietcombank.com.vn\\@evil.top/",
        "https://evil.top\\@vietcombank.com.vn/",
        "https:\\\\vietcombank.com.vn/",
        "http://[::1]/",
        "http://[fe80::1]/",
        "http://[::ffff:8.8.8.8]/",
    ]
    for bad in blocked_urls:
        ok, reason, _ = validate_url_target(bad, resolve_dns=False)
        assert ok is False and reason is not None, f"Sync failed to block {bad!r}"
        a_ok, a_reason, _ = await async_validate_url_target(bad, resolve_dns=False)
        assert a_ok is False and a_reason is not None, f"Async failed to block {bad!r}"


@pytest.mark.asyncio
async def test_nv01_preserves_public_ipv6_single_trailing_dot_and_valid_idn() -> None:
    ok_v6, reason_v6, ips_v6 = validate_url_target(
        "http://[2606:4700:4700::1111]/dns-query",
        resolve_dns=False,
    )
    assert ok_v6 is True and reason_v6 is None
    assert ips_v6 == ["2606:4700:4700::1111"]

    ok_fqdn, reason_fqdn, _ = await async_validate_url_target(
        "https://vietcombank.com.vn./",
        resolve_dns=False,
    )
    assert ok_fqdn is True and reason_fqdn is None

    ok_idn, reason_idn, _ = validate_url_target(
        "https://bìnhan.example/info",
        resolve_dns=False,
    )
    assert ok_idn is True and reason_idn is None


# ---------------------------------------------------------------------------
# NV-05: url_inspector backslash & strict authority enforcement
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nv05_url_inspector_backslash_never_matches_official_and_preserves_reason() -> None:
    for spoof_url in (
        "https://vietcombank.com.vn\\@evil.top/login",
        "https://evil.top\\@vietcombank.com.vn/login",
        "https:\\\\vietcombank.com.vn/login",
    ):
        finding = await inspect_url(spoof_url, enable_network=False)
        assert finding.risk_points == 90
        assert finding.is_blocked_ssrf is True
        assert any("gạch chéo ngược" in r.lower() for r in finding.reasons), finding.reasons
        assert all("mạng nội bộ" not in r.lower() for r in finding.reasons), finding.reasons

    # Userinfo and double-trailing-dot official lookalikes must never score 0
    for sneaky in (
        "https://evil.top@vietcombank.com.vn/login",
        "https://vietcombank.com.vn../login",
    ):
        finding = await inspect_url(sneaky, enable_network=False)
        assert finding.is_blocked_ssrf is True
        assert finding.risk_points >= 90

    # Legitimate official domain (including canonical single FQDN dot) stays SAFE
    legit = await inspect_url("https://vietcombank.com.vn./vi-VN", enable_network=False)
    assert legit.is_blocked_ssrf is False
    assert legit.risk_points == 0


@pytest.mark.asyncio
async def test_nv05_url_inspector_redirect_to_backslash_preserves_specific_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _allow_first(
        target: str,
        resolve_dns: bool = True,
        timeout_sec: float = 2.5,
    ) -> tuple[bool, str | None, list[str]]:
        if target == "https://short.example/go":
            return True, None, ["93.184.216.34"]
        return await async_validate_url_target(target, resolve_dns=False, timeout_sec=timeout_sec)

    monkeypatch.setattr("app.services.url_inspector.async_validate_url_target", _allow_first)

    def _handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302,
            headers={"Location": "https://vietcombank.com.vn\\@evil.top/phish"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(_handler)) as mock_client:
        res = await inspect_url("https://short.example/go", enable_network=True, client=mock_client)
    assert res.is_blocked_ssrf is True
    assert res.risk_points == 90
    assert any("gạch chéo ngược" in r.lower() for r in res.reasons)


# ---------------------------------------------------------------------------
# NV-03: Audio magic allowlist, playlist/video rejection, multi-channel caps
# ---------------------------------------------------------------------------


def test_nv03_security_reexports_and_audio_magic_allowlist() -> None:
    assert security.validate_upload_bytes is media_security.validate_upload_bytes
    assert security.detect_audio_format is media_security.detect_audio_format
    assert security.decode_audio_to_pcm16k is media_security.decode_audio_to_pcm16k
    assert security.normalize_image_for_downstream is media_security.normalize_image_for_downstream

    wav_b = _make_wav()
    ogg_b = _make_pyav_audio("ogg", "libopus", rate=48000)
    flac_b = _make_pyav_audio("flac", "flac", rate=16000)
    m4a_b = _make_pyav_audio("ipod", "aac", rate=16000)
    webm_b = _make_pyav_audio("webm", "libopus", rate=48000)

    assert detect_audio_format(wav_b) == ("wav", "audio/wav")
    assert detect_audio_format(ogg_b) == ("ogg", "audio/ogg")
    assert detect_audio_format(flac_b) == ("flac", "audio/flac")
    assert detect_audio_format(m4a_b) == ("mp4", "audio/mp4")
    assert detect_audio_format(webm_b) == ("matroska", "audio/webm")
    # Valid raw MPEG-1 Layer III frame sync (0xFF 0xFB 0x90 0x00)
    assert detect_audio_format(b"\xff\xfb\x90\x00" + b"\x00" * 16) == ("mp3", "audio/mpeg")
    # JPEG must NOT match MP3 frame sync
    assert detect_audio_format(_make_image_bytes("JPEG")) is None

    for raw_b, mime in (
        (wav_b, "audio/wav"),
        (ogg_b, "audio/ogg"),
        (flac_b, "audio/flac"),
        (flac_b, "audio/x-flac"),
        (m4a_b, "audio/m4a"),
        (webm_b, "audio/webm"),
    ):
        validate_upload_bytes(raw_b, max_bytes=1024 * 1024, kind="audio", declared_mime=mime)
        pcm = decode_audio_to_pcm16k(raw_b)
        assert isinstance(pcm, np.ndarray)
        assert pcm.ndim == 1 and pcm.dtype == np.float32 and pcm.size > 0
        assert float(np.max(np.abs(pcm))) <= 1.0


def test_nv03_blocks_playlists_ffconcat_sdp_video_streams_and_channel_sample_bombs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hostile_payloads = [
        b"#EXTM3U\n#EXT-X-VERSION:3\n#EXTINF:10.0,\nfile:///etc/passwd\n",
        b"ffconcat version 1.0\nfile '/etc/passwd'\n",
        b"v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=probe\r\nc=IN IP4 169.254.169.254\r\n",
        b"XXXXftypisom\x00\x00\x02\x00isom",
    ]
    for payload in hostile_payloads:
        assert detect_audio_format(payload) is None
        with pytest.raises(InvalidMediaError):
            validate_upload_bytes(payload, max_bytes=1024 * 1024, kind="audio")
        with pytest.raises(InvalidMediaError):
            decode_audio_to_pcm16k(payload)

    # MP4 containing a non-attached_pic video track + audio track must be rejected
    mp4_video = _make_mp4_with_video_and_audio()
    with pytest.raises(InvalidMediaError, match="Video streams"):
        validate_upload_bytes(mp4_video, max_bytes=1024 * 1024, kind="audio")

    # Channel count > MAX_AUDIO_CHANNELS blocked
    wav_10ch = _make_wav(duration_ms=20, sample_rate=8000, channels=10)
    with pytest.raises(InvalidMediaError, match="channel"):
        validate_upload_bytes(wav_10ch, max_bytes=1024 * 1024, kind="audio")

    # Multi-channel sample budget cap: 4 channels * 400 samples = 1600 > 500 * 2 = 1000
    wav_4ch = _make_wav(duration_ms=50, sample_rate=8000, channels=4)
    monkeypatch.setattr(media_security, "MAX_DECODED_AUDIO_SAMPLES", 500)
    with pytest.raises(InvalidMediaError, match="budget"):
        validate_upload_bytes(wav_4ch, max_bytes=1024 * 1024, kind="audio")


def test_p0_audio_sample_rate_duration_and_resampled_pcm16k_oom_guards(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 10 Hz WAV (1600x resampling amplification bomb) must be rejected on both upload & decode
    wav_10hz = _make_wav(duration_ms=2000, sample_rate=10, channels=1)
    with pytest.raises(InvalidMediaError, match="sample rate"):
        validate_upload_bytes(wav_10hz, max_bytes=1024 * 1024, kind="audio")
    with pytest.raises(InvalidMediaError, match="sample rate"):
        decode_audio_to_pcm16k(wav_10hz)

    # Above MAX_AUDIO_SAMPLE_RATE (192 kHz) is also rejected
    wav_384khz = _make_wav(duration_ms=2, sample_rate=384_000, channels=1)
    with pytest.raises(InvalidMediaError, match="sample rate"):
        validate_upload_bytes(wav_384khz, max_bytes=1024 * 1024, kind="audio")

    # Duration cap blocks long low-rate (8 kHz) streams even under raw sample budget
    wav_8khz_100ms = _make_wav(duration_ms=100, sample_rate=8000, channels=1)
    monkeypatch.setattr(media_security, "MAX_AUDIO_DURATION_SEC", 0.05)
    with pytest.raises(InvalidMediaError, match="budget"):
        validate_upload_bytes(wav_8khz_100ms, max_bytes=1024 * 1024, kind="audio")
    monkeypatch.undo()

    # Resampled 16 kHz PCM sample cap aborts before allocating unbounded chunks
    monkeypatch.setattr(media_security, "MAX_RESAMPLED_PCM16K_SAMPLES", 500)
    with pytest.raises(InvalidMediaError, match="PCM budget"):
        decode_audio_to_pcm16k(wav_8khz_100ms)


@pytest.mark.asyncio
async def test_p1_url_authority_rejects_control_chars_whitespace_and_invisible_chars() -> None:
    malicious_urls = [
        "https://evil.top\t.vietcombank.com.vn/login",
        "https://vietcombank.com.vn /login",
        "https://vietcombank.com.vn\u200b/",
        "https://vietcombank.com.vn\ufeff/login",
        "https://evil.top\r\n.vietcombank.com.vn/login",
    ]
    for bad in malicious_urls:
        assert extract_strict_ascii_host(bad) is None, f"extract_strict_ascii_host accepted {bad!r}"
        ok, reason, _, _, _ = _parse_url_authority(bad)
        assert ok is False and reason is not None, f"_parse_url_authority accepted {bad!r}"
        finding = await inspect_url(bad, enable_network=False)
        assert finding.is_blocked_ssrf is True
        assert finding.risk_points >= 90

    ok_ws, reason_ws, _, _, _ = _parse_url_authority("https://vietcombank.com.vn /login")
    assert ok_ws is False
    assert reason_ws == "Whitespace in hostname is disallowed"


# ---------------------------------------------------------------------------
# NV-06: MIME bypass, animated images, polyglot/EXIF strip, RapidOCR & LLM
# ---------------------------------------------------------------------------


def test_nv06_mime_bypass_animated_rejection_and_image_normalization() -> None:
    png_b = _make_image_bytes("PNG")
    gif_b = _make_image_bytes("GIF")
    webp_b = _make_image_bytes("WEBP")

    # Malformed/empty declared MIME parameters must be rejected
    for bad_mime in ("; image/jpeg", "   ", "", "image/svg+xml", "text/html; charset=utf-8"):
        with pytest.raises(InvalidMediaError):
            validate_upload_bytes(png_b, max_bytes=1024 * 1024, kind="image", declared_mime=bad_mime)
    with pytest.raises(InvalidMediaError):
        validate_upload_bytes(_make_wav(), max_bytes=1024 * 1024, kind="audio", declared_mime="; audio/wav")

    # Single-frame GIF & WebP are allowed
    validate_upload_bytes(gif_b, max_bytes=1024 * 1024, kind="image", declared_mime="image/gif")
    validate_upload_bytes(webp_b, max_bytes=1024 * 1024, kind="image", declared_mime="image/webp")
    assert detect_canonical_image_mime(gif_b) == "image/gif"
    assert detect_canonical_image_mime(webp_b) == "image/webp"

    # Animated GIF, WebP, APNG are rejected
    for anim_fmt in ("GIF", "WEBP", "PNG"):
        anim_bytes = _make_animated_bytes(anim_fmt)
        with pytest.raises(InvalidMediaError, match="Animated"):
            validate_upload_bytes(anim_bytes, max_bytes=1024 * 1024, kind="image")
        with pytest.raises(InvalidMediaError, match="Animated"):
            normalize_image_for_downstream(anim_bytes)

    # JPEG with EXIF Orientation=6 (rotate 90 CW) + Artist PII + polyglot tail
    base = Image.new("RGB", (40, 20), color=(10, 200, 30))
    exif = base.getexif()
    exif[0x0112] = 6  # Rotate 90 CW -> 20x40 after exif_transpose
    exif[0x013B] = "SECRET_ARTIST_PII"
    jbuf = io.BytesIO()
    base.save(jbuf, format="JPEG", exif=exif.tobytes())
    polyglot_jpeg = jbuf.getvalue() + b"POLYGLOT_HTML_<script>alert(1)</script>"

    clean_jpeg, clean_mime = normalize_image_for_downstream(polyglot_jpeg)
    assert clean_mime == "image/jpeg"
    assert b"SECRET_ARTIST_PII" not in clean_jpeg
    assert b"POLYGLOT_HTML" not in clean_jpeg
    with Image.open(io.BytesIO(clean_jpeg)) as check_img:
        assert check_img.size == (20, 40)  # Transposed!
        assert len(check_img.getexif()) == 0

    # Non-JPEG (single-frame GIF) normalizes cleanly to PNG
    clean_from_gif, gif_norm_mime = normalize_image_for_downstream(gif_b)
    assert gif_norm_mime == "image/png"
    assert clean_from_gif.startswith(b"\x89PNG\r\n\x1a\n")


def test_nv06_rapidocr_pillow_fallback_decodes_single_frame_gif(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gif_b = _make_image_bytes("GIF", size=(48, 24))
    captured_shapes: list[tuple[int, ...]] = []

    def _fake_engine(bgr: Any) -> Any:
        captured_shapes.append(tuple(bgr.shape))
        return SimpleNamespace(
            boxes=[[[2, 2], [40, 2], [40, 20], [2, 20]]],
            txts=["GIF OCR OK"],
            scores=[0.97],
        )

    provider = RapidOcrOnnxProvider(allow_download=False)
    monkeypatch.setattr(provider, "_get_engine", lambda: _fake_engine)
    # Force cv2.imdecode to return None (simulating GIF/unsupported OpenCV codec)
    monkeypatch.setattr("app.services.ocr.rapidocr_provider.cv2.imdecode", lambda *_a, **_kw: None)

    res = provider.extract(gif_b, mime_type="image/gif")
    assert res.available is True
    assert res.status == "ok"
    assert res.full_text == "GIF OCR OK"
    assert captured_shapes == [(24, 48, 3)]


@pytest.mark.asyncio
async def test_nv06_gemini_ocr_and_llm_client_canonicalize_images_and_audio(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    png_polyglot = _make_image_bytes("PNG") + b"POLYGLOT_TAIL_SECRET"
    wav_b = _make_wav()
    flac_b = _make_pyav_audio("flac", "flac", rate=16000)

    # 1. Gemini OCR OpenAI-compatible path: strips polyglot tail & enforces canonical MIME
    cfg_cpa = Settings(
        _env_file=None,
        llm_provider="openai_compatible",
        gemini_base_url="https://cpa.example/v1",
        gemini_model="gemini-2.5-flash",
        gemini_api_key="test_key",
    )
    seen_ocr_url: list[str] = []

    def _ocr_handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content.decode("utf-8"))
        img_url = body["messages"][1]["content"][1]["image_url"]["url"]
        seen_ocr_url.append(img_url)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"text": "OK", "confidence": 0.9}'}}]},
        )

    with respx.mock(assert_all_called=True) as router:
        router.post("https://cpa.example/v1/chat/completions").mock(side_effect=_ocr_handler)
        ocr_res = await extract_ocr_via_gemini(
            cfg_cpa,
            png_polyglot,
            image_mime="image/svg+xml",  # Spoofed MIME must be ignored!
        )
    assert ocr_res.status == "ok"
    assert seen_ocr_url[0].startswith("data:image/png;base64,")
    decoded_sent = base64.b64decode(seen_ocr_url[0].split(",", 1)[1])
    assert b"POLYGLOT_TAIL_SECRET" not in decoded_sent

    # Invalid/animated image fails closed before network call in Gemini OCR
    bad_ocr = await extract_ocr_via_gemini(cfg_cpa, _make_animated_bytes("GIF"), image_mime="image/gif")
    assert bad_ocr.available is False and bad_ocr.error_code == "INVALID_IMAGE_MEDIA"

    # 1b. Gemini OCR Google GenAI path also canonicalizes image bytes & MIME
    cfg_google = Settings(
        _env_file=None,
        llm_provider="google_genai",
        gemini_base_url="",
        gemini_model="gemini-2.5-flash",
        gemini_api_key="test_google_key",
    )
    ocr_google_parts: list[Any] = []

    class _FakeOcrModels:
        async def generate_content(self, *, model: str, contents: Any, config: Any) -> Any:
            _ = (model, config)
            ocr_google_parts.extend(contents)
            return SimpleNamespace(
                prompt_feedback=None,
                candidates=[],
                parsed={"text": "GOOGLE OCR OK", "confidence": 0.94},
                text="",
            )

    class _FakeOcrClient:
        def __init__(self, api_key: str) -> None:
            _ = api_key
            self.aio = SimpleNamespace(models=_FakeOcrModels(), aclose=self._aclose)

        async def _aclose(self) -> None:
            return None

    monkeypatch.setattr("app.services.ocr.gemini_provider.genai.Client", _FakeOcrClient)
    google_ocr = await extract_ocr_via_gemini(
        cfg_google,
        png_polyglot,
        image_mime="image/jpeg",  # Spoofed MIME ignored!
    )
    assert google_ocr.status == "ok" and google_ocr.full_text == "GOOGLE OCR OK"
    assert ocr_google_parts[0].inline_data.mime_type == "image/png"
    assert b"POLYGLOT_TAIL_SECRET" not in ocr_google_parts[0].inline_data.data

    # 2. llm_client._build_openai_user_content canonicalizes image + audio (never octet-stream)
    parts = _build_openai_user_content(
        prompt="check",
        image_bytes=png_polyglot,
        image_mime="image/jpeg",  # Wrong declared MIME
        audio_bytes=flac_b,
        audio_mime="application/octet-stream",  # Must NOT produce format="octet-stream"
    )
    assert isinstance(parts, list)
    img_part = next(p for p in parts if p["type"] == "image_url")
    aud_part = next(p for p in parts if p["type"] == "input_audio")
    assert img_part["image_url"]["url"].startswith("data:image/png;base64,")
    assert b"POLYGLOT_TAIL_SECRET" not in base64.b64decode(img_part["image_url"]["url"].split(",", 1)[1])
    assert aud_part["input_audio"]["format"] == "flac"

    # Unrecognized playlist audio is dropped cleanly (never format="octet-stream")
    parts_bad_aud = _build_openai_user_content(
        prompt="check",
        image_bytes=None,
        image_mime="image/jpeg",
        audio_bytes=b"#EXTM3U\nfile:///etc/passwd\n",
        audio_mime="application/octet-stream",
    )
    assert parts_bad_aud == "check"

    # 3. _call_openai_key & _call_google_genai_key send magic-derived canonical MIME
    captured_google_parts: list[Any] = []

    class _FakeModels:
        async def generate_content(self, *, model: str, contents: Any, config: Any) -> Any:
            _ = (model, config)
            captured_google_parts.extend(contents)
            return SimpleNamespace(
                model_version="gemini-2.5-flash",
                prompt_feedback=None,
                candidates=[],
                parsed={"ai_risk_score": 15, "summary_vi": "Bình thường."},
                text="",
            )

    class _FakeClient:
        def __init__(self, api_key: str) -> None:
            _ = api_key
            self.aio = SimpleNamespace(models=_FakeModels(), aclose=self._aclose)

        async def _aclose(self) -> None:
            return None

    monkeypatch.setattr("app.services.llm_client.genai.Client", _FakeClient)
    parsed_g, _, _, err_g = await _call_google_genai_key(
        api_key="test_g",
        model_name="gemini-2.5-flash",
        prompt="test",
        timeout_sec=5.0,
        max_retries=0,
        image_bytes=png_polyglot,
        image_mime="application/octet-stream",
        audio_bytes=wav_b,
        audio_mime="application/octet-stream",
    )
    assert err_g is None and parsed_g is not None
    inline_mimes = [
        p.inline_data.mime_type
        for p in captured_google_parts
        if hasattr(p, "inline_data") and p.inline_data is not None
    ]
    assert inline_mimes == ["image/png", "audio/wav"]
    inline_blobs = [
        p.inline_data.data
        for p in captured_google_parts
        if hasattr(p, "inline_data") and p.inline_data is not None
    ]
    assert b"POLYGLOT_TAIL_SECRET" not in inline_blobs[0]

    # Verify _call_openai_key also emits canonical format="wav" for octet-stream audio
    seen_openai_payloads: list[dict[str, Any]] = []

    def _openai_handler(req: httpx.Request) -> httpx.Response:
        seen_openai_payloads.append(json.loads(req.content.decode("utf-8")))
        return httpx.Response(
            200,
            json={
                "model": "gemini-2.5-flash",
                "choices": [{"message": {"content": '{"ai_risk_score": 20, "summary_vi": "OK"}'}}],
            },
        )

    with respx.mock(assert_all_called=True) as router:
        router.post("https://cpa.example/v1/chat/completions").mock(side_effect=_openai_handler)
        parsed_o, _, _, err_o = await _call_openai_key(
            endpoint="https://cpa.example/v1/chat/completions",
            api_key="test_k",
            model_name="gemini-2.5-flash",
            prompt="test",
            timeout_sec=5.0,
            max_retries=0,
            image_bytes=None,
            image_mime="image/jpeg",
            audio_bytes=wav_b,
            audio_mime="application/octet-stream",
        )
    assert err_o is None and parsed_o is not None
    user_parts = seen_openai_payloads[0]["messages"][1]["content"]
    assert user_parts[1]["input_audio"]["format"] == "wav"


# ---------------------------------------------------------------------------
# NV-24: LocalSttResult explicit status + zero tempfile in-memory decoding
# ---------------------------------------------------------------------------


def test_nv24_local_stt_status_distinctions_and_zero_tempfiles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _forbid_tmp(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("NamedTemporaryFile must never be used in run_local_stt")

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", _forbid_tmp)

    # 1. disabled
    res_disabled = run_local_stt(_make_wav(), "call.wav", enabled=False)
    assert res_disabled.available is False and res_disabled.status == "disabled"

    # 2. empty bytes when enabled -> error
    res_empty_bytes = run_local_stt(b"", "call.wav", enabled=True)
    assert res_empty_bytes.available is False and res_empty_bytes.status == "error"

    # 3. unavailable (model load failure)
    def _boom_model() -> Any:
        raise RuntimeError("Whisper cache missing")

    monkeypatch.setattr(local_stt, "_get_whisper_model", _boom_model)
    res_unavail = run_local_stt(_make_wav(), "call.wav", enabled=True)
    assert res_unavail.available is False and res_unavail.status == "unavailable"

    # 4. error on corrupt / playlist audio (never crashes, never touches disk)
    class _EmptyWhisper:
        def transcribe(self, audio: Any, **_kwargs: Any) -> tuple[list[Any], None]:
            assert isinstance(audio, np.ndarray) and audio.dtype == np.float32
            return ([], None)

    monkeypatch.setattr(local_stt, "_get_whisper_model", lambda: _EmptyWhisper())
    res_bad_audio = run_local_stt(b"#EXTM3U\nfile:///etc/passwd\n", "evil.m3u8", enabled=True)
    assert res_bad_audio.available is False and res_bad_audio.status == "error"

    # 5. empty transcript (model ran successfully, detected silence)
    res_silent = run_local_stt(_make_wav(), "silence.wav", enabled=True)
    assert res_silent.available is True and res_silent.status == "empty" and res_silent.transcript == ""

    # 6. transcribe runtime exception -> error
    class _FailingWhisper:
        def transcribe(self, _audio: Any, **_kwargs: Any) -> Any:
            raise ValueError("decoder failure")

    monkeypatch.setattr(local_stt, "_get_whisper_model", lambda: _FailingWhisper())
    res_err = run_local_stt(_make_wav(), "call.wav", enabled=True)
    assert res_err.available is False and res_err.status == "error"
