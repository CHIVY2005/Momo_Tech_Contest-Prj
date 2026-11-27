"""Security unit tests for WP-9 (NV-34 media executors/downscaling & NV-39 LLM resilience)."""

from __future__ import annotations

import asyncio
import base64
import io
import math
import struct
import sys
import threading
import time
import types
import wave
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Any

import cv2
import httpx
import numpy as np
import pytest
import respx
from PIL import Image, ImageOps

from app.config import Settings
from app.core.media_executors import (
    BoundedExecutorPool,
    MediaExecutorBusyError,
    run_forensics_bounded,
    run_ocr_bounded,
    run_pdf_bounded,
    run_stt_bounded,
)
from app.services import image_forensics, llm_client, llm_resilience, local_stt
from app.services.llm_client import (
    _call_google_genai_key,
    _call_openai_key,
    execute_llm_call,
)
from app.services.llm_resilience import (
    reset_llm_circuit_breaker,
    should_failover_backup_key,
)
from app.services.ocr.base import OcrResult
from app.services.ocr.gemini_provider import extract_ocr_via_gemini
from app.services.ocr.rapidocr_provider import RapidOcrOnnxProvider
from app.services.ocr.service import OcrOrchestrator


@pytest.fixture(autouse=True)
def _reset_wp9_circuit_breaker() -> Any:
    reset_llm_circuit_breaker()
    yield
    reset_llm_circuit_breaker()


def _make_png(width: int = 120, height: int = 80) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (width, height), color=(235, 240, 245)).save(buf, format="PNG")
    return buf.getvalue()


def _make_wav_bytes(duration_ms: int = 40, sample_rate: int = 16000) -> bytes:
    buf = io.BytesIO()
    n_samples = int(sample_rate * duration_ms / 1000)
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        frames = bytearray()
        for i in range(n_samples):
            val = int(10000 * math.sin(2 * math.pi * 440 * i / sample_rate))
            frames.extend(struct.pack("<h", val))
        wf.writeframes(bytes(frames))
    return buf.getvalue()


def _ok_openai_response(score: int = 25, model: str = "wp9-test-model") -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "model": model,
            "choices": [
                {
                    "message": {
                        "content": f'{{"ai_risk_score": {score}, "summary_vi": "Ket qua kiem tra."}}'
                    }
                }
            ],
        },
    )


# ---------------------------------------------------------------------------
# NV-34: Dedicated Media Executors, Non-Detaching Semaphores, Chunking & Scaling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nv34_non_detaching_semaphore_holds_slot_and_preserves_default_executor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ex = ThreadPoolExecutor(max_workers=2, thread_name_prefix="wp9-test")
    pool = BoundedExecutorPool(ex, max_concurrency=1)
    started = threading.Event()
    release = threading.Event()

    def _blocking_job() -> str:
        started.set()
        release.wait(timeout=5.0)
        return "done"

    try:
        with pytest.raises(TimeoutError):
            await pool.run(_blocking_job, timeout_sec=0.05, acquire_timeout_sec=0.5)

        assert started.is_set()
        # Timed-out thread is still running, so the semaphore slot MUST remain held.
        with pytest.raises(MediaExecutorBusyError):
            await pool.run(lambda: "second", timeout_sec=1.0, acquire_timeout_sec=0.06)

        # Default asyncio executor MUST remain completely unstarved.
        default_res = await asyncio.wait_for(asyncio.to_thread(lambda: "default-ok"), timeout=0.5)
        assert default_res == "default-ok"
    finally:
        release.set()

    # Wait briefly for the done callback to release the slot back to the loop, then recover.
    await asyncio.sleep(0.05)
    recovered = await pool.run(lambda: "recovered", timeout_sec=1.0, acquire_timeout_sec=0.5)
    assert recovered == "recovered"

    # Verify _await_cf is a real coroutine safe when tests monkeypatch asyncio.wait_for + coro.close()
    orig_wait_for = asyncio.wait_for
    call_idx = 0

    async def _closing_wait_for(aw: Any, timeout: float | None = None) -> Any:
        nonlocal call_idx
        call_idx += 1
        if call_idx == 2:
            aw.close()
            raise TimeoutError
        return await orig_wait_for(aw, timeout=timeout)

    monkeypatch.setattr(asyncio, "wait_for", _closing_wait_for)
    with pytest.raises(TimeoutError):
        await pool.run(lambda: "fast", timeout_sec=0.1, acquire_timeout_sec=0.5)
    monkeypatch.setattr(asyncio, "wait_for", orig_wait_for)
    await asyncio.sleep(0.05)
    assert await pool.run(lambda: "after-close", timeout_sec=1.0, acquire_timeout_sec=0.5) == "after-close"

    # Submit-failure leak guard: if executor.submit raises, semaphore slot MUST be released
    fail_once = True
    orig_submit = ex.submit

    def _flaky_submit(fn: Any, /, *a: Any, **kw: Any) -> Any:
        nonlocal fail_once
        if fail_once:
            fail_once = False
            raise RuntimeError("submit failed")
        return orig_submit(fn, *a, **kw)

    monkeypatch.setattr(ex, "submit", _flaky_submit)
    with pytest.raises(RuntimeError, match="submit failed"):
        await pool.run(lambda: "never", timeout_sec=1.0, acquire_timeout_sec=0.5)
    assert await pool.run(lambda: "post-submit-err", timeout_sec=1.0, acquire_timeout_sec=0.5) == (
        "post-submit-err"
    )
    ex.shutdown(wait=True)


def test_nv34_closed_loop_done_callback_does_not_raise() -> None:
    slow_ex = ThreadPoolExecutor(max_workers=1, thread_name_prefix="wp9-closed-loop")
    slow_pool = BoundedExecutorPool(slow_ex, max_concurrency=1)
    done_ev = threading.Event()
    release_ev = threading.Event()

    def _late_finish() -> str:
        release_ev.wait(timeout=2.0)
        done_ev.set()
        return "late"

    temp_loop = asyncio.new_event_loop()
    try:
        with pytest.raises(TimeoutError):
            temp_loop.run_until_complete(
                slow_pool.run(_late_finish, timeout_sec=0.05, acquire_timeout_sec=0.5)
            )
    finally:
        temp_loop.close()
    release_ev.set()
    assert done_ev.wait(timeout=2.0)
    slow_ex.shutdown(wait=True)


@pytest.mark.asyncio
async def test_nv34_bounded_entrypoints_use_isolated_named_executors() -> None:
    def _thread_name() -> str:
        return threading.current_thread().name

    assert (await run_ocr_bounded(_thread_name)).startswith("vs-ocr")
    assert (await run_stt_bounded(_thread_name)).startswith("vs-stt")
    assert (await run_forensics_bounded(_thread_name)).startswith("vs-forensics")
    assert (await run_pdf_bounded(_thread_name)).startswith("vs-pdf")


@pytest.mark.asyncio
async def test_nv34_ocr_busy_skips_gemini_fallback_and_batch_chunks_without_starvation() -> None:
    started = threading.Event()
    release = threading.Event()

    class _BlockingOcrProvider:
        name = "blocking_ocr"
        model_id = "blk-1"
        license_name = "MIT"

        def is_available(self) -> bool:
            return True

        def extract(self, image_bytes: bytes, *, mime_type: str = "image/jpeg") -> OcrResult:
            _ = (image_bytes, mime_type)
            started.set()
            release.wait(timeout=5.0)
            return OcrResult(available=True, status="ok", provider=self.name, full_text="late")

    fb_calls = 0

    async def _fake_gemini(
        _settings: Settings, _img: bytes, _mime: str, _timeout: float
    ) -> OcrResult:
        nonlocal fb_calls
        fb_calls += 1
        return OcrResult(
            available=True,
            status="ok",
            provider="gemini_multimodal",
            model_id="gemini-2.5-flash",
            full_text="fallback-text",
            mean_confidence=0.9,
        )

    cfg = Settings(
        _env_file=None,
        gemini_api_key="wp9-test-key",
        ocr_timeout_sec=0.5,
        ocr_max_concurrency=1,
        enable_gemini_ocr_fallback=True,
    )
    orch = OcrOrchestrator(
        settings=cfg,
        primary_provider=_BlockingOcrProvider(),
        gemini_fallback_fn=_fake_gemini,
    )
    png = _make_png()
    try:
        # 1. Genuine OCR_TIMEOUT triggers Gemini fallback
        res1 = await orch.extract(png, mime_type="image/png")
        assert started.is_set()
        assert res1.status == "ok" and res1.provider == "gemini_multimodal"
        assert fb_calls == 1

        # 2. Saturated pool returns OCR_BUSY and MUST NOT burn Gemini fallback
        res2 = await orch.extract(png, mime_type="image/png")
        assert res2.available is False
        assert res2.status == "timeout"
        assert res2.error_code == "OCR_BUSY"
        assert fb_calls == 1
    finally:
        release.set()
    await asyncio.sleep(0.05)

    # 3. 4-image extract_batch chunks sequentially by ocr_max_concurrency=2 without self-starving
    lock = threading.Lock()
    completed = 0
    third_saw_completed = 0
    active = 0
    max_active = 0
    call_num = 0

    class _ChunkSpyProvider:
        name = "chunk_spy"
        model_id = "spy-1"
        license_name = "MIT"

        def is_available(self) -> bool:
            return True

        def extract(self, image_bytes: bytes, *, mime_type: str = "image/jpeg") -> OcrResult:
            nonlocal completed, third_saw_completed, active, max_active, call_num
            _ = (image_bytes, mime_type)
            with lock:
                call_num += 1
                idx = call_num
                if idx == 3:
                    third_saw_completed = completed
                active += 1
                max_active = max(max_active, active)
            try:
                time.sleep(0.06)
                return OcrResult(
                    available=True,
                    status="ok",
                    provider=self.name,
                    model_id=self.model_id,
                    full_text=f"img-{idx}",
                    mean_confidence=0.95,
                )
            finally:
                with lock:
                    active -= 1
                    completed += 1

    cfg_batch = Settings(
        _env_file=None,
        gemini_api_key="",
        ocr_timeout_sec=1.0,
        ocr_max_concurrency=2,
        enable_gemini_ocr_fallback=False,
    )
    orch_batch = OcrOrchestrator(settings=cfg_batch, primary_provider=_ChunkSpyProvider())
    batch = await orch_batch.extract_batch([(png, "image/png") for _ in range(4)])
    assert len(batch) == 4
    assert all(r.status == "ok" and r.error_code is None for r in batch)
    assert max_active <= 2
    assert third_saw_completed >= 2


def test_nv34_rapidocr_and_image_forensics_downscale_oversized_images_and_single_transpose(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    large_png = _make_png(width=3000, height=2400)

    # 1. RapidOcrOnnxProvider downscales >2048px before invoking engine(bgr)
    seen_ocr_shapes: list[tuple[int, ...]] = []

    def _fake_engine(bgr: np.ndarray[Any, Any]) -> Any:
        seen_ocr_shapes.append(tuple(bgr.shape))
        return SimpleNamespace(boxes=[], txts=[], scores=[])

    provider = RapidOcrOnnxProvider(allow_download=False)
    monkeypatch.setattr(provider, "_get_engine", lambda: _fake_engine)
    ocr_res = provider.extract(large_png, mime_type="image/png")
    assert ocr_res.available is True
    assert seen_ocr_shapes and max(seen_ocr_shapes[0][:2]) == 2048
    assert seen_ocr_shapes[0][:2] == (1638, 2048)

    # 2. analyze_image_forensics transposes EXIF ONCE and downscales QR <=2048 & ELA <=1600
    transpose_calls = 0
    orig_transpose = ImageOps.exif_transpose

    def _spy_transpose(img: Image.Image) -> Image.Image:
        nonlocal transpose_calls
        transpose_calls += 1
        return orig_transpose(img)

    seen_qr_shapes: list[tuple[int, ...]] = []
    orig_qr_bgr = image_forensics._decode_qr_from_bgr  # noqa: SLF001

    def _spy_qr_bgr(bgr: np.ndarray[Any, Any]) -> list[str]:
        seen_qr_shapes.append(tuple(bgr.shape))
        return orig_qr_bgr(bgr)

    seen_ela_sizes: list[tuple[int, int]] = []
    orig_ela = image_forensics._compute_ela_and_tamper_score  # noqa: SLF001

    def _spy_ela(rgb_img: Image.Image) -> tuple[int, str, list[str]]:
        seen_ela_sizes.append(rgb_img.size)
        return orig_ela(rgb_img)

    monkeypatch.setattr(ImageOps, "exif_transpose", _spy_transpose)
    monkeypatch.setattr(image_forensics, "_decode_qr_from_bgr", _spy_qr_bgr)
    monkeypatch.setattr(image_forensics, "_compute_ela_and_tamper_score", _spy_ela)

    fr = image_forensics.analyze_image_forensics(large_png, "big.png", enable_ocr=False)
    assert transpose_calls == 1
    assert fr.width == 3000 and fr.height == 2400
    assert len(fr.dhash_hex) == 16
    assert seen_qr_shapes and max(seen_qr_shapes[0][:2]) <= 2048
    assert seen_ela_sizes and max(seen_ela_sizes[0]) <= 1600

    # 3. Public decode_qr_codes also downscales >2048px before QRCodeDetector
    detector_shapes: list[tuple[int, ...]] = []

    class _SpyQrDetector:
        def detectAndDecodeMulti(self, img: np.ndarray[Any, Any]) -> tuple[bool, Any, Any, Any]:
            detector_shapes.append(tuple(img.shape))
            return False, None, None, None

        def detectAndDecode(self, img: np.ndarray[Any, Any]) -> tuple[str, Any, Any]:
            detector_shapes.append(tuple(img.shape))
            return "", None, None

    monkeypatch.setattr(cv2, "QRCodeDetector", _SpyQrDetector)
    assert image_forensics.decode_qr_codes(large_png) == []
    assert detector_shapes and all(max(s[:2]) <= 2048 for s in detector_shapes)


def test_nv34_local_stt_configures_whisper_with_two_cpu_threads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class _FakeWhisperModel:
        def __init__(self, model_size: str, **kwargs: Any) -> None:
            captured["model_size"] = model_size
            captured.update(kwargs)

    fake_mod = types.ModuleType("faster_whisper")
    fake_mod.WhisperModel = _FakeWhisperModel  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "faster_whisper", fake_mod)
    local_stt._get_whisper_model.cache_clear()  # noqa: SLF001
    try:
        local_stt._get_whisper_model("base")  # noqa: SLF001
    finally:
        local_stt._get_whisper_model.cache_clear()  # noqa: SLF001

    assert captured["cpu_threads"] == 2
    assert captured["device"] == "cpu"
    assert captured["compute_type"] == "int8"


# ---------------------------------------------------------------------------
# NV-39: Overall Deadline, Outer Timeout, Failover Policy, Memoization, Breaker & Cap
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nv39_outer_openai_timeout_and_overall_deadline_cap_slow_calls() -> None:
    endpoint = "https://wp9-timeout.test/v1/chat/completions"

    slow_entered = 0

    async def _slow_post(_req: httpx.Request) -> httpx.Response:
        nonlocal slow_entered
        slow_entered += 1
        await asyncio.sleep(2.0)
        return _ok_openai_response()

    # 1. Outer asyncio.timeout catches slow main post cleanly
    t0 = time.perf_counter()
    with respx.mock(assert_all_called=False) as router:
        router.post(endpoint).mock(side_effect=_slow_post)
        parsed, _, attempts, err = await _call_openai_key(
            endpoint=endpoint,
            api_key="k1",
            model_name="m1",
            prompt="test",
            timeout_sec=0.12,
            max_retries=0,
            image_bytes=None,
            image_mime="image/jpeg",
            audio_bytes=None,
            audio_mime="audio/wav",
        )
    assert slow_entered == 1
    assert parsed is None and err == "TIMEOUT" and attempts == 1
    assert (time.perf_counter() - t0) < 0.8

    # 2. Step-1 response_format compat post also enforces outer asyncio.timeout
    step1_calls = 0

    async def _compat1_slow(_req: httpx.Request) -> httpx.Response:
        nonlocal step1_calls
        step1_calls += 1
        if step1_calls == 1:
            return httpx.Response(400, json={"error": "no response_format"})
        await asyncio.sleep(2.0)
        return _ok_openai_response()

    with respx.mock(assert_all_called=True) as router:
        router.post(endpoint).mock(side_effect=_compat1_slow)
        _, _, attempts_c1, err_c1 = await _call_openai_key(
            endpoint=endpoint,
            api_key="k1",
            model_name="m1",
            prompt="test",
            timeout_sec=0.12,
            max_retries=0,
            image_bytes=None,
            image_mime="image/jpeg",
            audio_bytes=None,
            audio_mime="audio/wav",
        )
    assert err_c1 == "TIMEOUT" and attempts_c1 == 2

    # 3. Step-2 audio-drop compat post also enforces outer asyncio.timeout
    step2_calls = 0

    async def _compat2_slow(_req: httpx.Request) -> httpx.Response:
        nonlocal step2_calls
        step2_calls += 1
        if step2_calls <= 2:
            return httpx.Response(400, json={"error": "bad param"})
        await asyncio.sleep(2.0)
        return _ok_openai_response()

    with respx.mock(assert_all_called=True) as router:
        router.post(endpoint).mock(side_effect=_compat2_slow)
        _, _, attempts_c2, err_c2 = await _call_openai_key(
            endpoint=endpoint,
            api_key="k1",
            model_name="m1",
            prompt="test",
            timeout_sec=0.12,
            max_retries=0,
            image_bytes=None,
            image_mime="image/jpeg",
            audio_bytes=_make_wav_bytes(),
            audio_mime="audio/wav",
            has_non_audio_evidence=True,
        )
    assert err_c2 == "TIMEOUT" and attempts_c2 == 3

    # 4. Overall deadline bounds total retry loop duration even with max_retries=5
    slow_entered = 0
    loop = asyncio.get_running_loop()
    t_dl = time.perf_counter()
    with respx.mock(assert_all_called=False) as router:
        router.post(endpoint).mock(side_effect=_slow_post)
        _, _, attempts_dl, err_dl = await _call_openai_key(
            endpoint=endpoint,
            api_key="k1",
            model_name="m1",
            prompt="test",
            timeout_sec=0.2,
            max_retries=5,
            image_bytes=None,
            image_mime="image/jpeg",
            audio_bytes=None,
            audio_mime="audio/wav",
            deadline=loop.time() + 0.3,
        )
    assert slow_entered >= 1
    assert err_dl == "TIMEOUT"
    assert attempts_dl <= 2
    assert (time.perf_counter() - t_dl) < 0.8


@pytest.mark.asyncio
async def test_nv39_backup_failover_short_circuits_non_key_errors_and_fails_over_on_auth_quota() -> None:
    for allowed_code in ("HTTP_401", "HTTP_403", "HTTP_429", "CLIENT_INIT_RUNTIMEERROR"):
        assert should_failover_backup_key(allowed_code) is True

    for blocked_code in (
        "TIMEOUT",
        "NETWORK_TRANSPORT_ERROR",
        "HTTP_500",
        "HTTP_502",
        "HTTP_503",
        "HTTP_504",
        "HTTP_400",
        "HTTP_422",
        "SAFETY_BLOCKED",
        "UNSUPPORTED_AUDIO_INPUT",
        "INVALID_STRUCTURED_JSON",
        "EMPTY_COMPLETION_CONTENT",
        "HTTP_429_RETRY_AFTER_EXCEEDED",
        "HTTP_503_RETRY_AFTER_EXCEEDED",
    ):
        assert should_failover_backup_key(blocked_code) is False

    base_url = "https://wp9-failover.test/v1"
    endpoint = f"{base_url}/chat/completions"
    cfg = Settings(
        _env_file=None,
        llm_provider="openai_compatible",
        gemini_base_url=base_url,
        gemini_model="wp9-model",
        gemini_api_key="primary_key",
        gemini_backup_api_key="backup_key",
        llm_timeout_sec=2.0,
        llm_max_retries=0,
    )

    # Non-key errors (503, TIMEOUT, 400, INVALID_STRUCTURED_JSON) MUST NOT call backup key
    for label, response_factory, expected_err in (
        ("503", lambda _r: httpx.Response(503, json={"error": "down"}), "HTTP_503"),
        ("400", lambda _r: httpx.Response(400, json={"error": "bad"}), "HTTP_400"),
        (
            "bad_json",
            lambda _r: httpx.Response(
                200, json={"choices": [{"message": {"content": "not-json-at-all"}}]}
            ),
            "INVALID_STRUCTURED_JSON",
        ),
    ):
        reset_llm_circuit_breaker()
        seen_keys: list[str] = []

        def _handler(
            req: httpx.Request,
            rf: Any = response_factory,
            sk: list[str] = seen_keys,
        ) -> httpx.Response:
            sk.append(req.headers.get("authorization", ""))
            return rf(req)

        with respx.mock(assert_all_called=True) as router:
            router.post(endpoint).mock(side_effect=_handler)
            out = await execute_llm_call(settings=cfg, prompt=f"case-{label}")
        assert out.parsed is None and out.error_code == expected_err
        assert "Bearer backup_key" not in seen_keys

    # TIMEOUT also short-circuits backup key
    reset_llm_circuit_breaker()
    seen_timeout_keys: list[str] = []

    def _timeout_handler(req: httpx.Request) -> httpx.Response:
        seen_timeout_keys.append(req.headers.get("authorization", ""))
        raise httpx.ReadTimeout("timed out")

    with respx.mock(assert_all_called=True) as router:
        router.post(endpoint).mock(side_effect=_timeout_handler)
        out_to = await execute_llm_call(settings=cfg, prompt="case-timeout")
    assert out_to.error_code == "TIMEOUT"
    assert seen_timeout_keys == ["Bearer primary_key"]

    # 401 and 429 MUST fail over to backup key and succeed
    for status_code in (401, 429):
        reset_llm_circuit_breaker()
        seen_auth: list[str] = []

        def _auth_failover(
            req: httpx.Request,
            sc: int = status_code,
            sa: list[str] = seen_auth,
        ) -> httpx.Response:
            auth = req.headers.get("authorization", "")
            sa.append(auth)
            if auth == "Bearer primary_key":
                return httpx.Response(sc, json={"error": "key issue"})
            return _ok_openai_response(score=33)

        with respx.mock(assert_all_called=True) as router:
            router.post(endpoint).mock(side_effect=_auth_failover)
            out_ok = await execute_llm_call(settings=cfg, prompt=f"failover-{status_code}")
        assert out_ok.parsed is not None and out_ok.parsed.ai_risk_score == 33
        assert out_ok.used_backup_key is True
        assert seen_auth == ["Bearer primary_key", "Bearer backup_key"]


@pytest.mark.asyncio
async def test_nv39_base64_encoded_once_across_compat_and_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint = "https://wp9-b64.test/v1/chat/completions"
    b64_calls = 0
    orig_b64encode = base64.b64encode

    def _spy_b64encode(data: bytes) -> bytes:
        nonlocal b64_calls
        b64_calls += 1
        return orig_b64encode(data)

    monkeypatch.setattr(llm_client.base64, "b64encode", _spy_b64encode)

    http_calls = 0

    def _compat_then_retry(_req: httpx.Request) -> httpx.Response:
        nonlocal http_calls
        http_calls += 1
        if http_calls <= 2:
            return httpx.Response(400, json={"error": "drop response_format then audio"})
        if http_calls == 3:
            return httpx.Response(503, headers={"Retry-After": "0"}, json={"error": "busy"})
        return _ok_openai_response(score=44)

    with respx.mock(assert_all_called=True) as router:
        router.post(endpoint).mock(side_effect=_compat_then_retry)
        parsed, _, attempts, err = await _call_openai_key(
            endpoint=endpoint,
            api_key="k1",
            model_name="m1",
            prompt="check media",
            timeout_sec=5.0,
            max_retries=2,
            image_bytes=_make_png(),
            image_mime="image/png",
            audio_bytes=_make_wav_bytes(),
            audio_mime="audio/wav",
            has_non_audio_evidence=True,
        )

    assert err is None and parsed is not None and parsed.ai_risk_score == 44
    assert http_calls == 4 and attempts == 4
    # Exactly 1 encode for image + 1 encode for audio across all 4 HTTP posts!
    assert b64_calls == 2


@pytest.mark.asyncio
async def test_nv39_invalid_structured_json_retries_capped_at_one_for_both_providers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint = "https://wp9-json-cap.test/v1/chat/completions"
    monkeypatch.setattr(llm_client, "jittered_retry_delay", lambda *_a, **_kw: 0.01)

    openai_calls = 0

    def _bad_json(_req: httpx.Request) -> httpx.Response:
        nonlocal openai_calls
        openai_calls += 1
        return httpx.Response(200, json={"choices": [{"message": {"content": "{not valid json"}}]})

    with respx.mock(assert_all_called=True) as router:
        router.post(endpoint).mock(side_effect=_bad_json)
        parsed_o, _, attempts_o, err_o = await _call_openai_key(
            endpoint=endpoint,
            api_key="k1",
            model_name="m1",
            prompt="test",
            timeout_sec=5.0,
            max_retries=4,
            image_bytes=None,
            image_mime="image/jpeg",
            audio_bytes=None,
            audio_mime="audio/wav",
        )
    assert parsed_o is None and err_o == "INVALID_STRUCTURED_JSON"
    assert openai_calls == 2 and attempts_o == 2

    google_calls = 0

    class _BadJsonModels:
        async def generate_content(self, *, model: str, contents: Any, config: Any) -> Any:
            nonlocal google_calls
            _ = (contents, config)
            google_calls += 1
            return SimpleNamespace(
                model_version=model,
                prompt_feedback=None,
                candidates=[],
                parsed={"ai_risk_score": 999, "summary_vi": "out of range"},
                text="",
            )

    class _FakeGenClient:
        def __init__(self, api_key: str) -> None:
            _ = api_key
            self.aio = SimpleNamespace(models=_BadJsonModels(), aclose=self._aclose)

        async def _aclose(self) -> None:
            return None

    monkeypatch.setattr("app.services.llm_client.genai.Client", _FakeGenClient)
    parsed_g, _, attempts_g, err_g = await _call_google_genai_key(
        api_key="g1",
        model_name="gemini-2.5-flash",
        prompt="test",
        timeout_sec=5.0,
        max_retries=4,
        image_bytes=None,
        image_mime="image/jpeg",
        audio_bytes=None,
        audio_mime="audio/wav",
    )
    assert parsed_g is None and err_g == "INVALID_STRUCTURED_JSON"
    assert google_calls == 2 and attempts_g == 2


@pytest.mark.asyncio
async def test_nv39_circuit_breaker_opens_blocks_llm_and_gemini_ocr_and_recovers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base_url = "https://wp9-breaker.test/v1"
    endpoint = f"{base_url}/chat/completions"
    cfg = Settings(
        _env_file=None,
        llm_provider="openai_compatible",
        gemini_base_url=base_url,
        gemini_model="wp9-model",
        gemini_api_key="k1",
        llm_timeout_sec=2.0,
        llm_max_retries=0,
    )

    clock = [1000.0]
    monkeypatch.setattr(llm_resilience.time, "monotonic", lambda: clock[0])

    # 5 consecutive 503 outages trip the per-endpoint breaker
    calls = 0

    def _fail_503(_req: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, json={"error": "outage"})

    with respx.mock(assert_all_called=True) as router:
        router.post(endpoint).mock(side_effect=_fail_503)
        for _ in range(5):
            out = await execute_llm_call(settings=cfg, prompt="trip")
            assert out.error_code == "HTTP_503"
    assert calls == 5

    # 6th LLM call and Gemini OCR call MUST fast-fail without hitting upstream
    with respx.mock(assert_all_called=False) as router:
        route = router.post(endpoint).mock(return_value=_ok_openai_response())
        blocked_llm = await execute_llm_call(settings=cfg, prompt="blocked")
        blocked_ocr = await extract_ocr_via_gemini(cfg, _make_png(), timeout_sec=1.0)
        assert route.call_count == 0
    assert blocked_llm.error_code == "CIRCUIT_BREAKER_OPEN"
    assert blocked_ocr.available is False and blocked_ocr.error_code == "CIRCUIT_BREAKER_OPEN"

    # After 20s cooldown, allow exactly 1 half-open probe while concurrent 2nd call is rejected
    clock[0] += 21.0
    probe_started = asyncio.Event()
    probe_release = asyncio.Event()
    probe_count = 0

    async def _probe_handler(_req: httpx.Request) -> httpx.Response:
        nonlocal probe_count
        probe_count += 1
        probe_started.set()
        await probe_release.wait()
        return _ok_openai_response(score=18)

    with respx.mock(assert_all_called=True) as router:
        router.post(endpoint).mock(side_effect=_probe_handler)
        task_probe = asyncio.create_task(execute_llm_call(settings=cfg, prompt="probe"))
        await asyncio.wait_for(probe_started.wait(), timeout=1.0)

        concurrent_out = await execute_llm_call(settings=cfg, prompt="concurrent-blocked")
        assert concurrent_out.error_code == "CIRCUIT_BREAKER_OPEN"

        probe_release.set()
        probe_out = await task_probe
    assert probe_count == 1
    assert probe_out.parsed is not None and probe_out.parsed.ai_risk_score == 18

    # Breaker is now closed again
    with respx.mock(assert_all_called=True) as router:
        router.post(endpoint).mock(return_value=_ok_openai_response(score=11))
        after_out = await execute_llm_call(settings=cfg, prompt="recovered")
    assert after_out.parsed is not None and after_out.parsed.ai_risk_score == 11


@pytest.mark.asyncio
async def test_nv39_concurrency_cap_and_gemini_ocr_outer_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base_url = "https://wp9-conc.test/v1"
    endpoint = f"{base_url}/chat/completions"
    cfg = Settings(
        _env_file=None,
        llm_provider="openai_compatible",
        gemini_base_url=base_url,
        gemini_model="wp9-model",
        gemini_api_key="k1",
        llm_timeout_sec=2.0,
        llm_max_retries=0,
    )

    monkeypatch.setattr(llm_resilience, "MAX_CONCURRENT_LLM_CALLS", 2)
    monkeypatch.setattr(llm_resilience, "LLM_SEMAPHORE_ACQUIRE_TIMEOUT_SEC", 0.08)

    entered = 0
    both_entered = asyncio.Event()
    release_calls = asyncio.Event()

    async def _gated_ok(_req: httpx.Request) -> httpx.Response:
        nonlocal entered
        entered += 1
        if entered >= 2:
            both_entered.set()
        await release_calls.wait()
        return _ok_openai_response(score=15)

    with respx.mock(assert_all_called=True) as router:
        router.post(endpoint).mock(side_effect=_gated_ok)
        t1 = asyncio.create_task(execute_llm_call(settings=cfg, prompt="c1"))
        t2 = asyncio.create_task(execute_llm_call(settings=cfg, prompt="c2"))
        await asyncio.wait_for(both_entered.wait(), timeout=1.0)

        limited = await execute_llm_call(settings=cfg, prompt="c3-overflow")
        assert limited.parsed is None and limited.error_code == "LLM_CONCURRENCY_LIMITED"

        release_calls.set()
        r1, r2 = await asyncio.gather(t1, t2)
    assert r1.parsed is not None and r2.parsed is not None

    # After active calls complete, semaphore slots are released cleanly
    with respx.mock(assert_all_called=True) as router:
        router.post(endpoint).mock(return_value=_ok_openai_response(score=9))
        after = await execute_llm_call(settings=cfg, prompt="c4-ok")
    assert after.parsed is not None and after.parsed.ai_risk_score == 9

    # ocr/gemini_provider enforces outer asyncio.timeout on slow OpenAI post
    ocr_base = "https://wp9-ocr-slow.test/v1"
    ocr_cfg = cfg.model_copy(update={"gemini_base_url": ocr_base})

    ocr_slow_entered = 0

    async def _slow_ocr(_req: httpx.Request) -> httpx.Response:
        nonlocal ocr_slow_entered
        ocr_slow_entered += 1
        await asyncio.sleep(2.0)
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"text":"ok"}'}}]})

    t_ocr = time.perf_counter()
    with respx.mock(assert_all_called=False) as router:
        router.post(f"{ocr_base}/chat/completions").mock(side_effect=_slow_ocr)
        ocr_timeout = await extract_ocr_via_gemini(ocr_cfg, _make_png(), timeout_sec=0.12)
    assert ocr_slow_entered == 1
    assert ocr_timeout.available is False
    assert ocr_timeout.status == "timeout"
    assert ocr_timeout.error_code == "GEMINI_OCR_TIMEOUT"
    assert (time.perf_counter() - t_ocr) < 0.8

    # Jittered backoff, Retry-After cap, remaining-deadline clamping, and arbitrary HTTP_5xx outage check
    assert llm_resilience.is_endpoint_outage_error("HTTP_524") is True
    assert llm_resilience.is_endpoint_outage_error("HTTP_503_RETRY_AFTER_EXCEEDED") is True
    assert llm_resilience.is_endpoint_outage_error("HTTP_429") is False
    assert llm_resilience.jittered_retry_delay(0, 9.0, 20.0) is None
    assert llm_resilience.jittered_retry_delay(0, 2.0, 1.5) is None
    assert llm_resilience.jittered_retry_delay(0, None, 0.1) is None
    ra_delay = llm_resilience.jittered_retry_delay(0, 1.0, 5.0)
    assert ra_delay is not None and 1.01 <= ra_delay <= 1.25
    exp_clamped = llm_resilience.jittered_retry_delay(3, None, 0.5)
    assert exp_clamped is not None and 0.01 <= exp_clamped <= 0.35


@pytest.mark.asyncio
async def test_wp9_polish_google_ocr_503_breaker_client_init_and_ocr_concurrency_clamp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 1. Google GenAI OCR 503 trips & keeps breaker open; aclose error never fails valid OCR
    cfg_g = Settings(
        _env_file=None,
        llm_provider="google_genai",
        gemini_base_url="",
        gemini_model="gemini-2.5-flash",
        gemini_api_key="google_ocr_key_test",
    )
    clock = [2000.0]
    monkeypatch.setattr(llm_resilience.time, "monotonic", lambda: clock[0])

    class _FakeServer503(Exception):
        code = 503

    mode = ["fail_503"]
    gen_calls = 0

    class _FakeModels:
        async def generate_content(self, **_kwargs: Any) -> Any:
            nonlocal gen_calls
            gen_calls += 1
            if mode[0] == "fail_503":
                raise _FakeServer503("upstream 503")
            return SimpleNamespace(
                prompt_feedback=None,
                candidates=[],
                parsed={"text": "STK 190399998888", "confidence": 0.91},
                text="",
            )

    class _FakeGoogleClient:
        def __init__(self, *, api_key: str) -> None:
            _ = api_key
            self.aio = SimpleNamespace(models=_FakeModels(), aclose=self._aclose)

        async def _aclose(self) -> None:
            if mode[0] == "ok_aclose_boom":
                raise RuntimeError("aclose cleanup error")

    monkeypatch.setattr("app.services.ocr.gemini_provider.genai.Client", _FakeGoogleClient)
    png = _make_png()

    for _ in range(5):
        r = await extract_ocr_via_gemini(cfg_g, png, timeout_sec=1.0)
        assert r.available is False and r.error_code == "HTTP_503"
    assert gen_calls == 5

    # 6th call blocked immediately by open breaker
    blocked = await extract_ocr_via_gemini(cfg_g, png, timeout_sec=1.0)
    assert blocked.available is False and blocked.error_code == "CIRCUIT_BREAKER_OPEN"
    assert gen_calls == 5

    # Half-open probe hitting 503 MUST extend open breaker (NOT close it!)
    clock[0] += 21.0
    probe_503 = await extract_ocr_via_gemini(cfg_g, png, timeout_sec=1.0)
    assert probe_503.error_code == "HTTP_503"
    assert gen_calls == 6
    still_open = await extract_ocr_via_gemini(cfg_g, png, timeout_sec=1.0)
    assert still_open.error_code == "CIRCUIT_BREAKER_OPEN"
    assert gen_calls == 6

    # Half-open probe succeeding even when aclose() raises MUST return ok and close breaker
    clock[0] += 21.0
    mode[0] = "ok_aclose_boom"
    recovered = await extract_ocr_via_gemini(cfg_g, png, timeout_sec=1.0)
    assert recovered.available is True
    assert recovered.status == "ok"
    assert recovered.full_text == "STK 190399998888"
    assert gen_calls == 7

    # 2. CLIENT_INIT_* releases half-open probe WITHOUT closing breaker or clearing failure_times
    reset_llm_circuit_breaker()
    ep = "google_genai"
    for _ in range(5):
        llm_resilience.circuit_record_outcome(ep, "HTTP_503", now=3000.0)
    assert llm_resilience.circuit_try_acquire(ep, now=3005.0) == (False, False)
    assert llm_resilience.circuit_try_acquire(ep, now=3025.0) == (True, True)
    llm_resilience.circuit_record_outcome(
        ep, "CLIENT_INIT_VALUEERROR", is_half_open_probe=True, now=3025.0
    )
    # Must STILL be half-open (not closed): next call gets probe slot and blocks concurrent caller
    assert llm_resilience.circuit_try_acquire(ep, now=3026.0) == (True, True)
    assert llm_resilience.circuit_try_acquire(ep, now=3026.0) == (False, False)
    llm_resilience.circuit_release_probe(ep)

    # On a closed breaker, CLIENT_INIT_* must not wipe accumulated outage failures
    ep2 = "https://client-init-closed.test/v1/chat/completions"
    for idx in range(4):
        llm_resilience.circuit_record_outcome(ep2, "HTTP_503", now=4000.0 + idx)
    llm_resilience.circuit_record_outcome(ep2, "CLIENT_INIT_RUNTIMEERROR", now=4004.0)
    llm_resilience.circuit_record_outcome(ep2, "HTTP_503", now=4005.0)
    assert llm_resilience.circuit_try_acquire(ep2, now=4006.0) == (False, False)

    # 3. OcrOrchestrator clamps OCR_MAX_CONCURRENCY=4 down to OCR_EXECUTOR worker cap (2)
    lock = threading.Lock()
    active = 0
    max_active = 0
    completed = 0
    third_saw_completed = 0
    call_idx = 0

    class _ClampSpyProvider:
        name = "clamp_spy"
        model_id = "spy-2"
        license_name = "MIT"

        def is_available(self) -> bool:
            return True

        def extract(self, image_bytes: bytes, *, mime_type: str = "image/jpeg") -> OcrResult:
            nonlocal active, max_active, completed, third_saw_completed, call_idx
            _ = (image_bytes, mime_type)
            with lock:
                call_idx += 1
                if call_idx == 3:
                    third_saw_completed = completed
                active += 1
                max_active = max(max_active, active)
            try:
                time.sleep(0.05)
                return OcrResult(available=True, status="ok", provider=self.name, full_text="ok")
            finally:
                with lock:
                    active -= 1
                    completed += 1

    cfg_clamp = Settings(
        _env_file=None,
        gemini_api_key="",
        ocr_timeout_sec=1.0,
        ocr_max_concurrency=4,
        enable_gemini_ocr_fallback=False,
    )
    orch_clamp = OcrOrchestrator(settings=cfg_clamp, primary_provider=_ClampSpyProvider())
    assert orch_clamp._max_conc == 2  # noqa: SLF001
    assert orch_clamp._pool._max_concurrency == 2  # noqa: SLF001
    batch_res = await orch_clamp.extract_batch([(png, "image/png") for _ in range(4)])
    assert len(batch_res) == 4 and all(r.status == "ok" for r in batch_res)
    assert max_active <= 2
    assert third_saw_completed >= 2

