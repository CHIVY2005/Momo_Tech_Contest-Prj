"""Integration & security tests for Task 10: Phase-3 local-only ephemeral evidence & explicit persist."""

from __future__ import annotations

import io
import json
import sqlite3
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from fastapi.testclient import TestClient
from PIL import Image

from app.config import Settings
from app.main import create_app
from app.schemas import ActionBundle, AnalysisReport, ExtractedIOCs, PreTransferIntervention
from app.services.ai_orchestrator import run_gemini_reasoning
from app.services.assistant_evidence import EphemeralEvidenceStage
from app.services.guardrails import evaluate_guardrails
from app.services.image_forensics import compute_dhash_hex
from app.services.ocr.base import OcrResult
from app.services.ocr.service import OcrOrchestrator
from app.services.pipeline import EphemeralAnalysisBundle


def _parse_sse(raw_stream: str) -> list[tuple[str, dict[str, Any]]]:
    events: list[tuple[str, dict[str, Any]]] = []
    for block in raw_stream.split("\n\n"):
        ev_type = ""
        ev_data = ""
        for line in block.splitlines():
            if line.startswith("event:"):
                ev_type = line.split(":", 1)[1].strip()
            elif line.startswith("data:"):
                ev_data = line.split(":", 1)[1].strip()
        if ev_type and ev_data:
            events.append((ev_type, json.loads(ev_data)))
    return events


def _make_large_valid_png(min_bytes: int = 300_000) -> bytes:
    """Create a valid high-entropy PNG strictly larger than 256 KB and well below 10 MB."""
    rng = np.random.default_rng(20261127)
    side = 420
    while True:
        arr = rng.integers(0, 256, size=(side, side, 3), dtype=np.uint8)
        img = Image.fromarray(arr, mode="RGB")
        buf = io.BytesIO()
        img.save(buf, format="PNG", compress_level=1)
        data = buf.getvalue()
        if len(data) >= min_bytes:
            return data
        side += 80


def _make_small_valid_png(seed: int = 42) -> bytes:
    rng = np.random.default_rng(seed)
    arr = rng.integers(0, 256, size=(120, 120, 3), dtype=np.uint8)
    img = Image.fromarray(arr, mode="RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _table_counts(sqlite_path: str) -> dict[str, int]:
    tables = ("cases", "ioc_sightings", "ioc_edges", "campaigns", "receipt_hashes")
    conn = sqlite3.connect(sqlite_path)
    try:
        return {
            tbl: int(conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0])  # noqa: S608
            for tbl in tables
        }
    finally:
        conn.close()


def _make_app_client(
    tmp_path: Path,
    *,
    gemini_api_key: str = "AIzaSyntheticTestKeyForLocalGuardCheck0001",
    enable_gemini_ocr_fallback: bool = True,
    max_upload_bytes: int = 10_485_760,
) -> tuple[Any, TestClient, str]:
    db_path = str(tmp_path / "evidence_test.db")
    cfg = Settings(
        _env_file=None,
        sqlite_path=db_path,
        gemini_api_key=gemini_api_key,
        gemini_backup_api_key="",
        enable_gemini_ocr_fallback=enable_gemini_ocr_fallback,
        enable_local_ocr=True,
        enable_local_stt=False,
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
        telegram_bot_token="",
        app_env="demo",
        analyst_pin="2026",
        max_upload_bytes=max_upload_bytes,
        rate_limit_per_minute=200,
        assistant_rate_limit_per_minute=200,
        assistant_rate_limit_per_hour=500,
    )
    app = create_app(cfg)
    return app, TestClient(app), db_path


def _create_parent_case(
    client: TestClient,
    *,
    mode: str = "personal",
    demo_id: str | None = None,
    text: str = "Cán bộ công an yêu cầu chuyển 20 triệu vào tài khoản 888777666555",
) -> tuple[str, str]:
    form_data: dict[str, str] = {"mode": mode}
    if demo_id:
        form_data["demo_id"] = demo_id
    else:
        form_data["text"] = text
    res = client.post("/api/v1/analyze", data=form_data)
    assert res.status_code == 200
    token = res.headers.get("x-case-access-token")
    assert token
    return str(res.json()["case_id"]), token


class _FailingLocalOcrProvider:
    name = "stub_failing_local"
    model_id = "stub"

    def is_available(self) -> bool:
        return True

    def extract(self, image_bytes: bytes, *, mime_type: str = "image/png") -> OcrResult:
        _ = (image_bytes, mime_type)
        return OcrResult(
            available=False,
            status="error",
            provider=self.name,
            model_id=self.model_id,
            error_code="STUB_LOCAL_ERROR",
        )


@pytest.mark.asyncio
async def test_local_only_guards_skip_gemini_ocr_fallback_and_llm_completely(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "guard.db"),
        gemini_api_key="AIzaSyntheticKeyForLocalGuard0002",
        enable_gemini_ocr_fallback=True,
        enable_local_ocr=True,
    )

    fallback_calls = 0

    async def _boom_ocr_fallback(
        _settings: Settings, _img: bytes, _mime: str, _timeout: float
    ) -> OcrResult:
        nonlocal fallback_calls
        fallback_calls += 1
        return OcrResult(available=True, status="ok", provider="gemini_ocr", full_text="SHOULD_NOT_RUN")

    orch = OcrOrchestrator(
        settings=cfg,
        primary_provider=_FailingLocalOcrProvider(),
        gemini_fallback_fn=_boom_ocr_fallback,
    )
    png = _make_small_valid_png(1)
    res_local = await orch.extract_batch(
        [(png, "image/png")],
        allow_gemini_fallback=False,
        allow_empty_fallback=True,
    )
    assert len(res_local) == 1
    assert res_local[0].status == "error"
    assert fallback_calls == 0

    # Verify run_gemini_reasoning(..., local_only=True) skips ALL external LLM calls
    llm_exec_calls = 0
    override_calls = 0

    async def _boom_exec(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal llm_exec_calls
        llm_exec_calls += 1
        raise AssertionError("execute_llm_call must not run when local_only=True")

    async def _boom_override(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal override_calls
        override_calls += 1
        raise AssertionError("_generate_override must not run when local_only=True")

    monkeypatch.setattr("app.services.ai_orchestrator.execute_llm_call", _boom_exec)
    out = await run_gemini_reasoning(
        settings=cfg,
        text="Biên lai chuyển khoản giả mạo",
        mode="merchant",
        guardrails=evaluate_guardrails("Biên lai chuyển khoản giả mạo"),
        classifier=None,
        iocs=ExtractedIOCs(),
        url_findings=[],
        vietqr_findings=[],
        image_forensics=None,
        receipt_logic=None,
        matched_playbooks=[],
        image_bytes=png,
        local_only=True,
        _generate_override=_boom_override,
    )
    assert out.degraded_mode is True
    assert out.llm_error == "LOCAL_ONLY_PRIVACY_MODE"
    assert llm_exec_calls == 0
    assert override_calls == 0


def test_ephemeral_stage_lru_ttl_parent_binding_and_atomic_single_use() -> None:
    now = [1000.0]
    stage = EphemeralEvidenceStage(max_entries=2, ttl_seconds=900.0, clock=lambda: now[0])

    def _dummy_bundle(cid: str) -> EphemeralAnalysisBundle:
        rep = AnalysisReport(
            case_id=cid,
            created_at="2026-11-27T07:00:00Z",
            mode="personal",
            risk_score=75,
            verdict="HIGH_RISK",
            confidence=0.85,
            summary_vi="Cảnh báo rủi ro cao.",
            actions=ActionBundle(
                urgent_steps=["Dừng chuyển tiền."],
                pre_transfer=PreTransferIntervention(should_hold_transfer=True),
            ),
        )
        return EphemeralAnalysisBundle(
            live_report=rep,
            staged_redacted_report=rep,
            prehashed_iocs=[],
            replay_fingerprints=[],
        )

    d1 = stage.stage(
        parent_case_id="vs_parent_1",
        parent_is_demo=False,
        bundle=_dummy_bundle("vs_tmp_1"),
        allow_external_media_ai=False,
    )
    d2 = stage.stage(
        parent_case_id="vs_parent_2",
        parent_is_demo=True,
        bundle=_dummy_bundle("vs_tmp_2"),
        allow_external_media_ai=False,
    )
    # Wrong parent must return None WITHOUT deleting d2
    assert stage.pop_for_parent(d2.draft_id, "vs_wrong_parent") is None
    # Adding d3 evicts LRU d1
    d3 = stage.stage(
        parent_case_id="vs_parent_3",
        parent_is_demo=False,
        bundle=_dummy_bundle("vs_tmp_3"),
        allow_external_media_ai=False,
    )
    assert stage.pop_for_parent(d1.draft_id, "vs_parent_1") is None
    # Single-use pop succeeds once, then returns None
    popped = stage.pop_for_parent(d2.draft_id, "vs_parent_2")
    assert popped is not None and popped.draft_id == d2.draft_id
    assert stage.pop_for_parent(d2.draft_id, "vs_parent_2") is None
    # Expiry removes d3 after 901s
    now[0] += 901.0
    assert stage.pop_for_parent(d3.draft_id, "vs_parent_3") is None


def test_evidence_stream_allows_gt_256kb_png_blocks_oversize_and_corrupt_and_keeps_json_256kb_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, client, db_path = _make_app_client(tmp_path)
    monkeypatch.setattr(
        "app.services.ai_orchestrator.execute_llm_call",
        lambda *_a, **_kw: (_ for _ in ()).throw(AssertionError("No Gemini API allowed")),
    )
    parent_id, parent_token = _create_parent_case(client, mode="personal")

    # 1. > 256 KB valid PNG passes middleware and returns HTTP 200 SSE
    big_png = _make_large_valid_png(min_bytes=300_000)
    assert len(big_png) > 262_144

    counts_before = _table_counts(db_path)
    with client.stream(
        "POST",
        "/api/v1/assistant/chat/evidence/stream",
        headers={"X-Case-Access-Token": parent_token},
        data={"case_id": parent_id, "message": "Kiểm tra giúp ảnh chụp bổ sung này"},
        files={"image": ("evidence_large.png", big_png, "image/png")},
    ) as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        assert "no-store" in resp.headers.get("cache-control", "").lower()
        assert "x-case-access-token" in resp.headers.get("vary", "").lower()
        events = _parse_sse("".join(resp.iter_text()))

    assert _table_counts(db_path) == counts_before
    assert any(ev == "evidence_report" for ev, _ in events)
    assert events[-1][0] == "done"

    # 2. > 10 MB upload rejected with HTTP 413
    oversize = b"\x89PNG\r\n\x1a\n" + (b"\x00" * (app.state.settings.max_upload_bytes + 1024))
    r_413 = client.post(
        "/api/v1/assistant/chat/evidence/stream",
        headers={"X-Case-Access-Token": parent_token},
        data={"case_id": parent_id, "message": "Oversize test"},
        files={"image": ("huge.png", oversize, "image/png")},
    )
    assert r_413.status_code == 413

    # 3. Empty & corrupt files rejected with HTTP 400
    r_empty = client.post(
        "/api/v1/assistant/chat/evidence/stream",
        headers={"X-Case-Access-Token": parent_token},
        data={"case_id": parent_id, "message": "Empty file"},
        files={"image": ("empty.png", b"", "image/png")},
    )
    assert r_empty.status_code == 400

    r_corrupt = client.post(
        "/api/v1/assistant/chat/evidence/stream",
        headers={"X-Case-Access-Token": parent_token},
        data={"case_id": parent_id, "message": "Corrupt file"},
        files={"image": ("bad.png", b"NOT_A_REAL_PNG_FILE", "image/png")},
    )
    assert r_corrupt.status_code == 400

    r_corrupt_audio = client.post(
        "/api/v1/assistant/chat/evidence/stream",
        headers={"X-Case-Access-Token": parent_token},
        data={"case_id": parent_id, "message": "Corrupt audio"},
        files={"audio": ("bad.wav", b"NOT_A_VALID_WAV_STREAM", "audio/wav")},
    )
    assert r_corrupt_audio.status_code == 400

    r_blank = client.post(
        "/api/v1/assistant/chat/evidence/stream",
        headers={"X-Case-Access-Token": parent_token},
        data={"case_id": parent_id, "message": "   "},
    )
    assert r_blank.status_code == 400

    # 4. Standard JSON chat route STILL enforces 256 KB body limit
    huge_json = json.dumps({"message": "a" * 280_000}).encode("utf-8")
    r_json_413 = client.post(
        "/api/v1/assistant/chat/stream",
        content=huge_json,
        headers={"Content-Type": "application/json"},
    )
    assert r_json_413.status_code == 413


def test_evidence_stream_auth_403_before_streaming(tmp_path: Path) -> None:
    _app, client, _db_path = _make_app_client(tmp_path)
    parent_id, parent_token = _create_parent_case(client, mode="personal")
    png = _make_small_valid_png(7)

    # Missing token
    r_missing = client.post(
        "/api/v1/assistant/chat/evidence/stream",
        data={"case_id": parent_id, "message": "Kiểm tra ảnh"},
        files={"image": ("a.png", png, "image/png")},
    )
    assert r_missing.status_code == 403
    assert "no-store" in r_missing.headers.get("cache-control", "").lower()
    assert "x-case-access-token" in r_missing.headers.get("vary", "").lower()
    assert not r_missing.headers.get("content-type", "").startswith("text/event-stream")

    # Wrong token
    r_wrong = client.post(
        "/api/v1/assistant/chat/evidence/stream",
        headers={"X-Case-Access-Token": parent_token + "tampered"},
        data={"case_id": parent_id, "message": "Kiểm tra ảnh"},
        files={"image": ("a.png", png, "image/png")},
    )
    assert r_wrong.status_code == 403
    assert not r_wrong.headers.get("content-type", "").startswith("text/event-stream")


def test_default_local_only_zero_gemini_calls_zero_db_writes_and_detects_replayed_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, client, db_path = _make_app_client(
        tmp_path,
        gemini_api_key="AIzaSyntheticActiveKeyForZeroEgressCheck0003",
        enable_gemini_ocr_fallback=True,
    )
    parent_id, parent_token = _create_parent_case(client, mode="merchant")

    # Seed a known receipt dhash into receipt_hashes before ephemeral check
    receipt_png = _make_small_valid_png(99)
    with Image.open(io.BytesIO(receipt_png)) as pil_img:
        known_dhash = compute_dhash_hex(pil_img)
    claimed_first = app.state.repo.claim_receipt_replay(
        known_dhash, "Vietcombank", None, register_if_new=True
    )
    assert claimed_first is False
    assert app.state.repo.is_receipt_replayed(known_dhash, "Vietcombank", None) is True

    # Low-confidence OCR (would normally trigger Gemini fallback if enabled!)
    class _LowConfReceiptOcr:
        name = "stub_low_conf_receipt"
        model_id = "stub"

        def is_available(self) -> bool:
            return True

        def extract(self, image_bytes: bytes, *, mime_type: str = "image/png") -> OcrResult:
            _ = (image_bytes, mime_type)
            return OcrResult(
                available=True,
                status="ok",
                provider=self.name,
                model_id=self.model_id,
                full_text=(
                    "Vietcombank Chuyen tien thanh cong 5.000.000 VND "
                    "Ma GD FT2633019991 STK nhan 190399998888"
                ),
                mean_confidence=0.20,
            )

    ocr_fallback_calls = 0
    gemini_llm_calls = 0
    chat_llm_calls = 0

    async def _spy_ocr_fallback(
        _settings: Settings, _img: bytes, _mime: str, _timeout: float
    ) -> OcrResult:
        nonlocal ocr_fallback_calls
        ocr_fallback_calls += 1
        return OcrResult(available=True, status="ok", provider="gemini_ocr", full_text="BAD")

    async def _spy_execute_llm(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal gemini_llm_calls
        gemini_llm_calls += 1
        raise AssertionError("Gemini Vision / LLM must NOT be called when allow_external_media_ai=false")

    async def _spy_stream_assistant_llm(*_args: Any, **_kwargs: Any) -> AsyncIterator[str]:
        nonlocal chat_llm_calls
        chat_llm_calls += 1
        yield "SHOULD_NOT_RUN"

    app.state.pipeline.ocr_orchestrator = OcrOrchestrator(
        settings=app.state.settings,
        primary_provider=_LowConfReceiptOcr(),
        gemini_fallback_fn=_spy_ocr_fallback,
    )
    monkeypatch.setattr("app.services.ai_orchestrator.execute_llm_call", _spy_execute_llm)
    monkeypatch.setattr("app.services.assistant_service.stream_assistant_llm", _spy_stream_assistant_llm)

    counts_before = _table_counts(db_path)

    with client.stream(
        "POST",
        "/api/v1/assistant/chat/evidence/stream",
        headers={"X-Case-Access-Token": parent_token},
        data={
            "case_id": parent_id,
            "message": "Kiểm tra ảnh biên lai khách vừa gửi thêm",
            # default allow_external_media_ai="false"
        },
        files={"image": ("replayed_receipt.png", receipt_png, "image/png")},
    ) as resp:
        assert resp.status_code == 200
        events = _parse_sse("".join(resp.iter_text()))

    assert ocr_fallback_calls == 0
    assert gemini_llm_calls == 0
    assert chat_llm_calls == 0
    assert _table_counts(db_path) == counts_before

    ev_reports = [data for name, data in events if name == "evidence_report"]
    assert len(ev_reports) == 1
    ev_rep = ev_reports[0]
    assert ev_rep["draft_id"].startswith("drf_")
    assert ev_rep["can_contribute_radar"] is True
    assert ev_rep["receipt_verification_status"] == "REPLAYED_RECEIPT"
    assert ev_rep["risk_score"] >= 75

    # Merchant receipt safety notice MUST be emitted
    assert any(
        name == "safety_notice" and data["code"] == "MERCHANT_BALANCE_REQUIRED"
        for name, data in events
    )
    assert any(name == "delta" and len(data["text"].strip()) > 20 for name, data in events)
    assert events[-1][0] == "done"


def test_explicit_persist_private_default_atomic_single_use_and_child_pdf_isolation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _app, client, db_path = _make_app_client(tmp_path)
    monkeypatch.setattr(
        "app.services.ai_orchestrator.execute_llm_call",
        lambda *_a, **_kw: (_ for _ in ()).throw(AssertionError("No external LLM expected")),
    )
    parent_id, parent_token = _create_parent_case(client, mode="personal")

    counts_before = _table_counts(db_path)
    with client.stream(
        "POST",
        "/api/v1/assistant/chat/evidence/stream",
        headers={"X-Case-Access-Token": parent_token},
        data={
            "case_id": parent_id,
            "message": (
                "Kẻ gian nhắn gọi 0912345678 và chuyển 12 triệu vào STK 999888777666 "
                "qua link https://vietcombank-xacminh-247.top/login"
            ),
        },
    ) as resp:
        assert resp.status_code == 200
        events = _parse_sse("".join(resp.iter_text()))

    assert _table_counts(db_path) == counts_before
    draft_id = [data["draft_id"] for name, data in events if name == "evidence_report"][0]

    # Wrong token on /persist -> 403 and does NOT consume the draft
    r_bad = client.post(
        f"/api/v1/assistant/evidence/{draft_id}/persist",
        headers={"X-Case-Access-Token": parent_token + "bad"},
        json={"case_id": parent_id, "contribute_to_radar": False},
    )
    assert r_bad.status_code == 403

    # Default persist (contribute_to_radar=False): inserts 1 row in cases, 0 in Radar/receipt_hashes
    r_persist = client.post(
        f"/api/v1/assistant/evidence/{draft_id}/persist",
        headers={"X-Case-Access-Token": parent_token},
        json={"case_id": parent_id, "contribute_to_radar": False},
    )
    assert r_persist.status_code == 200
    assert "no-store" in r_persist.headers.get("cache-control", "").lower()
    assert "x-case-access-token" in r_persist.headers.get("vary", "").lower()
    body = r_persist.json()
    child_id = body["child_case_id"]
    child_token = body["child_case_access_token"]
    assert child_id.startswith("vs_") and len(child_id) == 35
    assert child_id != parent_id
    assert body["parent_case_id"] == parent_id
    assert body["contributed_to_radar"] is False
    assert body["expires_at"]

    counts_after = _table_counts(db_path)
    assert counts_after["cases"] == counts_before["cases"] + 1
    assert counts_after["ioc_sightings"] == counts_before["ioc_sightings"]
    assert counts_after["ioc_edges"] == counts_before["ioc_edges"]
    assert counts_after["campaigns"] == counts_before["campaigns"]
    assert counts_after["receipt_hashes"] == counts_before["receipt_hashes"]

    # Verify DB metadata on child case row
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT owner_channel, parent_case_id, contributes_to_radar, is_demo "
            "FROM cases WHERE case_id = ?",
            (child_id,),
        ).fetchone()
    finally:
        conn.close()
    assert row == ("web_token", parent_id, 0, 0)

    # Atomic single-use: second /persist on same draft_id MUST return 404
    r_replay = client.post(
        f"/api/v1/assistant/evidence/{draft_id}/persist",
        headers={"X-Case-Access-Token": parent_token},
        json={"case_id": parent_id, "contribute_to_radar": False},
    )
    assert r_replay.status_code == 404

    # Child PDF access isolation: ONLY child_case_access_token succeeds!
    r_pdf_none = client.get(f"/api/v1/cases/{child_id}/report.pdf")
    assert r_pdf_none.status_code == 403

    r_pdf_parent = client.get(
        f"/api/v1/cases/{child_id}/report.pdf",
        headers={"X-Case-Access-Token": parent_token},
    )
    assert r_pdf_parent.status_code == 403

    r_pdf_child = client.get(
        f"/api/v1/cases/{child_id}/report.pdf",
        headers={"X-Case-Access-Token": child_token},
    )
    assert r_pdf_child.status_code == 200
    assert r_pdf_child.content.startswith(b"%PDF-")

    # Symmetric isolation: child token MUST NOT open parent's PDF!
    r_parent_pdf_with_child = client.get(
        f"/api/v1/cases/{parent_id}/report.pdf",
        headers={"X-Case-Access-Token": child_token},
    )
    assert r_parent_pdf_with_child.status_code == 403


def test_explicit_persist_with_radar_opt_in_on_real_vs_demo_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, client, db_path = _make_app_client(tmp_path)
    monkeypatch.setattr(
        "app.services.ai_orchestrator.execute_llm_call",
        lambda *_a, **_kw: (_ for _ in ()).throw(AssertionError("No external LLM expected")),
    )

    class _ReceiptOcrStub:
        name = "stub_receipt_ocr"
        model_id = "stub"

        def is_available(self) -> bool:
            return True

        def extract(self, image_bytes: bytes, *, mime_type: str = "image/png") -> OcrResult:
            _ = (image_bytes, mime_type)
            return OcrResult(
                available=True,
                status="ok",
                provider=self.name,
                model_id=self.model_id,
                full_text=(
                    "Vietcombank Chuyen tien thanh cong 8.500.000 VND "
                    "Ma GD FT2633099881 STK nhan 190388887777"
                ),
                mean_confidence=0.92,
            )

    app.state.pipeline.ocr_orchestrator = OcrOrchestrator(
        settings=app.state.settings,
        primary_provider=_ReceiptOcrStub(),
    )

    # A. Real non-demo parent -> contribute_to_radar=True writes pre-hashed IOCs + receipt_hashes
    real_parent_id, real_parent_token = _create_parent_case(client, mode="merchant")
    png_real = _make_small_valid_png(123)
    counts_before_real = _table_counts(db_path)

    with client.stream(
        "POST",
        "/api/v1/assistant/chat/evidence/stream",
        headers={"X-Case-Access-Token": real_parent_token},
        data={
            "case_id": real_parent_id,
            "message": (
                "Đối tượng gọi 0987654321 gửi link https://napas-hoantien-999.top/claim "
                "và ép chuyển vào STK 777666555444"
            ),
        },
        files={"image": ("receipt_real.png", png_real, "image/png")},
    ) as resp:
        assert resp.status_code == 200
        events = _parse_sse("".join(resp.iter_text()))

    assert _table_counts(db_path) == counts_before_real
    ev_real = [data for name, data in events if name == "evidence_report"][0]
    assert ev_real["can_contribute_radar"] is True
    assert ev_real["risk_score"] >= 45

    r_real_persist = client.post(
        f"/api/v1/assistant/evidence/{ev_real['draft_id']}/persist",
        headers={"X-Case-Access-Token": real_parent_token},
        json={"case_id": real_parent_id, "contribute_to_radar": True},
    )
    assert r_real_persist.status_code == 200
    real_body = r_real_persist.json()
    assert real_body["contributed_to_radar"] is True

    counts_after_real = _table_counts(db_path)
    assert counts_after_real["cases"] == counts_before_real["cases"] + 1
    assert counts_after_real["ioc_sightings"] > counts_before_real["ioc_sightings"]
    assert counts_after_real["receipt_hashes"] > counts_before_real["receipt_hashes"]

    # Confirm zero raw PII entered ioc_sightings
    conn = sqlite3.connect(db_path)
    try:
        masked_vals = [str(r[0]) for r in conn.execute("SELECT masked_value FROM ioc_sightings").fetchall()]
    finally:
        conn.close()
    joined_masked = " ".join(masked_vals)
    assert "0987654321" not in joined_masked
    assert "777666555444" not in joined_masked
    assert "190388887777" not in joined_masked

    # B. Demo parent -> can_contribute_radar=False and server FORCES contributed_to_radar=False!
    demo_parent_id, demo_parent_token = _create_parent_case(
        client,
        mode="personal",
        demo_id="demo_napas_sms",
    )
    png_demo = _make_small_valid_png(456)
    counts_before_demo = _table_counts(db_path)

    with client.stream(
        "POST",
        "/api/v1/assistant/chat/evidence/stream",
        headers={"X-Case-Access-Token": demo_parent_token},
        data={
            "case_id": demo_parent_id,
            "message": "Kẻ gian gửi link https://demo-scam-test-777.top và gọi 0911223344",
        },
        files={"image": ("receipt_demo.png", png_demo, "image/png")},
    ) as resp:
        assert resp.status_code == 200
        demo_events = _parse_sse("".join(resp.iter_text()))

    assert _table_counts(db_path) == counts_before_demo
    ev_demo = [data for name, data in demo_events if name == "evidence_report"][0]
    assert ev_demo["can_contribute_radar"] is False

    r_demo_persist = client.post(
        f"/api/v1/assistant/evidence/{ev_demo['draft_id']}/persist",
        headers={"X-Case-Access-Token": demo_parent_token},
        json={"case_id": demo_parent_id, "contribute_to_radar": True},
    )
    assert r_demo_persist.status_code == 200
    demo_body = r_demo_persist.json()
    assert demo_body["contributed_to_radar"] is False

    counts_after_demo = _table_counts(db_path)
    assert counts_after_demo["cases"] == counts_before_demo["cases"] + 1
    assert counts_after_demo["ioc_sightings"] == counts_before_demo["ioc_sightings"]
    assert counts_after_demo["ioc_edges"] == counts_before_demo["ioc_edges"]
    assert counts_after_demo["campaigns"] == counts_before_demo["campaigns"]
    assert counts_after_demo["receipt_hashes"] == counts_before_demo["receipt_hashes"]


def test_staged_draft_has_zero_raw_pii_cross_parent_cannot_hijack_and_opt_in_external_works(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, client, _db_path = _make_app_client(tmp_path)
    parent_a, token_a = _create_parent_case(client, mode="personal")
    parent_b, token_b = _create_parent_case(client, mode="personal")

    # 1. Local-only staging contains ZERO raw PII / ZERO visual base64 blobs in RAM
    with client.stream(
        "POST",
        "/api/v1/assistant/chat/evidence/stream",
        headers={"X-Case-Access-Token": token_a},
        data={
            "case_id": parent_a,
            "message": "Số lạ 0912345678 yêu cầu chuyển vào STK 190366665555",
        },
        files={"image": ("scan.png", _make_small_valid_png(11), "image/png")},
    ) as resp:
        assert resp.status_code == 200
        ev_a = _parse_sse("".join(resp.iter_text()))

    draft_id = [d["draft_id"] for n, d in ev_a if n == "evidence_report"][0]
    staged_draft = app.state.evidence_stage._drafts[draft_id]
    serialized_report = staged_draft.staged_redacted_report.model_dump_json()
    serialized_iocs = json.dumps(staged_draft.prehashed_iocs)
    assert "0912345678" not in serialized_report
    assert "190366665555" not in serialized_report
    assert "0912345678" not in serialized_iocs
    assert "190366665555" not in serialized_iocs
    assert staged_draft.staged_redacted_report.image_forensics is not None
    assert staged_draft.staged_redacted_report.image_forensics.ela_heatmap_base64 is None
    assert len(staged_draft.prehashed_iocs) >= 2

    # 2. Parent B attempting to persist Parent A's draft gets 404 WITHOUT consuming Parent A's draft
    r_hijack = client.post(
        f"/api/v1/assistant/evidence/{draft_id}/persist",
        headers={"X-Case-Access-Token": token_b},
        json={"case_id": parent_b, "contribute_to_radar": False},
    )
    assert r_hijack.status_code == 404

    # Parent A can still persist their draft!
    r_owner = client.post(
        f"/api/v1/assistant/evidence/{draft_id}/persist",
        headers={"X-Case-Access-Token": token_a},
        json={"case_id": parent_a, "contribute_to_radar": False},
    )
    assert r_owner.status_code == 200

    # 3. Extra unknown JSON fields on /persist rejected (extra="forbid" -> 422)
    r_extra = client.post(
        f"/api/v1/assistant/evidence/{draft_id}/persist",
        headers={"X-Case-Access-Token": token_a},
        json={"case_id": parent_a, "contribute_to_radar": False, "unexpected": True},
    )
    assert r_extra.status_code == 422

    # 4. Explicit opt-in allow_external_media_ai="true" invokes external AI explanation path
    chat_llm_calls = 0

    async def _fake_stream_llm(*_args: Any, **_kwargs: Any) -> AsyncIterator[str]:
        nonlocal chat_llm_calls
        chat_llm_calls += 1
        yield "Đây là dấu hiệu lừa đảo rõ rệt từ bằng chứng bổ sung. "
        yield "Bạn tuyệt đối không chuyển tiền và không cung cấp mã OTP."

    async def _fake_exec_llm(*_args: Any, **_kwargs: Any) -> Any:
        from app.services.llm_client import GeminiStructuredSchema, LlmCallOutcome

        return LlmCallOutcome(
            parsed=GeminiStructuredSchema(
                ai_risk_score=84,
                summary_vi="Phân tích đa phương thức ghi nhận dấu hiệu lừa đảo.",
            ),
            provider="google_genai",
            actual_model="gemini-2.5-flash",
            latency_ms=12,
            attempts=1,
        )

    monkeypatch.setattr("app.services.ai_orchestrator.execute_llm_call", _fake_exec_llm)
    monkeypatch.setattr("app.services.assistant_service.stream_assistant_llm", _fake_stream_llm)

    with client.stream(
        "POST",
        "/api/v1/assistant/chat/evidence/stream",
        headers={"X-Case-Access-Token": token_a},
        data={
            "case_id": parent_a,
            "message": "Phân tích sâu ảnh tin nhắn đòi chuyển tiền này",
            "allow_external_media_ai": "true",
        },
        files={"image": ("opt_in.png", _make_small_valid_png(12), "image/png")},
    ) as resp_opt:
        assert resp_opt.status_code == 200
        ev_opt = _parse_sse("".join(resp_opt.iter_text()))

    assert chat_llm_calls == 1
    assert any(n == "evidence_report" for n, _ in ev_opt)
    assert ev_opt[-1][0] == "done"


def test_local_only_ephemeral_mode_disables_outbound_url_network_beacons(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, client, _db_path = _make_app_client(tmp_path)
    app.state.settings.enable_live_network_checks = True
    parent_id, parent_token = _create_parent_case(client, mode="personal")

    observed_net_flags: list[bool] = []
    from app.services import pipeline as pipeline_mod

    orig_inspect = pipeline_mod.inspect_url

    async def _spy_inspect(url: str, *, enable_network: bool = False, **kwargs: Any) -> Any:
        observed_net_flags.append(enable_network)
        return await orig_inspect(url, enable_network=False, **kwargs)

    monkeypatch.setattr("app.services.pipeline.inspect_url", _spy_inspect)

    with client.stream(
        "POST",
        "/api/v1/assistant/chat/evidence/stream",
        headers={"X-Case-Access-Token": parent_token},
        data={
            "case_id": parent_id,
            "message": "Kiểm tra link lạ https://vietcombank-check-247.top/track",
            "allow_external_media_ai": "false",
        },
    ) as resp:
        assert resp.status_code == 200
        events = _parse_sse("".join(resp.iter_text()))

    assert observed_net_flags == [False]
    assert any(n == "evidence_report" for n, _ in events)


