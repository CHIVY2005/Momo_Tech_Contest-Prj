"""Security regression tests for WP-11 (NV-29, NV-36, NV-37, NV-38, NV-40, NV-41)."""

from __future__ import annotations

import asyncio
import io
import json
import sqlite3
import threading
import time
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import respx
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pypdf import PdfReader

from app.api.v1.assistant import _guarded_sse_response
from app.config import Settings
from app.core.case_tokens import hash_telegram_private_owner, issue_case_access_token
from app.core.media_executors import MediaExecutorBusyError
from app.db.repository import CaseRepository
from app.main import PROTECTED_SAFE_DEMO_IOCS, _load_protected_official_iocs, create_app
from app.schemas import (
    ActionBundle,
    AnalysisReport,
    EvidenceItem,
    ExtractedIOCs,
    PreTransferIntervention,
)
from app.services.assistant_evidence import (
    EphemeralEvidenceStage,
    stream_ephemeral_evidence,
)
from app.services.assistant_rag import AssistantKnowledgeRetriever
from app.services.assistant_service import MAX_CONCURRENT_STREAMS
from app.services.assistant_slots import (
    MAX_CONCURRENT_STREAMS_PER_IP_AUTH,
    MAX_CONCURRENT_STREAMS_PER_IP_UNAUTH,
    MAX_UNAUTH_CONCURRENT_STREAMS,
    AssistantSlotManager,
)
from app.services.assistant_stage import MAX_DRAFTS_PER_CASE, MAX_DRAFTS_PER_OWNER
from app.services.assistant_tools import execute_controlled_tool, run_pre_tools_for_vault
from app.services.assistant_vault import RequestEntityVault
from app.services.pipeline import AnalysisPipeline, EphemeralAnalysisBundle
from app.services.report_pdf import MAX_PDF_IOCS_PER_TYPE, generate_incident_pdf
from app.services.telegram_bot import (
    TelegramDeliveryError,
    TelegramPermanentDeliveryError,
    _deliver_telegram_message,
    _resolve_demo_id,
    handle_telegram_update,
)

_DATA_DIR = Path(__file__).resolve().parents[2] / "app" / "data"


def _make_settings(tmp_path: Path, name: str = "wp11.db", **overrides: Any) -> Settings:
    params: dict[str, Any] = {
        "_env_file": None,
        "sqlite_path": str(tmp_path / name),
        "gemini_api_key": "",
        "gemini_backup_api_key": "",
        "app_env": "demo",
        "analyst_pin": "2026",
        "telegram_bot_token": "999111:SYNTHETIC_WP11_TOKEN",
        "telegram_webhook_secret": "wp11_tg_secret",
        "enable_live_network_checks": False,
        "enable_playwright_sandbox": False,
        "enable_local_ocr": False,
        "enable_local_stt": False,
        "rate_limit_per_minute": 45,
        "assistant_rate_limit_per_minute": 100,
        "assistant_rate_limit_per_hour": 500,
    }
    params.update(overrides)
    return Settings(**params)


def _sample_report(case_id: str = "vs_wp11_case_01", **overrides: Any) -> AnalysisReport:
    params: dict[str, Any] = {
        "case_id": case_id,
        "created_at": "2026-11-27T10:00:00+00:00",
        "mode": "personal",
        "risk_score": 82,
        "verdict": "CRITICAL_SCAM",
        "confidence": 0.9,
        "summary_vi": "Phát hiện dấu hiệu giả mạo ngân hàng.",
        "matched_playbooks": ["scam_phishing_link"],
        "iocs": ExtractedIOCs(
            phones=["091****678"],
            bank_accounts=["19****01"],
            domains=["phish.top"],
        ),
        "evidence": [
            EvidenceItem(
                source="url_inspector",
                severity="HIGH",
                title="Tên miền giả mạo",
                detail="Phát hiện đường dẫn lừa đảo.",
            )
        ],
        "actions": ActionBundle(
            urgent_steps=["Không chuyển tiền.", "Liên hệ ngân hàng chính thức."],
            pre_transfer=PreTransferIntervention(should_hold_transfer=True),
        ),
    }
    params.update(overrides)
    return AnalysisReport(**params)


def _dummy_bundle(cid: str) -> EphemeralAnalysisBundle:
    rep = _sample_report(case_id=cid)
    return EphemeralAnalysisBundle(
        live_report=rep,
        staged_redacted_report=rep,
        prehashed_iocs=[],
        replay_fingerprints=[],
    )


# ---------------------------------------------------------------------------
# NV-29: Full KB Official Domain Protection Seeding in main.py
# ---------------------------------------------------------------------------


def test_nv29_protected_official_iocs_loaded_and_return_409(tmp_path: Path) -> None:
    assert ("domain", "vietcombank.com.vn") in PROTECTED_SAFE_DEMO_IOCS
    merged = _load_protected_official_iocs(_DATA_DIR)
    domains = {val for t, val in merged if t == "domain"}
    assert "techcombank.com" in domains
    assert "vietinbank.vn" in domains
    assert "zalopay.vn" in domains
    assert len(merged) == len(set(merged))

    app = create_app(_make_settings(tmp_path, name="nv29.db"))
    client = TestClient(app)
    for official_dom in (
        "techcombank.com",
        "vietinbank.vn",
        "vcbdigibank.vietcombank.com.vn",
        "portal.vietinbank.vn",
    ):
        resp = client.post(
            "/api/v1/radar/block-rules",
            json={
                "ioc_type": "domain",
                "value": official_dom,
                "reason": "Test official domain block attempt",
                "analyst_pin": "2026",
            },
        )
        assert resp.status_code == 409, f"Expected 409 for protected domain {official_dom}"


# ---------------------------------------------------------------------------
# NV-36: GET Rate Limits, PDF Caps/Cache/503, Async Radar, Assistant Tools
# ---------------------------------------------------------------------------


def test_nv36_pdf_caps_already_redacted_and_cache_and_503(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 1. PDF caps IOC lists at MAX_PDF_IOCS_PER_TYPE=8, playbooks[:8], steps[:12], summary[:2000]
    assert MAX_PDF_IOCS_PER_TYPE == 8
    heavy_report = _sample_report(
        summary_vi="Tóm tắt cảnh báo " + ("X" * 3000),
        matched_playbooks=[f"pb_{i}" for i in range(15)],
        iocs=ExtractedIOCs(
            phones=[f"091****{i:03d}" for i in range(20)],
            bank_accounts=[f"19****{i:02d}" for i in range(20)],
            domains=[f"bad{i}.top" for i in range(20)],
        ),
        actions=ActionBundle(
            urgent_steps=[f"Bước an toàn số {i}" for i in range(20)],
            pre_transfer=PreTransferIntervention(should_hold_transfer=True),
        ),
    )
    pdf_bytes = generate_incident_pdf(heavy_report)
    assert pdf_bytes[:5] == b"%PDF-"
    extracted = "\n".join(page.extract_text() or "" for page in PdfReader(io.BytesIO(pdf_bytes)).pages)
    assert "(+12 mục khác)" in extracted
    assert "(+7 mục khác)" in extracted
    assert "Bước an toàn số 11" in extracted
    assert "Bước an toàn số 12" not in extracted

    # 2. already_redacted=True skips redact_report_pii
    def _boom_redact(*_a: Any, **_kw: Any) -> Any:
        raise AssertionError("redact_report_pii should be skipped when already_redacted=True")

    monkeypatch.setattr("app.services.report_pdf.redact_report_pii", _boom_redact)
    fast_pdf = generate_incident_pdf(heavy_report, already_redacted=True)
    assert fast_pdf[:5] == b"%PDF-"

    # 3. cases.py: auth runs BEFORE pdf_cache, cache hits avoid re-rendering, busy -> 503
    app = create_app(_make_settings(tmp_path, name="nv36_cases.db", rate_limit_per_minute=20))
    client = TestClient(app)
    rep = _sample_report(case_id="vs_pdf_cache_01")
    app.state.repo.save_report(rep, owner_channel="web_token")
    token, _ = issue_case_access_token(rep.case_id, app.state.case_token_secret)

    render_calls: list[bool] = []

    def _stub_pdf(r: AnalysisReport, already_redacted: bool = False) -> bytes:
        _ = r
        render_calls.append(already_redacted)
        return b"%PDF-1.4\n%stub\n"

    monkeypatch.setattr("app.api.v1.cases.generate_incident_pdf", _stub_pdf)

    r1 = client.get(f"/api/v1/cases/{rep.case_id}/report.pdf", headers={"X-Case-Access-Token": token})
    assert r1.status_code == 200
    assert render_calls == [True]

    # Unauthorized request MUST still return 403 even after cache is populated
    r_unauth = client.get(f"/api/v1/cases/{rep.case_id}/report.pdf")
    assert r_unauth.status_code == 403

    # Second authorized request hits app.state.pdf_cache
    r2 = client.get(f"/api/v1/cases/{rep.case_id}/report.pdf", headers={"X-Case-Access-Token": token})
    assert r2.status_code == 200
    assert r2.content == b"%PDF-1.4\n%stub\n"
    assert len(render_calls) == 1

    # Cache miss + MediaExecutorBusyError -> HTTP 503 with Retry-After, Cache-Control, Vary
    app.state.pdf_cache.clear()

    async def _busy_pdf(*_a: Any, **_kw: Any) -> bytes:
        raise MediaExecutorBusyError("PDF pool saturated")

    monkeypatch.setattr("app.api.v1.cases.run_pdf_bounded", _busy_pdf)
    r_busy = client.get(
        f"/api/v1/cases/{rep.case_id}/report.pdf", headers={"X-Case-Access-Token": token}
    )
    assert r_busy.status_code == 503
    assert r_busy.headers.get("retry-after") == "2"
    assert "no-store" in r_busy.headers.get("cache-control", "").lower()
    assert "x-case-access-token" in r_busy.headers.get("vary", "").lower()


def test_nv36_get_rate_limits_and_async_radar_thread_offload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = create_app(_make_settings(tmp_path, name="nv36_rl.db", rate_limit_per_minute=3))
    client = TestClient(app)

    # Radar GET rate limit respects low cfg.rate_limit_per_minute (min(60, 3) == 3)
    observed_threads: list[int] = []
    orig_get_radar = app.state.repo.get_radar_graph

    def _tracked_radar(*args: Any, **kwargs: Any) -> Any:
        observed_threads.append(threading.get_ident())
        return orig_get_radar(*args, **kwargs)

    monkeypatch.setattr(app.state.repo, "get_radar_graph", _tracked_radar)

    for _ in range(3):
        resp = client.get("/api/v1/radar/graph")
        assert resp.status_code == 200
    assert len(observed_threads) == 3
    r_radar_429 = client.get("/api/v1/radar/graph")
    assert r_radar_429.status_code == 429
    assert "retry-after" in r_radar_429.headers
    assert "no-store" in r_radar_429.headers.get("cache-control", "").lower()

    # PDF GET rate limit respects low cfg.rate_limit_per_minute (min(20, 3) == 3) with Vary header
    for _ in range(3):
        resp = client.get("/api/v1/cases/vs_any_case/report.pdf")
        assert resp.status_code == 403
    r_pdf_429 = client.get("/api/v1/cases/vs_any_case/report.pdf")
    assert r_pdf_429.status_code == 429
    assert "retry-after" in r_pdf_429.headers
    assert "no-store" in r_pdf_429.headers.get("cache-control", "").lower()
    assert "x-case-access-token" in r_pdf_429.headers.get("vary", "").lower()


@pytest.mark.asyncio
async def test_nv36_assistant_tools_uses_indexed_campaign_lookup_and_url_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _make_settings(tmp_path, name="nv36_tools.db")
    repo = CaseRepository(cfg.sqlite_path, ioc_hmac_secret=cfg.resolved_ioc_hmac_secret)
    repo.init_db()
    repo.seed_if_empty(str(_DATA_DIR / "seed_iocs.json"))
    retriever = AssistantKnowledgeRetriever(
        _DATA_DIR / "models" / "assistant_kb_index.json",
        _DATA_DIR / "models" / "assistant_kb_embeddings.npy",
    )

    def _no_full_graph(*_a: Any, **_kw: Any) -> Any:
        raise AssertionError("assistant_tools must NOT call get_radar_graph()")

    monkeypatch.setattr(repo, "get_radar_graph", _no_full_graph)

    seed_payload = json.loads((_DATA_DIR / "seed_iocs.json").read_text(encoding="utf-8"))
    camp = next(c for c in seed_payload["campaigns"] if c["primary_ioc_type"] == "domain")
    raw_dom = camp["primary_ioc_raw_synthetic"]
    _, vault = RequestEntityVault.extract_from_message(f"Kiểm tra trang https://{raw_dom}/login")
    url_ref = next(it["ref_id"] for it in vault.list_public_refs() if it["entity_type"] == "url")
    res = await execute_controlled_tool(
        "lookup_ioc_reputation",
        {"entity_ref_id": url_ref},
        vault=vault,
        report=None,
        repo=repo,
        retriever=retriever,
        settings=cfg,
    )
    assert res["ok"] is True
    assert res["known_sightings"] > 0
    assert camp["title_vi"][:12] in res["risk_summary"]

    # max_url_checks=1 caps pre-tool URL inspections to 1 even with 2 URLs in message
    _, vault2 = RequestEntityVault.extract_from_message(
        "Kiểm tra https://alpha-scam.top và https://beta-scam.top giúp tôi"
    )
    evs, _sums, _cits = await run_pre_tools_for_vault(
        vault=vault2,
        report=None,
        repo=repo,
        retriever=retriever,
        settings=cfg,
        max_url_checks=1,
    )
    url_done = [e for e in evs if e["tool"] == "check_url_safety" and e["state"] != "running"]
    assert len(url_done) == 1


# ---------------------------------------------------------------------------
# NV-37: Partitioned Assistant Slots, Per-IP Cap & Outer SSE Timeout
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nv37_slot_partitioning_per_ip_caps_and_outer_sse_timeout(tmp_path: Path) -> None:
    mgr = AssistantSlotManager(acquire_timeout_sec=0.05)
    assert MAX_UNAUTH_CONCURRENT_STREAMS == 2
    assert MAX_CONCURRENT_STREAMS_PER_IP_UNAUTH == 2
    assert MAX_CONCURRENT_STREAMS_PER_IP_AUTH == 3

    # 1. Unauth slots capped at 2 globally while auth slots 3..6 still succeed
    unauth_rels = [
        await mgr.acquire(authenticated=False, client_ip="198.51.100.1"),
        await mgr.acquire(authenticated=False, client_ip="198.51.100.2"),
    ]
    with pytest.raises(HTTPException) as exc_unauth:
        await mgr.acquire(authenticated=False, client_ip="198.51.100.3")
    assert exc_unauth.value.status_code == 429

    auth_rels = [
        await mgr.acquire(authenticated=True, client_ip="203.0.113.1"),
        await mgr.acquire(authenticated=True, client_ip="203.0.113.1"),
        await mgr.acquire(authenticated=True, client_ip="203.0.113.1"),
    ]
    # 4th auth from same IP immediately rejected with HTTP 429
    with pytest.raises(HTTPException) as exc_ip:
        await mgr.acquire(authenticated=True, client_ip="203.0.113.1")
    assert exc_ip.value.status_code == 429
    # Different IP can still take the 6th global slot
    rel6 = await mgr.acquire(authenticated=True, client_ip="203.0.113.2")
    for fn in (*unauth_rels, *auth_rels, rel6):
        fn()
        fn()  # Idempotent release
    assert mgr.global_semaphore._value == MAX_CONCURRENT_STREAMS
    assert mgr.unauth_semaphore._value == MAX_UNAUTH_CONCURRENT_STREAMS
    assert mgr._active_by_ip == {}

    # 2. Outer SSE timeout + stalled aclose() (capped at 2s) still releases slot cleanly
    app = create_app(_make_settings(tmp_path, name="nv37_sse.db"))
    svc = app.state.assistant_service
    rel = await svc.acquire_stream_slot(authenticated=False, client_ip="198.51.100.9")

    async def _stalled_stream() -> AsyncIterator[str]:
        try:
            yield "event: status\ndata: {}\n\n"
            await asyncio.sleep(30.0)
        finally:
            await asyncio.sleep(10.0)  # Stalled teardown must be cut off by 2s cap

    resp = _guarded_sse_response(svc, _stalled_stream(), rel, outer_timeout_sec=0.1)

    async def _receive() -> dict[str, Any]:
        await asyncio.sleep(30.0)
        return {"type": "http.disconnect"}

    async def _send(_msg: dict[str, Any]) -> None:
        return None

    scope = {"type": "http", "method": "POST", "path": "/api/v1/assistant/chat/stream"}
    await asyncio.wait_for(resp(scope, _receive, _send), timeout=5.0)
    assert svc._semaphore._value == MAX_CONCURRENT_STREAMS
    assert svc._slots.unauth_semaphore._value == MAX_UNAUTH_CONCURRENT_STREAMS
    assert svc._slots._active_by_ip == {}


# ---------------------------------------------------------------------------
# NV-38: Fair Eviction in EphemeralEvidenceStage & media_prevalidated Wiring
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nv38_fair_eviction_protects_victim_and_forwards_media_prevalidated(
    tmp_path: Path,
) -> None:
    assert MAX_DRAFTS_PER_CASE == 3
    assert MAX_DRAFTS_PER_OWNER == 6

    # 1. 1-IP attacker flooding 64 drafts cannot evict victim's draft
    stage = EphemeralEvidenceStage(max_entries=16)
    victim = stage.stage(
        parent_case_id="vs_victim",
        parent_is_demo=False,
        bundle=_dummy_bundle("vs_v_tmp"),
        allow_external_media_ai=False,
        owner_key="10.0.0.1",
    )
    for i in range(64):
        stage.stage(
            parent_case_id=f"vs_att1_case_{i}",
            parent_is_demo=False,
            bundle=_dummy_bundle(f"vs_a1_{i}"),
            allow_external_media_ai=False,
            owner_key="198.51.100.1",
        )
    att1_count = sum(1 for d in stage._drafts.values() if d.owner_key == "198.51.100.1")
    assert att1_count == MAX_DRAFTS_PER_OWNER
    assert stage.pop_for_parent(victim.draft_id, "vs_victim") is not None

    # 2. 2-IP attacker flooding 64 drafts into small max_entries=10 stage still cannot evict victim
    small_stage = EphemeralEvidenceStage(max_entries=10)
    victim2 = small_stage.stage(
        parent_case_id="vs_victim_2",
        parent_is_demo=False,
        bundle=_dummy_bundle("vs_v2_tmp"),
        allow_external_media_ai=False,
        owner_key="10.0.0.2",
    )
    for i in range(64):
        ip = "198.51.100.10" if i % 2 == 0 else "198.51.100.11"
        small_stage.stage(
            parent_case_id=f"vs_att2_case_{i}",
            parent_is_demo=False,
            bundle=_dummy_bundle(f"vs_a2_{i}"),
            allow_external_media_ai=False,
            owner_key=ip,
        )
    assert len(small_stage._drafts) <= 10
    assert small_stage.pop_for_parent(victim2.draft_id, "vs_victim_2") is not None

    # 3. Per-case cap evicts ONLY that case's oldest draft
    case_stage = EphemeralEvidenceStage(max_entries=16)
    c_drafts = [
        case_stage.stage(
            parent_case_id="vs_same",
            parent_is_demo=False,
            bundle=_dummy_bundle(f"vs_c_{i}"),
            allow_external_media_ai=False,
            owner_key="10.0.0.3",
        )
        for i in range(4)
    ]
    assert case_stage.pop_for_parent(c_drafts[0].draft_id, "vs_same") is None
    assert case_stage.pop_for_parent(c_drafts[3].draft_id, "vs_same") is not None

    # 4. stream_ephemeral_evidence forwards owner_key & media_prevalidated=True
    app = create_app(_make_settings(tmp_path, name="nv38_wire.db"))
    seen_kwargs: dict[str, Any] = {}

    async def _fake_run_ephemeral(**kwargs: Any) -> EphemeralAnalysisBundle:
        seen_kwargs.update(kwargs)
        return _dummy_bundle("vs_ephem_1")

    app.state.pipeline.run_ephemeral = _fake_run_ephemeral  # type: ignore[method-assign]
    stage_wire = EphemeralEvidenceStage()
    frames = [
        frame
        async for frame in stream_ephemeral_evidence(
            pipeline=app.state.pipeline,
            service=app.state.assistant_service,
            evidence_stage=stage_wire,
            parent_case_id="vs_parent_wire",
            parent_report=_sample_report("vs_parent_wire"),
            parent_is_demo=False,
            raw_msg="Kiểm tra bổ sung",
            img_items=[],
            aud_items=[],
            allow_external=False,
            owner_key="203.0.113.77",
            media_prevalidated=True,
        )
    ]
    assert any("evidence_report" in f for f in frames)
    assert seen_kwargs.get("media_prevalidated") is True
    assert len(stage_wire._drafts) == 1
    assert next(iter(stage_wire._drafts.values())).owner_key == "203.0.113.77"


# ---------------------------------------------------------------------------
# NV-40: Decoupled Telegram Webhook Limiter & Per-Chat/Sender Quota Guard
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nv40_telegram_chat_isolation_quota_and_no_orphan_claims(tmp_path: Path) -> None:
    cfg = _make_settings(tmp_path, name="nv40.db", rate_limit_per_minute=45)
    app = create_app(cfg)
    client = TestClient(app)

    with respx.mock(assert_all_called=False) as router:
        router.post(f"https://api.telegram.org/bot{cfg.telegram_bot_token}/sendMessage").mock(
            return_value=httpx.Response(200, json={"ok": True, "result": {"message_id": 1}})
        )
        router.post(f"https://api.telegram.org/bot{cfg.telegram_bot_token}/sendChatAction").mock(
            return_value=httpx.Response(200, json={"ok": True, "result": True})
        )

        # 50 /help updates from Chat A on the same relay IP never hit HTTP 429
        delivered_a = 0
        rate_limited_a = 0
        for uid in range(1, 51):
            resp = client.post(
                "/api/v1/bot/telegram",
                headers={"X-Telegram-Bot-Api-Secret-Token": cfg.telegram_webhook_secret},
                json={
                    "update_id": uid,
                    "message": {
                        "chat": {"id": 1001, "type": "private"},
                        "from": {"id": 1001},
                        "text": "/help",
                    },
                },
            )
            assert resp.status_code == 200
            body = resp.json()
            if body.get("delivered"):
                delivered_a += 1
            if body.get("rate_limited"):
                rate_limited_a += 1

        assert delivered_a == 8  # TG_SENDER_LIMIT_PER_MIN == 8
        assert rate_limited_a == 42

        # Chat B on the SAME relay IP succeeds immediately (zero cross-chat 429!)
        resp_b = client.post(
            "/api/v1/bot/telegram",
            headers={"X-Telegram-Bot-Api-Secret-Token": cfg.telegram_webhook_secret},
            json={
                "update_id": 500,
                "message": {
                    "chat": {"id": 2002, "type": "private"},
                    "from": {"id": 2002},
                    "text": "/help",
                },
            },
        )
        assert resp_b.status_code == 200
        assert resp_b.json()["delivered"] is True

        # Chat C heavy analysis capped at 4/min, 5th returns rate_limited=True, /help still passes!
        for idx in range(4):
            r_heavy = client.post(
                "/api/v1/bot/telegram",
                headers={"X-Telegram-Bot-Api-Secret-Token": cfg.telegram_webhook_secret},
                json={
                    "update_id": 600 + idx,
                    "message": {
                        "chat": {"id": 3003, "type": "private"},
                        "from": {"id": 3003},
                        "text": f"Kiểm tra link https://heavy-{idx}.top",
                    },
                },
            )
            assert r_heavy.status_code == 200 and r_heavy.json()["delivered"] is True

        r_heavy_5 = client.post(
            "/api/v1/bot/telegram",
            headers={"X-Telegram-Bot-Api-Secret-Token": cfg.telegram_webhook_secret},
            json={
                "update_id": 605,
                "message": {
                    "chat": {"id": 3003, "type": "private"},
                    "from": {"id": 3003},
                    "text": "Kiểm tra link https://heavy-5.top",
                },
            },
        )
        assert r_heavy_5.status_code == 200
        assert r_heavy_5.json() == {"ok": True, "delivered": False, "rate_limited": True}

        r_help_c = client.post(
            "/api/v1/bot/telegram",
            headers={"X-Telegram-Bot-Api-Secret-Token": cfg.telegram_webhook_secret},
            json={
                "update_id": 606,
                "message": {
                    "chat": {"id": 3003, "type": "private"},
                    "from": {"id": 3003},
                    "text": "/help",
                },
            },
        )
        assert r_help_c.status_code == 200 and r_help_c.json()["delivered"] is True

    # Zero orphan 'processing' rows left behind in telegram_updates
    with sqlite3.connect(cfg.sqlite_path) as conn:
        orphans = conn.execute(
            "SELECT COUNT(*) FROM telegram_updates WHERE status = 'processing'"
        ).fetchone()[0]
    assert orphans == 0


# ---------------------------------------------------------------------------
# NV-41: Permanent 4xx Quarantine, Transient Retries, /demo DoS & Pre-Cache Errors
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nv41_permanent_transient_quarantine_demo_dos_and_precache_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _make_settings(tmp_path, name="nv41.db")
    app = create_app(cfg)
    client = TestClient(app)

    # 1. _deliver_telegram_message classifies 400/403/404 as TelegramPermanentDeliveryError
    with respx.mock(assert_all_called=False) as router:
        for code in (400, 403, 404):
            router.post("https://api.telegram.org/botTOK/sendMessage").mock(
                return_value=httpx.Response(code, json={"ok": False, "description": "Forbidden"})
            )
            with pytest.raises(TelegramPermanentDeliveryError):
                await _deliver_telegram_message("TOK", 123, "hello")
        router.post("https://api.telegram.org/botTOK/sendMessage").mock(
            return_value=httpx.Response(503, json={"ok": False, "description": "Service Unavailable"})
        )
        with pytest.raises(TelegramDeliveryError) as exc_503:
            await _deliver_telegram_message("TOK", 123, "hello")
        assert not isinstance(exc_503.value, TelegramPermanentDeliveryError)

    # 2. _resolve_demo_id blocks Unicode superscript /demo ² and 5000-digit integer DoS
    assert _resolve_demo_id(app.state.pipeline, "²") is None
    assert _resolve_demo_id(app.state.pipeline, "9" * 5000) is None
    assert _resolve_demo_id(app.state.pipeline, "1") is not None

    with respx.mock(assert_all_called=False) as router:
        router.post(f"https://api.telegram.org/bot{cfg.telegram_bot_token}/sendChatAction").mock(
            return_value=httpx.Response(200, json={"ok": True, "result": True})
        )
        ok_msg = router.post(
            f"https://api.telegram.org/bot{cfg.telegram_bot_token}/sendMessage"
        ).mock(return_value=httpx.Response(200, json={"ok": True, "result": {"message_id": 1}}))

        for uid, txt in ((7001, "/demo ²"), (7002, "/demo " + ("9" * 5000))):
            r_demo = client.post(
                "/api/v1/bot/telegram",
                headers={"X-Telegram-Bot-Api-Secret-Token": cfg.telegram_webhook_secret},
                json={"update_id": uid, "message": {"chat": {"id": 4100}, "text": txt}},
            )
            assert r_demo.status_code == 200 and r_demo.json()["delivered"] is True
        assert ok_msg.call_count == 2

    # 3. Permanent HTTP 403 -> HTTP 200 permanent_error=True, replay -> quarantined (0 sends!)
    with respx.mock(assert_all_called=False) as router:
        send_403 = router.post(
            f"https://api.telegram.org/bot{cfg.telegram_bot_token}/sendMessage"
        ).mock(return_value=httpx.Response(403, json={"ok": False, "description": "bot was blocked"}))
        perm_upd = {
            "update_id": 7100,
            "message": {"chat": {"id": 4101, "type": "private"}, "from": {"id": 4101}, "text": "/help"},
        }
        r_p1 = client.post(
            "/api/v1/bot/telegram",
            headers={"X-Telegram-Bot-Api-Secret-Token": cfg.telegram_webhook_secret},
            json=perm_upd,
        )
        assert r_p1.status_code == 200
        assert r_p1.json() == {"ok": True, "delivered": False, "permanent_error": True}
        assert send_403.call_count == 1

        r_p2 = client.post(
            "/api/v1/bot/telegram",
            headers={"X-Telegram-Bot-Api-Secret-Token": cfg.telegram_webhook_secret},
            json=perm_upd,
        )
        assert r_p2.status_code == 200
        assert r_p2.json() == {"ok": True, "delivered": False, "quarantined": True}
        assert send_403.call_count == 1

    # 4. Transient HTTP 503 -> HTTP 502 on attempts 1 & 2, HTTP 200 quarantined on attempt 3 & 4
    with respx.mock(assert_all_called=False) as router:
        send_503 = router.post(
            f"https://api.telegram.org/bot{cfg.telegram_bot_token}/sendMessage"
        ).mock(return_value=httpx.Response(503, json={"ok": False}))
        trans_upd = {
            "update_id": 7200,
            "message": {"chat": {"id": 4102, "type": "private"}, "from": {"id": 4102}, "text": "/help"},
        }
        assert (
            client.post(
                "/api/v1/bot/telegram",
                headers={"X-Telegram-Bot-Api-Secret-Token": cfg.telegram_webhook_secret},
                json=trans_upd,
            ).status_code
            == 502
        )
        assert (
            client.post(
                "/api/v1/bot/telegram",
                headers={"X-Telegram-Bot-Api-Secret-Token": cfg.telegram_webhook_secret},
                json=trans_upd,
            ).status_code
            == 502
        )
        r_t3 = client.post(
            "/api/v1/bot/telegram",
            headers={"X-Telegram-Bot-Api-Secret-Token": cfg.telegram_webhook_secret},
            json=trans_upd,
        )
        assert r_t3.status_code == 200
        assert r_t3.json() == {"ok": True, "delivered": False, "quarantined": True}
        assert send_503.call_count == 3

        r_t4 = client.post(
            "/api/v1/bot/telegram",
            headers={"X-Telegram-Bot-Api-Secret-Token": cfg.telegram_webhook_secret},
            json=trans_upd,
        )
        assert r_t4.status_code == 200
        assert r_t4.json() == {"ok": True, "delivered": False, "quarantined": True}
        assert send_503.call_count == 3

    # 5. Pre-cache unexpected RuntimeError quarantines after 3 attempts (both msg & PDF callback)
    repo2 = CaseRepository(str(tmp_path / "nv41_precache.db"))
    repo2.init_db()
    pipe2 = AnalysisPipeline(settings=cfg, repo=repo2)

    async def _boom_run(**_kw: Any) -> AnalysisReport:
        raise RuntimeError("synthetic pre-cache boom")

    monkeypatch.setattr(pipe2, "run", _boom_run)
    crash_upd = {
        "update_id": 7300,
        "message": {
            "chat": {"id": 4200, "type": "private"},
            "from": {"id": 4200},
            "text": "Kiểm tra link https://crash.top",
        },
    }
    for _ in range(2):
        with pytest.raises(RuntimeError, match="synthetic pre-cache boom"):
            await handle_telegram_update(crash_upd, pipe2, cfg)
    r_c3 = await handle_telegram_update(crash_upd, pipe2, cfg)
    assert r_c3 == {"ok": True, "delivered": False, "quarantined": True}
    r_c4 = await handle_telegram_update(crash_upd, pipe2, cfg)
    assert r_c4 == {"ok": True, "delivered": False, "quarantined": True}

    # 6. Pre-cache unexpected RuntimeError in PDF callback quarantines after 3 attempts
    priv_rep = _sample_report(case_id="vs_tg_pdf_crash_01")
    repo2.save_report(
        priv_rep,
        owner_channel="telegram_private",
        owner_chat_hash=hash_telegram_private_owner(4300, 4300, pipe2.case_token_secret),
    )

    async def _boom_pdf(*_a: Any, **_kw: Any) -> bytes:
        raise RuntimeError("synthetic pdf boom")

    monkeypatch.setattr("app.services.telegram_bot.run_pdf_bounded", _boom_pdf)
    pdf_cb = {
        "update_id": 7400,
        "callback_query": {
            "id": "cb_crash_pdf",
            "from": {"id": 4300},
            "data": f"pdf:{priv_rep.case_id}",
            "message": {"chat": {"id": 4300, "type": "private"}},
        },
    }
    for _ in range(2):
        with pytest.raises(RuntimeError, match="synthetic pdf boom"):
            await handle_telegram_update(pdf_cb, pipe2, cfg)
    r_pc3 = await handle_telegram_update(pdf_cb, pipe2, cfg)
    assert r_pc3 == {"ok": True, "delivered": False, "pdf_sent": False, "quarantined": True}
    r_pc4 = await handle_telegram_update(pdf_cb, pipe2, cfg)
    assert r_pc4 == {"ok": True, "delivered": False, "pdf_sent": False, "quarantined": True}

    # 7. PDF callback busy/timeout releases claim cleanly and returns HTTP 200 pdf_sent=False
    async def _busy_tg_pdf(*_a: Any, **_kw: Any) -> bytes:
        raise MediaExecutorBusyError("busy")

    monkeypatch.setattr("app.services.telegram_bot.run_pdf_bounded", _busy_tg_pdf)
    with respx.mock(assert_all_called=False) as router:
        ack_route = router.post(
            f"https://api.telegram.org/bot{cfg.telegram_bot_token}/answerCallbackQuery"
        ).mock(return_value=httpx.Response(200, json={"ok": True, "result": True}))
        pdf_busy_cb = {
            "update_id": 7401,
            "callback_query": {
                "id": "cb_busy_pdf",
                "from": {"id": 4300},
                "data": f"pdf:{priv_rep.case_id}",
                "message": {"chat": {"id": 4300, "type": "private"}},
            },
        }
        r_pb = await handle_telegram_update(pdf_busy_cb, pipe2, cfg)
        assert r_pb["ok"] is True and r_pb["pdf_sent"] is False
        assert ack_route.call_count == 1
    with sqlite3.connect(str(tmp_path / "nv41_precache.db")) as conn:
        row = conn.execute(
            "SELECT status FROM telegram_updates WHERE update_id = 7401"
        ).fetchone()
    assert row is None


@pytest.mark.asyncio
async def test_wp11_polish_asgi24_stalled_finally_slow_send_google_aclose_radar_400_and_tg_anon(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.assistant_llm import stream_assistant_llm
    from app.services.telegram_limits import TelegramQuotaGuard

    app = create_app(_make_settings(tmp_path, name="wp11_polish.db"))
    svc = app.state.assistant_service
    scope_24: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "method": "POST",
        "path": "/api/v1/assistant/chat/stream",
    }

    async def _receive_wait() -> dict[str, Any]:
        await asyncio.sleep(30.0)
        return {"type": "http.disconnect"}

    async def _send_noop(_msg: dict[str, Any]) -> None:
        return None

    # 1. ASGI 2.4+ stalled generator + stalled finally MUST release Assistant slot within ~2.1s
    rel_24 = await svc.acquire_stream_slot(authenticated=False, client_ip="198.51.100.24")

    async def _stalled_finally_stream() -> AsyncIterator[str]:
        try:
            yield "event: status\ndata: {}\n\n"
            await asyncio.sleep(30.0)
        finally:
            await asyncio.sleep(10.0)

    resp_24 = _guarded_sse_response(svc, _stalled_finally_stream(), rel_24, outer_timeout_sec=0.1)
    t0 = time.perf_counter()
    await asyncio.wait_for(resp_24(scope_24, _receive_wait, _send_noop), timeout=4.0)
    elapsed_24 = time.perf_counter() - t0
    assert elapsed_24 < 3.0
    assert svc._semaphore._value == MAX_CONCURRENT_STREAMS
    assert svc._slots.unauth_semaphore._value == MAX_UNAUTH_CONCURRENT_STREAMS
    assert svc._slots._active_by_ip == {}

    # 2. ASGI 2.4+ slow send() MUST be cut off at outer_timeout_sec, close generator & release slot
    rel_slow = await svc.acquire_stream_slot(authenticated=True, client_ip="203.0.113.24")
    gen_closed = False

    async def _normal_stream() -> AsyncIterator[str]:
        nonlocal gen_closed
        try:
            yield "event: delta\ndata: {\"text\":\"a\"}\n\n"
            yield "event: delta\ndata: {\"text\":\"b\"}\n\n"
        finally:
            gen_closed = True

    async def _slow_send(msg: dict[str, Any]) -> None:
        if msg["type"] == "http.response.body":
            await asyncio.sleep(30.0)

    resp_slow = _guarded_sse_response(svc, _normal_stream(), rel_slow, outer_timeout_sec=0.1)
    t_slow = time.perf_counter()
    await asyncio.wait_for(resp_slow(scope_24, _receive_wait, _slow_send), timeout=2.0)
    assert (time.perf_counter() - t_slow) < 1.0
    assert gen_closed is True
    assert svc._semaphore._value == MAX_CONCURRENT_STREAMS
    assert svc._slots._active_by_ip == {}

    # 3. assistant_llm._raw_google_stream bounds hanging client.aio.aclose() to 2.0s
    class _HangingAcloseModels:
        async def generate_content_stream(self, **_kwargs: Any) -> AsyncIterator[Any]:
            async def _gen() -> AsyncIterator[Any]:
                yield SimpleNamespace(text="Cảnh báo lừa đảo.", candidates=[], prompt_feedback=None)

            return _gen()

    class _HangingAcloseClient:
        def __init__(self, *, api_key: str) -> None:
            _ = api_key
            self.aio = SimpleNamespace(models=_HangingAcloseModels(), aclose=self._hang_aclose)

        async def _hang_aclose(self) -> None:
            await asyncio.sleep(10.0)

    monkeypatch.setattr("app.services.assistant_llm.genai.Client", _HangingAcloseClient)
    g_cfg = Settings(_env_file=None, llm_provider="google_genai", gemini_api_key="hang_key_test")
    t_ac = time.perf_counter()
    chunks = [
        c
        async for c in stream_assistant_llm(
            g_cfg,
            system_instruction="sys",
            user_prompt="<UNTRUSTED_USER_CONTENT>\nhello\n</UNTRUSTED_USER_CONTENT>",
            timeout_sec=5.0,
        )
    ]
    assert "".join(chunks) == "Cảnh báo lừa đảo."
    assert (time.perf_counter() - t_ac) < 3.5

    # 4. POST /api/v1/radar/block-rules with punctuation-only value="..." returns HTTP 400 (not 500)
    client = TestClient(app)
    for bad_type in ("domain", "phone", "bank_account"):
        r_bad = client.post(
            "/api/v1/radar/block-rules",
            json={
                "ioc_type": bad_type,
                "value": "...",
                "reason": "Test malformed IOC value",
                "analyst_pin": "2026",
            },
        )
        assert r_bad.status_code == 400, f"Expected 400 for {bad_type}='...'"

    # 5. TelegramQuotaGuard throttles anonymous updates (chat_id=None, sender_user_id=None)
    tg_guard = TelegramQuotaGuard(chat_per_min=2, sender_per_min=5, heavy_per_min=1)
    assert tg_guard.allow_message(chat_id=None, sender_user_id=None) is True
    assert tg_guard.allow_message(chat_id=None, sender_user_id=None) is True
    assert tg_guard.allow_message(chat_id=None, sender_user_id=None) is False
    assert tg_guard.allow_heavy(chat_id=None, sender_user_id=None) is True
    assert tg_guard.allow_heavy(chat_id=None, sender_user_id=None) is False

