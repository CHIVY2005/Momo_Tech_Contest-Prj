import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from app.config import Settings
from app.core.case_tokens import hash_telegram_private_owner, issue_case_access_token
from app.main import create_app
from app.schemas import AnalysisReport


def _make_test_client(tmp_path: Path) -> TestClient:
    cfg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "api_test.db"),
        gemini_api_key="",
        gemini_backup_api_key="",
        telegram_bot_token="",
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
        enable_local_stt=False,
        app_env="demo",
        analyst_pin="2026",
        telegram_webhook_secret="tg_secret_2026",
        rate_limit_per_minute=200,
    )
    return TestClient(create_app(cfg))


def test_health_headers_and_all_five_canonical_demos(tmp_path: Path) -> None:
    client = _make_test_client(tmp_path)

    health = client.get("/api/v1/health")
    assert health.status_code == 200
    assert health.headers.get("x-content-type-options") == "nosniff"
    assert health.headers.get("x-frame-options") == "DENY"

    demos_res = client.get("/api/v1/demos")
    assert demos_res.status_code == 200
    demos = demos_res.json()
    assert len(demos) == 5

    last_token: str | None = None
    for demo in demos:
        res = client.post("/api/v1/analyze", data={"demo_id": demo["demo_id"]})
        assert res.status_code == 200, f"Demo {demo['demo_id']} failed: {res.text}"
        assert res.headers.get("x-case-access-token")
        assert "no-store" in res.headers.get("cache-control", "").lower()
        last_token = res.headers.get("x-case-access-token")
        body = res.json()
        if demo["expected_verdict"] == "SAFE":
            assert body["verdict"] == "SAFE"
            assert body["risk_score"] <= 24
        else:
            assert body["risk_score"] >= 55

    # Verify case lookup and PDF download require X-Case-Access-Token
    case_id = body["case_id"]
    assert last_token is not None
    assert client.get(f"/api/v1/cases/{case_id}").status_code == 403
    assert client.get(f"/api/v1/cases/{case_id}/report.pdf").status_code == 403

    auth_headers = {"X-Case-Access-Token": last_token}
    case_res = client.get(f"/api/v1/cases/{case_id}", headers=auth_headers)
    assert case_res.status_code == 200
    assert "no-store" in case_res.headers.get("cache-control", "").lower()
    assert "x-case-access-token" in case_res.headers.get("vary", "").lower()

    pdf_res = client.get(f"/api/v1/cases/{case_id}/report.pdf", headers=auth_headers)
    assert pdf_res.status_code == 200
    assert "no-store" in pdf_res.headers.get("cache-control", "").lower()
    assert "x-case-access-token" in pdf_res.headers.get("vary", "").lower()
    assert pdf_res.headers["content-type"].startswith("application/pdf")
    assert pdf_res.content[:5] == b"%PDF-"


def test_closed_loop_radar_block_rules_pin_protection_and_reset(tmp_path: Path) -> None:
    client = _make_test_client(tmp_path)

    graph = client.get("/api/v1/radar/graph").json()
    assert len(graph["campaigns"]) >= 1

    # Wrong PIN -> 403; Protected SAFE demo IOC -> 409
    bad_pin = client.post(
        "/api/v1/radar/block-rules",
        json={
            "ioc_type": "bank_account",
            "value": "999888777666",
            "reason": "Mule ring",
            "analyst_pin": "0000",
        },
    )
    assert bad_pin.status_code == 403

    sabotage = client.post(
        "/api/v1/radar/block-rules",
        json={
            "ioc_type": "domain",
            "value": "vietcombank.com.vn",
            "reason": "Sabotage",
            "analyst_pin": "2026",
        },
    )
    assert sabotage.status_code == 409

    # Valid 1-click block rule immediately blocks subsequent wallet transfer (>= 95)
    ok_rule = client.post(
        "/api/v1/radar/block-rules",
        json={
            "ioc_type": "bank_account",
            "value": "999888777666",
            "reason": "Confirmed mule account",
            "analyst_pin": "2026",
        },
    )
    assert ok_rule.status_code == 200

    tx = client.post(
        "/api/v1/analyze",
        data={
            "mode": "wallet_transfer",
            "in_active_call": "true",
            "text": "Chuyển gấp 12 triệu vào STK 999888777666",
        },
    )
    assert tx.status_code == 200
    tx_body = tx.json()
    assert tx_body["active_block_rule_hit"] is True
    assert tx_body["risk_score"] >= 95
    assert tx_body["actions"]["pre_transfer"]["should_hold_transfer"] is True

    # Single-rule revoke removes only that specific rule_id before full reset
    rule_id = ok_rule.json()["rule_id"]
    rev_res = client.post(
        f"/api/v1/radar/block-rules/{rule_id}/revoke",
        json={"analyst_pin": "2026"},
    )
    assert rev_res.status_code == 200
    assert rev_res.json()["revoked"] is True

    # Reset restores clean transient state
    reset_res = client.post("/api/v1/radar/block-rules/reset", json={"analyst_pin": "2026"})
    assert reset_res.status_code == 200


def test_empty_analyze_rejected_and_backup_gemini_key_reflected_in_health(tmp_path: Path) -> None:
    cfg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "backup_key.db"),
        gemini_api_key="",
        gemini_backup_api_key="backup_only_key_123",
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
    )
    client = TestClient(create_app(cfg))

    health = client.get("/api/v1/health").json()
    assert health["gemini_configured"] is True

    empty_sync = client.post("/api/v1/analyze", data={"mode": "personal", "text": "   "})
    assert empty_sync.status_code == 400

    empty_sse = client.post("/api/v1/analyze/stream", data={"mode": "personal", "text": ""})
    assert empty_sse.status_code == 400


def _parse_sse_events(raw_stream: str) -> list[tuple[str, dict[str, Any]]]:
    events: list[tuple[str, dict[str, Any]]] = []
    for block in raw_stream.split("\n\n"):
        ev_type = ""
        ev_data = ""
        for ln in block.splitlines():
            if ln.startswith("event:"):
                ev_type = ln.split(":", 1)[1].strip()
            elif ln.startswith("data:"):
                ev_data = ln.split(":", 1)[1].strip()
        if ev_type and ev_data:
            events.append((ev_type, json.loads(ev_data)))
    return events


def test_case_access_token_enforcement_cross_channel_and_sse_session(tmp_path: Path) -> None:
    cfg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "case_auth.db"),
        gemini_api_key="",
        gemini_backup_api_key="",
        telegram_bot_token="",
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
        enable_local_stt=False,
        app_env="demo",
        analyst_pin="2026",
        rate_limit_per_minute=200,
    )
    app = create_app(cfg)
    client = TestClient(app)
    secret: str = app.state.case_token_secret
    repo = app.state.repo

    # 1. Sync /analyze issues X-Case-Access-Token + Cache-Control: no-store
    res_a = client.post(
        "/api/v1/analyze",
        data={"mode": "personal", "text": "NAPAS đổi điểm tại https://napas-vip.top/auth"},
    )
    assert res_a.status_code == 200
    case_a = res_a.json()["case_id"]
    token_a = res_a.headers.get("x-case-access-token")
    assert token_a is not None
    assert "no-store" in res_a.headers.get("cache-control", "").lower()

    # 2. SSE /analyze/stream sets Cache-Control: no-store, no-cache and emits event: session after result
    with client.stream(
        "POST",
        "/api/v1/analyze/stream",
        data={"mode": "personal", "text": "Kiểm tra liên kết https://vneid-update.top/apk"},
    ) as sse_resp:
        assert sse_resp.status_code == 200
        cc = sse_resp.headers.get("cache-control", "").lower()
        assert "no-store" in cc and "no-cache" in cc
        stream_text = "".join(sse_resp.iter_text())

    events = _parse_sse_events(stream_text)
    event_names = [name for name, _ in events]
    assert "result" in event_names and "session" in event_names
    assert event_names.index("result") < event_names.index("session")
    result_b = next(data for name, data in events if name == "result")
    session_b = next(data for name, data in events if name == "session")
    case_b = result_b["case_id"]
    token_b = session_b["case_access_token"]
    assert session_b["case_id"] == case_b
    assert session_b["expires_at"]

    # Valid token_b unlocks case_b JSON + PDF with privacy cache headers
    ok_b = client.get(f"/api/v1/cases/{case_b}", headers={"X-Case-Access-Token": token_b})
    assert ok_b.status_code == 200
    assert "no-store" in ok_b.headers.get("cache-control", "").lower()
    assert "x-case-access-token" in ok_b.headers.get("vary", "").lower()
    ok_b_pdf = client.get(
        f"/api/v1/cases/{case_b}/report.pdf", headers={"X-Case-Access-Token": token_b}
    )
    assert ok_b_pdf.status_code == 200
    assert ok_b_pdf.content[:5] == b"%PDF-"
    assert "no-store" in ok_b_pdf.headers.get("cache-control", "").lower()
    assert "x-case-access-token" in ok_b_pdf.headers.get("vary", "").lower()

    # 3. Missing, tampered, wrong-case, expired, and missing-case requests all return uniform 403
    expired_token, _ = issue_case_access_token(case_a, secret, ttl_seconds=60, now=1_000_000)
    ghost_id = "vs_" + ("0" * 32)
    ghost_valid_token, _ = issue_case_access_token(ghost_id, secret)

    expected_detail: str | None = None
    for url, hdrs in [
        (f"/api/v1/cases/{case_a}", {}),
        (f"/api/v1/cases/{case_a}/report.pdf", {}),
        (f"/api/v1/cases/{case_a}", {"X-Case-Access-Token": token_a[:-4] + "0000"}),
        (f"/api/v1/cases/{case_a}/report.pdf", {"X-Case-Access-Token": token_a[:-4] + "0000"}),
        (f"/api/v1/cases/{case_b}", {"X-Case-Access-Token": token_a}),
        (f"/api/v1/cases/{case_a}", {"X-Case-Access-Token": expired_token}),
        (f"/api/v1/cases/{ghost_id}", {}),
        (f"/api/v1/cases/{ghost_id}", {"X-Case-Access-Token": ghost_valid_token}),
    ]:
        r = client.get(url, headers=hdrs)
        assert r.status_code == 403, f"Expected 403 for {url} with {hdrs}, got {r.status_code}"
        assert "no-store" in r.headers.get("cache-control", "").lower()
        assert "x-case-access-token" in r.headers.get("vary", "").lower()
        detail = r.json()["detail"]
        if expected_detail is None:
            expected_detail = detail
        else:
            assert detail == expected_detail

    # 4. Cross-channel & legacy isolation: legacy_locked, telegram_private, telegram_group_locked -> 403
    base_report = AnalysisReport.model_validate(res_a.json())
    for idx, (channel, owner_hash) in enumerate(
        [
            ("legacy_locked", None),
            ("telegram_private", hash_telegram_private_owner(1234, 1234, secret)),
            ("telegram_group_locked", None),
        ],
        start=1,
    ):
        cid = f"vs_{idx:032x}"
        cloned = base_report.model_copy(update={"case_id": cid})
        repo.save_report(cloned, owner_channel=channel, owner_chat_hash=owner_hash)
        forged_web_token, _ = issue_case_access_token(cid, secret)
        r_json = client.get(f"/api/v1/cases/{cid}", headers={"X-Case-Access-Token": forged_web_token})
        r_pdf = client.get(
            f"/api/v1/cases/{cid}/report.pdf", headers={"X-Case-Access-Token": forged_web_token}
        )
        assert r_json.status_code == 403
        assert r_pdf.status_code == 403
        assert r_json.json()["detail"] == expected_detail

    # 5. Simulation mode must NOT issue web access tokens on sync or SSE endpoints
    sim_sync = client.post(
        "/api/v1/analyze",
        data={"mode": "personal", "is_simulation": "true", "text": "Mô phỏng kiểm tra tin nhắn"},
    )
    assert sim_sync.status_code == 200
    assert "x-case-access-token" not in {k.lower() for k in sim_sync.headers}

    with client.stream(
        "POST",
        "/api/v1/analyze/stream",
        data={"mode": "personal", "is_simulation": "true", "text": "Mô phỏng luồng SSE"},
    ) as sim_sse:
        assert sim_sse.status_code == 200
        sim_events = _parse_sse_events("".join(sim_sse.iter_text()))
    assert any(name == "result" for name, _ in sim_events)
    assert not any(name == "session" for name, _ in sim_events)
