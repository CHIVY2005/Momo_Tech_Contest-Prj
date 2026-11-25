from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def _make_test_client(tmp_path: Path) -> TestClient:
    cfg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "api_test.db"),
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
        enable_local_stt=False,
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

    for demo in demos:
        res = client.post("/api/v1/analyze", data={"demo_id": demo["demo_id"]})
        assert res.status_code == 200, f"Demo {demo['demo_id']} failed: {res.text}"
        body = res.json()
        if demo["expected_verdict"] == "SAFE":
            assert body["verdict"] == "SAFE"
            assert body["risk_score"] <= 24
        else:
            assert body["risk_score"] >= 55

    # Verify case lookup and PDF download on the last analyzed case
    case_id = body["case_id"]
    case_res = client.get(f"/api/v1/cases/{case_id}")
    assert case_res.status_code == 200

    pdf_res = client.get(f"/api/v1/cases/{case_id}/report.pdf")
    assert pdf_res.status_code == 200
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
