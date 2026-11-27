"""Security, HMAC-SHA256, audit log, production-seed, and simulation isolation tests for /radar."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config import Settings
from app.db.repository import CaseRepository, ProtectedDemoIocError
from app.main import create_app
from app.schemas import ExtractedIOCs
from app.services.ioc_extractor import hash_ioc


def test_hmac_sha256_ioc_hashing_and_repository_matching(tmp_path: Path) -> None:
    plain_hash = hash_ioc("bank_account", "999888777666")
    keyed_hash = hash_ioc("bank_account", "999888777666", hmac_key="super_secret_hmac_key_2026")
    assert plain_hash != keyed_hash
    assert len(keyed_hash) == 64

    repo = CaseRepository(
        str(tmp_path / "hmac_radar.db"),
        default_ttl_minutes=30,
        ioc_hmac_secret="super_secret_hmac_key_2026",
        app_env="production",
    )
    repo.init_db()
    repo.seed_if_empty(None, protected_iocs=[("domain", "vietcombank.com.vn")])

    # Protected official domain still blocked under HMAC-SHA256
    with pytest.raises(ProtectedDemoIocError):
        repo.add_block_rule("domain", reason="Sabotage test", raw_value="vietcombank.com.vn")

    # Rule created & matched consistently via keyed HMAC-SHA256
    t0 = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)
    rule = repo.add_block_rule(
        "bank_account",
        reason="Tài khoản nghi nhận tiền lừa đảo",
        raw_value="999888777666",
        ttl_minutes=15,
        now=t0,
    )
    assert rule.masked_value == "99****66"

    hits = repo.match_active_block_rules(
        ExtractedIOCs(phones=[], bank_accounts=["999888777666"], urls=[], domains=[], brands=[]),
        now=t0,
    )
    assert len(hits) == 1
    assert hits[0].rule_id == rule.rule_id


def test_production_env_skips_demo_seed_enforces_hmac_policy_and_protects_banks(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            app_env="production",
            analyst_pin="StrongPin#2026",
            ioc_hmac_secret="short",
        )

    cfg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "prod_radar.db"),
        gemini_api_key="",
        gemini_backup_api_key="",
        telegram_bot_token="",
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
        enable_local_stt=False,
        app_env="production",
        analyst_pin="StrongPin#2026",
        ioc_hmac_secret="prod_dedicated_hmac_secret_2026_v2",
        case_token_secret="prod_dedicated_case_token_secret_2026_v2",
        rate_limit_per_minute=200,
    )
    client = TestClient(create_app(cfg))

    graph = client.get("/api/v1/radar/graph").json()
    assert graph["data_scope"] == "live"
    assert graph["stats"]["demo_campaigns"] == 0
    assert graph["stats"]["emerging_campaigns"] == 0

    # Official bank domain remains protected even without demo seed campaigns
    blocked_official = client.post(
        "/api/v1/radar/block-rules",
        json={
            "ioc_type": "domain",
            "value": "vietcombank.com.vn",
            "reason": "Test official protection",
            "analyst_pin": "StrongPin#2026",
        },
    )
    assert blocked_official.status_code == 409


def test_simulation_does_not_pollute_stats_and_admin_actions_record_pii_free_audit_logs(
    tmp_path: Path,
) -> None:
    cfg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "sim_audit.db"),
        gemini_api_key="",
        gemini_backup_api_key="",
        telegram_bot_token="",
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
        enable_local_stt=False,
        app_env="demo",
        analyst_pin="PinSec#8842",
        ioc_hmac_secret="demo_hmac_secret_key_for_test_2026",
        rate_limit_per_minute=200,
    )
    client = TestClient(create_app(cfg))

    before = client.get("/api/v1/radar/graph").json()
    assert before["data_scope"] == "demo_only"
    assert before["stats"]["total_cases"] == 0
    initial_camp_cases = {c["campaign_id"]: c["case_count"] for c in before["campaigns"]}

    # Failed auth creates denied audit event without exposing PIN
    bad = client.post(
        "/api/v1/radar/block-rules",
        json={
            "ioc_type": "bank_account",
            "value": "999888777666",
            "reason": "Thử sai PIN",
            "analyst_pin": "999999",
        },
    )
    assert bad.status_code == 403

    # Create real block rule with custom TTL
    created = client.post(
        "/api/v1/radar/block-rules",
        json={
            "ioc_type": "bank_account",
            "value": "999888777666",
            "reason": "Tài khoản nghi nhận tiền giả danh công an",
            "ttl_minutes": 15,
            "analyst_pin": "PinSec#8842",
        },
    )
    assert created.status_code == 200
    rule_id = created.json()["rule_id"]

    # Run simulation -> MUST match active rule & populate matched_block_rules, ZERO DB pollution
    sim = client.post(
        "/api/v1/analyze",
        data={
            "mode": "wallet_transfer",
            "in_active_call": "true",
            "is_simulation": "true",
            "text": "Chuyển gấp 15.000.000 VND vào STK 999888777666 theo yêu cầu cán bộ",
        },
    )
    assert sim.status_code == 200
    sim_body = sim.json()
    assert sim_body["is_simulation"] is True
    assert sim_body["active_block_rule_hit"] is True
    assert len(sim_body["matched_block_rules"]) == 1
    assert sim_body["matched_block_rules"][0]["rule_id"] == rule_id
    assert sim_body["risk_score"] >= 95

    after_sim = client.get("/api/v1/radar/graph").json()
    assert after_sim["stats"]["total_cases"] == 0
    for c in after_sim["campaigns"]:
        assert c["case_count"] == initial_camp_cases[c["campaign_id"]]

    # Revoke rule and verify complete PII-free audit trail
    rev = client.post(
        f"/api/v1/radar/block-rules/{rule_id}/revoke",
        json={"analyst_pin": "PinSec#8842"},
    )
    assert rev.status_code == 200 and rev.json()["revoked"] is True

    final_graph = client.get("/api/v1/radar/graph").json()
    actions = [ev["action"] for ev in final_graph["recent_audit_logs"]]
    assert "revoke_rule" in actions
    assert "create_rule" in actions
    assert "auth_failed" in actions
    audit_dump = str(final_graph["recent_audit_logs"])
    assert "999888777666" not in audit_dump
    assert "999999" not in audit_dump
    assert "PinSec#8842" not in audit_dump
