"""WP-4 security remediation tests covering NV-10, NV-12, NV-14/NV-03, NV-15, and NV-23."""

from __future__ import annotations

import asyncio
import io
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from PIL import Image
from pydantic import ValidationError

from app.config import Settings
from app.core.case_tokens import generate_case_id, resolve_case_token_secret
from app.db.repository import (
    MAX_DOMAIN_PARENT_LEVELS,
    MAX_LOOKUP_IOC_HASHES,
    CaseRepository,
    sanitize_rule_id,
)
from app.main import create_app
from app.schemas import AnalysisReport, ExtractedIOCs, ReceiptLogicResult
from app.services.ioc_extractor import (
    MAX_EXTRACTED_ACCOUNTS,
    MAX_EXTRACTED_DOMAINS,
    MAX_EXTRACTED_PHONES,
    MAX_EXTRACTED_URLS,
    extract_iocs,
)
from app.services.pii_scrubber import scrub_persisted_pii
from app.services.pipeline import AnalysisPipeline
from app.services.telegram_bot import handle_telegram_update


def _make_png_bytes() -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (64, 64), color=(15, 25, 45)).save(buf, format="PNG")
    return buf.getvalue()


def _prod_base_kwargs(tmp_path: Path, **overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "_env_file": None,
        "sqlite_path": str(tmp_path / "wp4_prod.db"),
        "app_env": "production",
        "analyst_pin": "ProdPin#9876",
        "ioc_hmac_secret": "hmac_prod_dedicated_secret_alpha_2026",
        "case_token_secret": "token_prod_dedicated_secret_beta_2026_xyz",
        "gemini_api_key": "",
        "gemini_backup_api_key": "",
        "telegram_bot_token": "",
        "telegram_webhook_secret": "",
        "enable_live_network_checks": False,
        "enable_playwright_sandbox": False,
        "enable_local_ocr": False,
        "enable_local_stt": False,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# NV-10: Production Secret Isolation & Telegram Webhook Secret Policy
# ---------------------------------------------------------------------------


def test_nv10_production_secret_isolation_and_webhook_secret_validation(tmp_path: Path) -> None:
    # 1. Missing ioc_hmac_secret or case_token_secret rejected in production
    with pytest.raises(ValidationError):
        Settings(**_prod_base_kwargs(tmp_path, ioc_hmac_secret=""))
    with pytest.raises(ValidationError):
        Settings(**_prod_base_kwargs(tmp_path, case_token_secret=""))

    # 2. Reusing analyst_pin or sharing ioc_hmac_secret == case_token_secret rejected in prod
    long_pin = "ProdPin#9876543210_superlong_32chars!"
    with pytest.raises(ValidationError):
        Settings(**_prod_base_kwargs(tmp_path, analyst_pin=long_pin, ioc_hmac_secret=long_pin))
    with pytest.raises(ValidationError):
        Settings(**_prod_base_kwargs(tmp_path, analyst_pin=long_pin, case_token_secret=long_pin))
    shared_32 = "shared_secret_value_for_both_1234567890"
    with pytest.raises(ValidationError):
        Settings(
            **_prod_base_kwargs(
                tmp_path, ioc_hmac_secret=shared_32, case_token_secret=shared_32
            )
        )

    # 3. telegram_webhook_secret rejects placeholders & == pin in ANY env; requires >=24 in prod
    for bad_wh in ("change_me", "changeme_webhook_000000000000", "2026", "2026_hook"):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, app_env="demo", telegram_webhook_secret=bad_wh)
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            app_env="development",
            analyst_pin="DevPin#9999",
            telegram_webhook_secret="DevPin#9999",
        )
    with pytest.raises(ValidationError):
        Settings(**_prod_base_kwargs(tmp_path, telegram_webhook_secret="short_wh_secret_123"))
    # Production with TELEGRAM_BOT_TOKEN requires TELEGRAM_WEBHOOK_SECRET >= 24 chars
    with pytest.raises(ValidationError):
        Settings(
            **_prod_base_kwargs(
                tmp_path,
                telegram_bot_token="123456:SYNTHETIC_PROD_TOKEN",
                telegram_webhook_secret="",
            )
        )
    valid_prod = Settings(
        **_prod_base_kwargs(
            tmp_path,
            telegram_bot_token="123456:SYNTHETIC_PROD_TOKEN",
            telegram_webhook_secret="wh_prod_strong_secret_token_987654",
        )
    )
    assert valid_prod.resolved_ioc_hmac_secret == "hmac_prod_dedicated_secret_alpha_2026"
    assert resolve_case_token_secret(valid_prod) == "token_prod_dedicated_secret_beta_2026_xyz"

    # 4. model_construct bypass: no SHA-256(ANALYST_PIN) derivation & create_app fails closed
    bypassed = Settings.model_construct(
        **_prod_base_kwargs(tmp_path, ioc_hmac_secret=""),
    )
    assert bypassed.resolved_ioc_hmac_secret == ""
    with pytest.raises(ValueError, match="IOC_HMAC_SECRET"):
        create_app(bypassed)

    bypassed_short_tok = Settings.model_construct(
        **_prod_base_kwargs(tmp_path, case_token_secret="too_short"),
    )
    with pytest.raises(ValueError, match="CASE_TOKEN_SECRET"):
        resolve_case_token_secret(bypassed_short_tok)


# ---------------------------------------------------------------------------
# NV-12: Telegram update_id Context Binding, Ownership Re-Verification & Hygiene
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nv12_telegram_claim_context_mismatch_cache_preserve_and_webhook_isolation(
    tmp_path: Path,
) -> None:
    db_file = tmp_path / "nv12.db"
    # Pre-seed legacy telegram_updates schema without metadata columns to verify ALTER TABLE
    recent_ts = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    with sqlite3.connect(str(db_file)) as conn:
        conn.executescript(
            """
            CREATE TABLE telegram_updates (
                update_id INTEGER PRIMARY KEY,
                case_id TEXT,
                reply_text TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            """
        )
        conn.execute(
            "INSERT INTO telegram_updates (update_id, case_id, reply_text, created_at) "
            "VALUES (1000, NULL, 'legacy reply', ?)",
            (recent_ts,),
        )

    repo = CaseRepository(str(db_file))
    repo.init_db()

    # Legacy NULL-metadata row rejects claim from any real chat (fail closed)
    assert repo.claim_telegram_update(1000, chat_id=5001, sender_user_id=5001)[0] == "mismatch"

    # 1. Context mismatch blocked on in_progress, expired-lease reclaim, AND completed!
    st1, _, _ = repo.claim_telegram_update(
        2001,
        owner_id="w1",
        lease_seconds=120,
        chat_id=7001,
        sender_user_id=7001,
        chat_type="private",
        update_kind="message",
    )
    assert st1 == "claimed"
    # While in_progress: mismatched chat, sender, chat_type, or update_kind -> mismatch
    assert (
        repo.claim_telegram_update(
            2001, owner_id="w2", chat_id=9999, sender_user_id=7001, chat_type="private"
        )[0]
        == "mismatch"
    )
    assert (
        repo.claim_telegram_update(
            2001, owner_id="w2", chat_id=7001, sender_user_id=8888, chat_type="private"
        )[0]
        == "mismatch"
    )
    assert (
        repo.claim_telegram_update(
            2001, owner_id="w2", chat_id=7001, sender_user_id=7001, chat_type="group"
        )[0]
        == "mismatch"
    )
    assert (
        repo.claim_telegram_update(
            2001,
            owner_id="w2",
            chat_id=7001,
            sender_user_id=7001,
            chat_type="private",
            update_kind="pdf_callback",
        )[0]
        == "mismatch"
    )
    # Same context -> in_progress
    assert (
        repo.claim_telegram_update(
            2001, owner_id="w2", chat_id=7001, sender_user_id=7001, chat_type="private"
        )[0]
        == "in_progress"
    )

    # Expired lease reclaim ALSO enforces context match
    st_exp, _, _ = repo.claim_telegram_update(
        2002,
        owner_id="w1",
        lease_seconds=0,
        chat_id=7002,
        sender_user_id=7002,
        chat_type="private",
        update_kind="message",
    )
    assert st_exp == "claimed"
    assert (
        repo.claim_telegram_update(
            2002, owner_id="w2", chat_id=9999, sender_user_id=7002, chat_type="private"
        )[0]
        == "mismatch"
    )
    assert (
        repo.claim_telegram_update(
            2002, owner_id="w2", chat_id=7002, sender_user_id=7002, chat_type="private"
        )[0]
        == "claimed"
    )

    # save_telegram_update_cache with owner_id=None PRESERVES stored metadata columns!
    repo.save_telegram_update_cache(2002, None, "done_reply", owner_id=None)
    assert (
        repo.claim_telegram_update(
            2002, owner_id="w3", chat_id=9999, sender_user_id=7002, chat_type="private"
        )[0]
        == "mismatch"
    )
    st_ok, _, rep_ok = repo.claim_telegram_update(
        2002, owner_id="w3", chat_id=7002, sender_user_id=7002, chat_type="private"
    )
    assert (st_ok, rep_ok) == ("cached", "done_reply")

    # 2. End-to-end Telegram webhook replay isolation & response hygiene
    cfg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "nv12_bot.db"),
        gemini_api_key="",
        gemini_backup_api_key="",
        telegram_bot_token="888777:SYNTHETIC_TOKEN",
        telegram_webhook_secret="nv12_webhook_secret_token_123456",
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
        enable_local_ocr=False,
        enable_local_stt=False,
    )
    bot_repo = CaseRepository(cfg.sqlite_path)
    bot_repo.init_db()
    pipe = AnalysisPipeline(settings=cfg, repo=bot_repo)

    with respx.mock(assert_all_called=False) as router:
        msg_route = router.post(
            "https://api.telegram.org/bot888777:SYNTHETIC_TOKEN/sendMessage"
        ).mock(return_value=httpx.Response(200, json={"ok": True, "result": {"message_id": 1}}))
        ack_route = router.post(
            "https://api.telegram.org/bot888777:SYNTHETIC_TOKEN/answerCallbackQuery"
        ).mock(return_value=httpx.Response(200, json={"ok": True, "result": True}))
        router.post(
            "https://api.telegram.org/bot888777:SYNTHETIC_TOKEN/sendChatAction"
        ).mock(return_value=httpx.Response(200, json={"ok": True, "result": True}))

        # Legitimate private message
        r1 = await handle_telegram_update(
            {
                "update_id": 3001,
                "message": {
                    "chat": {"id": 5100, "type": "private"},
                    "from": {"id": 5100},
                    "text": "Kiểm tra link https://napas-nv12.top",
                },
            },
            pipe,
            cfg,
        )
        assert r1["delivered"] is True
        assert "reply_text" not in r1
        cid = r1["case_id"]
        assert msg_route.call_count == 1

        # Cross-chat replay of update_id=3001 -> ignored, zero sendMessage, zero reply_text/case_id
        r_spoof = await handle_telegram_update(
            {
                "update_id": 3001,
                "message": {
                    "chat": {"id": 9999, "type": "private"},
                    "from": {"id": 9999},
                    "text": "steal cached reply",
                },
            },
            pipe,
            cfg,
        )
        assert r_spoof == {"ok": True, "delivered": False, "ignored": True}
        assert msg_route.call_count == 1

        # Cross-kind PDF callback colliding with message update_id=3001 -> ignored, ZERO ack!
        r_pdf_spoof = await handle_telegram_update(
            {
                "update_id": 3001,
                "callback_query": {
                    "id": "cb_spoof",
                    "from": {"id": 5100},
                    "data": f"pdf:{cid}",
                    "message": {"chat": {"id": 5100, "type": "private"}},
                },
            },
            pipe,
            cfg,
        )
        assert r_pdf_spoof == {"ok": True, "delivered": False, "pdf_sent": False, "ignored": True}
        assert ack_route.call_count == 0

        # Message without chat_id -> omits reply_text, case_id, verdict, risk_score; cached retry ignored
        r_no_chat = await handle_telegram_update(
            {"update_id": 3002, "message": {"text": "Kiểm tra tin nhắn không có chat id"}},
            pipe,
            cfg,
        )
        assert "reply_text" not in r_no_chat
        assert "case_id" not in r_no_chat
        assert "verdict" not in r_no_chat
        assert "risk_score" not in r_no_chat
        r_no_chat_retry = await handle_telegram_update(
            {"update_id": 3002, "message": {"text": "retry"}},
            pipe,
            cfg,
        )
        assert r_no_chat_retry == {"ok": True, "delivered": False, "ignored": True}

        # Tampered owner_chat_hash in cases table causes same-chat cached retry to fail closed!
        with sqlite3.connect(cfg.sqlite_path) as raw_conn:
            raw_conn.execute(
                "UPDATE cases SET owner_chat_hash = '0000' WHERE case_id = ?",
                (cid,),
            )
        r_tampered = await handle_telegram_update(
            {
                "update_id": 3001,
                "message": {
                    "chat": {"id": 5100, "type": "private"},
                    "from": {"id": 5100},
                    "text": "retry",
                },
            },
            pipe,
            cfg,
        )
        assert r_tampered == {"ok": True, "delivered": False, "ignored": True}
        assert msg_route.call_count == 1


# ---------------------------------------------------------------------------
# NV-14 & NV-03: Input Bounds, Thread Offload, Priority IOC Caps & DB Caps
# ---------------------------------------------------------------------------


def test_nv14_and_nv03_analyze_bounds_thread_offload_and_ioc_db_caps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "nv14.db"),
        gemini_api_key="",
        gemini_backup_api_key="",
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
        enable_local_ocr=False,
        enable_local_stt=False,
        rate_limit_per_minute=200,
    )
    app = create_app(cfg)
    client = TestClient(app)

    # 1. Oversize text (>8000), url (>2048), expected_merchant_account (>64) -> HTTP 400 on sync & SSE
    for endpoint in ("/api/v1/analyze", "/api/v1/analyze/stream"):
        assert client.post(endpoint, data={"text": "A" * 8_001}).status_code == 400
        assert (
            client.post(endpoint, data={"url": "https://evil.top/" + ("x" * 2_040)}).status_code
            == 400
        )
        assert (
            client.post(
                endpoint,
                data={"text": "biên lai", "expected_merchant_account": "1" * 65},
            ).status_code
            == 400
        )

    # 2. NV-03: validate_upload_bytes offloaded via asyncio.to_thread in analyze.py
    offloaded_funcs: list[str] = []
    real_to_thread = asyncio.to_thread

    async def _spy_to_thread(func: Any, /, *args: Any, **kwargs: Any) -> Any:
        offloaded_funcs.append(getattr(func, "__name__", str(func)))
        return await real_to_thread(func, *args, **kwargs)

    monkeypatch.setattr("app.api.v1.analyze.asyncio.to_thread", _spy_to_thread)
    res_img = client.post(
        "/api/v1/analyze",
        data={"mode": "personal", "text": "ảnh kiểm tra"},
        files={"image": ("sample.png", _make_png_bytes(), "image/png")},
    )
    assert res_img.status_code == 200
    assert "validate_upload_bytes" in offloaded_funcs

    # 3. extract_iocs prioritizes extra_urls over decoy text URLs and enforces caps
    decoy_urls = " ".join(f"https://decoy{i}.example.com/p" for i in range(20))
    decoy_phones = " ".join(f"09123456{i:02d}" for i in range(20))
    decoy_accts = " ".join(f"STK: 19030000{i:04d}" for i in range(20))
    extracted = extract_iocs(
        f"{decoy_urls} {decoy_phones} {decoy_accts}",
        extra_urls=["https://critical-phish.top/login", "https://qr-trap.vip/pay"],
    )
    assert len(extracted.urls) == MAX_EXTRACTED_URLS
    assert len(extracted.domains) == MAX_EXTRACTED_DOMAINS
    assert len(extracted.phones) == MAX_EXTRACTED_PHONES
    assert len(extracted.bank_accounts) == MAX_EXTRACTED_ACCOUNTS
    assert extracted.urls[0] == "https://critical-phish.top/login"
    assert extracted.urls[1] == "https://qr-trap.vip/pay"
    assert "critical-phish.top" in extracted.domains

    # 4. Repository domain expansion capped at 4 parents while keeping apex; lookup capped at 24
    repo: CaseRepository = app.state.repo
    deep_dom = "l1.l2.l3.l4.l5.l6.l7.evil-apex.top"
    expanded = repo._expand_domain_candidates([deep_dom])
    assert len(expanded) == 1 + MAX_DOMAIN_PARENT_LEVELS
    assert expanded[0] == deep_dom
    assert "evil-apex.top" in expanded

    repo.add_block_rule("domain", reason="Apex block", raw_value="evil-apex.top")
    hits = repo.match_active_block_rules(
        ExtractedIOCs(domains=[deep_dom]),
        now=datetime.now(UTC),
    )
    assert len(hits) == 1

    huge_iocs = ExtractedIOCs(
        phones=[f"09123456{i:02d}" for i in range(15)],
        bank_accounts=[f"19031111{i:04d}" for i in range(15)],
        domains=[f"sub{i}.d{i}.top" for i in range(15)],
    )
    bounded = repo._bounded_lookup_hashes(huge_iocs)
    assert len(bounded) == MAX_LOOKUP_IOC_HASHES
    assert len(set(bounded)) == MAX_LOOKUP_IOC_HASHES


# ---------------------------------------------------------------------------
# NV-15: Radar Audit rule_id Validation & Partitioned Retention
# ---------------------------------------------------------------------------


def test_nv15_radar_rule_id_sanitization_and_partitioned_audit_retention(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert sanitize_rule_id("rule_0123abcdef") == "rule_0123abcdef"
    assert sanitize_rule_id("rule_0123ABCDEF") is None
    assert sanitize_rule_id("rule_short") is None
    assert sanitize_rule_id("bad_id\nforged_log=1") is None

    cfg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "nv15.db"),
        app_env="demo",
        analyst_pin="PinAdmin#77",
        gemini_api_key="",
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
        rate_limit_per_minute=500,
    )
    app = create_app(cfg)
    client = TestClient(app)
    repo: CaseRepository = app.state.repo

    # 1. Invalid rule_id on /revoke skips DB calls and stores rule_id=NULL in audit logs
    db_called = False
    orig_get = repo.get_block_rule

    def _spy_get(rid: str) -> Any:
        nonlocal db_called
        db_called = True
        return orig_get(rid)

    monkeypatch.setattr(repo, "get_block_rule", _spy_get)

    bad_pin_res = client.post(
        "/api/v1/radar/block-rules/INVALID_INJECTED_ID/revoke",
        json={"analyst_pin": "WrongPin99"},
    )
    assert bad_pin_res.status_code == 403
    ok_pin_res = client.post(
        "/api/v1/radar/block-rules/INVALID_INJECTED_ID/revoke",
        json={"analyst_pin": "PinAdmin#77"},
    )
    assert ok_pin_res.status_code == 200
    assert ok_pin_res.json() == {"ok": True, "rule_id": None, "revoked": False}
    assert db_called is False

    graph_json = json.dumps(client.get("/api/v1/radar/graph").json(), ensure_ascii=False)
    assert "INVALID_INJECTED_ID" not in graph_json

    # 2. init_db cleans pre-existing invalid rule_id rows in radar_audit_logs
    with sqlite3.connect(cfg.sqlite_path) as conn:
        conn.execute(
            "INSERT INTO radar_audit_logs "
            "(audit_id, created_at, action, outcome, rule_id, detail, client_ip_hash) "
            "VALUES ('aud_legacy_bad', '2026-11-26T00:00:00+00:00', 'auth_failed', 'denied', "
            "'<script>alert(1)</script>', 'legacy bad', 'abcd')"
        )
        conn.execute(
            "INSERT INTO radar_audit_logs "
            "(audit_id, created_at, action, outcome, rule_id, detail, client_ip_hash) "
            "VALUES ('aud_legacy_ok', '2026-11-26T00:00:01+00:00', 'revoke_rule', 'allowed', "
            "'rule_0123456789', 'legacy ok', 'abcd')"
        )
    repo.init_db()
    with sqlite3.connect(cfg.sqlite_path) as conn:
        bad_row = conn.execute(
            "SELECT rule_id FROM radar_audit_logs WHERE audit_id = 'aud_legacy_bad'"
        ).fetchone()
        ok_row = conn.execute(
            "SELECT rule_id FROM radar_audit_logs WHERE audit_id = 'aud_legacy_ok'"
        ).fetchone()
    assert bad_row[0] is None
    assert ok_row[0] == "rule_0123456789"

    # 3. Partitioned retention: 65 auth_failed events cannot evict privileged create_rule logs
    for idx in range(8):
        repo.record_audit_log(
            action="create_rule",
            outcome="allowed",
            rule_id=f"rule_000000000{idx}",
            detail=f"Privileged admin event {idx}",
        )
    for idx in range(65):
        repo.record_audit_log(
            action="auth_failed",
            outcome="denied",
            detail=f"Brute force attempt {idx}",
        )

    with sqlite3.connect(cfg.sqlite_path) as conn:
        auth_cnt = int(
            conn.execute(
                "SELECT COUNT(*) FROM radar_audit_logs WHERE action = 'auth_failed'"
            ).fetchone()[0]
        )
        priv_cnt = int(
            conn.execute(
                "SELECT COUNT(*) FROM radar_audit_logs WHERE action != 'auth_failed'"
            ).fetchone()[0]
        )
    assert auth_cnt == 50
    assert priv_cnt >= 8

    recent = repo.get_radar_graph().recent_audit_logs
    assert len(recent) <= 20
    auth_in_recent = [e for e in recent if e.action == "auth_failed"]
    priv_in_recent = [e for e in recent if e.action != "auth_failed"]
    assert len(auth_in_recent) == 5
    assert len(priv_in_recent) >= 8
    # Preserves created_at DESC ordering
    timestamps = [e.created_at for e in recent]
    assert timestamps == sorted(timestamps, reverse=True)


# ---------------------------------------------------------------------------
# NV-23: Persisted PII Scrubber, Telegram Cache Migration & Hashed Receipt Refs
# ---------------------------------------------------------------------------


def test_nv23_pii_scrubber_idempotency_telegram_migration_and_hashed_receipt_refs(
    tmp_path: Path,
    sample_report: AnalysisReport,
) -> None:
    raw_text = (
        "Truy cập https://alice:SuperSecret99@evil.top/pay?p=%30%39%31%32%33%34%35%36%37%38 "
        "Email: victim.user+1@gmail.com | OTP: 482910 | CVV: 842 | Mật khẩu: MyPass@2026 | "
        "Mật khẩu là thông tin bảo mật | Thẻ 4111-2222-3333-4444 | "
        "CCCD: 079\u200b201\u202e001234 và 079.201.001.234 | "
        "STK VietQR: shop-1234 và VQRQ00123456 | "
        "Số tiền 15.000.000 đ tại BIN 970436 ngày 26/11/2026"
    )
    once = scrub_persisted_pii(
        raw_text,
        known_phones=["0912345678"],
        known_accounts=["SHOP1234", "VQRQ00123456"],
    )
    twice = scrub_persisted_pii(
        once,
        known_phones=["0912345678"],
        known_accounts=["SHOP1234", "VQRQ00123456"],
    )
    assert once == twice
    assert scrub_persisted_pii(once) == once

    assert "https://[CRED_REDACTED]@evil.top" in once
    assert "[ENCODED_NUM_REDACTED]" in once
    assert "[EMAIL_REDACTED]" in once
    assert "OTP: [OTP_REDACTED]" in once
    assert "CVV: [OTP_REDACTED]" in once
    assert "Mật khẩu: [OTP_REDACTED]" in once
    assert "[CARD_REDACTED]" in once
    assert "[CCCD_REDACTED]" in once
    assert "SH****34" in once
    assert "VQ****56" in once

    for leaked in (
        "SuperSecret99",
        "alice:",
        "victim.user+1@gmail.com",
        "482910",
        "842",
        "MyPass@2026",
        "4111-2222-3333-4444",
        "079201001234",
        "079.201.001.234",
        "shop-1234",
        "VQRQ00123456",
        "%30%39%31%32",
        "\u200b",
        "\u202e",
    ):
        assert leaked not in once, f"Leaked {leaked!r} in: {once}"

    # Financial amounts, BINs, dates, and safety prose preserved intact!
    assert "15.000.000 đ" in once
    assert "BIN 970436" in once
    assert "26/11/2026" in once
    assert "Mật khẩu là thông tin bảo mật" in once

    # Database migrations: vs_tg_* replacement & scrubbing in telegram_updates.reply_text + ref_h:*
    db_file = tmp_path / "nv23_repo.db"
    repo = CaseRepository(str(db_file), ioc_hmac_secret="nv23_hmac_key_for_receipt_refs")
    repo.init_db()

    leg_tg = sample_report.model_copy(update={"case_id": "vs_tg_777888"})
    recent_ts = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    with sqlite3.connect(str(db_file)) as conn:
        conn.execute(
            "INSERT INTO cases (case_id, created_at, verdict, risk_score, report_json) "
            "VALUES (?, ?, ?, ?, ?)",
            ("vs_tg_777888", leg_tg.created_at, leg_tg.verdict, 88, leg_tg.model_dump_json()),
        )
        conn.execute(
            "INSERT INTO telegram_updates (update_id, status, case_id, reply_text, created_at) "
            "VALUES (777888, 'completed', 'vs_tg_777888', "
            "'Mã hồ sơ: <code>vs_tg_777888</code> Email: leak@example.com CCCD 079.201.001.234', ?)",
            (recent_ts,),
        )
        conn.execute(
            "INSERT INTO receipt_hashes (fingerprint, created_at) "
            "VALUES ('ref:Vietcombank:FT2633099999', ?)",
            (recent_ts,),
        )

    repo.init_db()
    tg_cached = repo.get_telegram_update_cache(777888)
    assert tg_cached is not None and tg_cached[0] is not None
    rotated_cid, scrubbed_reply = tg_cached
    assert rotated_cid != "vs_tg_777888"
    assert rotated_cid in scrubbed_reply
    assert "vs_tg_777888" not in scrubbed_reply
    assert "leak@example.com" not in scrubbed_reply
    assert "079.201.001.234" not in scrubbed_reply

    # Legacy receipt ref migrated to ref_h:* and replay lookup matches!
    assert repo.is_receipt_replayed(None, "Vietcombank", "FT2633099999") is True
    # New claim_receipt_replay, save_report, and save_staged_report store ONLY ref_h:*!
    assert repo.claim_receipt_replay(None, "MB Bank", "FT2633088888", register_if_new=True) is False
    assert repo.claim_receipt_replay(None, "MB Bank", "FT2633088888", register_if_new=True) is True

    rep_with_ref = sample_report.model_copy(
        update={
            "case_id": "vs_nv23_ref_report",
            "receipt_logic": ReceiptLogicResult(
                is_receipt_candidate=True,
                bank_detected="Techcombank",
                reference_code="FT2633077777",
                reference_valid=True,
                verification_status="UNVERIFIED_SCREENSHOT",
            ),
        }
    )
    repo.save_report(rep_with_ref, track_replay=True)
    assert repo.is_receipt_replayed(None, "Techcombank", "FT2633077777") is True

    repo.save_staged_report(
        sample_report,
        child_case_id="vs_nv23_staged_child",
        parent_case_id="vs_nv23_ref_report",
        prehashed_iocs=[],
        replay_fingerprints=[{"kind": "ref", "fingerprint": "ref:BIDV:FT2633066666"}],
        contribute_to_radar=True,
    )
    assert repo.is_receipt_replayed(None, "BIDV", "FT2633066666") is True

    with sqlite3.connect(str(db_file)) as conn:
        fps = [str(r[0]) for r in conn.execute("SELECT fingerprint FROM receipt_hashes").fetchall()]
    assert len(fps) == 4
    assert all(fp.startswith("ref_h:") and len(fp) == 70 for fp in fps)
    for raw_ref in ("FT2633099999", "FT2633088888", "FT2633077777", "FT2633066666"):
        assert all(raw_ref not in fp for fp in fps)


def test_nv23_internal_ids_preserved_colon_prose_safe_unicode_emails_and_proto_rel_userinfo() -> None:
    # 1. 50 random generate_case_id() values + phone-prefixed synthetic internal IDs NEVER corrupted
    ids = [
        "vs_0912345678abcdef0123456789abcdef",
        "drf_0912345678abcdef0123456789abcdef",
        "rule_0912345678",
        "aud_0912345678",
        *(generate_case_id() for _ in range(50)),
    ]
    for ident in ids:
        msg = f"Mã hồ sơ: <code>{ident}</code> — SĐT đối tượng 0912345678"
        once = scrub_persisted_pii(msg, known_phones=["0912345678"])
        twice = scrub_persisted_pii(once, known_phones=["0912345678"])
        assert once == twice
        assert ident in once, f"Internal ID corrupted: {ident} -> {once}"
        assert "0912345678" not in once.replace(ident, "")

    # 2. Vietnamese prose after "mật khẩu:" preserved while synthetic passwords still redacted
    prose = "Lưu ý bảo mật mật khẩu: không chia sẻ cho bất kỳ ai."
    assert scrub_persisted_pii(prose) == prose
    assert scrub_persisted_pii(scrub_persisted_pii(prose)) == prose

    pw_samples = (
        ("Mật khẩu: MyPass@2026", "MyPass@2026"),
        ("Mật khẩu: Abc123", "Abc123"),
        ("Mật khẩu: 123456", "123456"),
    )
    for raw_pw, secret in pw_samples:
        out_pw = scrub_persisted_pii(raw_pw)
        assert out_pw == "Mật khẩu: [OTP_REDACTED]"
        assert secret not in out_pw
        assert scrub_persisted_pii(out_pw) == out_pw

    # 3. Unicode/IDN emails + protocol-relative / ftp(s) / sftp userinfo redacted idempotently
    mixed = (
        "Liên hệ victim@ngânhàng.vn hoặc victim@bank.\u0440\u0444 và "
        "//alice:Secret99@192.168.1.1/pay hoặc ftps://bob:Pass99@10.0.0.1/a "
        "và sftp://root:Root99@10.0.0.2/b"
    )
    scrubbed = scrub_persisted_pii(mixed)
    assert scrub_persisted_pii(scrubbed) == scrubbed
    assert scrubbed.count("[EMAIL_REDACTED]") == 2
    assert "//[CRED_REDACTED]@192.168.1.1/pay" in scrubbed
    assert "ftps://[CRED_REDACTED]@10.0.0.1/a" in scrubbed
    assert "sftp://[CRED_REDACTED]@10.0.0.2/b" in scrubbed
    for secret in (
        "victim@ngânhàng.vn",
        "victim@bank.\u0440\u0444",
        "alice:Secret99",
        "bob:Pass99",
        "root:Root99",
    ):
        assert secret not in scrubbed


def test_nv14_per_type_lookup_budget_and_exact_apex_interleaving_prevent_rule_starvation(
    tmp_path: Path,
) -> None:
    repo = CaseRepository(str(tmp_path / "nv14_budget.db"))
    repo.init_db()
    repo.add_block_rule("domain", reason="Blocked apex", raw_value="blocked-apex.top")

    # Exact host + registrable apex interleaved BEFORE intermediate subdomain tiers
    expanded = repo._expand_domain_candidates(
        ["a.b.c.d1.top", "x.y.z.d2.top"]
    )
    assert expanded[:4] == ["a.b.c.d1.top", "d1.top", "x.y.z.d2.top", "d2.top"]

    # 8 decoy phones + 8 decoy bank accounts + 7 decoy multi-level domains + 1 target subdomain
    # MUST NOT starve the active block rule on blocked-apex.top!
    crowded = ExtractedIOCs(
        phones=[f"09123456{i:02d}" for i in range(8)],
        bank_accounts=[f"19031111{i:04d}" for i in range(8)],
        domains=[
            *(f"s1.s2.s3.decoy{i}.top" for i in range(7)),
            "a.b.c.blocked-apex.top",
        ],
    )
    hits = repo.match_active_block_rules(crowded, now=datetime.now(UTC))
    assert len(hits) == 1
    assert hits[0].reason == "Blocked apex"


@pytest.mark.asyncio
async def test_nv12_telegram_demo_callback_uses_callback_update_kind_isolated_from_message(
    tmp_path: Path,
) -> None:
    cfg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "nv12_cb_kind.db"),
        gemini_api_key="",
        gemini_backup_api_key="",
        telegram_bot_token="888777:SYNTHETIC_TOKEN",
        telegram_webhook_secret="nv12_cb_webhook_secret_token_12345",
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
        enable_local_ocr=False,
        enable_local_stt=False,
    )
    repo = CaseRepository(cfg.sqlite_path)
    repo.init_db()
    pipe = AnalysisPipeline(settings=cfg, repo=repo)

    with respx.mock(assert_all_called=False) as router:
        router.post("https://api.telegram.org/bot888777:SYNTHETIC_TOKEN/sendMessage").mock(
            return_value=httpx.Response(200, json={"ok": True, "result": {"message_id": 1}})
        )
        router.post("https://api.telegram.org/bot888777:SYNTHETIC_TOKEN/answerCallbackQuery").mock(
            return_value=httpx.Response(200, json={"ok": True, "result": True})
        )
        router.post("https://api.telegram.org/bot888777:SYNTHETIC_TOKEN/sendChatAction").mock(
            return_value=httpx.Response(200, json={"ok": True, "result": True})
        )

        cb_res = await handle_telegram_update(
            {
                "update_id": 4001,
                "callback_query": {
                    "id": "cb_demo_1",
                    "from": {"id": 5200},
                    "data": "demo:demo_zalo_fake_bill",
                    "message": {"chat": {"id": 5200, "type": "private"}},
                },
            },
            pipe,
            cfg,
        )
        assert cb_res["delivered"] is True

        with sqlite3.connect(cfg.sqlite_path) as conn:
            row = conn.execute(
                "SELECT update_kind FROM telegram_updates WHERE update_id = 4001"
            ).fetchone()
        assert row is not None and row[0] == "callback"

        # A regular message colliding with callback update_id=4001 MUST fail closed (mismatch)
        msg_collision = await handle_telegram_update(
            {
                "update_id": 4001,
                "message": {
                    "chat": {"id": 5200, "type": "private"},
                    "from": {"id": 5200},
                    "text": "collide with callback",
                },
            },
            pipe,
            cfg,
        )
        assert msg_collision == {"ok": True, "delivered": False, "ignored": True}
