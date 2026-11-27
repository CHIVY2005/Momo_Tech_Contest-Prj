"""Unit tests for Task 1: 128-bit case IDs, HMAC tokens, DB channel columns, and E5 encode_text."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from tokenizers import Tokenizer
from tokenizers.models import WordLevel
from tokenizers.pre_tokenizers import Whitespace

from app.config import Settings
from app.core.case_tokens import (
    generate_case_id,
    hash_telegram_private_owner,
    issue_case_access_token,
    resolve_case_token_secret,
    verify_case_access_token,
)
from app.db.repository import CaseRepository, StoredCaseRecord
from app.main import create_app
from app.schemas import SCAM_LABELS, AnalysisReport
from app.services.pipeline import AnalysisPipeline
from app.services.scam_classifier import ScamClassifier

CASE_ID_128_RE = re.compile(r"^vs_[0-9a-f]{32}$")


class _StubOnnxSession:
    """Minimal ONNX session stub capturing input feeds for encode_text/predict_and_encode tests."""

    def __init__(self) -> None:
        self.calls: list[dict[str, np.ndarray]] = []

    def run(self, _output_names: Any, input_feed: dict[str, np.ndarray]) -> list[np.ndarray]:
        self.calls.append(input_feed)
        logits = np.array([[-1.0, -1.0, 3.0, -1.0, -1.0, -1.0, -1.0]], dtype=np.float32)
        emb = np.arange(1, 385, dtype=np.float32).reshape(1, 384)
        return [logits, emb]


def test_generate_case_id_is_128_bit_and_unique() -> None:
    cid1 = generate_case_id()
    cid2 = generate_case_id()
    assert len(cid1) == 35
    assert CASE_ID_128_RE.fullmatch(cid1) is not None
    assert CASE_ID_128_RE.fullmatch(cid2) is not None
    assert cid1 != cid2


def test_issue_and_verify_case_access_token_roundtrip_tamper_expiry_and_claims() -> None:
    secret = "a" * 64
    cid = generate_case_id()
    parent_cid = generate_case_id()
    t0 = 1_760_000_000

    token, expires_at = issue_case_access_token(
        cid,
        secret,
        ttl_seconds=3600,
        parent_case_id=parent_cid,
        now=t0,
    )
    assert "." in token
    assert expires_at == datetime.fromtimestamp(t0 + 3600, tz=UTC).isoformat()

    verified = verify_case_access_token(token, cid, secret, now=t0 + 100)
    assert verified is not None
    assert verified["v"] == 1
    assert verified["cid"] == cid
    assert verified["ch"] == "web"
    assert verified["scope"] == "case_access"
    assert verified["exp"] == t0 + 3600
    assert verified["pcid"] == parent_cid

    # Clamped minimum TTL of 60s and omitted parent_case_id when None
    short_tok, short_exp = issue_case_access_token(cid, secret, ttl_seconds=5, now=t0)
    assert short_exp == datetime.fromtimestamp(t0 + 60, tz=UTC).isoformat()
    short_payload = verify_case_access_token(short_tok, cid, secret, now=t0 + 59)
    assert short_payload is not None
    assert "pcid" not in short_payload
    assert verify_case_access_token(short_tok, cid, secret, now=t0 + 60) is None

    # Tampered signature, tampered payload, wrong cid, wrong secret, expired, malformed
    b64_part, sig_part = token.split(".", 1)
    flipped_sig = ("0" if sig_part[0] != "0" else "1") + sig_part[1:]
    assert verify_case_access_token(f"{b64_part}.{flipped_sig}", cid, secret, now=t0) is None
    assert verify_case_access_token(f"{b64_part}x.{sig_part}", cid, secret, now=t0) is None
    assert verify_case_access_token(f"{b64_part}.éééé", cid, secret, now=t0) is None
    assert verify_case_access_token(f"éééé.{sig_part}", cid, secret, now=t0) is None
    assert verify_case_access_token(token, generate_case_id(), secret, now=t0) is None
    assert verify_case_access_token(token, cid, "b" * 64, now=t0) is None
    assert verify_case_access_token(token, cid, secret, now=t0 + 3600) is None
    assert verify_case_access_token(None, cid, secret, now=t0) is None
    assert verify_case_access_token("", cid, secret, now=t0) is None
    assert verify_case_access_token("not-a-valid-token", cid, secret, now=t0) is None
    assert verify_case_access_token(token, "   ", secret, now=t0) is None
    assert verify_case_access_token(token, cid, "   ", now=t0) is None

    with pytest.raises(ValueError):
        issue_case_access_token("   ", secret)
    with pytest.raises(ValueError):
        issue_case_access_token(cid, "   ")

    # Boolean claim spoofing (True == 1 in Python) must be rejected even with valid signature
    bad_payload = json.dumps(
        {"v": True, "cid": cid, "ch": "web", "scope": "case_access", "exp": t0 + 9999},
        separators=(",", ":"),
    ).encode("utf-8")
    bad_b64 = base64.urlsafe_b64encode(bad_payload).rstrip(b"=").decode("ascii")
    bad_sig = hmac.new(secret.encode("utf-8"), bad_b64.encode("ascii"), hashlib.sha256).hexdigest()
    assert verify_case_access_token(f"{bad_b64}.{bad_sig}", cid, secret, now=t0) is None


def test_hash_telegram_private_owner_is_deterministic_and_scoped() -> None:
    secret = "s" * 64
    h1 = hash_telegram_private_owner(12345, 67890, secret)
    h2 = hash_telegram_private_owner("12345", "67890", secret)
    h_diff_user = hash_telegram_private_owner(12345, 99999, secret)
    h_diff_chat = hash_telegram_private_owner(54321, 67890, secret)
    assert len(h1) == 64
    assert h1 == h2
    assert h1 != h_diff_user
    assert h1 != h_diff_chat
    with pytest.raises(ValueError):
        hash_telegram_private_owner(12345, 67890, "")
    with pytest.raises(ValueError):
        hash_telegram_private_owner(12345, 67890, "   ")


def test_settings_and_resolve_case_token_secret_policies() -> None:
    # Demo mode must STILL reject placeholder / "2026" secrets even when analyst_pin defaults to "2026"
    for bad_secret in ("change_me", "CHANGE_ME_SECRET_000000000000000000", "2026", "2026_demo"):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, app_env="demo", ioc_hmac_secret=bad_secret)
        with pytest.raises(ValidationError):
            Settings(_env_file=None, app_env="demo", case_token_secret=bad_secret)

    # Demo mode with unset secrets generates fresh distinct 256-bit ephemeral keys (never "" or "2026")
    demo_cfg = Settings(_env_file=None, app_env="demo")
    assert demo_cfg.analyst_pin == "2026"
    assert demo_cfg.onnx_intra_threads == 2
    assert demo_cfg.assistant_rate_limit_per_minute == 12
    assert demo_cfg.assistant_rate_limit_per_hour == 60
    k1 = resolve_case_token_secret(demo_cfg)
    k2 = resolve_case_token_secret(demo_cfg)
    assert len(k1) == 64 and len(k2) == 64
    assert k1 != k2
    assert k1 not in ("", "2026")

    # Production rejects missing both secrets
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="production", analyst_pin="StrongPin#2026")

    # Production rejects short or placeholder case_token_secret
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            app_env="production",
            analyst_pin="StrongPin#2026",
            case_token_secret="short_token_secret",
        )
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            app_env="production",
            analyst_pin="StrongPin#2026",
            case_token_secret="change_me_" + "a" * 32,
        )
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            app_env="production",
            analyst_pin="StrongPin#2026",
            case_token_secret="2026_" + "a" * 32,
        )

    # Production requires BOTH explicit IOC_HMAC_SECRET (>= 16) and explicit CASE_TOKEN_SECRET (>= 32)
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            app_env="production",
            analyst_pin="StrongPin#2026",
            ioc_hmac_secret="prod_explicit_hmac_secret_value_v1",
        )
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            app_env="production",
            analyst_pin="StrongPin#2026",
            case_token_secret="k" * 40,
        )

    # Even if validation were bypassed via model_construct, production MUST NOT derive
    # IOC HMAC from analyst_pin OR case_token_secret from ioc_hmac_secret!
    bypassed_prod = Settings.model_construct(
        app_env="production",
        analyst_pin="StrongPin#2026",
        ioc_hmac_secret="",
        case_token_secret="",
    )
    assert bypassed_prod.resolved_ioc_hmac_secret == ""
    with pytest.raises(ValueError, match="APP_ENV=production"):
        resolve_case_token_secret(bypassed_prod)

    bypassed_hmac_only = Settings.model_construct(
        app_env="production",
        analyst_pin="StrongPin#2026",
        ioc_hmac_secret="prod_explicit_hmac_secret_value_v1",
        case_token_secret="",
    )
    with pytest.raises(ValueError, match="APP_ENV=production"):
        resolve_case_token_secret(bypassed_hmac_only)

    # Production accepts distinct explicit IOC_HMAC_SECRET + CASE_TOKEN_SECRET (even random hex 2026*)
    explicit_hmac = "h" * 32
    explicit_secret = "k" * 40
    prod_explicit = Settings(
        _env_file=None,
        app_env="production",
        analyst_pin="StrongPin#2026",
        ioc_hmac_secret=explicit_hmac,
        case_token_secret=explicit_secret,
    )
    assert resolve_case_token_secret(prod_explicit) == explicit_secret
    assert prod_explicit.resolved_ioc_hmac_secret == explicit_hmac

    # Reusing the same secret for both IOC_HMAC_SECRET and CASE_TOKEN_SECRET is forbidden in prod
    random_hex_2026 = "2026" + "a1b2c3d4" * 7 + "ef01"
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            app_env="production",
            analyst_pin="StrongPin#2026",
            ioc_hmac_secret=random_hex_2026,
            case_token_secret=random_hex_2026,
        )

    random_hex_2026_tok = "2026" + "d4c3b2a1" * 7 + "10fe"
    prod_hex_2026 = Settings(
        _env_file=None,
        app_env="production",
        analyst_pin="StrongPin#2026",
        ioc_hmac_secret=random_hex_2026,
        case_token_secret=random_hex_2026_tok,
    )
    assert resolve_case_token_secret(prod_hex_2026) == random_hex_2026_tok


def test_repository_legacy_migration_owner_channels_radar_gating_and_128bit_ids(
    tmp_path: Path,
    sample_report: AnalysisReport,
) -> None:
    db_file = tmp_path / "legacy_upgrade.db"

    # Create pre-Phase-0 5-column cases schema with a legacy case and a legacy vs_tg_* case
    with sqlite3.connect(str(db_file)) as conn:
        conn.executescript(
            """
            CREATE TABLE cases (
                case_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                report_json TEXT NOT NULL
            );
            CREATE TABLE telegram_updates (
                update_id INTEGER PRIMARY KEY,
                case_id TEXT,
                reply_text TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            """
        )
        legacy_rep = sample_report.model_copy(update={"case_id": "vs_legacy_001"})
        legacy_tg = sample_report.model_copy(update={"case_id": "vs_tg_424242"})
        conn.execute(
            "INSERT INTO cases (case_id, created_at, verdict, risk_score, report_json) "
            "VALUES (?, ?, ?, ?, ?)",
            ("vs_legacy_001", legacy_rep.created_at, legacy_rep.verdict, 88, legacy_rep.model_dump_json()),
        )
        conn.execute(
            "INSERT INTO cases (case_id, created_at, verdict, risk_score, report_json) "
            "VALUES (?, ?, ?, ?, ?)",
            ("vs_tg_424242", legacy_tg.created_at, legacy_tg.verdict, 88, legacy_tg.model_dump_json()),
        )
        recent_ts = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        conn.execute(
            "INSERT INTO telegram_updates (update_id, case_id, reply_text, created_at) "
            "VALUES (424242, 'vs_tg_424242', 'ok', ?)",
            (recent_ts,),
        )

    repo = CaseRepository(str(db_file))
    repo.init_db()

    # Legacy row defaults to legacy_locked
    legacy_rec = repo.get_report_with_owner("vs_legacy_001")
    assert isinstance(legacy_rec, StoredCaseRecord)
    assert legacy_rec.owner_channel == "legacy_locked"
    assert legacy_rec.owner_chat_hash is None
    assert legacy_rec.is_demo is False
    assert legacy_rec.parent_case_id is None

    # Rotated legacy vs_tg_* row got a 128-bit case_id and remains legacy_locked
    tg_cache = repo.get_telegram_update_cache(424242)
    assert tg_cache is not None and tg_cache[0] is not None
    assert CASE_ID_128_RE.fullmatch(tg_cache[0]) is not None
    rotated_rec = repo.get_report_with_owner(tg_cache[0])
    assert rotated_rec is not None
    assert rotated_rec.owner_channel == "legacy_locked"

    # New Telegram claim allocates a 128-bit case_id
    claim_state, alloc_cid, _ = repo.claim_telegram_update(777001)
    assert claim_state == "claimed"
    assert alloc_cid is not None and CASE_ID_128_RE.fullmatch(alloc_cid) is not None

    # Private case with contributes_to_radar=False writes 0 IOC sightings and does NOT bump total_cases
    graph_before = repo.get_radar_graph()
    cases_before = graph_before.stats["total_cases"]
    iocs_before = graph_before.stats["tracked_iocs"]

    private_cid = generate_case_id()
    parent_cid = generate_case_id()
    private_rep = sample_report.model_copy(update={"case_id": private_cid})
    repo.save_report(
        private_rep,
        owner_channel="web_token",
        owner_chat_hash=None,
        parent_case_id=parent_cid,
        contributes_to_radar=False,
        is_demo=True,
    )

    priv_rec = repo.get_report_with_owner(private_cid)
    assert priv_rec is not None
    assert priv_rec.owner_channel == "web_token"
    assert priv_rec.parent_case_id == parent_cid
    assert priv_rec.is_demo is True

    graph_after_private = repo.get_radar_graph()
    assert graph_after_private.stats["total_cases"] == cases_before
    assert graph_after_private.stats["tracked_iocs"] == iocs_before

    # Case with contributes_to_radar=True DOES bump total_cases and tracked_iocs
    radar_cid = generate_case_id()
    radar_rep = sample_report.model_copy(update={"case_id": radar_cid})
    repo.save_report(radar_rep, owner_channel="web_token", contributes_to_radar=True, is_demo=False)
    graph_after_radar = repo.get_radar_graph()
    assert graph_after_radar.stats["total_cases"] == cases_before + 1
    assert graph_after_radar.stats["tracked_iocs"] > iocs_before


def test_scam_classifier_encode_text_and_predict_and_encode(tmp_path: Path) -> None:
    vocab = {
        "<pad>": 0,
        "<s>": 1,
        "</s>": 2,
        "<unk>": 3,
        "query": 4,
        "passage": 5,
        ":": 6,
        "chuyen": 7,
        "tien": 8,
    }
    tok = Tokenizer(WordLevel(vocab=vocab, unk_token="<unk>"))
    tok.pre_tokenizer = Whitespace()
    tok.save(str(tmp_path / "tokenizer.json"))
    (tmp_path / "label_map.json").write_text(
        json.dumps({"labels": list(SCAM_LABELS)}),
        encoding="utf-8",
    )

    stub = _StubOnnxSession()
    clf = ScamClassifier(str(tmp_path), _injected_session=stub, intra_threads=2)

    q_vec = clf.encode_text("chuyen tien", prefix="query")
    p_vec = clf.encode_text("chuyen tien", prefix="passage")
    assert q_vec is not None and q_vec.shape == (384,) and q_vec.dtype == np.float32
    assert p_vec is not None and p_vec.shape == (384,) and p_vec.dtype == np.float32
    assert abs(float(np.linalg.norm(q_vec)) - 1.0) < 1e-5
    assert list(stub.calls[0]["input_ids"][0][:2]) == [vocab["query"], vocab[":"]]
    assert list(stub.calls[1]["input_ids"][0][:2]) == [vocab["passage"], vocab[":"]]
    assert clf.encode_text("   ") is None

    pred, vec = clf.predict_and_encode("chuyen tien")
    assert pred.available is True
    assert pred.predicted_label == "SCAM_IMPERSONATION"
    assert vec is not None and vec.shape == (384,) and vec.dtype == np.float32
    assert abs(float(np.linalg.norm(vec)) - 1.0) < 1e-5

    # Also verify real exported ONNX artifact with intra_threads=2
    model_dir = Path(__file__).resolve().parents[2] / "app" / "data" / "models"
    real_clf = ScamClassifier(str(model_dir), intra_threads=2)
    assert real_clf.is_available is True
    real_q = real_clf.encode_text(
        "Tôi lỡ chuyển tiền cho kẻ lừa đảo cần làm gì?",
        prefix="query",
    )
    real_p = real_clf.encode_text(
        "Quy trình khóa tài khoản khi chuyển nhầm cho kẻ lừa đảo",
        prefix="passage",
    )
    real_pred, real_pe = real_clf.predict_and_encode("Tôi lỡ chuyển tiền cho kẻ lừa đảo cần làm gì?")
    assert real_q is not None and real_q.shape == (384,) and real_q.dtype == np.float32
    assert real_p is not None and real_p.shape == (384,) and real_p.dtype == np.float32
    assert real_pe is not None and real_pe.shape == (384,) and real_pe.dtype == np.float32
    assert abs(float(np.linalg.norm(real_q)) - 1.0) < 1e-4
    assert abs(float(np.linalg.norm(real_p)) - 1.0) < 1e-4
    assert np.allclose(real_q, real_pe, atol=1e-5)
    assert real_pred.available is True


@pytest.mark.asyncio
async def test_app_state_secret_cors_expose_headers_and_pipeline_128bit_id(tmp_path: Path) -> None:
    cfg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "app_tokens.db"),
        gemini_api_key="",
        gemini_backup_api_key="",
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
        enable_local_ocr=False,
        enable_local_stt=False,
        app_env="demo",
        cors_origins=["https://verishield.example"],
    )
    app = create_app(cfg)
    assert isinstance(app.state.case_token_secret, str)
    assert len(app.state.case_token_secret) == 64
    assert app.state.pipeline.case_token_secret == app.state.case_token_secret

    # CORS preflight / actual response exposes X-Case-Access-Token
    client = TestClient(app)
    res = client.get("/api/v1/health", headers={"Origin": "https://verishield.example"})
    assert res.status_code == 200
    exposed = res.headers.get("access-control-expose-headers", "")
    assert "X-Case-Access-Token" in exposed

    # Direct pipeline instantiation holds stable secret, emits 128-bit case_id, records is_demo flag
    repo = CaseRepository(str(tmp_path / "direct_pipe.db"))
    repo.init_db()
    pipe = AnalysisPipeline(settings=cfg, repo=repo)
    assert len(pipe.case_token_secret) == 64

    normal_rep = await pipe.run(mode="personal", text="Chào bạn, hẹn tối nay đi ăn cơm nhé.")
    assert CASE_ID_128_RE.fullmatch(normal_rep.case_id) is not None
    normal_stored = repo.get_report_with_owner(normal_rep.case_id)
    assert normal_stored is not None
    assert normal_stored.is_demo is False
    assert normal_stored.owner_channel == "web_token"

    demo_ids = [d.demo_id for d in pipe.list_demos()]
    if demo_ids:
        demo_rep = await pipe.run(demo_id=demo_ids[0])
        assert CASE_ID_128_RE.fullmatch(demo_rep.case_id) is not None
        demo_stored = repo.get_report_with_owner(demo_rep.case_id)
        assert demo_stored is not None
        assert demo_stored.is_demo is True
