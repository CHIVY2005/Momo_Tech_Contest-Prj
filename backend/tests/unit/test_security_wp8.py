"""WP-8 tests: NV-25, NV-28, NV-29, NV-30, NV-31, NV-33, NV-35, NV-36, NV-41."""

from __future__ import annotations

import gc
import sqlite3
import time
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from app.db.repository import (
    MAX_DOMAIN_PARENT_LEVELS,
    MAX_LOOKUP_CROSS_HASHES,
    MAX_LOOKUP_DOMAIN_HASHES,
    MAX_LOOKUP_IOC_HASHES,
    MAX_SIGHTINGS_PER_CASE,
    CaseRepository,
    ProtectedDemoIocError,
    strip_visual_blobs_copy,
)
from app.schemas import (
    AnalysisReport,
    ExtractedIOCs,
    ImageForensicsResult,
    ReceiptLogicResult,
    SandboxInspection,
    ScamClassifierOutput,
    UrlFinding,
    VietQRInfo,
)

EXPECTED_INDEXES = {
    "idx_cases_radar_demo_created",
    "idx_cases_redaction_ver",
    "idx_cases_created_at",
    "idx_ioc_sightings_hits",
    "idx_ioc_sightings_demo",
    "idx_campaigns_primary_hash",
    "idx_block_rules_expires",
    "idx_receipt_hashes_created",
    "idx_telegram_updates_status_created",
    "idx_radar_audit_action_created",
}


# ---------------------------------------------------------------------------
# NV-25: Dedicated cross-hash lookup bucket without domain starvation
# ---------------------------------------------------------------------------


def test_nv25_cross_hash_lookup_bucket_matches_phone_and_account_without_starving_domains(
    tmp_path: Path,
) -> None:
    repo = CaseRepository(str(tmp_path / "nv25.db"), ioc_hmac_secret="wp8_nv25_secret_key_001")
    repo.init_db()

    # 1. Rule on phone matches when IOC was extracted as a phone-shaped bank_account
    r_phone = repo.add_block_rule("phone", reason="Blocked scam phone", raw_value="0912345678")
    hits_from_acct = repo.match_active_block_rules(
        ExtractedIOCs(bank_accounts=["0912345678"]),
        now=datetime.now(UTC),
    )
    assert [h.rule_id for h in hits_from_acct] == [r_phone.rule_id]

    # 2. Rule on bank_account matches when IOC was extracted as a phone
    r_acct = repo.add_block_rule("bank_account", reason="Phone-as-STK mule", raw_value="0987654321")
    hits_from_phone = repo.match_active_block_rules(
        ExtractedIOCs(phones=["0987654321"]),
        now=datetime.now(UTC),
    )
    assert [h.rule_id for h in hits_from_phone] == [r_acct.rule_id]

    # 3. Cross-hash prioritizes phone-shaped accounts BEFORE phones and preserves all 16 domain slots
    repo.add_block_rule("domain", reason="Target domain", raw_value="target-nv25.top")
    crowded = ExtractedIOCs(
        phones=[f"09010000{i:02d}" for i in range(10)],
        bank_accounts=[f"03550000{i:02d}" for i in range(MAX_LOOKUP_CROSS_HASHES)],
        domains=[*(f"s1.s2.decoy{i}.top" for i in range(7)), "a.b.c.target-nv25.top"],
    )
    bounded = repo._bounded_lookup_hashes(crowded)
    assert len(bounded) == MAX_LOOKUP_IOC_HASHES
    assert MAX_LOOKUP_DOMAIN_HASHES == 16
    assert repo.hash_ioc_value("phone", "0355000000") in bounded
    assert repo.hash_ioc_value("domain", "target-nv25.top") in bounded
    assert any(r.reason == "Target domain" for r in repo.match_active_block_rules(crowded))


# ---------------------------------------------------------------------------
# NV-28 & NV-32: Poisoning guard, sighting cap, LIMIT-60/120 protection, blob strip
# ---------------------------------------------------------------------------


def test_nv28_prompt_injection_poisoning_guard_cap_and_limit_priority(
    tmp_path: Path,
    sample_report: AnalysisReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed_file = Path(__file__).resolve().parents[2] / "app" / "data" / "seed_iocs.json"
    repo = CaseRepository(str(tmp_path / "nv28.db"))
    repo.init_db()
    repo.seed_if_empty(str(seed_file))

    # 1. strip_visual_blobs_copy clears blobs without mutating source; save_report scrubs ONCE
    img_item = ImageForensicsResult(
        filename="receipt.png",
        format="PNG",
        width=200,
        height=200,
        dhash_hex="1234567890abcdef",
        exif_software="Adobe Photoshop 25",
        ela_heatmap_base64="BASE64_ELA_DATA",
    )
    rich_report = sample_report.model_copy(
        update={
            "case_id": "vs_nv28_blobs_01",
            "sandbox": SandboxInspection(
                available=True,
                visited_url="https://evil-blob.top",
                screenshot_base64="BASE64_SCREENSHOT",
            ),
            "image_forensics": img_item,
            "image_forensics_list": [img_item],
        }
    )
    stripped = strip_visual_blobs_copy(rich_report)
    assert stripped.sandbox is not None and stripped.sandbox.screenshot_base64 is None
    assert stripped.image_forensics is not None
    assert stripped.image_forensics.ela_heatmap_base64 is None
    assert stripped.image_forensics.exif_software is None
    assert stripped.image_forensics_list[0].ela_heatmap_base64 is None
    assert stripped.image_forensics_list[0].exif_software is None
    assert rich_report.sandbox is not None
    assert rich_report.sandbox.screenshot_base64 == "BASE64_SCREENSHOT"
    assert rich_report.image_forensics is not None
    assert rich_report.image_forensics.ela_heatmap_base64 == "BASE64_ELA_DATA"

    import app.db.repository as repo_mod

    scrub_calls = 0
    orig_redact = repo_mod.redact_report_pii

    def _spy_redact(rep: AnalysisReport, strip_visual_blobs: bool = False) -> AnalysisReport:
        nonlocal scrub_calls
        scrub_calls += 1
        return orig_redact(rep, strip_visual_blobs=strip_visual_blobs)

    monkeypatch.setattr(repo_mod, "redact_report_pii", _spy_redact)
    live = repo.save_report(rich_report, contributes_to_radar=False, track_replay=False)
    assert scrub_calls == 1
    assert live.sandbox is not None and live.sandbox.screenshot_base64 == "BASE64_SCREENSHOT"
    monkeypatch.setattr(repo_mod, "redact_report_pii", orig_redact)

    # 2. Prompt-injection-only submission skipped in BOTH save_report & save_staged_report
    inj_only = sample_report.model_copy(
        update={
            "case_id": "vs_nv28_inj_only",
            "prompt_injection_detected": True,
            "active_block_rule_hit": False,
            "url_findings": [
                UrlFinding(
                    url="https://benign-low.top",
                    domain="benign-low.top",
                    normalized_ascii_domain="benign-low.top",
                    risk_points=10,
                )
            ],
            "vietqr_findings": [],
            "receipt_logic": None,
            "image_forensics": None,
            "image_forensics_list": [],
            "classifier": ScamClassifierOutput(
                available=True,
                predicted_label="PROMPT_INJECTION",
                scam_probability=0.92,
                injection_probability=0.95,
            ),
            "iocs": ExtractedIOCs(
                phones=["0911223344"],
                bank_accounts=["888877776666"],
                domains=["poison-attempt.top"],
            ),
        }
    )
    repo.save_report(inj_only, contributes_to_radar=True, track_replay=False)
    assert repo.count_ioc_hits(ExtractedIOCs(domains=["poison-attempt.top"])) == 0

    staged_hash = repo.hash_ioc_value("domain", "staged-poison.top")
    repo.save_staged_report(
        inj_only,
        child_case_id="vs_nv28_staged_inj",
        parent_case_id="vs_nv28_inj_only",
        prehashed_iocs=[
            {"ioc_type": "domain", "ioc_hash": staged_hash, "masked_value": "st****.top"}
        ],
        replay_fingerprints=[],
        contribute_to_radar=True,
    )
    assert repo.count_ioc_hits(ExtractedIOCs(domains=["staged-poison.top"])) == 0

    # 3. Corroborated prompt-injection submissions DO ingest
    corroborated_variants: list[tuple[str, dict[str, Any]]] = [
        (
            "corrob-url.top",
            {
                "url_findings": [
                    UrlFinding(
                        url="https://corrob-url.top",
                        domain="corrob-url.top",
                        normalized_ascii_domain="corrob-url.top",
                        risk_points=45,
                    )
                ]
            },
        ),
        (
            "corrob-vqr.top",
            {
                "vietqr_findings": [
                    VietQRInfo(
                        raw="000201",
                        kind="VALID_VIETQR",
                        crc_valid=True,
                        receive_scam_detected=True,
                    )
                ]
            },
        ),
        (
            "corrob-rcpt.top",
            {
                "receipt_logic": ReceiptLogicResult(
                    is_receipt_candidate=True,
                    amount_format_anomaly=True,
                    logic_risk_points=25,
                )
            },
        ),
        (
            "corrob-img.top",
            {
                "image_forensics": ImageForensicsResult(
                    filename="t.jpg",
                    format="JPEG",
                    width=100,
                    height=100,
                    dhash_hex="1111222233334444",
                    tamper_score=40,
                )
            },
        ),
        ("corrob-rule.top", {"active_block_rule_hit": True}),
        (
            "corrob-onnx.top",
            {
                "classifier": ScamClassifierOutput(
                    available=True,
                    predicted_label="SCAM_IMPERSONATION",
                    scam_probability=0.72,
                )
            },
        ),
    ]
    for idx, (dom, extra) in enumerate(corroborated_variants):
        rep_c = inj_only.model_copy(
            update={
                "case_id": f"vs_nv28_corrob_{idx}",
                "iocs": ExtractedIOCs(domains=[dom]),
                **extra,
            }
        )
        repo.save_report(rep_c, contributes_to_radar=True, track_replay=False)
        assert repo.count_ioc_hits(ExtractedIOCs(domains=[dom])) == 1, f"Failed for {dom}"

    # 4. Cap sightings BEFORE upsert at MAX_SIGHTINGS_PER_CASE = 8
    cap_repo = CaseRepository(str(tmp_path / "nv28_cap.db"))
    cap_repo.init_db()
    noisy_rep = sample_report.model_copy(
        update={
            "case_id": "vs_nv28_cap_live",
            "iocs": ExtractedIOCs(
                phones=[f"09100000{i:02d}" for i in range(6)],
                bank_accounts=[f"19030000{i:04d}" for i in range(6)],
                domains=[f"spam{i}.top" for i in range(6)],
            ),
        }
    )
    cap_repo.save_report(noisy_rep, contributes_to_radar=True, track_replay=False)
    with closing(sqlite3.connect(str(tmp_path / "nv28_cap.db"))) as conn:
        cnt_live = int(conn.execute("SELECT COUNT(*) FROM ioc_sightings").fetchone()[0])
    assert cnt_live == MAX_SIGHTINGS_PER_CASE == 8

    cap_staged_repo = CaseRepository(str(tmp_path / "nv28_cap_staged.db"))
    cap_staged_repo.init_db()
    prehashed_12 = [
        {
            "ioc_type": "domain",
            "ioc_hash": cap_staged_repo.hash_ioc_value("domain", f"st{i}.top"),
            "masked_value": "st****.top",
        }
        for i in range(12)
    ]
    cap_staged_repo.save_staged_report(
        sample_report,
        child_case_id="vs_nv28_cap_child",
        parent_case_id="vs_parent",
        prehashed_iocs=prehashed_12,
        replay_fingerprints=[],
        contribute_to_radar=True,
    )
    with closing(sqlite3.connect(str(tmp_path / "nv28_cap_staged.db"))) as conn:
        cnt_staged = int(conn.execute("SELECT COUNT(*) FROM ioc_sightings").fetchone()[0])
    assert cnt_staged == MAX_SIGHTINGS_PER_CASE == 8

    # 5. Flooding high-hit sightings + co_occurs edges cannot evict blocked/campaign items
    blocked_hash = repo.hash_ioc_value("domain", "low-hit-blocked.top")
    repo.add_block_rule("domain", reason="Must stay visible", raw_value="low-hit-blocked.top")
    with closing(sqlite3.connect(str(tmp_path / "nv28.db"))) as conn, conn:
        conn.execute(
            "INSERT INTO ioc_sightings "
            "(ioc_hash, ioc_type, masked_value, hit_count, is_demo, label_ver) "
            "VALUES (?, 'domain', 'lo****.top', 1, 0, 1)",
            (blocked_hash,),
        )
        for i in range(80):
            jh = f"junk{i:060d}"
            conn.execute(
                "INSERT INTO ioc_sightings "
                "(ioc_hash, ioc_type, masked_value, hit_count, is_demo, label_ver) "
                "VALUES (?, 'domain', 'ju****.top', 999, 0, 1)",
                (jh,),
            )
        for i in range(150):
            conn.execute(
                "INSERT OR IGNORE INTO ioc_edges (source_id, target_id, relation) "
                "VALUES (?, ?, 'co_occurs')",
                (f"junk{i % 40:060d}", f"junk{(i + 1) % 40:060d}"),
            )
    repo._invalidate_radar_cache()
    graph = repo.get_radar_graph()
    node_ids = {n.node_id for n in graph.nodes}
    assert blocked_hash in node_ids
    for camp in graph.campaigns:
        assert camp.primary_ioc_hash in node_ids
    assert any(e.relation == "primary_ioc" for e in graph.edges)
    assert any(e.relation == "associated_ioc" for e in graph.edges)


# ---------------------------------------------------------------------------
# NV-29: Official KB domains, subdomains, bare public suffixes & empty values
# ---------------------------------------------------------------------------


def test_nv29_protected_official_subdomains_kb_domains_and_empty_rejection(
    tmp_path: Path,
    sample_report: AnalysisReport,
) -> None:
    repo = CaseRepository(str(tmp_path / "nv29.db"), ioc_hmac_secret="nv29_secret_key_test")
    repo.init_db()
    repo.seed_if_empty(None, protected_iocs=[("domain", "custom-safe.org")])

    protected_domains = (
        "vietcombank.com.vn",
        "ebank.vietcombank.com.vn",
        "a.b.c.d.e.pay.shopee.vn",
        "shopee.vn",
        "zalopay.vn",
        "vnpay.vn",
        "tpb.vn",
        "evn.com.vn",
        "techcombank.com",
        "chinhphu.vn",
        "portal.chinhphu.vn",
        "custom.bca.gov.vn",
        "sub.custom-safe.org",
        "com.vn",
        "gov.vn",
        "net.vn",
        "org.vn",
        "edu.vn",
        "int.vn",
        "ac.vn",
    )
    for dom in protected_domains:
        assert repo.is_protected_ioc("domain", raw_value=dom) is True, f"Should protect {dom}"
        with pytest.raises(ProtectedDemoIocError):
            repo.add_block_rule("domain", reason="Sabotage", raw_value=dom)

    # Hash-only attempt against KB official domain is also rejected
    with pytest.raises(ProtectedDemoIocError):
        repo.add_block_rule(
            "domain",
            reason="Hash sabotage",
            ioc_hash=repo.hash_ioc_value("domain", "shopee.vn"),
        )

    # Empty canonical values rejected cleanly
    for bad_type, bad_val in (("phone", "---"), ("bank_account", "!!!"), ("domain", "...")):
        with pytest.raises(ValueError):
            repo.add_block_rule(bad_type, reason="Empty test", raw_value=bad_val)

    # Lookalikes are NOT protected and can be blocked
    for lookalike in ("evil-vietcombank.com.vn", "vietcombank.com.vn.evil.top"):
        assert repo.is_protected_ioc("domain", raw_value=lookalike) is False
        rule = repo.add_block_rule("domain", reason="Confirmed phish", raw_value=lookalike)
        assert rule.active is True

    # save_report & save_staged_report skip protected IOCs
    rep_with_official = sample_report.model_copy(
        update={
            "case_id": "vs_nv29_skip_official",
            "iocs": ExtractedIOCs(
                domains=["ebank.vietcombank.com.vn", "shopee.vn", "bad-actor.top"]
            ),
        }
    )
    repo.save_report(rep_with_official, contributes_to_radar=True, track_replay=False)
    assert repo.count_ioc_hits(ExtractedIOCs(domains=["ebank.vietcombank.com.vn"])) == 0
    assert repo.count_ioc_hits(ExtractedIOCs(domains=["shopee.vn"])) == 0
    assert repo.count_ioc_hits(ExtractedIOCs(domains=["bad-actor.top"])) == 1

    shopee_h = repo.hash_ioc_value("domain", "shopee.vn")
    staged_bad_h = repo.hash_ioc_value("domain", "staged-bad.top")
    repo.save_staged_report(
        sample_report,
        child_case_id="vs_nv29_staged_skip",
        parent_case_id="vs_nv29_skip_official",
        prehashed_iocs=[
            {"ioc_type": "domain", "ioc_hash": shopee_h, "masked_value": "sh****.vn"},
            {"ioc_type": "domain", "ioc_hash": staged_bad_h, "masked_value": "st****.top"},
        ],
        replay_fingerprints=[],
        contribute_to_radar=True,
    )
    assert repo.count_ioc_hits(ExtractedIOCs(domains=["shopee.vn"])) == 0
    assert repo.count_ioc_hits(ExtractedIOCs(domains=["staged-bad.top"])) == 1


# ---------------------------------------------------------------------------
# NV-30: Demo Radar exclusion & vs_tg_* 10-column + child cascade migration
# ---------------------------------------------------------------------------


def test_nv30_demo_exclusion_and_vs_tg_10col_child_cascade_migration(
    tmp_path: Path,
    sample_report: AnalysisReport,
) -> None:
    db_file = tmp_path / "nv30.db"
    repo = CaseRepository(str(db_file))
    repo.init_db()

    # 1. save_report(..., is_demo=True, contributes_to_radar=True) forces effective_radar=False
    demo_rep = sample_report.model_copy(
        update={"case_id": "vs_nv30_demo", "iocs": ExtractedIOCs(domains=["demo-only-scam.top"])}
    )
    repo.save_report(demo_rep, contributes_to_radar=True, is_demo=True, track_replay=False)
    assert repo.count_ioc_hits(ExtractedIOCs(domains=["demo-only-scam.top"])) == 0
    assert repo.get_radar_graph().stats["total_cases"] == 0

    with closing(sqlite3.connect(str(db_file))) as conn, conn:
        conn.execute("UPDATE cases SET contributes_to_radar = 1 WHERE case_id = 'vs_nv30_demo'")
    repo._invalidate_radar_cache()
    assert repo.get_radar_graph().stats["total_cases"] == 0

    # 2. Legacy vs_tg_* rotation preserves ALL 10 columns + cascades parent_case_id
    parent_leg = sample_report.model_copy(update={"case_id": "vs_tg_parent_1"})
    child_tg = sample_report.model_copy(update={"case_id": "vs_tg_child_2"})
    child_web = sample_report.model_copy(update={"case_id": "vs_web_child_3"})
    with closing(sqlite3.connect(str(db_file))) as conn, conn:
        conn.execute(
            "INSERT INTO cases (case_id, created_at, verdict, risk_score, report_json, "
            "owner_channel, owner_chat_hash, parent_case_id, contributes_to_radar, "
            "is_demo, redaction_ver) "
            "VALUES (?, ?, ?, ?, ?, 'telegram_private', 'owner_hash_xyz', 'vs_root_0', 0, 1, 0)",
            ("vs_tg_parent_1", parent_leg.created_at, parent_leg.verdict, 88, parent_leg.model_dump_json()),
        )
        conn.execute(
            "INSERT INTO cases (case_id, created_at, verdict, risk_score, report_json, "
            "owner_channel, owner_chat_hash, parent_case_id, contributes_to_radar, "
            "is_demo, redaction_ver) "
            "VALUES (?, ?, ?, ?, ?, 'telegram_private', 'owner_hash_xyz', 'vs_tg_parent_1', 0, 0, 0)",
            ("vs_tg_child_2", child_tg.created_at, child_tg.verdict, 88, child_tg.model_dump_json()),
        )
        conn.execute(
            "INSERT INTO cases (case_id, created_at, verdict, risk_score, report_json, "
            "owner_channel, owner_chat_hash, parent_case_id, contributes_to_radar, "
            "is_demo, redaction_ver) "
            "VALUES (?, ?, ?, ?, ?, 'web_token', NULL, 'vs_tg_parent_1', 1, 0, 2)",
            ("vs_web_child_3", child_web.created_at, child_web.verdict, 88, child_web.model_dump_json()),
        )

    repo.init_db()
    assert repo.get_report("vs_tg_parent_1") is None
    assert repo.get_report("vs_tg_child_2") is None

    web_child_rec = repo.get_report_with_owner("vs_web_child_3")
    assert web_child_rec is not None and web_child_rec.parent_case_id is not None
    rotated_parent_id = web_child_rec.parent_case_id
    assert rotated_parent_id != "vs_tg_parent_1" and not rotated_parent_id.startswith("vs_tg_")

    rotated_parent_rec = repo.get_report_with_owner(rotated_parent_id)
    assert rotated_parent_rec is not None
    assert rotated_parent_rec.owner_channel == "telegram_private"
    assert rotated_parent_rec.owner_chat_hash == "owner_hash_xyz"
    assert rotated_parent_rec.parent_case_id == "vs_root_0"
    assert rotated_parent_rec.is_demo is True

    with closing(sqlite3.connect(str(db_file))) as conn:
        conn.row_factory = sqlite3.Row
        p_row = conn.execute(
            "SELECT contributes_to_radar, redaction_ver FROM cases WHERE case_id = ?",
            (rotated_parent_id,),
        ).fetchone()
        c2_row = conn.execute(
            "SELECT case_id, parent_case_id, owner_channel, owner_chat_hash, redaction_ver "
            "FROM cases WHERE case_id != ? AND case_id != 'vs_web_child_3' "
            "AND owner_channel = 'telegram_private'",
            (rotated_parent_id,),
        ).fetchone()
    assert p_row is not None
    assert int(p_row["contributes_to_radar"]) == 0
    assert int(p_row["redaction_ver"]) == 2
    assert c2_row is not None
    assert str(c2_row["parent_case_id"]) == rotated_parent_id
    assert str(c2_row["owner_chat_hash"]) == "owner_hash_xyz"
    assert int(c2_row["redaction_ver"]) == 2


# ---------------------------------------------------------------------------
# NV-31: Bank-agnostic ref_h:, 30d TTL + upsert refresh, Hamming <= 3 dHash
# ---------------------------------------------------------------------------


def test_nv31_bank_agnostic_ref_ttl_upsert_refresh_and_hamming_dhash(tmp_path: Path) -> None:
    db_file = tmp_path / "nv31.db"
    repo = CaseRepository(str(db_file), ioc_hmac_secret="nv31_secret_key", receipt_ttl_days=30)
    repo.init_db()

    # 1. Bank-agnostic ref_h: across different detected bank names & casing
    fp_vcb = repo.hash_receipt_ref_fingerprint("Vietcombank", "ft2633090001")
    fp_mb = repo.hash_receipt_ref_fingerprint("MB Bank", "FT2633090001")
    fp_none = repo.hash_receipt_ref_fingerprint(None, " FT2633090001 ")
    assert fp_vcb == fp_mb == fp_none
    assert fp_vcb.startswith("ref_h:") and len(fp_vcb) == 70

    t0 = datetime.now(UTC)
    assert repo.claim_receipt_replay(None, "Vietcombank", "FT2633090001", now=t0) is False
    assert repo.is_receipt_replayed(None, "Techcombank", "ft2633090001", now=t0) is True
    assert repo.is_receipt_replayed(None, None, "FT2633090001", now=t0) is True

    # 2. Expired row (> 30d) is ignored on read, and re-claiming refreshes created_at via upsert!
    old_ts = (t0 - timedelta(days=35)).isoformat()
    with closing(sqlite3.connect(str(db_file))) as conn, conn:
        conn.execute(
            "INSERT INTO receipt_hashes (fingerprint, created_at) VALUES (?, ?)",
            (repo.hash_receipt_ref_fingerprint("ACB", "FT_EXPIRED_01"), old_ts),
        )
    assert repo.is_receipt_replayed(None, "ACB", "FT_EXPIRED_01", now=t0) is False
    assert (
        repo.claim_receipt_replay(None, "ACB", "FT_EXPIRED_01", register_if_new=True, now=t0)
        is False
    )
    assert repo.is_receipt_replayed(None, "ACB", "FT_EXPIRED_01", now=t0) is True

    # 3. Hamming distance <= 3 on 64-bit hex dHash (and 4 bits is NOT a collision)
    assert repo.claim_receipt_replay("0000000000000000", None, None, now=t0) is False
    assert repo.is_receipt_replayed("0000000000000001", None, None, now=t0) is True
    assert repo.is_receipt_replayed("0000000000000003", None, None, now=t0) is True
    assert repo.is_receipt_replayed("0000000000000007", None, None, now=t0) is True
    assert repo.is_receipt_replayed("000000000000000f", None, None, now=t0) is False

    # Expired Hamming-close dHash + malformed dHash entries never falsely hit or raise
    with closing(sqlite3.connect(str(db_file))) as conn, conn:
        conn.execute(
            "INSERT INTO receipt_hashes (fingerprint, created_at) "
            "VALUES ('dhash:ffffffffffffffff', ?)",
            (old_ts,),
        )
        conn.execute(
            "INSERT INTO receipt_hashes (fingerprint, created_at) "
            "VALUES ('dhash:not_valid_hex!!!', ?)",
            (t0.isoformat(),),
        )
    assert repo.is_receipt_replayed("fffffffffffffffe", None, None, now=t0) is False
    assert repo.is_receipt_replayed("zzzz", None, None, now=t0) is False

    # 4. Legacy ref: migration keeps MAX(created_at) on conflict
    older_recent = (t0 - timedelta(hours=5)).isoformat()
    newer_recent = (t0 - timedelta(hours=1)).isoformat()
    with closing(sqlite3.connect(str(db_file))) as conn, conn:
        conn.execute(
            "INSERT INTO receipt_hashes (fingerprint, created_at) "
            "VALUES ('ref:VCB:FT_MERGE_9', ?)",
            (older_recent,),
        )
        conn.execute(
            "INSERT INTO receipt_hashes (fingerprint, created_at) "
            "VALUES ('ref:MB:FT_MERGE_9', ?)",
            (newer_recent,),
        )
    repo.init_db()
    merged_fp = repo.hash_receipt_ref_fingerprint(None, "FT_MERGE_9")
    with closing(sqlite3.connect(str(db_file))) as conn:
        row = conn.execute(
            "SELECT created_at FROM receipt_hashes WHERE fingerprint = ?", (merged_fp,)
        ).fetchone()
    assert row is not None and str(row[0]) == newer_recent


# ---------------------------------------------------------------------------
# NV-33: O(1) domain expansion & 500-hash SQL IN chunking
# ---------------------------------------------------------------------------


def test_nv33_domain_expansion_o1_and_sql_chunking(tmp_path: Path) -> None:
    repo = CaseRepository(str(tmp_path / "nv33.db"))
    repo.init_db()

    # 50k-label adversarial domain rejected in O(1)
    huge_host = "a." * 50_000 + "evil.top"
    t0 = time.perf_counter()
    assert repo._expand_domain_candidates([huge_host]) == []
    assert (time.perf_counter() - t0) < 0.25

    # Deep .com.vn domain still yields all 4 valid parent levels (never bare com.vn)
    deep_vn = "a.b.c.d.e.f.g.bank.com.vn"
    expanded_vn = repo._expand_domain_candidates([deep_vn])
    assert len(expanded_vn) == 1 + MAX_DOMAIN_PARENT_LEVELS
    assert expanded_vn[0] == deep_vn
    assert "bank.com.vn" in expanded_vn
    assert "e.f.g.bank.com.vn" in expanded_vn
    assert "com.vn" not in expanded_vn

    # 1,200 hashes (> SQLite 999 bind parameter limit) succeed via chunking
    h_high = repo.hash_ioc_value("domain", "camp-high.top")
    h_low = repo.hash_ioc_value("domain", "camp-low.top")
    with closing(sqlite3.connect(str(tmp_path / "nv33.db"))) as conn, conn:
        conn.execute(
            "INSERT INTO campaigns (campaign_id, title_vi, playbook_id, case_count, "
            "primary_ioc_type, primary_ioc_hash, primary_ioc_masked, recommended_action, "
            "is_demo, label_ver) "
            "VALUES ('c_low', 'Chiến dịch nhỏ', 'pb1', 2, 'domain', ?, 'ca****.top', 'act', 0, 1)",
            (h_low,),
        )
        conn.execute(
            "INSERT INTO campaigns (campaign_id, title_vi, playbook_id, case_count, "
            "primary_ioc_type, primary_ioc_hash, primary_ioc_masked, recommended_action, "
            "is_demo, label_ver) "
            "VALUES ('c_high', 'Chiến dịch lớn', 'pb2', 25, 'domain', ?, 'ca****.top', 'act', 0, 1)",
            (h_high,),
        )
    many_hashes = [f"{i:064x}" for i in range(1200)] + [h_low, h_high]
    titles = repo.find_campaign_titles_for_hashes(many_hashes, limit=2)
    assert titles == ["Chiến dịch lớn", "Chiến dịch nhỏ"]


# ---------------------------------------------------------------------------
# NV-35: Batched init_db (>100 rows), indexes & retention pruning
# ---------------------------------------------------------------------------


def test_nv35_batched_init_db_indexes_and_retention_pruning(
    tmp_path: Path,
    sample_report: AnalysisReport,
) -> None:
    db_file = tmp_path / "nv35_batch.db"
    repo = CaseRepository(str(db_file))
    repo.init_db()

    with closing(sqlite3.connect(str(db_file))) as conn:
        indexes = {
            str(r[0])
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()
        }
    assert EXPECTED_INDEXES.issubset(indexes)

    recent_ts = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    with closing(sqlite3.connect(str(db_file))) as conn, conn:
        for i in range(225):
            rep_i = sample_report.model_copy(update={"case_id": f"vs_leg_{i:04d}"})
            conn.execute(
                "INSERT INTO cases (case_id, created_at, verdict, risk_score, report_json, "
                "redaction_ver) VALUES (?, ?, ?, 88, ?, 0)",
                (rep_i.case_id, rep_i.created_at, rep_i.verdict, rep_i.model_dump_json()),
            )
            conn.execute(
                "INSERT INTO telegram_updates (update_id, status, reply_text, created_at, scrubbed) "
                "VALUES (?, 'completed', ?, ?, 0)",
                (10_000 + i, f"Email leak{i}@example.com", recent_ts),
            )
            conn.execute(
                "INSERT INTO ioc_sightings "
                "(ioc_hash, ioc_type, masked_value, hit_count, is_demo, label_ver) "
                "VALUES (?, 'bank_account', '190384756201****', 1, 0, 0)",
                (f"legacyhash{i:054d}",),
            )
            conn.execute(
                "INSERT INTO radar_audit_logs "
                "(audit_id, created_at, action, outcome, rule_id, detail, client_ip_hash) "
                "VALUES (?, ?, 'revoke_rule', 'allowed', 'BAD_RULE_ID', 'd', 'ip')",
                (f"aud_leg_{i:04d}", recent_ts),
            )
            conn.execute(
                "INSERT INTO receipt_hashes (fingerprint, created_at) VALUES (?, ?)",
                (f"ref:VCB:FT_BATCH_{i:04d}", recent_ts),
            )

    repo.init_db()
    with closing(sqlite3.connect(str(db_file))) as conn:
        assert conn.execute("SELECT COUNT(*) FROM cases WHERE redaction_ver < 2").fetchone()[0] == 0
        assert (
            conn.execute("SELECT COUNT(*) FROM telegram_updates WHERE scrubbed = 0").fetchone()[0]
            == 0
        )
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM telegram_updates WHERE reply_text LIKE '%@example.com%'"
            ).fetchone()[0]
            == 0
        )
        assert (
            conn.execute("SELECT COUNT(*) FROM ioc_sightings WHERE label_ver < 1").fetchone()[0]
            == 0
        )
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM ioc_sightings WHERE masked_value LIKE '190384756201%'"
            ).fetchone()[0]
            == 0
        )
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM radar_audit_logs WHERE rule_id = 'BAD_RULE_ID'"
            ).fetchone()[0]
            == 0
        )
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM receipt_hashes WHERE fingerprint LIKE 'ref:%'"
            ).fetchone()[0]
            == 0
        )
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM receipt_hashes WHERE fingerprint LIKE 'ref_h:%'"
            ).fetchone()[0]
            == 225
        )

    # save_telegram_update_cache scrubs PII on write & sets scrubbed=1
    repo.save_telegram_update_cache(999_001, None, "Email: secret@example.com OTP: 918273")
    cached = repo.get_telegram_update_cache(999_001)
    assert cached is not None
    assert "secret@example.com" not in cached[1]
    assert "918273" not in cached[1]
    with closing(sqlite3.connect(str(db_file))) as conn:
        row_sc = conn.execute(
            "SELECT scrubbed FROM telegram_updates WHERE update_id = 999001"
        ).fetchone()
    assert row_sc is not None and row_sc[0] == 1

    # Retention pruning preserves demo, campaign, primary_ioc, block_rule & campaign edges
    prune_db = tmp_path / "nv35_prune.db"
    p_repo = CaseRepository(
        str(prune_db),
        max_stored_cases=3,
        max_stored_ioc_sightings=5,
        max_stored_receipt_hashes=3,
        max_stored_telegram_updates=3,
        receipt_ttl_days=30,
        telegram_update_ttl_days=7,
    )
    p_repo.init_db()
    seed_file = Path(__file__).resolve().parents[2] / "app" / "data" / "seed_iocs.json"
    p_repo.seed_if_empty(str(seed_file))

    base_dt = datetime.now(UTC)
    for i in range(5):
        r = sample_report.model_copy(
            update={
                "case_id": f"vs_prune_c_{i}",
                "created_at": (base_dt + timedelta(minutes=i)).isoformat(),
                "iocs": ExtractedIOCs(domains=[f"prune-dom-{i}.top", f"prune-co-{i}.top"]),
            }
        )
        p_repo.save_report(r, contributes_to_radar=True, track_replay=False)

    blk_rule = p_repo.add_block_rule("domain", reason="Keep blocked", raw_value="keep-blocked.top")
    blk_hash = p_repo.hash_ioc_value("domain", "keep-blocked.top")
    with closing(sqlite3.connect(str(prune_db))) as conn, conn:
        conn.execute(
            "INSERT OR REPLACE INTO ioc_sightings "
            "(ioc_hash, ioc_type, masked_value, hit_count, is_demo, label_ver) "
            "VALUES (?, 'domain', 'ke****.top', 1, 0, 1)",
            (blk_hash,),
        )
        expired_rcpt = (base_dt - timedelta(days=40)).isoformat()
        expired_tg = (base_dt - timedelta(days=10)).isoformat()
        conn.execute("INSERT INTO receipt_hashes VALUES ('dhash:1111111111111111', ?)", (expired_rcpt,))
        for i in range(5):
            conn.execute(
                "INSERT INTO receipt_hashes VALUES (?, ?)",
                (f"dhash:222222222222222{i}", (base_dt + timedelta(seconds=i)).isoformat()),
            )
        conn.execute(
            "INSERT INTO telegram_updates (update_id, status, reply_text, created_at, scrubbed) "
            "VALUES (1, 'completed', 'old', ?, 1)",
            (expired_tg,),
        )
        conn.execute(
            "INSERT INTO telegram_updates (update_id, status, reply_text, created_at, scrubbed) "
            "VALUES (2, 'quarantined', 'oldq', ?, 1)",
            (expired_tg,),
        )
        for i in range(5):
            conn.execute(
                "INSERT INTO telegram_updates (update_id, status, reply_text, created_at, scrubbed) "
                "VALUES (?, 'completed', 'new', ?, 1)",
                (10 + i, (base_dt + timedelta(seconds=i)).isoformat()),
            )

    p_repo.init_db()
    with closing(sqlite3.connect(str(prune_db))) as conn:
        case_ids = {r[0] for r in conn.execute("SELECT case_id FROM cases").fetchall()}
        assert case_ids == {"vs_prune_c_2", "vs_prune_c_3", "vs_prune_c_4"}
        sight_hashes = {r[0] for r in conn.execute("SELECT ioc_hash FROM ioc_sightings").fetchall()}
        assert blk_hash in sight_hashes
        assert conn.execute("SELECT COUNT(*) FROM ioc_sightings WHERE is_demo = 1").fetchone()[0] > 0
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM ioc_edges WHERE relation = 'primary_ioc'"
            ).fetchone()[0]
            > 0
        )
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM ioc_edges WHERE relation = 'associated_ioc'"
            ).fetchone()[0]
            > 0
        )
        orphan_edges = conn.execute(
            "SELECT COUNT(*) FROM ioc_edges WHERE "
            "(source_id NOT IN (SELECT ioc_hash FROM ioc_sightings) "
            "AND source_id NOT IN (SELECT campaign_id FROM campaigns)) "
            "OR (target_id NOT IN (SELECT ioc_hash FROM ioc_sightings) "
            "AND target_id NOT IN (SELECT campaign_id FROM campaigns))"
        ).fetchone()[0]
        assert orphan_edges == 0
        assert conn.execute("SELECT COUNT(*) FROM receipt_hashes").fetchone()[0] == 3
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM receipt_hashes WHERE fingerprint = 'dhash:1111111111111111'"
            ).fetchone()[0]
            == 0
        )
        assert conn.execute("SELECT COUNT(*) FROM telegram_updates").fetchone()[0] == 3
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM telegram_updates WHERE update_id IN (1, 2)"
            ).fetchone()[0]
            == 0
        )
    assert blk_rule.active is True

    # Prompt connection close check (no leaked SQLite handles from CaseRepository on Windows)
    was_gc = gc.isenabled()
    gc.disable()
    try:
        prune_db.unlink()
        for sfx in ("-wal", "-shm"):
            side = Path(f"{prune_db}{sfx}")
            if side.exists():
                side.unlink()
    finally:
        if was_gc:
            gc.enable()
    assert not prune_db.exists()


# ---------------------------------------------------------------------------
# NV-36: Short-TTL versioned Radar cache & invalidation on every write
# ---------------------------------------------------------------------------


def test_nv36_radar_cache_hit_isolation_and_write_invalidation(
    tmp_path: Path,
    sample_report: AnalysisReport,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = CaseRepository(str(tmp_path / "nv36.db"))
    repo.init_db()

    session_calls = 0
    orig_session = repo._session

    def _counting_session() -> Any:
        nonlocal session_calls
        session_calls += 1
        return orig_session()

    monkeypatch.setattr(repo, "_session", _counting_session)

    g1 = repo.get_radar_graph()
    assert session_calls == 1
    g1.stats["total_cases"] = 9999
    g2 = repo.get_radar_graph()
    assert session_calls == 1
    assert g2.stats["total_cases"] == 0

    _ = repo.get_radar_graph(now=datetime.now(UTC))
    assert session_calls == 2

    rule = repo.add_block_rule("domain", reason="Cache inv", raw_value="cache-inv.top")
    g3 = repo.get_radar_graph()
    assert len(g3.active_block_rules) == 1

    repo.revoke_block_rule(rule.rule_id)
    assert len(repo.get_radar_graph().active_block_rules) == 0

    repo.add_block_rule("domain", reason="Cache inv 2", raw_value="cache-inv-2.top")
    repo.reset_transient_rules()
    assert len(repo.get_radar_graph().active_block_rules) == 0

    repo.record_audit_log(action="reset_rules", outcome="allowed", detail="Audit cache check")
    assert any(a.detail == "Audit cache check" for a in repo.get_radar_graph().recent_audit_logs)

    repo.save_report(
        sample_report.model_copy(update={"case_id": "vs_nv36_live"}),
        contributes_to_radar=True,
        track_replay=False,
    )
    assert repo.get_radar_graph().stats["total_cases"] == 1


# ---------------------------------------------------------------------------
# NV-41: Telegram delivery failure attempts, immediate lease expiry & quarantine
# ---------------------------------------------------------------------------


def test_nv41_telegram_delivery_attempts_lease_expiry_and_quarantine(tmp_path: Path) -> None:
    repo = CaseRepository(str(tmp_path / "nv41.db"))
    repo.init_db()

    st1, cid1, _ = repo.claim_telegram_update(
        5001, owner_id="w1", lease_seconds=180, chat_id=100, sender_user_id=200, chat_type="private"
    )
    assert st1 == "claimed" and cid1 is not None

    # Wrong owner_id is ignored
    res_wrong = repo.record_telegram_delivery_failure(
        5001, permanent=False, max_attempts=3, owner_id="wrong"
    )
    assert res_wrong == (0, False)

    # Attempt 1 transient failure -> lease expired immediately so w2 reclaims without 180s deadlock
    assert repo.record_telegram_delivery_failure(
        5001, permanent=False, max_attempts=3, owner_id="w1"
    ) == (1, False)
    st2, cid2, _ = repo.claim_telegram_update(
        5001, owner_id="w2", lease_seconds=180, chat_id=100, sender_user_id=200, chat_type="private"
    )
    assert st2 == "claimed" and cid2 == cid1

    # Attempt 2 transient failure -> still reclaimable
    assert repo.record_telegram_delivery_failure(
        5001, permanent=False, max_attempts=3, owner_id="w2"
    ) == (2, False)
    st3, cid3, _ = repo.claim_telegram_update(
        5001, owner_id="w3", lease_seconds=180, chat_id=100, sender_user_id=200, chat_type="private"
    )
    assert st3 == "claimed" and cid3 == cid1

    # Attempt 3 hits max_attempts=3 -> quarantined!
    assert repo.record_telegram_delivery_failure(
        5001, permanent=False, max_attempts=3, owner_id="w3"
    ) == (3, True)
    assert repo.claim_telegram_update(
        5001, owner_id="w4", chat_id=100, sender_user_id=200, chat_type="private"
    ) == ("quarantined", None, None)
    assert repo.claim_telegram_update(
        5001, owner_id="w4", chat_id=999, sender_user_id=200, chat_type="private"
    ) == ("mismatch", None, None)

    # 2. Permanent failure on processing quarantines immediately on attempt 1
    st_p, _, _ = repo.claim_telegram_update(
        5002, owner_id="p1", chat_id=101, sender_user_id=201, chat_type="private"
    )
    assert st_p == "claimed"
    assert repo.record_telegram_delivery_failure(
        5002, permanent=True, max_attempts=3, owner_id="p1"
    ) == (1, True)
    assert repo.claim_telegram_update(
        5002, owner_id="p2", chat_id=101, sender_user_id=201, chat_type="private"
    ) == ("quarantined", None, None)

    # 3. Completed row delivery failure increments attempts and quarantines at threshold
    st_c, _, _ = repo.claim_telegram_update(
        5003, owner_id="c1", chat_id=102, sender_user_id=202, chat_type="private"
    )
    assert st_c == "claimed"
    repo.save_telegram_update_cache(5003, "vs_c3", "cached reply", owner_id="c1")
    assert repo.record_telegram_delivery_failure(5003, permanent=False, max_attempts=2) == (1, False)
    st_cached, _, _ = repo.claim_telegram_update(
        5003, owner_id="c2", chat_id=102, sender_user_id=202, chat_type="private"
    )
    assert st_cached == "cached"
    assert repo.record_telegram_delivery_failure(5003, permanent=False, max_attempts=2) == (2, True)
    assert repo.claim_telegram_update(
        5003, owner_id="c3", chat_id=102, sender_user_id=202, chat_type="private"
    ) == ("quarantined", None, None)
