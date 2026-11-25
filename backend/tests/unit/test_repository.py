from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.db.repository import CaseRepository, ProtectedDemoIocError
from app.schemas import AnalysisReport, ExtractedIOCs
from app.services.ioc_extractor import hash_ioc


def test_wal_pii_redaction_ttl_protected_demo_and_hash_blocking(
    tmp_path: Path,
    sample_report: AnalysisReport,
) -> None:
    db_file = tmp_path / "verishield.db"
    seed_file = Path(__file__).resolve().parents[2] / "app" / "data" / "seed_iocs.json"
    repo = CaseRepository(str(db_file), default_ttl_minutes=30)
    repo.init_db()
    repo.seed_if_empty(
        str(seed_file),
        protected_iocs=[("domain", "vietcombank.com.vn"), ("bank_account", "0011009999999")],
    )

    # Protected SAFE demo IOCs cannot be blocked by raw value OR by pre-computed hash
    with pytest.raises(ProtectedDemoIocError):
        repo.add_block_rule("domain", reason="Attempted sabotage", raw_value="vietcombank.com.vn")
    with pytest.raises(ProtectedDemoIocError):
        repo.add_block_rule(
            "bank_account",
            reason="Hash sabotage",
            ioc_hash=hash_ioc("bank_account", "0011009999999"),
            masked_value="0011****9999",
        )

    t0 = datetime(2026, 11, 26, 10, 0, tzinfo=UTC)
    rule = repo.add_block_rule(
        "bank_account",
        reason="Confirmed mule ring",
        raw_value="190384756201",
        ttl_minutes=30,
        now=t0,
    )
    assert rule.masked_value == "1903****6201"

    probe_iocs = ExtractedIOCs(
        phones=["0912345678"],
        bank_accounts=["190384756201"],
        urls=[],
        domains=[],
        brands=[],
    )
    assert len(repo.match_active_block_rules(probe_iocs, now=t0 + timedelta(minutes=15))) == 1
    assert len(repo.match_active_block_rules(probe_iocs, now=t0 + timedelta(minutes=31))) == 0

    # Save report and verify persisted case & radar graph contain ZERO raw phone/STK PII
    repo.save_report(sample_report, receipt_dhash="a1b2c3d4e5f60718")
    loaded = repo.get_report(sample_report.case_id)
    assert loaded is not None
    dumped_case = loaded.model_dump_json()
    assert "0912345678" not in dumped_case
    assert "190384756201" not in dumped_case
    assert "091****678" in loaded.iocs.phones
    assert "1903****6201" in loaded.iocs.bank_accounts

    assert repo.is_receipt_replayed("a1b2c3d4e5f60718", None, None) is True
    assert repo.is_receipt_replayed("ffffffffffffffff", None, None) is False

    graph = repo.get_radar_graph(now=t0 + timedelta(minutes=5))
    graph_json = graph.model_dump_json()
    assert "190384756201" not in graph_json
    assert "0912345678" not in graph_json
    assert len(graph.campaigns) >= 1

    # Block an emerging campaign by opaque primary_ioc_hash (1-click /radar flow)
    first_camp = graph.campaigns[0]
    camp_rule = repo.add_block_rule(
        first_camp.primary_ioc_type,
        reason="1-Click Fraud Ops Campaign Block",
        ioc_hash=first_camp.primary_ioc_hash,
        now=t0 + timedelta(minutes=6),
    )
    assert camp_rule.active is True

    cleared = repo.reset_transient_rules()
    assert cleared >= 2
    assert len(repo.get_radar_graph(now=t0 + timedelta(minutes=7)).active_block_rules) == 0
