"""SQLite WAL repository: PII-redacted cases, masked IOC threat graph, replay hashes & TTL rules."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.schemas import (
    AnalysisReport,
    BlockRule,
    EmergingCampaign,
    ExtractedIOCs,
    IocType,
    RadarEdge,
    RadarGraphResponse,
    RadarNode,
)
from app.services.ioc_extractor import hash_ioc, mask_ioc


class ProtectedDemoIocError(ValueError):
    """Raised when attempting to create a block rule against a protected SAFE demo IOC (HTTP 409)."""


def redact_report_pii(report: AnalysisReport) -> AnalysisReport:
    """Return a deep copy of AnalysisReport with all raw phone/bank-account PII masked."""
    replacements: list[tuple[str, str]] = []
    masked_phones: list[str] = []
    for ph in report.iocs.phones:
        masked = ph if "****" in ph else mask_ioc("phone", ph)
        masked_phones.append(masked)
        if ph != masked:
            replacements.append((ph, masked))

    masked_accounts: list[str] = []
    for acct in report.iocs.bank_accounts:
        masked = acct if "****" in acct else mask_ioc("bank_account", acct)
        masked_accounts.append(masked)
        if acct != masked:
            replacements.append((acct, masked))

    masked_vqr = []
    for v in report.vietqr_findings:
        if v.account_number and "****" not in v.account_number:
            m_acct = mask_ioc("bank_account", v.account_number)
            replacements.append((v.account_number, m_acct))
            masked_vqr.append(v.model_copy(update={"account_number": m_acct}))
        else:
            masked_vqr.append(v)

    def _scrub_str(val: str | None) -> str | None:
        if not val:
            return val
        out = val
        for raw_val, m_val in replacements:
            if raw_val:
                out = out.replace(raw_val, m_val)
        return out

    scrubbed_ev = [
        ev.model_copy(
            update={
                "detail": _scrub_str(ev.detail) or ev.detail,
                "snippet": _scrub_str(ev.snippet),
            }
        )
        for ev in report.evidence
    ]

    return report.model_copy(
        update={
            "summary_vi": _scrub_str(report.summary_vi) or report.summary_vi,
            "transcript": _scrub_str(report.transcript),
            "iocs": report.iocs.model_copy(
                update={"phones": masked_phones, "bank_accounts": masked_accounts}
            ),
            "vietqr_findings": masked_vqr,
            "evidence": scrubbed_ev,
        }
    )


class CaseRepository:
    """Thread-safe SQLite WAL repository with multi-judge TTL block-rule isolation."""

    def __init__(self, sqlite_path: str, default_ttl_minutes: int = 30) -> None:
        self._db_path = sqlite_path
        self._default_ttl = max(1, default_ttl_minutes)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def init_db(self) -> None:
        """Initialize SQLite schema with hashed/masked-only IOC graph tables."""
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    report_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ioc_sightings (
                    ioc_hash TEXT PRIMARY KEY,
                    ioc_type TEXT NOT NULL,
                    masked_value TEXT NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 1,
                    campaign_id TEXT
                );
                CREATE TABLE IF NOT EXISTS ioc_edges (
                    source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    relation TEXT NOT NULL DEFAULT 'co_occurs',
                    PRIMARY KEY (source_id, target_id)
                );
                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    title_vi TEXT NOT NULL,
                    playbook_id TEXT NOT NULL,
                    case_count INTEGER NOT NULL DEFAULT 1,
                    primary_ioc_type TEXT NOT NULL,
                    primary_ioc_hash TEXT NOT NULL,
                    primary_ioc_masked TEXT NOT NULL,
                    recommended_action TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS block_rules (
                    rule_id TEXT PRIMARY KEY,
                    ioc_hash TEXT NOT NULL UNIQUE,
                    ioc_type TEXT NOT NULL,
                    masked_value TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS protected_demo_iocs (
                    ioc_hash TEXT PRIMARY KEY,
                    ioc_type TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS receipt_hashes (
                    fingerprint TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL
                );
                """
            )

    def seed_if_empty(
        self,
        seed_path: str,
        protected_iocs: list[tuple[str, str]] | None = None,
    ) -> None:
        """Seed synthetic masked IOC campaigns and register protected SAFE demo IOC hashes."""
        with self._connect() as conn:
            if protected_iocs:
                for prot_type, prot_raw in protected_iocs:
                    conn.execute(
                        "INSERT OR IGNORE INTO protected_demo_iocs (ioc_hash, ioc_type) VALUES (?, ?)",
                        (hash_ioc(prot_type, prot_raw), prot_type),
                    )

            existing = conn.execute("SELECT COUNT(*) AS cnt FROM campaigns").fetchone()
            if existing and int(existing["cnt"]) > 0:
                return

            seed_file = Path(seed_path)
            if not seed_file.exists():
                return
            payload = json.loads(seed_file.read_text(encoding="utf-8"))
            for camp in payload.get("campaigns", []):
                cid: str = camp["campaign_id"]
                p_type: IocType = camp["primary_ioc_type"]
                p_raw_syn: str = camp["primary_ioc_raw_synthetic"]
                p_hash = hash_ioc(p_type, p_raw_syn)
                p_masked = mask_ioc(p_type, p_raw_syn)
                c_count = int(camp.get("case_count", 3))

                conn.execute(
                    """
                    INSERT OR IGNORE INTO campaigns
                    (campaign_id, title_vi, playbook_id, case_count, primary_ioc_type,
                     primary_ioc_hash, primary_ioc_masked, recommended_action)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cid,
                        camp["title_vi"],
                        camp["playbook_id"],
                        c_count,
                        p_type,
                        p_hash,
                        p_masked,
                        camp["recommended_action"],
                    ),
                )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO ioc_sightings
                    (ioc_hash, ioc_type, masked_value, hit_count, campaign_id)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (p_hash, p_type, p_masked, c_count, cid),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO ioc_edges (source_id, target_id, relation) VALUES (?, ?, ?)",
                    (cid, p_hash, "primary_ioc"),
                )

                for co in camp.get("co_iocs", []):
                    co_t: IocType = co["ioc_type"]
                    co_raw: str = co["raw_synthetic"]
                    co_h = hash_ioc(co_t, co_raw)
                    co_m = mask_ioc(co_t, co_raw)
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO ioc_sightings
                        (ioc_hash, ioc_type, masked_value, hit_count, campaign_id)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (co_h, co_t, co_m, max(1, c_count - 1), cid),
                    )
                    conn.execute(
                        "INSERT OR IGNORE INTO ioc_edges (source_id, target_id, relation) VALUES (?, ?, ?)",
                        (cid, co_h, "associated_ioc"),
                    )

    def _upsert_sighting(
        self,
        conn: sqlite3.Connection,
        ioc_type: IocType,
        raw_val: str,
    ) -> str:
        h = hash_ioc(ioc_type, raw_val)
        m = mask_ioc(ioc_type, raw_val)
        conn.execute(
            """
            INSERT INTO ioc_sightings (ioc_hash, ioc_type, masked_value, hit_count)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(ioc_hash) DO UPDATE SET hit_count = hit_count + 1
            """,
            (h, ioc_type, m),
        )
        return h

    def save_report(
        self,
        report: AnalysisReport,
        receipt_dhash: str | None = None,
        track_replay: bool = True,
    ) -> AnalysisReport:
        """Persist PII-redacted case report, update masked IOC graph, and store replay hashes."""
        redacted = redact_report_pii(report)
        with self._connect() as conn:
            if report.risk_score >= 45:
                seen_hashes: list[str] = []
                for ph in report.iocs.phones:
                    if "****" not in ph:
                        seen_hashes.append(self._upsert_sighting(conn, "phone", ph))
                for acct in report.iocs.bank_accounts:
                    if "****" not in acct:
                        seen_hashes.append(self._upsert_sighting(conn, "bank_account", acct))
                for dom in report.iocs.domains:
                    if "****" not in dom:
                        seen_hashes.append(self._upsert_sighting(conn, "domain", dom))

                for idx in range(len(seen_hashes)):
                    for jdx in range(idx + 1, len(seen_hashes)):
                        conn.execute(
                            "INSERT OR IGNORE INTO ioc_edges (source_id, target_id, relation) "
                            "VALUES (?, ?, 'co_occurs')",
                            (seen_hashes[idx], seen_hashes[jdx]),
                        )

            if track_replay:
                now_iso = datetime.now(UTC).isoformat()
                if receipt_dhash:
                    conn.execute(
                        "INSERT OR IGNORE INTO receipt_hashes (fingerprint, created_at) VALUES (?, ?)",
                        (f"dhash:{receipt_dhash}", now_iso),
                    )
                if report.receipt_logic and report.receipt_logic.reference_code:
                    bank_lbl = report.receipt_logic.bank_detected or ""
                    ref_fp = f"ref:{bank_lbl}:{report.receipt_logic.reference_code}"
                    conn.execute(
                        "INSERT OR IGNORE INTO receipt_hashes (fingerprint, created_at) VALUES (?, ?)",
                        (ref_fp, now_iso),
                    )

            conn.execute(
                """
                INSERT OR REPLACE INTO cases (case_id, created_at, verdict, risk_score, report_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    redacted.case_id,
                    redacted.created_at,
                    redacted.verdict,
                    redacted.risk_score,
                    redacted.model_dump_json(),
                ),
            )
        return redacted

    def get_report(self, case_id: str) -> AnalysisReport | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT report_json FROM cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
        if not row:
            return None
        return AnalysisReport.model_validate_json(str(row["report_json"]))

    def is_receipt_replayed(
        self,
        dhash_hex: str | None,
        bank: str | None,
        ref_code: str | None,
    ) -> bool:
        probes: list[str] = []
        if dhash_hex:
            probes.append(f"dhash:{dhash_hex}")
        if ref_code:
            probes.append(f"ref:{bank or ''}:{ref_code}")
        if not probes:
            return False
        placeholders = ",".join("?" for _ in probes)
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT 1 FROM receipt_hashes WHERE fingerprint IN ({placeholders}) LIMIT 1",  # noqa: S608
                tuple(probes),
            ).fetchone()
        return row is not None

    def count_ioc_hits(self, iocs: ExtractedIOCs) -> int:
        hashes = (
            [hash_ioc("phone", p) for p in iocs.phones]
            + [hash_ioc("bank_account", a) for a in iocs.bank_accounts]
            + [hash_ioc("domain", d) for d in iocs.domains]
        )
        if not hashes:
            return 0
        placeholders = ",".join("?" for _ in hashes)
        with self._connect() as conn:
            sql = (
                f"SELECT COALESCE(SUM(hit_count), 0) AS total "  # noqa: S608
                f"FROM ioc_sightings WHERE ioc_hash IN ({placeholders})"
            )
            row = conn.execute(sql, tuple(hashes)).fetchone()
        return int(row["total"]) if row else 0

    def match_active_block_rules(
        self,
        iocs: ExtractedIOCs,
        now: datetime | None = None,
    ) -> list[BlockRule]:
        hashes = (
            [hash_ioc("phone", p) for p in iocs.phones]
            + [hash_ioc("bank_account", a) for a in iocs.bank_accounts]
            + [hash_ioc("domain", d) for d in iocs.domains]
        )
        if not hashes:
            return []
        now_iso = (now or datetime.now(UTC)).isoformat()
        placeholders = ",".join("?" for _ in hashes)
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT rule_id, ioc_type, masked_value, reason, created_at, expires_at
                FROM block_rules
                WHERE ioc_hash IN ({placeholders}) AND expires_at > ?
                """,  # noqa: S608
                (*hashes, now_iso),
            ).fetchall()
        return [
            BlockRule(
                rule_id=str(r["rule_id"]),
                ioc_type=r["ioc_type"],
                masked_value=str(r["masked_value"]),
                reason=str(r["reason"]),
                created_at=str(r["created_at"]),
                expires_at=str(r["expires_at"]),
                active=True,
            )
            for r in rows
        ]

    def add_block_rule(
        self,
        ioc_type: IocType,
        reason: str,
        raw_value: str | None = None,
        ioc_hash: str | None = None,
        masked_value: str | None = None,
        ttl_minutes: int | None = None,
        now: datetime | None = None,
    ) -> BlockRule:
        """Create/refresh a TTL-bounded block rule while protecting SAFE demo IOCs."""
        if raw_value and raw_value.strip():
            target_hash = hash_ioc(ioc_type, raw_value)
            resolved_mask = mask_ioc(ioc_type, raw_value)
        elif ioc_hash:
            target_hash = ioc_hash.strip().lower()
            resolved_mask = masked_value or ""
        else:
            raise ValueError("Either raw_value or ioc_hash is required.")

        ts_now = now or datetime.now(UTC)
        ttl = ttl_minutes if ttl_minutes is not None else self._default_ttl
        expires_iso = (ts_now + timedelta(minutes=ttl)).isoformat()
        created_iso = ts_now.isoformat()
        rule_id = f"rule_{uuid.uuid4().hex[:10]}"

        with self._connect() as conn:
            prot = conn.execute(
                "SELECT 1 FROM protected_demo_iocs WHERE ioc_hash = ?",
                (target_hash,),
            ).fetchone()
            if prot is not None:
                raise ProtectedDemoIocError(
                    "IOC này thuộc kịch bản Demo an toàn gốc nên được khóa bảo vệ chống ghi đè."
                )

            if not resolved_mask:
                sighting = conn.execute(
                    "SELECT masked_value FROM ioc_sightings WHERE ioc_hash = ?",
                    (target_hash,),
                ).fetchone()
                resolved_mask = str(sighting["masked_value"]) if sighting else f"{target_hash[:6]}****"

            conn.execute(
                """
                INSERT INTO block_rules
                (rule_id, ioc_hash, ioc_type, masked_value, reason, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ioc_hash) DO UPDATE SET
                    rule_id = excluded.rule_id,
                    reason = excluded.reason,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at
                """,
                (
                    rule_id,
                    target_hash,
                    ioc_type,
                    resolved_mask,
                    reason.strip(),
                    created_iso,
                    expires_iso,
                ),
            )

        return BlockRule(
            rule_id=rule_id,
            ioc_type=ioc_type,
            masked_value=resolved_mask,
            reason=reason.strip(),
            created_at=created_iso,
            expires_at=expires_iso,
            active=True,
        )

    def revoke_block_rule(self, rule_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM block_rules WHERE rule_id = ?", (rule_id,))
            return bool(cur.rowcount and cur.rowcount > 0)

    def reset_transient_rules(self) -> int:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM block_rules")
            conn.execute("DELETE FROM receipt_hashes")
            return int(cur.rowcount or 0)

    def get_radar_graph(self, now: datetime | None = None) -> RadarGraphResponse:
        now_iso = (now or datetime.now(UTC)).isoformat()
        with self._connect() as conn:
            rule_rows = conn.execute(
                """
                SELECT rule_id, ioc_hash, ioc_type, masked_value, reason, created_at, expires_at
                FROM block_rules WHERE expires_at > ? ORDER BY created_at DESC
                """,
                (now_iso,),
            ).fetchall()
            blocked_hashes = {str(r["ioc_hash"]) for r in rule_rows}

            camp_rows = conn.execute(
                "SELECT * FROM campaigns ORDER BY case_count DESC"
            ).fetchall()
            sighting_rows = conn.execute(
                "SELECT * FROM ioc_sightings ORDER BY hit_count DESC LIMIT 60"
            ).fetchall()
            edge_rows = conn.execute("SELECT * FROM ioc_edges LIMIT 120").fetchall()
            case_cnt_row = conn.execute("SELECT COUNT(*) AS c FROM cases").fetchone()

        nodes: list[RadarNode] = []
        valid_ids: set[str] = set()
        for c in camp_rows:
            cid = str(c["campaign_id"])
            valid_ids.add(cid)
            nodes.append(
                RadarNode(
                    node_id=cid,
                    kind="campaign",
                    label=str(c["title_vi"]),
                    hit_count=int(c["case_count"]),
                    risk_level="CRITICAL_SCAM",
                    blocked=str(c["primary_ioc_hash"]) in blocked_hashes,
                )
            )
        for s in sighting_rows:
            shash = str(s["ioc_hash"])
            valid_ids.add(shash)
            nodes.append(
                RadarNode(
                    node_id=shash,
                    kind=s["ioc_type"],
                    label=str(s["masked_value"]),
                    hit_count=int(s["hit_count"]),
                    risk_level="CRITICAL_SCAM" if shash in blocked_hashes else "HIGH_RISK",
                    blocked=shash in blocked_hashes,
                )
            )

        edges = [
            RadarEdge(
                source=str(e["source_id"]),
                target=str(e["target_id"]),
                relation=str(e["relation"]),
            )
            for e in edge_rows
            if str(e["source_id"]) in valid_ids and str(e["target_id"]) in valid_ids
        ]

        campaigns = [
            EmergingCampaign(
                campaign_id=str(c["campaign_id"]),
                title_vi=str(c["title_vi"]),
                playbook_id=str(c["playbook_id"]),
                case_count=int(c["case_count"]),
                primary_ioc_type=c["primary_ioc_type"],
                primary_ioc_masked=str(c["primary_ioc_masked"]),
                primary_ioc_hash=str(c["primary_ioc_hash"]),
                recommended_action=str(c["recommended_action"]),
                already_blocked=str(c["primary_ioc_hash"]) in blocked_hashes,
            )
            for c in camp_rows
        ]

        active_rules = [
            BlockRule(
                rule_id=str(r["rule_id"]),
                ioc_type=r["ioc_type"],
                masked_value=str(r["masked_value"]),
                reason=str(r["reason"]),
                created_at=str(r["created_at"]),
                expires_at=str(r["expires_at"]),
                active=True,
            )
            for r in rule_rows
        ]

        return RadarGraphResponse(
            nodes=nodes,
            edges=edges,
            campaigns=campaigns,
            active_block_rules=active_rules,
            stats={
                "total_cases": int(case_cnt_row["c"]) if case_cnt_row else 0,
                "tracked_iocs": len(sighting_rows),
                "emerging_campaigns": len(campaigns),
                "active_blocks": len(active_rules),
            },
        )
