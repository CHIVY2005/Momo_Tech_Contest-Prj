"""Schema DDL, indexes, batched startup migrations, and bounded SQLite retention pruning."""
from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta

from app.schemas import AnalysisReport
from app.services.pii_scrubber import scrub_persisted_pii

CURRENT_CASE_REDACTION_VER, CURRENT_RADAR_LABEL_VER, MIGRATION_BATCH_SIZE = 2, 1, 100
_RULE_ID_GLOB = "rule_" + "[0-9a-f]" * 10
_T, _PK = "TEXT NOT NULL", "TEXT PRIMARY KEY"
_I0, _I1 = "INTEGER NOT NULL DEFAULT 0", "INTEGER NOT NULL DEFAULT 1"

_TABLES: tuple[str, ...] = (
    f"cases(case_id {_PK}, created_at {_T}, verdict {_T}, risk_score INTEGER NOT NULL, report_json {_T}, "
    f"owner_channel {_T} DEFAULT 'legacy_locked', owner_chat_hash TEXT, parent_case_id TEXT, "
    f"contributes_to_radar {_I1}, is_demo {_I0}, redaction_ver {_I0})",
    f"ioc_sightings(ioc_hash {_PK}, ioc_type {_T}, masked_value {_T}, hit_count {_I1}, "
    f"campaign_id TEXT, is_demo {_I0}, label_ver {_I0})",
    f"ioc_edges(source_id {_T}, target_id {_T}, relation {_T} DEFAULT 'co_occurs', "
    "PRIMARY KEY(source_id, target_id))",
    f"campaigns(campaign_id {_PK}, title_vi {_T}, playbook_id {_T}, case_count {_I1}, "
    f"primary_ioc_type {_T}, primary_ioc_hash {_T}, primary_ioc_masked {_T}, "
    f"recommended_action {_T}, is_demo {_I0}, label_ver {_I0})",
    f"block_rules(rule_id {_PK}, ioc_hash {_T} UNIQUE, ioc_type {_T}, masked_value {_T}, "
    f"reason {_T}, created_at {_T}, expires_at {_T}, label_ver {_I0})",
    f"radar_audit_logs(audit_id {_PK}, created_at {_T}, action {_T}, outcome {_T}, ioc_type TEXT, "
    f"masked_target TEXT, rule_id TEXT, detail {_T}, client_ip_hash {_T})",
    f"protected_demo_iocs(ioc_hash {_PK}, ioc_type {_T})",
    f"receipt_hashes(fingerprint {_PK}, created_at {_T})",
    f"telegram_updates(update_id INTEGER PRIMARY KEY, status {_T} DEFAULT 'completed', lease_owner TEXT, "
    f"lease_expires_at TEXT, case_id TEXT, reply_text {_T} DEFAULT '', created_at {_T}, chat_id TEXT, "
    f"sender_user_id TEXT, chat_type TEXT, update_kind {_T} DEFAULT 'message', "
    f"scrubbed {_I0}, delivery_attempts {_I0})",
)
_INDEXES: tuple[str, ...] = (
    "idx_cases_radar_demo_created ON cases (contributes_to_radar, is_demo, created_at DESC)",
    "idx_cases_redaction_ver ON cases (redaction_ver)", "idx_cases_created_at ON cases (created_at DESC)",
    "idx_ioc_sightings_hits ON ioc_sightings (hit_count DESC)",
    "idx_ioc_sightings_demo ON ioc_sightings (is_demo, campaign_id)",
    "idx_campaigns_primary_hash ON campaigns (primary_ioc_hash)",
    "idx_block_rules_expires ON block_rules (expires_at DESC)",
    "idx_receipt_hashes_created ON receipt_hashes (created_at)",
    "idx_telegram_updates_status_created ON telegram_updates (status, created_at)",
    "idx_radar_audit_action_created ON radar_audit_logs (action, created_at DESC)",
)
_UPGRADES: dict[str, tuple[tuple[str, str], ...]] = {
    "cases": (("owner_channel", f"{_T} DEFAULT 'legacy_locked'"), ("owner_chat_hash", "TEXT"),
              ("parent_case_id", "TEXT"), ("contributes_to_radar", _I1), ("is_demo", _I0),
              ("redaction_ver", _I0)),
    "telegram_updates": (("status", f"{_T} DEFAULT 'completed'"), ("lease_owner", "TEXT"),
                         ("lease_expires_at", "TEXT"), ("chat_id", "TEXT"), ("sender_user_id", "TEXT"),
                         ("chat_type", "TEXT"), ("update_kind", f"{_T} DEFAULT 'message'"),
                         ("scrubbed", _I0), ("delivery_attempts", _I0)),
    "campaigns": (("is_demo", _I0), ("label_ver", _I0)),
    "ioc_sightings": (("is_demo", _I0), ("label_ver", _I0)), "block_rules": (("label_ver", _I0),),
}
_PROT = ("is_demo=1 OR campaign_id IS NOT NULL OR ioc_hash IN (SELECT primary_ioc_hash FROM campaigns) "
         "OR ioc_hash IN (SELECT ioc_hash FROM block_rules)")
_UNPROT = ("is_demo=0 AND campaign_id IS NULL AND ioc_hash NOT IN (SELECT primary_ioc_hash FROM campaigns) "
           "AND ioc_hash NOT IN (SELECT ioc_hash FROM block_rules)")


def ensure_schema_and_indexes(conn: sqlite3.Connection) -> None:
    """Create tables, apply idempotent column upgrades, and ensure all secondary indexes exist."""
    for ddl in _TABLES:
        conn.execute(f"CREATE TABLE IF NOT EXISTS {ddl};")
    for table, specs in _UPGRADES.items():
        cols = {str(r["name"]) for r in conn.execute(f"PRAGMA table_info({table});").fetchall()}
        for col_name, col_def in specs:
            if col_name not in cols:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def};")
    for idx_sql in _INDEXES:
        conn.execute(f"CREATE INDEX IF NOT EXISTS {idx_sql};")


def _batches(conn: sqlite3.Connection, sql: str, params: tuple[object, ...]) -> Iterator[list[sqlite3.Row]]:
    while rows := conn.execute(sql, params).fetchall():
        with conn:
            yield rows


def _migrate_case_row(
    conn: sqlite3.Connection, row: sqlite3.Row, rot_map: dict[str, str],
    parse_fn: Callable[[str], AnalysisReport | None],
    redact_fn: Callable[[AnalysisReport, bool], AnalysisReport], gen_id: Callable[[], str],
) -> None:
    ex, old_cid, c_ver = conn.execute, str(row["case_id"]), CURRENT_CASE_REDACTION_VER
    parsed = parse_fn(str(row["report_json"]))
    if parsed is None:
        ex("DELETE FROM cases WHERE case_id=?", (old_cid,))
        ex("UPDATE telegram_updates SET case_id=NULL WHERE case_id=?", (old_cid,))
        return
    if old_cid.startswith("vs_tg_"):
        new_cid = gen_id()
        rot_map[old_cid] = new_cid
        raw_p = str(row["parent_case_id"]) if row["parent_case_id"] else None
        rot = redact_fn(parsed.model_copy(update={"case_id": new_cid}), True)
        ex("INSERT INTO cases (case_id, created_at, verdict, risk_score, report_json, owner_channel, "
           "owner_chat_hash, parent_case_id, contributes_to_radar, is_demo, redaction_ver) "
           "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
           (new_cid, rot.created_at, rot.verdict, rot.risk_score, rot.model_dump_json(),
            str(row["owner_channel"]), row["owner_chat_hash"], rot_map.get(raw_p, raw_p) if raw_p else None,
            int(row["contributes_to_radar"]), int(row["is_demo"]), c_ver))
        ex("DELETE FROM cases WHERE case_id=?", (old_cid,))
        ex("UPDATE cases SET parent_case_id=? WHERE parent_case_id=?", (new_cid, old_cid))
        ex("UPDATE telegram_updates SET case_id=? WHERE case_id=?", (new_cid, old_cid))
        ex("UPDATE telegram_updates SET reply_text=REPLACE(reply_text,?,?), scrubbed=0 "
           "WHERE INSTR(reply_text,?)>0", (old_cid, new_cid, old_cid))
        return
    clean = redact_fn(parsed, True)
    c_json = clean.model_dump_json()
    if c_json != str(row["report_json"]):
        ex("UPDATE cases SET verdict=?, risk_score=?, report_json=?, redaction_ver=? WHERE case_id=?",
           (clean.verdict, clean.risk_score, c_json, c_ver, old_cid))
    else:
        ex("UPDATE cases SET redaction_ver=? WHERE case_id=?", (c_ver, old_cid))


def run_batched_migrations(
    connect_fn: Callable[[], sqlite3.Connection], *,
    parse_report_fn: Callable[[str], AnalysisReport | None],
    redact_report_fn: Callable[[AnalysisReport, bool], AnalysisReport],
    sanitize_label_fn: Callable[[str, str, str], str],
    normalize_replay_fp_fn: Callable[[str], str], generate_case_id_fn: Callable[[], str],
) -> None:
    """Run all legacy startup migrations in 100-row committed batches without full-table scans."""
    c_ver, l_ver, bs = CURRENT_CASE_REDACTION_VER, CURRENT_RADAR_LABEL_VER, MIGRATION_BATCH_SIZE
    conn = connect_fn()
    ex = conn.execute
    try:
        q_c = ("SELECT case_id, created_at, verdict, risk_score, report_json, owner_channel, "
               "owner_chat_hash, parent_case_id, contributes_to_radar, is_demo FROM cases "
               "WHERE redaction_ver<? OR case_id LIKE 'vs_tg_%' LIMIT ?")
        for rows in _batches(conn, q_c, (c_ver, bs)):
            rot_map: dict[str, str] = {}
            for r in rows:
                _migrate_case_row(conn, r, rot_map, parse_report_fn, redact_report_fn, generate_case_id_fn)
        for rows in _batches(conn, "SELECT update_id, reply_text FROM telegram_updates "
                             "WHERE scrubbed=0 LIMIT ?", (bs,)):
            for r in rows:
                val = scrub_persisted_pii(str(r["reply_text"])) if r["reply_text"] else ""
                ex("UPDATE telegram_updates SET reply_text=?, scrubbed=1 WHERE update_id=?",
                   (val, int(r["update_id"])))
        for rows in _batches(conn, "SELECT ioc_hash, ioc_type, masked_value FROM ioc_sightings "
                             "WHERE label_ver<? LIMIT ?", (l_ver, bs)):
            for r in rows:
                sh = str(r["ioc_hash"])
                cm = sanitize_label_fn(str(r["ioc_type"]), str(r["masked_value"]), sh)
                ex("UPDATE ioc_sightings SET masked_value=?, label_ver=? WHERE ioc_hash=?", (cm, l_ver, sh))
        for rows in _batches(conn, "SELECT campaign_id, primary_ioc_type, primary_ioc_hash, "
                             "primary_ioc_masked FROM campaigns WHERE label_ver<? LIMIT ?", (l_ver, bs)):
            for r in rows:
                cm = sanitize_label_fn(str(r["primary_ioc_type"]), str(r["primary_ioc_masked"]),
                                       str(r["primary_ioc_hash"]))
                ex("UPDATE campaigns SET primary_ioc_masked=?, label_ver=? WHERE campaign_id=?",
                   (cm, l_ver, str(r["campaign_id"])))
        for rows in _batches(conn, "SELECT rule_id, ioc_hash, ioc_type, masked_value, reason "
                             "FROM block_rules WHERE label_ver<? LIMIT ?", (l_ver, bs)):
            for r in rows:
                bh = str(r["ioc_hash"])
                tc = ex("SELECT primary_ioc_masked FROM campaigns WHERE primary_ioc_hash=? LIMIT 1",
                        (bh,)).fetchone()
                ts = ex("SELECT masked_value FROM ioc_sightings WHERE ioc_hash=? LIMIT 1", (bh,)).fetchone()
                cm = (str(tc["primary_ioc_masked"]) if tc else str(ts["masked_value"]) if ts
                      else sanitize_label_fn(str(r["ioc_type"]), str(r["masked_value"]), bh))
                ex("UPDATE block_rules SET masked_value=?, reason=?, label_ver=? WHERE rule_id=?",
                   (cm, scrub_persisted_pii(str(r["reason"])), l_ver, str(r["rule_id"])))
        for rows in _batches(conn, "SELECT audit_id FROM radar_audit_logs WHERE rule_id IS NOT NULL "
                             "AND rule_id NOT GLOB ? LIMIT ?", (_RULE_ID_GLOB, bs)):
            for r in rows:
                ex("UPDATE radar_audit_logs SET rule_id=NULL WHERE audit_id=?", (str(r["audit_id"]),))
        for rows in _batches(conn, "SELECT fingerprint, created_at FROM receipt_hashes "
                             "WHERE fingerprint LIKE 'ref:%' LIMIT ?", (bs,)):
            for r in rows:
                old_fp, h_fp = str(r["fingerprint"]), normalize_replay_fp_fn(str(r["fingerprint"]))
                if h_fp != old_fp:
                    ex("INSERT INTO receipt_hashes (fingerprint, created_at) VALUES (?,?) ON CONFLICT"
                       "(fingerprint) DO UPDATE SET created_at=MAX(created_at, excluded.created_at)",
                       (h_fp, str(r["created_at"])))
                ex("DELETE FROM receipt_hashes WHERE fingerprint=?", (old_fp,))
    finally:
        conn.close()


def prune_table_retention(
    conn: sqlite3.Connection, *, table: str, pk: str, order_by: str, max_rows: int,
    ttl_days: int | None = None, cond: str = "", now: datetime | None = None,
) -> None:
    """Enforce optional created_at TTL and maximum row count cap on a retention-managed table."""
    pfx = f"{cond} AND " if cond else ""
    if ttl_days is not None:
        cutoff = ((now or datetime.now(UTC)) - timedelta(days=max(1, ttl_days))).isoformat()
        conn.execute(f"DELETE FROM {table} WHERE {pfx}created_at<?", (cutoff,))  # noqa: S608
    cnt = conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()  # noqa: S608
    if cnt and int(cnt["c"]) > max_rows:
        conn.execute(f"DELETE FROM {table} WHERE {pfx}{pk} NOT IN "  # noqa: S608
                     f"(SELECT {pk} FROM {table} ORDER BY {order_by} LIMIT ?)", (max_rows,))


def prune_ioc_sightings_and_edges(
    conn: sqlite3.Connection, max_rows: int, *, force_edge_cleanup: bool = False
) -> None:
    """Prune non-protected IOC sightings beyond max_rows and remove only orphaned edges."""
    ex, pruned = conn.execute, False
    cnt = ex("SELECT COUNT(*) AS c FROM ioc_sightings").fetchone()
    if cnt and int(cnt["c"]) > max_rows:
        prot = ex(f"SELECT COUNT(*) AS c FROM ioc_sightings WHERE {_PROT}").fetchone()  # noqa: S608
        budget = max(0, max_rows - (int(prot["c"]) if prot else 0))
        ex(f"DELETE FROM ioc_sightings WHERE {_UNPROT} AND ioc_hash NOT IN (SELECT ioc_hash FROM "  # noqa: S608
           f"ioc_sightings WHERE {_UNPROT} ORDER BY hit_count DESC, rowid DESC LIMIT ?)", (budget,))
        pruned = True
    if pruned or force_edge_cleanup:
        ex("DELETE FROM ioc_edges WHERE (source_id NOT IN (SELECT ioc_hash FROM ioc_sightings) "
           "AND source_id NOT IN (SELECT campaign_id FROM campaigns)) OR "
           "(target_id NOT IN (SELECT ioc_hash FROM ioc_sightings) "
           "AND target_id NOT IN (SELECT campaign_id FROM campaigns))")
