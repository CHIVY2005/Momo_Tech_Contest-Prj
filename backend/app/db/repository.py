"""SQLite WAL repository: PII-redacted cases, masked IOC threat graph, replay hashes & TTL rules."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from app.schemas import (
    AnalysisReport,
    BlockRule,
    EmergingCampaign,
    ExtractedIOCs,
    ImageForensicsResult,
    IocType,
    RadarAuditEvent,
    RadarEdge,
    RadarGraphResponse,
    RadarNode,
    VerdictLevel,
    score_to_verdict,
)
from app.services.action_copilot import MERCHANT_HONESTY_BANNER
from app.services.ioc_extractor import (
    RECOGNIZED_DISPLAY_PUBLIC_SUFFIXES,
    hash_ioc,
    mask_ioc,
    scrub_free_text_pii,
)
from app.services.receipt_validator import build_trusted_merchant_summary
from app.services.vietqr_parser import VALID_VIETQR_AMOUNT_RE

MAX_CASE_GRAPH_IOCS = 20


class ProtectedDemoIocError(ValueError):
    """Raised when attempting to create a block rule against a protected SAFE demo IOC (HTTP 409)."""


def _parse_optional_nonneg_int(val: object) -> int:
    if val is None:
        return 0
    if isinstance(val, bool):
        raise ValueError("Boolean is not a valid numeric score")
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        return int(val.strip())
    raise ValueError(f"Unsupported score type: {type(val).__name__}")


def _parse_and_upgrade_stored_report(raw_json: str) -> AnalysisReport | None:
    """Upgrade recognized legacy merchant fields before strict schema validation, or return None."""
    try:
        data = json.loads(raw_json)
        if not isinstance(data, dict):
            return None

        mode = data.get("mode")
        img = data.get("image_forensics")
        rl = data.get("receipt_logic")
        vqr = data.get("vietqr_findings")
        is_merchant_receipt = mode == "merchant" and (
            img is not None or (isinstance(rl, dict) and bool(rl.get("is_receipt_candidate")))
        )
        if is_merchant_receipt:
            risk_val = data.get("risk_score")
            verdict = data.get("verdict")
            if (
                isinstance(risk_val, int)
                and not isinstance(risk_val, bool)
                and 0 <= risk_val <= 100
                and verdict is None
            ):
                verdict = score_to_verdict(risk_val)
                data["verdict"] = verdict
            cur_status = data.get("receipt_verification_status")
            if verdict == "SAFE":
                data["receipt_verification_status"] = "UNVERIFIED_SCREENSHOT"
            elif cur_status in (None, "", "NOT_APPLICABLE"):
                rl_status = rl.get("verification_status") if isinstance(rl, dict) else None
                has_qr_mismatch = isinstance(vqr, list) and any(
                    isinstance(v, dict) and bool(v.get("beneficiary_mismatch")) for v in vqr
                )
                has_tamper = isinstance(img, dict) and (
                    _parse_optional_nonneg_int(img.get("tamper_score")) >= 35
                    or bool(img.get("editing_software_detected"))
                )
                has_logic_anomaly = isinstance(rl, dict) and (
                    rl_status == "TAMPER_OR_LOGIC_ANOMALY"
                    or _parse_optional_nonneg_int(rl.get("logic_risk_points")) > 0
                )
                if isinstance(rl, dict) and (
                    bool(rl.get("is_replayed")) or rl_status == "REPLAYED_RECEIPT"
                ):
                    data["receipt_verification_status"] = "REPLAYED_RECEIPT"
                elif has_qr_mismatch or (
                    isinstance(rl, dict)
                    and (
                        bool(rl.get("beneficiary_mismatch"))
                        or rl_status == "BENEFICIARY_MISMATCH"
                    )
                ):
                    data["receipt_verification_status"] = "BENEFICIARY_MISMATCH"
                elif has_logic_anomaly or has_tamper:
                    data["receipt_verification_status"] = "TAMPER_OR_LOGIC_ANOMALY"
                else:
                    data["receipt_verification_status"] = "UNVERIFIED_SCREENSHOT"
            actions = data.get("actions")
            if isinstance(actions, dict):
                actions["merchant_balance_warning"] = MERCHANT_HONESTY_BANNER

        return AnalysisReport.model_validate(data)
    except Exception:
        return None


def _normalize_public_account_mask(acct: str) -> str:
    cleaned = acct.strip()
    if "****" not in cleaned:
        return mask_ioc("bank_account", cleaned)
    if (
        len(cleaned) == 12
        and cleaned[4:8] == "****"
        and cleaned[:4].isdigit()
        and cleaned[8:].isdigit()
    ):
        return f"{cleaned[:2]}****{cleaned[-2:]}"
    return cleaned


def redact_report_pii(report: AnalysisReport, strip_visual_blobs: bool = False) -> AnalysisReport:
    """Return a deep public-safe projection of AnalysisReport with zero raw phone/account PII."""
    raw_phones = list(report.iocs.phones)
    raw_accounts = list(report.iocs.bank_accounts)
    for v in report.vietqr_findings:
        if v.account_number and "****" not in v.account_number and v.account_number not in raw_accounts:
            raw_accounts.append(v.account_number)
    if (
        report.receipt_logic is not None
        and report.receipt_logic.extracted_recipient_account
        and "****" not in report.receipt_logic.extracted_recipient_account
        and report.receipt_logic.extracted_recipient_account not in raw_accounts
    ):
        raw_accounts.append(report.receipt_logic.extracted_recipient_account)

    masked_phones = [ph if "****" in ph else mask_ioc("phone", ph) for ph in report.iocs.phones]
    masked_accounts: list[str] = []
    for acct in raw_accounts:
        m_val = _normalize_public_account_mask(acct)
        if m_val not in masked_accounts:
            masked_accounts.append(m_val)

    def _scrub(val: str | None) -> str | None:
        if val is None:
            return None
        return scrub_free_text_pii(val, known_phones=raw_phones, known_accounts=raw_accounts)

    masked_urls = [_scrub(u) or u for u in report.iocs.urls]
    masked_domains = [
        d if "****" in d else (_scrub(d) or d)
        for d in report.iocs.domains
    ]

    known_numeric_iocs = {
        re.sub(r"\D", "", raw_val)
        for raw_val in (*raw_accounts, *raw_phones)
        if raw_val and "****" not in raw_val
    }
    masked_vqr = []
    for v in report.vietqr_findings:
        m_acct = _normalize_public_account_mask(v.account_number) if v.account_number else None
        raw_trimmed = v.raw.strip()
        is_payment_frame = (
            v.kind in ("VALID_VIETQR", "INVALID_CRC_VIETQR") or raw_trimmed.startswith("000201")
        )
        redacted_raw = (
            f"[VIETQR_REDACTED:{v.bank_bin or 'NAPAS'}:{m_acct or 'N/A'}]"
            if is_payment_frame
            else (_scrub(v.raw) or v.raw)
        )
        if v.amount is None:
            safe_amount: str | None = None
        else:
            amt_trimmed = v.amount.strip()
            if (
                VALID_VIETQR_AMOUNT_RE.fullmatch(amt_trimmed)
                and amt_trimmed not in known_numeric_iocs
            ):
                safe_amount = amt_trimmed
            else:
                safe_amount = _scrub(v.amount)
        masked_vqr.append(
            v.model_copy(
                update={
                    "raw": redacted_raw,
                    "account_number": m_acct,
                    "amount": safe_amount,
                    "note": _scrub(v.note),
                }
            )
        )

    scrubbed_urls = [
        u.model_copy(
            update={
                "url": _scrub(u.url) or u.url,
                "domain": _scrub(u.domain) or u.domain,
                "normalized_ascii_domain": _scrub(u.normalized_ascii_domain)
                or u.normalized_ascii_domain,
                "final_url": _scrub(u.final_url),
                "reasons": [_scrub(r) or r for r in u.reasons],
            }
        )
        for u in report.url_findings
    ]

    scrubbed_sandbox = (
        report.sandbox.model_copy(
            update={
                "visited_url": _scrub(report.sandbox.visited_url) or report.sandbox.visited_url,
                "final_url": _scrub(report.sandbox.final_url),
                "page_title": _scrub(report.sandbox.page_title),
                "screenshot_base64": None if strip_visual_blobs else report.sandbox.screenshot_base64,
                "reasons": [_scrub(r) or r for r in report.sandbox.reasons],
            }
        )
        if report.sandbox is not None
        else None
    )

    def _scrub_img_item(img_item: ImageForensicsResult) -> ImageForensicsResult:
        return img_item.model_copy(
            update={
                "filename": f"evidence.{img_item.format.lower()}",
                "exif_software": (
                    None if strip_visual_blobs else _scrub(img_item.exif_software)
                ),
                "ela_heatmap_base64": (
                    None if strip_visual_blobs else img_item.ela_heatmap_base64
                ),
                "qr_payloads": [
                    "[QR_PAYLOAD_REDACTED_IN_PUBLIC_CASE]"
                    for _ in img_item.qr_payloads
                ],
                "ocr_text": _scrub(img_item.ocr_text) or "",
                "reasons": [_scrub(r) or r for r in img_item.reasons],
            }
        )

    scrubbed_img = (
        _scrub_img_item(report.image_forensics) if report.image_forensics is not None else None
    )
    scrubbed_img_list = [_scrub_img_item(item) for item in report.image_forensics_list]

    scrubbed_receipt = (
        report.receipt_logic.model_copy(
            update={
                "extracted_recipient_account": (
                    _normalize_public_account_mask(report.receipt_logic.extracted_recipient_account)
                    if report.receipt_logic.extracted_recipient_account
                    else None
                ),
                "reference_code": _scrub(report.receipt_logic.reference_code),
                "reasons": [_scrub(r) or r for r in report.receipt_logic.reasons],
            }
        )
        if report.receipt_logic is not None
        else None
    )

    scrubbed_ev = [
        ev.model_copy(
            update={
                "title": _scrub(ev.title) or ev.title,
                "detail": _scrub(ev.detail) or ev.detail,
                "snippet": _scrub(ev.snippet),
            }
        )
        for ev in report.evidence
    ]

    raw_warn = report.actions.merchant_balance_warning
    if report.mode == "merchant" or report.receipt_verification_status != "NOT_APPLICABLE":
        scrubbed_warn: str | None = MERCHANT_HONESTY_BANNER
    else:
        scrubbed_warn = _scrub(raw_warn) if raw_warn is not None else None

    scrubbed_actions = report.actions.model_copy(
        update={
            "counter_replies": [_scrub(r) or r for r in report.actions.counter_replies],
            "family_shield_message": _scrub(report.actions.family_shield_message) or "",
            "urgent_steps": [_scrub(s) or s for s in report.actions.urgent_steps],
            "merchant_balance_warning": scrubbed_warn,
            "pre_transfer": report.actions.pre_transfer.model_copy(
                update={
                    "warning_headline": _scrub(report.actions.pre_transfer.warning_headline) or "",
                    "verification_questions": [
                        _scrub(q) or q for q in report.actions.pre_transfer.verification_questions
                    ],
                }
            ),
        }
    )

    scrubbed_trace = [
        st.model_copy(update={"detail": _scrub(st.detail) or st.detail}) for st in report.trace
    ]

    all_imgs = list(report.image_forensics_list)
    if report.image_forensics is not None and not all_imgs:
        all_imgs = [report.image_forensics]
    ocr_incomplete = bool(
        report.degraded_mode
        and (
            any(img.ocr_status in ("timeout", "error", "unavailable") for img in all_imgs)
            or any(ev.source == "ocr_engine" for ev in report.evidence)
        )
    )
    trusted_summary = build_trusted_merchant_summary(
        _scrub(report.summary_vi) or report.summary_vi,
        mode=report.mode,
        receipt_status=report.receipt_verification_status,
        has_qr_beneficiary_mismatch=any(v.beneficiary_mismatch for v in report.vietqr_findings),
        has_ocr_beneficiary_mismatch=bool(
            report.receipt_logic and report.receipt_logic.beneficiary_mismatch
        ),
        ocr_incomplete=ocr_incomplete,
    )

    return report.model_copy(
        update={
            "summary_vi": trusted_summary,
            "transcript": _scrub(report.transcript),
            "matched_playbooks": [_scrub(p) or p for p in report.matched_playbooks],
            "manipulation_tactics": [_scrub(t) or t for t in report.manipulation_tactics],
            "highlighted_phrases": [_scrub(h) or h for h in report.highlighted_phrases],
            "iocs": report.iocs.model_copy(
                update={
                    "phones": masked_phones,
                    "bank_accounts": masked_accounts,
                    "urls": masked_urls,
                    "domains": masked_domains,
                }
            ),
            "vietqr_findings": masked_vqr,
            "url_findings": scrubbed_urls,
            "sandbox": scrubbed_sandbox,
            "image_forensics": scrubbed_img,
            "image_forensics_list": scrubbed_img_list,
            "receipt_logic": scrubbed_receipt,
            "evidence": scrubbed_ev,
            "actions": scrubbed_actions,
            "trace": scrubbed_trace,
        }
    )


_STRICT_ACCOUNT_MASK_RE = re.compile(r"^(?:[A-Z0-9]{2}\*{4}[A-Z0-9]{2}|stk_[0-9a-f]{6}\*{4})$")
_STRICT_PHONE_MASK_RE = re.compile(r"^(?:\d{3}\*{4}\d{3}|\d{2}\*{4}\d|tel_[0-9a-f]{6}\*{4})$")
_STRICT_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9]{1,2}\*{4}$", re.IGNORECASE)


def _sanitize_legacy_radar_label(ioc_type: str, masked_value: str, ioc_hash: str) -> str:
    """Rewrite legacy stored radar labels that could expose full accounts or subdomains."""
    raw = masked_value.strip()
    if ioc_type == "domain":
        if re.match(r"^dom_[0-9a-f]{6}\*{4}$", raw):
            return raw
        had_wildcard = raw.startswith("*.")
        labels = [p for p in raw.split(".") if p and p != "*"]
        if len(labels) >= 2:
            two_sfx = f"{labels[-2]}.{labels[-1]}".lower()
            multi_sfx = {
                "com.vn",
                "gov.vn",
                "net.vn",
                "org.vn",
                "edu.vn",
                "int.vn",
                "ac.vn",
                "co.uk",
                "org.uk",
                "com.sg",
            }
            if len(labels) >= 3 and two_sfx in multi_sfx:
                suffix = two_sfx
                core = labels[-3]
                has_sub = had_wildcard or len(labels) > 3
            else:
                suffix = labels[-1].lower()
                core = labels[-2]
                has_sub = had_wildcard or len(labels) > 2
            if suffix not in RECOGNIZED_DISPLAY_PUBLIC_SUFFIXES:
                return f"dom_{ioc_hash[:6]}****"
            if _STRICT_DOMAIN_LABEL_RE.match(core) and not core[:2].isdigit():
                masked_core = core
            else:
                alnum_head = re.sub(r"[^a-z0-9]", "", core.lower())[:2]
                if not alnum_head or alnum_head.isdigit():
                    return f"dom_{ioc_hash[:6]}****"
                if re.search(r"\d{6,}", core) and any(ch.isdigit() for ch in alnum_head):
                    return f"dom_{ioc_hash[:6]}****"
                masked_core = f"{alnum_head}****"
            return f"*.{masked_core}.{suffix}" if has_sub else f"{masked_core}.{suffix}"
        return f"dom_{ioc_hash[:6]}****"

    if ioc_type == "bank_account":
        if _STRICT_ACCOUNT_MASK_RE.match(raw):
            return raw
        return f"stk_{ioc_hash[:6]}****"

    if ioc_type == "phone":
        if _STRICT_PHONE_MASK_RE.match(raw):
            return raw
        return f"tel_{ioc_hash[:6]}****"
    return f"ioc_{ioc_hash[:6]}****"


class CaseRepository:
    """Thread-safe SQLite WAL repository with multi-judge TTL block-rule isolation."""

    def __init__(
        self,
        sqlite_path: str,
        default_ttl_minutes: int = 30,
        ioc_hmac_secret: str = "",
        app_env: str = "development",
    ) -> None:
        self._db_path = sqlite_path
        self._default_ttl = max(1, default_ttl_minutes)
        self._ioc_hmac_secret = ioc_hmac_secret.strip()
        self._app_env = app_env

    def _hash_ioc(self, ioc_type: str, raw_value: str) -> str:
        return hash_ioc(ioc_type, raw_value, hmac_key=self._ioc_hmac_secret or None)

    def _hash_client_ip(self, client_ip: str) -> str:
        payload = f"ip:{client_ip.strip() or 'unknown'}".encode()
        if self._ioc_hmac_secret:
            return hmac.new(
                self._ioc_hmac_secret.encode("utf-8"), payload, hashlib.sha256
            ).hexdigest()[:16]
        return hashlib.sha256(payload).hexdigest()[:16]

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def is_wal_ready(self) -> bool:
        try:
            with self._session() as conn:
                row = conn.execute("PRAGMA journal_mode;").fetchone()
                return bool(row and str(row[0]).lower() == "wal")
        except sqlite3.Error:
            return False

    def init_db(self) -> None:
        """Initialize SQLite schema with hashed/masked-only IOC graph tables."""
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._session() as conn:
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
                    campaign_id TEXT,
                    is_demo INTEGER NOT NULL DEFAULT 0
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
                    recommended_action TEXT NOT NULL,
                    is_demo INTEGER NOT NULL DEFAULT 0
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
                CREATE TABLE IF NOT EXISTS radar_audit_logs (
                    audit_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    action TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    ioc_type TEXT,
                    masked_target TEXT,
                    rule_id TEXT,
                    detail TEXT NOT NULL,
                    client_ip_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS protected_demo_iocs (
                    ioc_hash TEXT PRIMARY KEY,
                    ioc_type TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS receipt_hashes (
                    fingerprint TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS telegram_updates (
                    update_id INTEGER PRIMARY KEY,
                    status TEXT NOT NULL DEFAULT 'completed',
                    lease_owner TEXT,
                    lease_expires_at TEXT,
                    case_id TEXT,
                    reply_text TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                """
            )
            cols = {
                str(r["name"])
                for r in conn.execute("PRAGMA table_info(telegram_updates);").fetchall()
            }
            if "status" not in cols:
                conn.execute(
                    "ALTER TABLE telegram_updates ADD COLUMN status TEXT NOT NULL DEFAULT 'completed';"
                )
            if "lease_owner" not in cols:
                conn.execute("ALTER TABLE telegram_updates ADD COLUMN lease_owner TEXT;")
            if "lease_expires_at" not in cols:
                conn.execute("ALTER TABLE telegram_updates ADD COLUMN lease_expires_at TEXT;")

            camp_cols = {
                str(r["name"])
                for r in conn.execute("PRAGMA table_info(campaigns);").fetchall()
            }
            if "is_demo" not in camp_cols:
                conn.execute(
                    "ALTER TABLE campaigns ADD COLUMN is_demo INTEGER NOT NULL DEFAULT 0;"
                )
            sight_cols = {
                str(r["name"])
                for r in conn.execute("PRAGMA table_info(ioc_sightings);").fetchall()
            }
            if "is_demo" not in sight_cols:
                conn.execute(
                    "ALTER TABLE ioc_sightings ADD COLUMN is_demo INTEGER NOT NULL DEFAULT 0;"
                )

            # Migrate any pre-remediation stored rows & rotate legacy predictable vs_tg_* IDs
            for row in conn.execute(
                "SELECT case_id, created_at, verdict, risk_score, report_json FROM cases"
            ).fetchall():
                old_cid = str(row["case_id"])
                parsed = _parse_and_upgrade_stored_report(str(row["report_json"]))
                if parsed is None:
                    conn.execute("DELETE FROM cases WHERE case_id = ?", (old_cid,))
                    conn.execute(
                        "UPDATE telegram_updates SET case_id = NULL WHERE case_id = ?",
                        (old_cid,),
                    )
                    continue
                if old_cid.startswith("vs_tg_"):
                    rotated_cid = f"vs_{uuid.uuid4().hex[:12]}"
                    redacted_rot = redact_report_pii(
                        parsed.model_copy(update={"case_id": rotated_cid}),
                        strip_visual_blobs=True,
                    )
                    conn.execute(
                        "INSERT INTO cases (case_id, created_at, verdict, risk_score, report_json) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (
                            rotated_cid,
                            redacted_rot.created_at,
                            redacted_rot.verdict,
                            redacted_rot.risk_score,
                            redacted_rot.model_dump_json(),
                        ),
                    )
                    conn.execute("DELETE FROM cases WHERE case_id = ?", (old_cid,))
                    conn.execute(
                        "UPDATE telegram_updates SET case_id = ? WHERE case_id = ?",
                        (rotated_cid, old_cid),
                    )
                else:
                    clean_rep = redact_report_pii(parsed, strip_visual_blobs=True)
                    clean_json = clean_rep.model_dump_json()
                    if clean_json != str(row["report_json"]):
                        conn.execute(
                            "UPDATE cases SET verdict = ?, risk_score = ?, report_json = ? "
                            "WHERE case_id = ?",
                            (clean_rep.verdict, clean_rep.risk_score, clean_json, old_cid),
                        )

            for s_row in conn.execute(
                "SELECT ioc_hash, ioc_type, masked_value FROM ioc_sightings"
            ).fetchall():
                s_hash = str(s_row["ioc_hash"])
                s_type = str(s_row["ioc_type"])
                raw_m = str(s_row["masked_value"])
                clean_m = _sanitize_legacy_radar_label(s_type, raw_m, s_hash)
                if clean_m != raw_m:
                    conn.execute(
                        "UPDATE ioc_sightings SET masked_value = ? WHERE ioc_hash = ?",
                        (clean_m, s_hash),
                    )

            for c_row in conn.execute(
                "SELECT campaign_id, primary_ioc_type, primary_ioc_hash, primary_ioc_masked "
                "FROM campaigns"
            ).fetchall():
                c_masked = str(c_row["primary_ioc_masked"])
                clean_cm = _sanitize_legacy_radar_label(
                    str(c_row["primary_ioc_type"]),
                    c_masked,
                    str(c_row["primary_ioc_hash"]),
                )
                if clean_cm != c_masked:
                    conn.execute(
                        "UPDATE campaigns SET primary_ioc_masked = ? WHERE campaign_id = ?",
                        (clean_cm, str(c_row["campaign_id"])),
                    )

            for b_row in conn.execute(
                "SELECT rule_id, ioc_hash, ioc_type, masked_value, reason FROM block_rules"
            ).fetchall():
                b_hash = str(b_row["ioc_hash"])
                b_type = str(b_row["ioc_type"])
                b_masked = str(b_row["masked_value"])
                b_reason = str(b_row["reason"])
                trusted_camp = conn.execute(
                    "SELECT primary_ioc_masked FROM campaigns WHERE primary_ioc_hash = ? LIMIT 1",
                    (b_hash,),
                ).fetchone()
                trusted_sight = conn.execute(
                    "SELECT masked_value FROM ioc_sightings WHERE ioc_hash = ? LIMIT 1",
                    (b_hash,),
                ).fetchone()
                if trusted_camp is not None:
                    clean_bm = str(trusted_camp["primary_ioc_masked"])
                elif trusted_sight is not None:
                    clean_bm = str(trusted_sight["masked_value"])
                else:
                    clean_bm = _sanitize_legacy_radar_label(b_type, b_masked, b_hash)
                clean_br = scrub_free_text_pii(b_reason)
                if clean_bm != b_masked or clean_br != b_reason:
                    conn.execute(
                        "UPDATE block_rules SET masked_value = ?, reason = ? WHERE rule_id = ?",
                        (clean_bm, clean_br, str(b_row["rule_id"])),
                    )

    def seed_if_empty(
        self,
        seed_path: str | None,
        protected_iocs: list[tuple[str, str]] | None = None,
    ) -> None:
        """Seed synthetic masked IOC campaigns (non-prod) and register protected SAFE IOC hashes."""
        with self._session() as conn:
            if protected_iocs:
                for prot_type, prot_raw in protected_iocs:
                    conn.execute(
                        "INSERT OR IGNORE INTO protected_demo_iocs (ioc_hash, ioc_type) VALUES (?, ?)",
                        (self._hash_ioc(prot_type, prot_raw), prot_type),
                    )

            if not seed_path:
                return
            seed_file = Path(seed_path)
            if not seed_file.exists():
                return
            payload = json.loads(seed_file.read_text(encoding="utf-8"))

            existing = conn.execute("SELECT COUNT(*) AS cnt FROM campaigns").fetchone()
            if existing and int(existing["cnt"]) > 0:
                for camp in payload.get("campaigns", []):
                    p_type_ex: IocType = camp["primary_ioc_type"]
                    p_raw_ex: str = camp["primary_ioc_raw_synthetic"]
                    p_hash_ex = self._hash_ioc(p_type_ex, p_raw_ex)
                    p_masked_ex = mask_ioc(p_type_ex, p_raw_ex)
                    conn.execute(
                        "UPDATE campaigns "
                        "SET title_vi = ?, recommended_action = ?, primary_ioc_masked = ?, is_demo = 1 "
                        "WHERE campaign_id = ?",
                        (camp["title_vi"], camp["recommended_action"], p_masked_ex, camp["campaign_id"]),
                    )
                    conn.execute(
                        "UPDATE ioc_sightings SET masked_value = ?, is_demo = 1 "
                        "WHERE ioc_hash = ?",
                        (p_masked_ex, p_hash_ex),
                    )
                    for co_ex in camp.get("co_iocs", []):
                        co_t_ex: IocType = co_ex["ioc_type"]
                        co_raw_ex: str = co_ex["raw_synthetic"]
                        conn.execute(
                            "UPDATE ioc_sightings SET masked_value = ?, is_demo = 1 "
                            "WHERE ioc_hash = ?",
                            (mask_ioc(co_t_ex, co_raw_ex), self._hash_ioc(co_t_ex, co_raw_ex)),
                        )
                    conn.execute(
                        "UPDATE ioc_sightings SET is_demo = 1 WHERE campaign_id = ?",
                        (camp["campaign_id"],),
                    )
                return
            for camp in payload.get("campaigns", []):
                cid: str = camp["campaign_id"]
                p_type: IocType = camp["primary_ioc_type"]
                p_raw_syn: str = camp["primary_ioc_raw_synthetic"]
                p_hash = self._hash_ioc(p_type, p_raw_syn)
                p_masked = mask_ioc(p_type, p_raw_syn)
                c_count = int(camp.get("case_count", 3))

                conn.execute(
                    """
                    INSERT OR IGNORE INTO campaigns
                    (campaign_id, title_vi, playbook_id, case_count, primary_ioc_type,
                     primary_ioc_hash, primary_ioc_masked, recommended_action, is_demo)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
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
                    (ioc_hash, ioc_type, masked_value, hit_count, campaign_id, is_demo)
                    VALUES (?, ?, ?, ?, ?, 1)
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
                    co_h = self._hash_ioc(co_t, co_raw)
                    co_m = mask_ioc(co_t, co_raw)
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO ioc_sightings
                        (ioc_hash, ioc_type, masked_value, hit_count, campaign_id, is_demo)
                        VALUES (?, ?, ?, ?, ?, 1)
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
        h = self._hash_ioc(ioc_type, raw_val)
        m = mask_ioc(ioc_type, raw_val)
        conn.execute(
            """
            INSERT INTO ioc_sightings (ioc_hash, ioc_type, masked_value, hit_count, is_demo)
            VALUES (?, ?, ?, 1, 0)
            ON CONFLICT(ioc_hash) DO UPDATE SET hit_count = hit_count + 1
            """,
            (h, ioc_type, m),
        )
        return h

    def claim_receipt_replay(
        self,
        dhash_hex: str | None,
        bank: str | None,
        ref_code: str | None,
        register_if_new: bool = True,
    ) -> bool:
        """Atomically check receipt fingerprints and only register new ones for receipt candidates."""
        probes: list[str] = []
        if dhash_hex:
            probes.append(f"dhash:{dhash_hex}")
        if ref_code:
            probes.append(f"ref:{bank or ''}:{ref_code}")
        if not probes:
            return False

        now_iso = datetime.now(UTC).isoformat()
        conn = self._connect()
        try:
            conn.isolation_level = None
            conn.execute("BEGIN IMMEDIATE;")
            placeholders = ",".join("?" for _ in probes)
            existing = conn.execute(
                f"SELECT 1 FROM receipt_hashes WHERE fingerprint IN ({placeholders}) LIMIT 1",  # noqa: S608
                tuple(probes),
            ).fetchone()
            if register_if_new and existing is None:
                for fp in probes:
                    conn.execute(
                        "INSERT OR IGNORE INTO receipt_hashes (fingerprint, created_at) VALUES (?, ?)",
                        (fp, now_iso),
                    )
            conn.execute("COMMIT;")
            return existing is not None
        except Exception:
            conn.execute("ROLLBACK;")
            raise
        finally:
            conn.close()

    def save_report(
        self,
        report: AnalysisReport,
        receipt_dhash: str | None = None,
        track_replay: bool = True,
    ) -> AnalysisReport:
        """Persist PII-redacted report, update IOC graph & campaigns, and store replay hashes."""
        live_redacted = redact_report_pii(report, strip_visual_blobs=False)
        stored_redacted = redact_report_pii(report, strip_visual_blobs=True)
        with self._session() as conn:
            already_saved = (
                conn.execute(
                    "SELECT 1 FROM cases WHERE case_id = ? LIMIT 1",
                    (stored_redacted.case_id,),
                ).fetchone()
                is not None
            )

            if not already_saved and report.risk_score >= 45:
                seen_hashes: list[str] = []
                for ph in report.iocs.phones:
                    if "****" not in ph:
                        h = self._upsert_sighting(conn, "phone", ph)
                        if h not in seen_hashes:
                            seen_hashes.append(h)
                for acct in report.iocs.bank_accounts:
                    if "****" not in acct:
                        h = self._upsert_sighting(conn, "bank_account", acct)
                        if h not in seen_hashes:
                            seen_hashes.append(h)
                for dom in report.iocs.domains:
                    if "****" not in dom:
                        h = self._upsert_sighting(conn, "domain", dom)
                        if h not in seen_hashes:
                            seen_hashes.append(h)

                bounded_hashes = seen_hashes[:MAX_CASE_GRAPH_IOCS]
                for idx in range(len(bounded_hashes)):
                    for jdx in range(idx + 1, len(bounded_hashes)):
                        conn.execute(
                            "INSERT OR IGNORE INTO ioc_edges (source_id, target_id, relation) "
                            "VALUES (?, ?, 'co_occurs')",
                            (bounded_hashes[idx], bounded_hashes[jdx]),
                        )

                if bounded_hashes:
                    placeholders = ",".join("?" for _ in bounded_hashes)
                    matched_cids: set[str] = set()
                    for row in conn.execute(
                        f"SELECT campaign_id FROM campaigns WHERE primary_ioc_hash IN ({placeholders})",  # noqa: S608
                        tuple(bounded_hashes),
                    ).fetchall():
                        matched_cids.add(str(row["campaign_id"]))
                    for row in conn.execute(
                        f"SELECT DISTINCT campaign_id FROM ioc_sightings "  # noqa: S608
                        f"WHERE ioc_hash IN ({placeholders}) AND campaign_id IS NOT NULL",
                        tuple(bounded_hashes),
                    ).fetchall():
                        matched_cids.add(str(row["campaign_id"]))
                    for cid in matched_cids:
                        conn.execute(
                            "UPDATE campaigns SET case_count = case_count + 1 WHERE campaign_id = ?",
                            (cid,),
                        )

            if track_replay:
                now_iso = datetime.now(UTC).isoformat()
                if receipt_dhash:
                    conn.execute(
                        "INSERT OR IGNORE INTO receipt_hashes (fingerprint, created_at) VALUES (?, ?)",
                        (f"dhash:{receipt_dhash}", now_iso),
                    )
                if (
                    report.receipt_logic
                    and report.receipt_logic.reference_valid
                    and report.receipt_logic.reference_code
                ):
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
                    stored_redacted.case_id,
                    stored_redacted.created_at,
                    stored_redacted.verdict,
                    stored_redacted.risk_score,
                    stored_redacted.model_dump_json(),
                ),
            )
        return live_redacted

    def get_report(self, case_id: str) -> AnalysisReport | None:
        with self._session() as conn:
            row = conn.execute(
                "SELECT report_json FROM cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
        if not row:
            return None
        parsed = _parse_and_upgrade_stored_report(str(row["report_json"]))
        if parsed is None:
            return None
        return redact_report_pii(parsed, strip_visual_blobs=True)

    def claim_telegram_update(
        self,
        update_id: int,
        owner_id: str = "default",
        lease_seconds: int = 180,
    ) -> tuple[str, str | None, str | None]:
        """Atomically claim update_id with an owner-tagged renewable lease."""
        now_dt = datetime.now(UTC)
        now_iso = now_dt.isoformat()
        expires_iso = (now_dt + timedelta(seconds=max(0, lease_seconds))).isoformat()
        conn = self._connect()
        try:
            conn.isolation_level = None
            conn.execute("BEGIN IMMEDIATE;")
            row = conn.execute(
                "SELECT status, lease_owner, lease_expires_at, case_id, reply_text, created_at "
                "FROM telegram_updates WHERE update_id = ?",
                (update_id,),
            ).fetchone()
            if row is None:
                alloc_case_id = f"vs_{uuid.uuid4().hex[:12]}"
                conn.execute(
                    "INSERT INTO telegram_updates "
                    "(update_id, status, lease_owner, lease_expires_at, case_id, reply_text, created_at) "
                    "VALUES (?, 'processing', ?, ?, ?, '', ?)",
                    (update_id, owner_id, expires_iso, alloc_case_id, now_iso),
                )
                conn.execute("COMMIT;")
                return ("claimed", alloc_case_id, None)

            status = str(row["status"])
            if status == "completed":
                conn.execute("COMMIT;")
                return (
                    "cached",
                    str(row["case_id"]) if row["case_id"] else None,
                    str(row["reply_text"]),
                )

            cur_expires = str(row["lease_expires_at"] or row["created_at"])
            if cur_expires <= now_iso:
                alloc_case_id = (
                    str(row["case_id"]) if row["case_id"] else f"vs_{uuid.uuid4().hex[:12]}"
                )
                conn.execute(
                    "UPDATE telegram_updates "
                    "SET status = 'processing', lease_owner = ?, lease_expires_at = ?, "
                    "case_id = ?, created_at = ? "
                    "WHERE update_id = ?",
                    (owner_id, expires_iso, alloc_case_id, now_iso, update_id),
                )
                conn.execute("COMMIT;")
                return ("claimed", alloc_case_id, None)

            conn.execute("COMMIT;")
            return ("in_progress", None, None)
        except Exception:
            conn.execute("ROLLBACK;")
            raise
        finally:
            conn.close()

    def renew_telegram_update_lease(
        self,
        update_id: int,
        owner_id: str,
        lease_seconds: int = 180,
    ) -> bool:
        expires_iso = (datetime.now(UTC) + timedelta(seconds=max(1, lease_seconds))).isoformat()
        with self._session() as conn:
            cur = conn.execute(
                "UPDATE telegram_updates SET lease_expires_at = ? "
                "WHERE update_id = ? AND status = 'processing' AND lease_owner = ?",
                (expires_iso, update_id, owner_id),
            )
            return bool(cur.rowcount and cur.rowcount > 0)

    def release_telegram_update_claim(
        self,
        update_id: int,
        owner_id: str | None = None,
    ) -> None:
        with self._session() as conn:
            if owner_id is not None:
                conn.execute(
                    "DELETE FROM telegram_updates "
                    "WHERE update_id = ? AND status = 'processing' AND lease_owner = ?",
                    (update_id, owner_id),
                )
            else:
                conn.execute(
                    "DELETE FROM telegram_updates WHERE update_id = ? AND status = 'processing'",
                    (update_id,),
                )

    def get_telegram_update_cache(self, update_id: int) -> tuple[str | None, str] | None:
        with self._session() as conn:
            row = conn.execute(
                "SELECT case_id, reply_text FROM telegram_updates "
                "WHERE update_id = ? AND status = 'completed'",
                (update_id,),
            ).fetchone()
        if not row:
            return None
        return (str(row["case_id"]) if row["case_id"] else None, str(row["reply_text"]))

    def save_telegram_update_cache(
        self,
        update_id: int,
        case_id: str | None,
        reply_text: str,
        owner_id: str | None = None,
    ) -> None:
        now_iso = datetime.now(UTC).isoformat()
        with self._session() as conn:
            if owner_id is not None:
                conn.execute(
                    """
                    UPDATE telegram_updates
                    SET status = 'completed',
                        case_id = ?,
                        reply_text = ?,
                        lease_expires_at = NULL,
                        created_at = ?
                    WHERE update_id = ? AND lease_owner = ? AND status = 'processing'
                    """,
                    (case_id, reply_text, now_iso, update_id, owner_id),
                )
            else:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO telegram_updates
                    (update_id, status, lease_owner, lease_expires_at, case_id, reply_text, created_at)
                    VALUES (?, 'completed', NULL, NULL, ?, ?, ?)
                    """,
                    (update_id, case_id, reply_text, now_iso),
                )

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
        with self._session() as conn:
            row = conn.execute(
                f"SELECT 1 FROM receipt_hashes WHERE fingerprint IN ({placeholders}) LIMIT 1",  # noqa: S608
                tuple(probes),
            ).fetchone()
        return row is not None

    @staticmethod
    def _expand_domain_candidates(domains: list[str]) -> list[str]:
        candidates: list[str] = []
        multi_sfx = {
            "com.vn",
            "gov.vn",
            "net.vn",
            "org.vn",
            "edu.vn",
            "int.vn",
            "ac.vn",
            "co.uk",
            "org.uk",
            "com.sg",
        }
        for raw in domains:
            host = raw.strip().lower().rstrip(".")
            if not host:
                continue
            if host not in candidates:
                candidates.append(host)
            labels = [lbl for lbl in host.split(".") if lbl]
            for start in range(1, len(labels) - 1):
                parent = ".".join(labels[start:])
                if parent in multi_sfx:
                    continue
                if parent not in candidates:
                    candidates.append(parent)
        return candidates

    def count_ioc_hits(self, iocs: ExtractedIOCs) -> int:
        domain_cands = self._expand_domain_candidates(iocs.domains)
        hashes = (
            [self._hash_ioc("phone", p) for p in iocs.phones]
            + [self._hash_ioc("bank_account", a) for a in iocs.bank_accounts]
            + [self._hash_ioc("domain", d) for d in domain_cands]
        )
        if not hashes:
            return 0
        placeholders = ",".join("?" for _ in hashes)
        with self._session() as conn:
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
        domain_cands = self._expand_domain_candidates(iocs.domains)
        hashes = (
            [self._hash_ioc("phone", p) for p in iocs.phones]
            + [self._hash_ioc("bank_account", a) for a in iocs.bank_accounts]
            + [self._hash_ioc("domain", d) for d in domain_cands]
        )
        if not hashes:
            return []
        now_iso = (now or datetime.now(UTC)).isoformat()
        placeholders = ",".join("?" for _ in hashes)
        with self._session() as conn:
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
        """Create/refresh a TTL-bounded block rule with server-authoritative masking & PII redaction."""
        _ = masked_value  # Never trust caller-supplied display labels on public radar rules
        has_raw = bool(raw_value and raw_value.strip())
        if has_raw and raw_value is not None:
            target_hash = self._hash_ioc(ioc_type, raw_value)
            resolved_type: IocType = ioc_type
            resolved_mask = mask_ioc(ioc_type, raw_value)
        elif ioc_hash:
            target_hash = ioc_hash.strip().lower()
            resolved_type = ioc_type
            resolved_mask = ""
        else:
            raise ValueError("Either raw_value or ioc_hash is required.")

        scrubbed_reason = scrub_free_text_pii(
            reason.strip(),
            known_phones=[raw_value] if (has_raw and raw_value and ioc_type == "phone") else None,
            known_accounts=[raw_value] if (has_raw and raw_value and ioc_type == "bank_account") else None,
        )

        ts_now = now or datetime.now(UTC)
        ttl = ttl_minutes if ttl_minutes is not None else self._default_ttl
        expires_iso = (ts_now + timedelta(minutes=ttl)).isoformat()
        created_iso = ts_now.isoformat()
        rule_id = f"rule_{uuid.uuid4().hex[:10]}"

        with self._session() as conn:
            prot = conn.execute(
                "SELECT 1 FROM protected_demo_iocs WHERE ioc_hash = ?",
                (target_hash,),
            ).fetchone()
            if prot is not None:
                raise ProtectedDemoIocError(
                    "Tên miền hoặc tài khoản này thuộc danh sách chính thức được bảo vệ, "
                    "không thể thêm vào danh sách chặn."
                )

            if not has_raw:
                camp_row = conn.execute(
                    "SELECT primary_ioc_type, primary_ioc_masked "
                    "FROM campaigns WHERE primary_ioc_hash = ? LIMIT 1",
                    (target_hash,),
                ).fetchone()
                if camp_row is not None:
                    resolved_type = camp_row["primary_ioc_type"]
                    resolved_mask = str(camp_row["primary_ioc_masked"])
                else:
                    sighting = conn.execute(
                        "SELECT ioc_type, masked_value FROM ioc_sightings WHERE ioc_hash = ? LIMIT 1",
                        (target_hash,),
                    ).fetchone()
                    if sighting is not None:
                        resolved_type = sighting["ioc_type"]
                        resolved_mask = str(sighting["masked_value"])
                    else:
                        resolved_mask = f"{target_hash[:6]}****"

            conn.execute(
                """
                INSERT INTO block_rules
                (rule_id, ioc_hash, ioc_type, masked_value, reason, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ioc_hash) DO UPDATE SET
                    rule_id = excluded.rule_id,
                    masked_value = excluded.masked_value,
                    reason = excluded.reason,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at
                """,
                (
                    rule_id,
                    target_hash,
                    resolved_type,
                    resolved_mask,
                    scrubbed_reason,
                    created_iso,
                    expires_iso,
                ),
            )
            persisted = conn.execute(
                "SELECT rule_id, ioc_type, masked_value, reason, created_at, expires_at "
                "FROM block_rules WHERE ioc_hash = ?",
                (target_hash,),
            ).fetchone()

        return BlockRule(
            rule_id=str(persisted["rule_id"]) if persisted else rule_id,
            ioc_type=persisted["ioc_type"] if persisted else resolved_type,
            masked_value=str(persisted["masked_value"]) if persisted else resolved_mask,
            reason=str(persisted["reason"]) if persisted else scrubbed_reason,
            created_at=str(persisted["created_at"]) if persisted else created_iso,
            expires_at=str(persisted["expires_at"]) if persisted else expires_iso,
            active=True,
        )

    def get_block_rule(self, rule_id: str) -> BlockRule | None:
        with self._session() as conn:
            row = conn.execute(
                "SELECT rule_id, ioc_type, masked_value, reason, created_at, expires_at "
                "FROM block_rules WHERE rule_id = ?",
                (rule_id,),
            ).fetchone()
        if not row:
            return None
        return BlockRule(
            rule_id=str(row["rule_id"]),
            ioc_type=row["ioc_type"],
            masked_value=str(row["masked_value"]),
            reason=str(row["reason"]),
            created_at=str(row["created_at"]),
            expires_at=str(row["expires_at"]),
            active=True,
        )

    def revoke_block_rule(self, rule_id: str) -> bool:
        with self._session() as conn:
            cur = conn.execute("DELETE FROM block_rules WHERE rule_id = ?", (rule_id,))
            return bool(cur.rowcount and cur.rowcount > 0)

    def reset_transient_rules(self) -> int:
        """Clear transient /radar block rules without erasing receipt-replay forensic history."""
        with self._session() as conn:
            cur = conn.execute("DELETE FROM block_rules")
            return int(cur.rowcount or 0)

    def record_audit_log(
        self,
        *,
        action: Literal[
            "create_rule",
            "revoke_rule",
            "reset_rules",
            "auth_failed",
            "protected_ioc_blocked",
        ],
        outcome: Literal["allowed", "denied"],
        detail: str,
        ioc_type: IocType | None = None,
        masked_target: str | None = None,
        rule_id: str | None = None,
        client_ip: str = "unknown",
    ) -> RadarAuditEvent:
        audit_id = f"aud_{uuid.uuid4().hex[:10]}"
        created_at = datetime.now(UTC).isoformat()
        clean_detail = scrub_free_text_pii(detail.strip())[:300]
        clean_target = scrub_free_text_pii(masked_target) if masked_target else None
        ip_hash = self._hash_client_ip(client_ip)
        with self._session() as conn:
            conn.execute(
                """
                INSERT INTO radar_audit_logs
                (audit_id, created_at, action, outcome, ioc_type, masked_target,
                 rule_id, detail, client_ip_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit_id,
                    created_at,
                    action,
                    outcome,
                    ioc_type,
                    clean_target,
                    rule_id,
                    clean_detail,
                    ip_hash,
                ),
            )
            conn.execute(
                """
                DELETE FROM radar_audit_logs
                WHERE audit_id NOT IN (
                    SELECT audit_id FROM radar_audit_logs ORDER BY created_at DESC LIMIT 200
                )
                """
            )
        return RadarAuditEvent(
            audit_id=audit_id,
            created_at=created_at,
            action=action,
            outcome=outcome,
            ioc_type=ioc_type,
            masked_target=clean_target,
            rule_id=rule_id,
            detail=clean_detail,
        )

    def get_radar_graph(self, now: datetime | None = None) -> RadarGraphResponse:
        now_iso = (now or datetime.now(UTC)).isoformat()
        with self._session() as conn:
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
            total_sightings_row = conn.execute(
                "SELECT COUNT(*) AS cnt, "
                "COALESCE(SUM(CASE WHEN is_demo = 1 THEN 1 ELSE 0 END), 0) AS demo_cnt "
                "FROM ioc_sightings"
            ).fetchone()
            edge_rows = conn.execute("SELECT * FROM ioc_edges LIMIT 120").fetchall()
            case_cnt_row = conn.execute("SELECT COUNT(*) AS c FROM cases").fetchone()
            audit_rows = conn.execute(
                """
                SELECT audit_id, created_at, action, outcome, ioc_type, masked_target, rule_id, detail
                FROM radar_audit_logs ORDER BY created_at DESC LIMIT 20
                """
            ).fetchall()

        camp_iocs: dict[str, set[str]] = {}
        for c in camp_rows:
            cid = str(c["campaign_id"])
            camp_iocs[cid] = {str(c["primary_ioc_hash"])}
        for s in sighting_rows:
            scid = str(s["campaign_id"]) if s["campaign_id"] else None
            if scid and scid in camp_iocs:
                camp_iocs[scid].add(str(s["ioc_hash"]))
        for e in edge_rows:
            src = str(e["source_id"])
            dst = str(e["target_id"])
            if src in camp_iocs and dst != src:
                camp_iocs[src].add(dst)
            elif dst in camp_iocs and src != dst:
                camp_iocs[dst].add(src)

        nodes: list[RadarNode] = []
        valid_ids: set[str] = set()
        for c in camp_rows:
            cid = str(c["campaign_id"])
            valid_ids.add(cid)
            linked = camp_iocs.get(cid, {str(c["primary_ioc_hash"])})
            case_cnt = int(c["case_count"])
            camp_risk: VerdictLevel = "CRITICAL_SCAM" if case_cnt >= 5 else "HIGH_RISK"
            nodes.append(
                RadarNode(
                    node_id=cid,
                    kind="campaign",
                    label=str(c["title_vi"]),
                    hit_count=case_cnt,
                    risk_level=camp_risk,
                    blocked=str(c["primary_ioc_hash"]) in blocked_hashes
                    or any(h in blocked_hashes for h in linked),
                    is_demo=bool(int(c["is_demo"])),
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
                    is_demo=bool(int(s["is_demo"])),
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

        campaigns: list[EmergingCampaign] = []
        demo_campaigns = 0
        for c in camp_rows:
            cid = str(c["campaign_id"])
            linked = camp_iocs.get(cid, {str(c["primary_ioc_hash"])})
            blocked_in_camp = sum(1 for h in linked if h in blocked_hashes)
            is_demo_camp = bool(int(c["is_demo"]))
            if is_demo_camp:
                demo_campaigns += 1
            case_cnt = int(c["case_count"])
            camp_risk_lvl: VerdictLevel = "CRITICAL_SCAM" if case_cnt >= 5 else "HIGH_RISK"
            campaigns.append(
                EmergingCampaign(
                    campaign_id=cid,
                    title_vi=str(c["title_vi"]),
                    playbook_id=str(c["playbook_id"]),
                    case_count=case_cnt,
                    primary_ioc_type=c["primary_ioc_type"],
                    primary_ioc_masked=str(c["primary_ioc_masked"]),
                    primary_ioc_hash=str(c["primary_ioc_hash"]),
                    recommended_action=str(c["recommended_action"]),
                    already_blocked=str(c["primary_ioc_hash"]) in blocked_hashes,
                    is_demo=is_demo_camp,
                    risk_level=camp_risk_lvl,
                    total_ioc_count=max(1, len(linked)),
                    blocked_ioc_count=blocked_in_camp,
                )
            )

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

        recent_audit_logs = [
            RadarAuditEvent(
                audit_id=str(a["audit_id"]),
                created_at=str(a["created_at"]),
                action=a["action"],
                outcome=a["outcome"],
                ioc_type=a["ioc_type"],
                masked_target=str(a["masked_target"]) if a["masked_target"] else None,
                rule_id=str(a["rule_id"]) if a["rule_id"] else None,
                detail=str(a["detail"]),
            )
            for a in audit_rows
        ]

        total_cases = int(case_cnt_row["c"]) if case_cnt_row else 0
        total_iocs = (
            int(total_sightings_row["cnt"]) if total_sightings_row else len(sighting_rows)
        )
        demo_iocs = int(total_sightings_row["demo_cnt"]) if total_sightings_row else 0
        real_iocs = max(0, total_iocs - demo_iocs)
        real_campaigns = max(0, len(campaigns) - demo_campaigns)

        has_demo = demo_campaigns > 0 or demo_iocs > 0
        has_real = total_cases > 0 or real_campaigns > 0 or real_iocs > 0
        if has_demo and has_real:
            data_scope: Literal["live", "mixed_with_demo", "demo_only"] = "mixed_with_demo"
        elif has_demo:
            data_scope = "demo_only"
        else:
            data_scope = "live"

        return RadarGraphResponse(
            nodes=nodes,
            edges=edges,
            campaigns=campaigns,
            active_block_rules=active_rules,
            stats={
                "total_cases": total_cases,
                "tracked_iocs": total_iocs,
                "demo_iocs": demo_iocs,
                "real_iocs": real_iocs,
                "emerging_campaigns": len(campaigns),
                "demo_campaigns": demo_campaigns,
                "real_campaigns": real_campaigns,
                "active_blocks": len(active_rules),
            },
            data_scope=data_scope,
            app_env=self._app_env,
            recent_audit_logs=recent_audit_logs,
        )
