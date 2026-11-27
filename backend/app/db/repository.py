"""SQLite WAL repository: PII-redacted cases, masked IOC threat graph, replay hashes & TTL rules."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from app.core.case_tokens import CaseOwnerChannel, generate_case_id
from app.db.migrations import (
    CURRENT_CASE_REDACTION_VER,
    CURRENT_RADAR_LABEL_VER,
    ensure_schema_and_indexes,
    prune_ioc_sightings_and_edges,
    prune_table_retention,
    run_batched_migrations,
)
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
    normalize_ioc_value,
)
from app.services.pii_scrubber import scrub_persisted_pii
from app.services.receipt_validator import build_trusted_merchant_summary
from app.services.vietqr_parser import VALID_VIETQR_AMOUNT_RE

MAX_CASE_GRAPH_IOCS = 20
MAX_SIGHTINGS_PER_CASE = 8
MAX_DOMAIN_PARENT_LEVELS = 4
MAX_LOOKUP_PHONE_HASHES = 8
MAX_LOOKUP_ACCOUNT_HASHES = 8
MAX_LOOKUP_CROSS_HASHES = 8
MAX_LOOKUP_DOMAIN_HASHES = 16
MAX_LOOKUP_IOC_HASHES = (
    MAX_LOOKUP_PHONE_HASHES
    + MAX_LOOKUP_ACCOUNT_HASHES
    + MAX_LOOKUP_CROSS_HASHES
    + MAX_LOOKUP_DOMAIN_HASHES
)
_SQL_IN_CHUNK = 500
RADAR_CACHE_TTL_SEC = 2.0
RECEIPT_DHASH_MAX_HAMMING = 3
RECEIPT_DHASH_SCAN_LIMIT = 2000
VALID_RULE_ID_RE = re.compile(r"^rule_[0-9a-f]{10}$")
_VN_PHONE_SHAPE_RE = re.compile(r"^0[35789]\d{8}$")
_DHASH_16HEX_RE = re.compile(r"^[0-9a-fA-F]{16}$")
_INVIS_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
_UNICODE_DOT_RE = re.compile(r"[\u3002\uff0e\uff61]")
_MULTI_PART_PUBLIC_SUFFIXES: frozenset[str] = frozenset(
    {
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
)
_BARE_PROTECTED_SUFFIXES: frozenset[str] = frozenset({*_MULTI_PART_PUBLIC_SUFFIXES, "vn"})
_FALLBACK_OFFICIAL_DOMAINS: frozenset[str] = frozenset(
    {
        "vietcombank.com.vn",
        "techcombank.com",
        "techcombank.com.vn",
        "mbbank.com.vn",
        "bidv.com.vn",
        "vietinbank.vn",
        "agribank.com.vn",
        "acb.com.vn",
        "vpbank.com.vn",
        "tpb.vn",
        "sacombank.com.vn",
        "napas.com.vn",
        "vneid.gov.vn",
        "dichvucong.gov.vn",
        "bocongan.gov.vn",
        "gdt.gov.vn",
        "evn.com.vn",
        "zalopay.vn",
        "vnpay.vn",
        "shopee.vn",
        "chinhphu.vn",
    }
)


def _iter_chunks(items: Sequence[str], size: int = _SQL_IN_CHUNK) -> Iterator[Sequence[str]]:
    for idx in range(0, len(items), size):
        yield items[idx : idx + size]


@lru_cache(maxsize=1)
def _load_kb_official_domains() -> frozenset[str]:
    """Load official Vietnamese institutional domains from vn_scam_kb.json plus chinhphu.vn."""
    kb_path = Path(__file__).resolve().parents[1] / "data" / "vn_scam_kb.json"
    domains: set[str] = {"chinhphu.vn"}
    try:
        payload = json.loads(kb_path.read_text(encoding="utf-8"))
        for brand in payload.get("official_brands", []):
            for raw_dom in brand.get("official_domains", []):
                cleaned = str(raw_dom).strip().lower().rstrip(".")
                if cleaned:
                    domains.add(cleaned)
    except (OSError, ValueError, TypeError):
        domains.update(_FALLBACK_OFFICIAL_DOMAINS)
    return frozenset(domains)


def _canonical_domain_host(raw: str) -> str:
    """Canonicalize a domain or URL host safely with RFC 1035 bounds (O(1) on oversized inputs)."""
    if not raw or len(raw) > 2048:
        return ""
    cleaned = _UNICODE_DOT_RE.sub(".", _INVIS_RE.sub("", raw.strip()))
    if not cleaned:
        return ""
    if "://" in cleaned:
        try:
            host = (urlsplit(cleaned).hostname or "").lower()
        except ValueError:
            return ""
    elif any(ch in cleaned for ch in "/?#@\\:") or any(ch.isspace() for ch in cleaned):
        try:
            host = (urlsplit(f"https://{cleaned}").hostname or "").lower()
        except ValueError:
            return ""
    else:
        host = cleaned.lower()
    if host.endswith(".."):
        return ""
    if host.endswith("."):
        host = host[:-1]
    if not host or len(host) > 253 or ".." in host or host.startswith("."):
        return ""
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return ""
        if not host or len(host) > 253 or ".." in host:
            return ""
    labels = host.split(".")
    if len(labels) > 127 or any(not lbl or len(lbl) > 63 for lbl in labels):
        return ""
    return host


def _is_official_or_public_suffix_domain(host: str) -> bool:
    """Return True for official KB domains (or any subdomain), .gov.vn, or bare public suffixes."""
    cleaned = host.strip().lower().rstrip(".")
    if not cleaned:
        return False
    if cleaned in _BARE_PROTECTED_SUFFIXES or cleaned in RECOGNIZED_DISPLAY_PUBLIC_SUFFIXES:
        return True
    if cleaned == "gov.vn" or cleaned.endswith(".gov.vn"):
        return True
    official = _load_kb_official_domains()
    return cleaned in official or any(cleaned.endswith(f".{od}") for od in official)


def strip_visual_blobs_copy(report: AnalysisReport) -> AnalysisReport:
    """Return a copy of report with visual blobs & EXIF software cleared without re-running PII scrub."""
    updates: dict[str, Any] = {}
    if report.sandbox is not None and report.sandbox.screenshot_base64 is not None:
        updates["sandbox"] = report.sandbox.model_copy(update={"screenshot_base64": None})
    if report.image_forensics is not None and (
        report.image_forensics.ela_heatmap_base64 is not None
        or report.image_forensics.exif_software is not None
    ):
        updates["image_forensics"] = report.image_forensics.model_copy(
            update={"ela_heatmap_base64": None, "exif_software": None}
        )
    if report.image_forensics_list:
        updates["image_forensics_list"] = [
            item.model_copy(update={"ela_heatmap_base64": None, "exif_software": None})
            for item in report.image_forensics_list
        ]
    return report.model_copy(update=updates) if updates else report.model_copy()


def _should_ingest_radar_iocs(report: AnalysisReport) -> bool:
    """Block prompt-injection-only reports without corroborating threat signals from Radar ingestion."""
    if report.risk_score < 45:
        return False
    if not report.prompt_injection_detected:
        return True
    if report.active_block_rule_hit:
        return True
    if any(uf.risk_points >= 40 or uf.is_blocked_ssrf for uf in report.url_findings):
        return True
    if any(
        v.receive_scam_detected
        or v.beneficiary_mismatch
        or not v.crc_valid
        or not v.tlv_valid
        for v in report.vietqr_findings
    ):
        return True
    rl = report.receipt_logic
    if rl is not None and (
        rl.is_replayed
        or rl.beneficiary_mismatch
        or rl.amount_format_anomaly
        or rl.timestamp_anomaly
        or rl.geometry_anomaly
        or not rl.reference_valid
        or rl.logic_risk_points > 0
    ):
        return True
    imgs = [
        img
        for img in (report.image_forensics, *report.image_forensics_list)
        if img is not None
    ]
    if any(img.tamper_score >= 35 for img in imgs):
        return True
    clf = report.classifier
    return bool(
        clf is not None
        and clf.available
        and clf.scam_probability >= 0.65
        and clf.predicted_label != "PROMPT_INJECTION"
    )


def sanitize_rule_id(rule_id: str | None) -> str | None:
    """Return rule_id only if it strictly matches the server-issued 'rule_<10hex>' format."""
    if not rule_id:
        return None
    cleaned = rule_id.strip()
    return cleaned if VALID_RULE_ID_RE.fullmatch(cleaned) else None


class ProtectedDemoIocError(ValueError):
    """Raised when attempting to create a block rule against a protected SAFE demo IOC (HTTP 409)."""


@dataclass(frozen=True, slots=True)
class StoredCaseRecord:
    """Persisted PII-redacted case report bundled with channel-isolation metadata."""

    report: AnalysisReport
    owner_channel: CaseOwnerChannel
    owner_chat_hash: str | None
    is_demo: bool
    parent_case_id: str | None


def _coerce_owner_channel(raw: object) -> CaseOwnerChannel:
    if raw == "web_token":
        return "web_token"
    if raw == "telegram_private":
        return "telegram_private"
    if raw == "telegram_group_locked":
        return "telegram_group_locked"
    return "legacy_locked"


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
            img is not None
            or (isinstance(vqr, list) and len(vqr) > 0)
            or (isinstance(rl, dict) and bool(rl.get("is_receipt_candidate")))
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
        if is_merchant_receipt or data.get("receipt_verification_status") not in (
            None,
            "",
            "NOT_APPLICABLE",
        ):
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
        return scrub_persisted_pii(val, known_phones=raw_phones, known_accounts=raw_accounts)

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
                "redirect_domains": [_scrub(d) or d for d in u.redirect_domains],
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
        max_stored_cases: int = 5000,
        max_stored_ioc_sightings: int = 2000,
        max_stored_receipt_hashes: int = 10000,
        max_stored_telegram_updates: int = 5000,
        receipt_ttl_days: int = 30,
        telegram_update_ttl_days: int = 7,
    ) -> None:
        self._db_path = sqlite_path
        self._default_ttl = max(1, default_ttl_minutes)
        self._ioc_hmac_secret = ioc_hmac_secret.strip()
        self._app_env = app_env
        self._max_stored_cases = max(1, max_stored_cases)
        self._max_stored_ioc_sightings = max(1, max_stored_ioc_sightings)
        self._max_stored_receipt_hashes = max(1, max_stored_receipt_hashes)
        self._max_stored_telegram_updates = max(1, max_stored_telegram_updates)
        self._receipt_ttl_days = max(1, receipt_ttl_days)
        self._telegram_update_ttl_days = max(1, telegram_update_ttl_days)
        self._radar_cache_lock = threading.Lock()
        self._radar_cache_ver = 0
        self._radar_cache: tuple[float, int, str | None, RadarGraphResponse] | None = None
        protected_domains = (
            _load_kb_official_domains() | _BARE_PROTECTED_SUFFIXES | RECOGNIZED_DISPLAY_PUBLIC_SUFFIXES
        )
        self._official_domain_hashes: frozenset[str] = frozenset(
            self._hash_ioc("domain", dom) for dom in protected_domains
        )

    def _invalidate_radar_cache(self) -> None:
        with self._radar_cache_lock:
            self._radar_cache_ver += 1
            self._radar_cache = None

    def _hash_ioc(self, ioc_type: str, raw_value: str) -> str:
        return hash_ioc(ioc_type, raw_value, hmac_key=self._ioc_hmac_secret or None)

    def hash_ioc_value(self, ioc_type: str, raw_value: str) -> str:
        """Compute keyed HMAC-SHA256 IOC hash matching this repository's secret."""
        return self._hash_ioc(ioc_type, raw_value)

    def hash_receipt_ref_fingerprint(self, bank: str | None, ref_code: str) -> str:
        """Compute bank-agnostic keyed ref_h:<hex> fingerprint for a receipt reference code."""
        _ = bank
        return f"ref_h:{self.hash_ioc_value('receipt_ref', ref_code.strip().upper())}"

    def _hash_receipt_ref_fingerprint(self, bank: str | None, ref_code: str) -> str:
        return self.hash_receipt_ref_fingerprint(bank, ref_code)

    def _normalize_replay_fingerprint(self, fp_str: str) -> str:
        cleaned = fp_str.strip()
        if cleaned[:4].lower() == "ref:":
            raw_payload = cleaned[4:]
            bank_part, sep, ref_part = raw_payload.partition(":")
            if sep and ref_part.strip():
                return self.hash_receipt_ref_fingerprint(bank_part, ref_part)
            return self.hash_receipt_ref_fingerprint(None, raw_payload)
        if cleaned[:6].lower() == "dhash:":
            return f"dhash:{cleaned[6:].strip().lower()}"
        return cleaned

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
        """Initialize SQLite schema, indexes, batched migrations, and retention bounds."""
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._session() as conn:
            ensure_schema_and_indexes(conn)
        run_batched_migrations(
            self._connect,
            parse_report_fn=_parse_and_upgrade_stored_report,
            redact_report_fn=redact_report_pii,
            sanitize_label_fn=_sanitize_legacy_radar_label,
            normalize_replay_fp_fn=self._normalize_replay_fingerprint,
            generate_case_id_fn=generate_case_id,
        )
        with self._session() as conn:
            self._prune_cases(conn)
            prune_ioc_sightings_and_edges(
                conn, self._max_stored_ioc_sightings, force_edge_cleanup=True
            )
            self._prune_receipt_hashes(conn)
            self._prune_telegram_updates(conn)
        self._invalidate_radar_cache()

    def _prune_cases(self, conn: sqlite3.Connection) -> None:
        prune_table_retention(
            conn,
            table="cases",
            pk="case_id",
            order_by="created_at DESC, rowid DESC",
            max_rows=self._max_stored_cases,
        )

    def _prune_receipt_hashes(
        self, conn: sqlite3.Connection, now: datetime | None = None
    ) -> None:
        prune_table_retention(
            conn,
            table="receipt_hashes",
            pk="fingerprint",
            order_by="created_at DESC, rowid DESC",
            max_rows=self._max_stored_receipt_hashes,
            ttl_days=self._receipt_ttl_days,
            now=now,
        )

    def _prune_telegram_updates(
        self, conn: sqlite3.Connection, now: datetime | None = None
    ) -> None:
        prune_table_retention(
            conn,
            table="telegram_updates",
            pk="update_id",
            order_by="CASE WHEN status='processing' THEN 0 ELSE 1 END, created_at DESC, rowid DESC",
            max_rows=self._max_stored_telegram_updates,
            ttl_days=self._telegram_update_ttl_days,
            cond="status IN ('completed','quarantined')",
            now=now,
        )

    def _is_protected_ioc_conn(
        self,
        conn: sqlite3.Connection,
        ioc_type: IocType,
        *,
        raw_value: str | None = None,
        ioc_hash: str | None = None,
    ) -> bool:
        hashes_to_check: list[str] = []
        seen: set[str] = set()
        if ioc_hash and ioc_hash.strip():
            h_clean = ioc_hash.strip().lower()
            if ioc_type == "domain" and h_clean in self._official_domain_hashes:
                return True
            seen.add(h_clean)
            hashes_to_check.append(h_clean)
        if raw_value and raw_value.strip():
            if ioc_type == "domain":
                canonical = _canonical_domain_host(raw_value)
                if canonical and _is_official_or_public_suffix_domain(canonical):
                    return True
                for cand in self._expand_domain_candidates([canonical]) if canonical else []:
                    if _is_official_or_public_suffix_domain(cand):
                        return True
                    h_cand = self._hash_ioc("domain", cand)
                    if h_cand not in seen:
                        seen.add(h_cand)
                        hashes_to_check.append(h_cand)
                if canonical:
                    h_raw = self._hash_ioc("domain", canonical)
                    if h_raw not in seen:
                        seen.add(h_raw)
                        hashes_to_check.append(h_raw)
            else:
                h_raw = self._hash_ioc(ioc_type, raw_value)
                if h_raw not in seen:
                    seen.add(h_raw)
                    hashes_to_check.append(h_raw)
        for chunk in _iter_chunks(hashes_to_check):
            placeholders = ",".join("?" for _ in chunk)
            row = conn.execute(
                f"SELECT 1 FROM protected_demo_iocs WHERE ioc_hash IN ({placeholders}) LIMIT 1",  # noqa: S608
                tuple(chunk),
            ).fetchone()
            if row is not None:
                return True
        return False

    def is_protected_ioc(
        self,
        ioc_type: IocType,
        *,
        raw_value: str | None = None,
        ioc_hash: str | None = None,
    ) -> bool:
        """Return True if raw_value/ioc_hash matches protected SAFE demo or official institutional IOCs."""
        with self._session() as conn:
            return self._is_protected_ioc_conn(
                conn, ioc_type, raw_value=raw_value, ioc_hash=ioc_hash
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
                self._invalidate_radar_cache()
                return
            seed_file = Path(seed_path)
            if not seed_file.exists():
                self._invalidate_radar_cache()
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
                        "SET title_vi = ?, recommended_action = ?, primary_ioc_masked = ?, "
                        "is_demo = 1, label_ver = ? "
                        "WHERE campaign_id = ?",
                        (
                            camp["title_vi"],
                            camp["recommended_action"],
                            p_masked_ex,
                            CURRENT_RADAR_LABEL_VER,
                            camp["campaign_id"],
                        ),
                    )
                    conn.execute(
                        "UPDATE ioc_sightings SET masked_value = ?, is_demo = 1, label_ver = ? "
                        "WHERE ioc_hash = ?",
                        (p_masked_ex, CURRENT_RADAR_LABEL_VER, p_hash_ex),
                    )
                    for co_ex in camp.get("co_iocs", []):
                        co_t_ex: IocType = co_ex["ioc_type"]
                        co_raw_ex: str = co_ex["raw_synthetic"]
                        conn.execute(
                            "UPDATE ioc_sightings SET masked_value = ?, is_demo = 1, label_ver = ? "
                            "WHERE ioc_hash = ?",
                            (
                                mask_ioc(co_t_ex, co_raw_ex),
                                CURRENT_RADAR_LABEL_VER,
                                self._hash_ioc(co_t_ex, co_raw_ex),
                            ),
                        )
                    conn.execute(
                        "UPDATE ioc_sightings SET is_demo = 1, label_ver = ? WHERE campaign_id = ?",
                        (CURRENT_RADAR_LABEL_VER, camp["campaign_id"]),
                    )
                self._invalidate_radar_cache()
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
                     primary_ioc_hash, primary_ioc_masked, recommended_action, is_demo, label_ver)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
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
                        CURRENT_RADAR_LABEL_VER,
                    ),
                )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO ioc_sightings
                    (ioc_hash, ioc_type, masked_value, hit_count, campaign_id, is_demo, label_ver)
                    VALUES (?, ?, ?, ?, ?, 1, ?)
                    """,
                    (p_hash, p_type, p_masked, c_count, cid, CURRENT_RADAR_LABEL_VER),
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
                        (ioc_hash, ioc_type, masked_value, hit_count, campaign_id, is_demo, label_ver)
                        VALUES (?, ?, ?, ?, ?, 1, ?)
                        """,
                        (co_h, co_t, co_m, max(1, c_count - 1), cid, CURRENT_RADAR_LABEL_VER),
                    )
                    conn.execute(
                        "INSERT OR IGNORE INTO ioc_edges (source_id, target_id, relation) VALUES (?, ?, ?)",
                        (cid, co_h, "associated_ioc"),
                    )
        self._invalidate_radar_cache()

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
            INSERT INTO ioc_sightings (ioc_hash, ioc_type, masked_value, hit_count, is_demo, label_ver)
            VALUES (?, ?, ?, 1, 0, ?)
            ON CONFLICT(ioc_hash) DO UPDATE SET hit_count = hit_count + 1, label_ver = excluded.label_ver
            """,
            (h, ioc_type, m, CURRENT_RADAR_LABEL_VER),
        )
        return h

    def _is_receipt_replayed_conn(
        self,
        conn: sqlite3.Connection,
        dhash_hex: str | None,
        bank: str | None,
        ref_code: str | None,
        *,
        cutoff_iso: str,
    ) -> bool:
        probes: list[str] = []
        clean_dhash: str | None = None
        if dhash_hex and dhash_hex.strip():
            raw_dh = dhash_hex.strip()
            clean_dhash = raw_dh.lower()
            probes.append(f"dhash:{clean_dhash}")
            if raw_dh != clean_dhash:
                probes.append(f"dhash:{raw_dh}")
        if ref_code and ref_code.strip():
            probes.append(self.hash_receipt_ref_fingerprint(bank, ref_code))
        if not probes:
            return False

        for chunk in _iter_chunks(probes):
            placeholders = ",".join("?" for _ in chunk)
            row = conn.execute(
                f"SELECT 1 FROM receipt_hashes WHERE fingerprint IN ({placeholders}) "  # noqa: S608
                f"AND created_at >= ? LIMIT 1",
                (*chunk, cutoff_iso),
            ).fetchone()
            if row is not None:
                return True

        if clean_dhash and _DHASH_16HEX_RE.fullmatch(clean_dhash):
            target_int = int(clean_dhash, 16)
            rows = conn.execute(
                "SELECT fingerprint FROM receipt_hashes "
                "WHERE fingerprint LIKE 'dhash:%' AND created_at >= ? "
                "ORDER BY created_at DESC LIMIT ?",
                (cutoff_iso, RECEIPT_DHASH_SCAN_LIMIT),
            ).fetchall()
            for r in rows:
                cand_hex = str(r["fingerprint"])[6:]
                if (
                    _DHASH_16HEX_RE.fullmatch(cand_hex)
                    and (target_int ^ int(cand_hex, 16)).bit_count() <= RECEIPT_DHASH_MAX_HAMMING
                ):
                    return True
        return False

    def claim_receipt_replay(
        self,
        dhash_hex: str | None,
        bank: str | None,
        ref_code: str | None,
        register_if_new: bool = True,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Atomically check non-expired receipt fingerprints (incl. Hamming <= 3) and register new ones."""
        insert_fps: list[str] = []
        if dhash_hex and dhash_hex.strip():
            insert_fps.append(f"dhash:{dhash_hex.strip().lower()}")
        if ref_code and ref_code.strip():
            insert_fps.append(self.hash_receipt_ref_fingerprint(bank, ref_code))
        if not insert_fps:
            return False

        now_dt = now or datetime.now(UTC)
        now_iso = now_dt.isoformat()
        cutoff_iso = (now_dt - timedelta(days=self._receipt_ttl_days)).isoformat()
        conn = self._connect()
        try:
            conn.isolation_level = None
            conn.execute("BEGIN IMMEDIATE;")
            replayed = self._is_receipt_replayed_conn(
                conn, dhash_hex, bank, ref_code, cutoff_iso=cutoff_iso
            )
            if register_if_new and not replayed:
                for fp in insert_fps:
                    conn.execute(
                        "INSERT INTO receipt_hashes (fingerprint, created_at) VALUES (?, ?) "
                        "ON CONFLICT(fingerprint) DO UPDATE SET created_at = excluded.created_at",
                        (fp, now_iso),
                    )
                self._prune_receipt_hashes(conn, now=now_dt)
            conn.execute("COMMIT;")
            return replayed
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK;")
            raise
        finally:
            conn.close()

    def _bump_matching_campaigns(self, conn: sqlite3.Connection, ioc_hashes: Sequence[str]) -> None:
        if not ioc_hashes:
            return
        matched_cids: set[str] = set()
        for chunk in _iter_chunks(ioc_hashes):
            placeholders = ",".join("?" for _ in chunk)
            for row in conn.execute(
                f"SELECT campaign_id FROM campaigns WHERE primary_ioc_hash IN ({placeholders})",  # noqa: S608
                tuple(chunk),
            ).fetchall():
                matched_cids.add(str(row["campaign_id"]))
            for row in conn.execute(
                f"SELECT DISTINCT campaign_id FROM ioc_sightings "  # noqa: S608
                f"WHERE ioc_hash IN ({placeholders}) AND campaign_id IS NOT NULL",
                tuple(chunk),
            ).fetchall():
                matched_cids.add(str(row["campaign_id"]))
        for cid in matched_cids:
            conn.execute(
                "UPDATE campaigns SET case_count = case_count + 1 WHERE campaign_id = ?",
                (cid,),
            )

    def save_report(
        self,
        report: AnalysisReport,
        receipt_dhash: str | None = None,
        track_replay: bool = True,
        owner_channel: CaseOwnerChannel = "web_token",
        owner_chat_hash: str | None = None,
        parent_case_id: str | None = None,
        contributes_to_radar: bool = True,
        is_demo: bool = False,
    ) -> AnalysisReport:
        """Persist PII-redacted report, update IOC graph & campaigns, and store replay hashes."""
        effective_radar = bool(contributes_to_radar) and not is_demo
        live_redacted = redact_report_pii(report, strip_visual_blobs=False)
        stored_redacted = strip_visual_blobs_copy(live_redacted)
        with self._session() as conn:
            already_saved = (
                conn.execute(
                    "SELECT 1 FROM cases WHERE case_id = ? LIMIT 1",
                    (stored_redacted.case_id,),
                ).fetchone()
                is not None
            )

            if not already_saved and effective_radar and _should_ingest_radar_iocs(report):
                raw_candidates: list[tuple[IocType, str]] = [
                    *(("phone", ph) for ph in report.iocs.phones if "****" not in ph),
                    *(("bank_account", acct) for acct in report.iocs.bank_accounts if "****" not in acct),
                    *(("domain", dom) for dom in report.iocs.domains if "****" not in dom),
                ]
                seen_hashes: list[str] = []
                seen_set: set[str] = set()
                for ioc_type_val, raw_val in raw_candidates:
                    if len(seen_hashes) >= MAX_SIGHTINGS_PER_CASE:
                        break
                    canonical = (
                        _canonical_domain_host(raw_val)
                        if ioc_type_val == "domain"
                        else normalize_ioc_value(ioc_type_val, raw_val)
                    )
                    if not canonical:
                        continue
                    if self._is_protected_ioc_conn(conn, ioc_type_val, raw_value=canonical):
                        continue
                    h = self._hash_ioc(ioc_type_val, canonical)
                    if h in seen_set:
                        continue
                    self._upsert_sighting(conn, ioc_type_val, canonical)
                    seen_set.add(h)
                    seen_hashes.append(h)

                for idx in range(len(seen_hashes)):
                    for jdx in range(idx + 1, len(seen_hashes)):
                        conn.execute(
                            "INSERT OR IGNORE INTO ioc_edges (source_id, target_id, relation) "
                            "VALUES (?, ?, 'co_occurs')",
                            (seen_hashes[idx], seen_hashes[jdx]),
                        )

                self._bump_matching_campaigns(conn, seen_hashes)
                if seen_hashes:
                    prune_ioc_sightings_and_edges(conn, self._max_stored_ioc_sightings)

            if track_replay:
                now_dt = datetime.now(UTC)
                now_iso = now_dt.isoformat()
                wrote_replay = False
                if receipt_dhash and receipt_dhash.strip():
                    conn.execute(
                        "INSERT INTO receipt_hashes (fingerprint, created_at) VALUES (?, ?) "
                        "ON CONFLICT(fingerprint) DO UPDATE SET created_at = excluded.created_at",
                        (f"dhash:{receipt_dhash.strip().lower()}", now_iso),
                    )
                    wrote_replay = True
                if (
                    report.receipt_logic
                    and report.receipt_logic.reference_valid
                    and report.receipt_logic.reference_code
                ):
                    ref_fp = self.hash_receipt_ref_fingerprint(
                        report.receipt_logic.bank_detected,
                        report.receipt_logic.reference_code,
                    )
                    conn.execute(
                        "INSERT INTO receipt_hashes (fingerprint, created_at) VALUES (?, ?) "
                        "ON CONFLICT(fingerprint) DO UPDATE SET created_at = excluded.created_at",
                        (ref_fp, now_iso),
                    )
                    wrote_replay = True
                if wrote_replay:
                    self._prune_receipt_hashes(conn, now=now_dt)

            conn.execute(
                """
                INSERT OR REPLACE INTO cases (
                    case_id,
                    created_at,
                    verdict,
                    risk_score,
                    report_json,
                    owner_channel,
                    owner_chat_hash,
                    parent_case_id,
                    contributes_to_radar,
                    is_demo,
                    redaction_ver
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    stored_redacted.case_id,
                    stored_redacted.created_at,
                    stored_redacted.verdict,
                    stored_redacted.risk_score,
                    stored_redacted.model_dump_json(),
                    owner_channel,
                    owner_chat_hash,
                    parent_case_id,
                    1 if effective_radar else 0,
                    1 if is_demo else 0,
                    CURRENT_CASE_REDACTION_VER,
                ),
            )
            self._prune_cases(conn)
        self._invalidate_radar_cache()
        return live_redacted

    def save_staged_report(
        self,
        staged_report: AnalysisReport,
        *,
        child_case_id: str,
        parent_case_id: str,
        prehashed_iocs: Sequence[dict[str, str]],
        replay_fingerprints: Sequence[dict[str, str]],
        contribute_to_radar: bool = False,
        is_demo: bool = False,
    ) -> AnalysisReport:
        """Persist a staged redacted supplementary report with optional pre-hashed Radar opt-in."""
        effective_radar = bool(contribute_to_radar) and not is_demo
        rekeyed = staged_report.model_copy(update={"case_id": child_case_id})
        stored_redacted = redact_report_pii(rekeyed, strip_visual_blobs=True)

        with self._session() as conn:
            already_saved = (
                conn.execute(
                    "SELECT 1 FROM cases WHERE case_id = ? LIMIT 1",
                    (stored_redacted.case_id,),
                ).fetchone()
                is not None
            )

            if not already_saved and effective_radar:
                now_dt = datetime.now(UTC)
                now_iso = now_dt.isoformat()
                wrote_replay = False
                for fp_item in replay_fingerprints:
                    fp_str = str(fp_item.get("fingerprint") or "").strip()
                    if not fp_str:
                        ph = str(fp_item.get("phash") or fp_item.get("dhash") or "").strip()
                        sha = str(fp_item.get("sha256") or "").strip()
                        fp_str = f"dhash:{ph}" if ph else (f"sha256:{sha}" if sha else "")
                    if fp_str:
                        fp_str = self._normalize_replay_fingerprint(fp_str)
                        conn.execute(
                            "INSERT INTO receipt_hashes (fingerprint, created_at) VALUES (?, ?) "
                            "ON CONFLICT(fingerprint) DO UPDATE SET created_at = excluded.created_at",
                            (fp_str, now_iso),
                        )
                        wrote_replay = True
                if wrote_replay:
                    self._prune_receipt_hashes(conn, now=now_dt)

                if _should_ingest_radar_iocs(stored_redacted):
                    seen_hashes: list[str] = []
                    seen_set: set[str] = set()
                    for ioc_item in prehashed_iocs:
                        if len(seen_hashes) >= MAX_SIGHTINGS_PER_CASE:
                            break
                        ioc_type_raw = str(ioc_item.get("ioc_type") or "").strip()
                        ioc_hash = str(ioc_item.get("ioc_hash") or "").strip().lower()
                        if ioc_type_raw not in ("phone", "bank_account", "domain") or not ioc_hash:
                            continue
                        ioc_type_typed: IocType = (
                            "phone"
                            if ioc_type_raw == "phone"
                            else ("bank_account" if ioc_type_raw == "bank_account" else "domain")
                        )
                        if ioc_hash in seen_set:
                            continue
                        if self._is_protected_ioc_conn(conn, ioc_type_typed, ioc_hash=ioc_hash):
                            continue
                        safe_mask = _sanitize_legacy_radar_label(
                            ioc_type_typed,
                            str(ioc_item.get("masked_value") or ""),
                            ioc_hash,
                        )
                        conn.execute(
                            """
                            INSERT INTO ioc_sightings
                            (ioc_hash, ioc_type, masked_value, hit_count, is_demo, label_ver)
                            VALUES (?, ?, ?, 1, 0, ?)
                            ON CONFLICT(ioc_hash) DO UPDATE SET
                                hit_count = hit_count + 1,
                                label_ver = excluded.label_ver
                            """,
                            (ioc_hash, ioc_type_typed, safe_mask, CURRENT_RADAR_LABEL_VER),
                        )
                        seen_set.add(ioc_hash)
                        seen_hashes.append(ioc_hash)

                    for idx in range(len(seen_hashes)):
                        for jdx in range(idx + 1, len(seen_hashes)):
                            conn.execute(
                                "INSERT OR IGNORE INTO ioc_edges (source_id, target_id, relation) "
                                "VALUES (?, ?, 'co_occurs')",
                                (seen_hashes[idx], seen_hashes[jdx]),
                            )

                    self._bump_matching_campaigns(conn, seen_hashes)
                    if seen_hashes:
                        prune_ioc_sightings_and_edges(conn, self._max_stored_ioc_sightings)

            conn.execute(
                """
                INSERT OR REPLACE INTO cases (
                    case_id,
                    created_at,
                    verdict,
                    risk_score,
                    report_json,
                    owner_channel,
                    owner_chat_hash,
                    parent_case_id,
                    contributes_to_radar,
                    is_demo,
                    redaction_ver
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    stored_redacted.case_id,
                    stored_redacted.created_at,
                    stored_redacted.verdict,
                    stored_redacted.risk_score,
                    stored_redacted.model_dump_json(),
                    "web_token",
                    None,
                    parent_case_id,
                    1 if effective_radar else 0,
                    1 if is_demo else 0,
                    CURRENT_CASE_REDACTION_VER,
                ),
            )
            self._prune_cases(conn)
        self._invalidate_radar_cache()
        return stored_redacted

    def get_report_with_owner(self, case_id: str) -> StoredCaseRecord | None:
        """Load a persisted PII-redacted case report along with its channel-isolation metadata."""
        with self._session() as conn:
            row = conn.execute(
                "SELECT report_json, owner_channel, owner_chat_hash, is_demo, parent_case_id "
                "FROM cases WHERE case_id = ?",
                (case_id,),
            ).fetchone()
        if not row:
            return None
        parsed = _parse_and_upgrade_stored_report(str(row["report_json"]))
        if parsed is None:
            return None
        redacted = redact_report_pii(parsed, strip_visual_blobs=True)
        return StoredCaseRecord(
            report=redacted,
            owner_channel=_coerce_owner_channel(row["owner_channel"]),
            owner_chat_hash=str(row["owner_chat_hash"]) if row["owner_chat_hash"] else None,
            is_demo=bool(int(row["is_demo"])),
            parent_case_id=str(row["parent_case_id"]) if row["parent_case_id"] else None,
        )

    def get_report(self, case_id: str) -> AnalysisReport | None:
        record = self.get_report_with_owner(case_id)
        return record.report if record is not None else None

    def claim_telegram_update(
        self,
        update_id: int,
        owner_id: str = "default",
        lease_seconds: int = 180,
        chat_id: int | str | None = None,
        sender_user_id: int | str | None = None,
        chat_type: str | None = None,
        update_kind: str = "message",
    ) -> tuple[str, str | None, str | None]:
        """Atomically claim update_id with an owner-tagged renewable lease and context binding."""
        now_dt = datetime.now(UTC)
        now_iso = now_dt.isoformat()
        expires_iso = (now_dt + timedelta(seconds=max(0, lease_seconds))).isoformat()
        in_chat = str(chat_id) if chat_id is not None else None
        in_sender = str(sender_user_id) if sender_user_id is not None else None
        in_chat_type = (
            chat_type.strip().lower() if isinstance(chat_type, str) and chat_type.strip() else None
        )
        in_kind = update_kind.strip() or "message"
        conn = self._connect()
        try:
            conn.isolation_level = None
            conn.execute("BEGIN IMMEDIATE;")
            row = conn.execute(
                "SELECT status, lease_owner, lease_expires_at, case_id, reply_text, created_at, "
                "chat_id, sender_user_id, chat_type, update_kind "
                "FROM telegram_updates WHERE update_id = ?",
                (update_id,),
            ).fetchone()
            if row is None:
                alloc_case_id = generate_case_id()
                conn.execute(
                    "INSERT INTO telegram_updates "
                    "(update_id, status, lease_owner, lease_expires_at, case_id, reply_text, "
                    "created_at, chat_id, sender_user_id, chat_type, update_kind, "
                    "scrubbed, delivery_attempts) "
                    "VALUES (?, 'processing', ?, ?, ?, '', ?, ?, ?, ?, ?, 1, 0)",
                    (
                        update_id,
                        owner_id,
                        expires_iso,
                        alloc_case_id,
                        now_iso,
                        in_chat,
                        in_sender,
                        in_chat_type,
                        in_kind,
                    ),
                )
                self._prune_telegram_updates(conn, now=now_dt)
                conn.execute("COMMIT;")
                return ("claimed", alloc_case_id, None)

            stored_chat = str(row["chat_id"]) if row["chat_id"] is not None else None
            stored_sender = (
                str(row["sender_user_id"]) if row["sender_user_id"] is not None else None
            )
            stored_chat_type = str(row["chat_type"]) if row["chat_type"] is not None else None
            stored_kind = str(row["update_kind"]) if row["update_kind"] is not None else "message"
            if (stored_chat, stored_sender, stored_chat_type, stored_kind) != (
                in_chat,
                in_sender,
                in_chat_type,
                in_kind,
            ):
                conn.execute("COMMIT;")
                return ("mismatch", None, None)

            status = str(row["status"])
            if status == "quarantined":
                conn.execute("COMMIT;")
                return ("quarantined", None, None)
            if status == "completed":
                conn.execute("COMMIT;")
                return (
                    "cached",
                    str(row["case_id"]) if row["case_id"] else None,
                    str(row["reply_text"]),
                )

            cur_expires = str(row["lease_expires_at"] or row["created_at"])
            if cur_expires <= now_iso:
                alloc_case_id = str(row["case_id"]) if row["case_id"] else generate_case_id()
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
            if conn.in_transaction:
                conn.execute("ROLLBACK;")
            raise
        finally:
            conn.close()

    def record_telegram_delivery_failure(
        self,
        update_id: int,
        *,
        permanent: bool,
        max_attempts: int = 3,
        owner_id: str | None = None,
    ) -> tuple[int, bool]:
        """Increment delivery_attempts, quarantine permanent/exhausted failures, or expire lease."""
        eff_max = max(1, max_attempts)
        now_dt = datetime.now(UTC)
        conn = self._connect()
        try:
            conn.isolation_level = None
            conn.execute("BEGIN IMMEDIATE;")
            row = conn.execute(
                "SELECT status, lease_owner, delivery_attempts "
                "FROM telegram_updates WHERE update_id = ?",
                (update_id,),
            ).fetchone()
            if row is None:
                conn.execute("COMMIT;")
                return (0, False)

            status = str(row["status"])
            cur_attempts = int(row["delivery_attempts"] or 0)
            if status == "quarantined":
                conn.execute("COMMIT;")
                return (cur_attempts, True)

            if status == "processing":
                stored_owner = str(row["lease_owner"]) if row["lease_owner"] is not None else None
                if owner_id is not None and stored_owner != owner_id:
                    conn.execute("COMMIT;")
                    return (cur_attempts, False)
                new_attempts = cur_attempts + 1
                quarantined = bool(permanent or new_attempts >= eff_max)
                if quarantined:
                    conn.execute(
                        "UPDATE telegram_updates "
                        "SET status = 'quarantined', delivery_attempts = ?, "
                        "lease_owner = NULL, lease_expires_at = NULL "
                        "WHERE update_id = ?",
                        (new_attempts, update_id),
                    )
                    self._prune_telegram_updates(conn, now=now_dt)
                else:
                    conn.execute(
                        "UPDATE telegram_updates "
                        "SET delivery_attempts = ?, lease_owner = NULL, "
                        "lease_expires_at = '1970-01-01T00:00:00+00:00' "
                        "WHERE update_id = ?",
                        (new_attempts, update_id),
                    )
                conn.execute("COMMIT;")
                return (new_attempts, quarantined)

            if status == "completed":
                new_attempts = cur_attempts + 1
                quarantined = bool(permanent or new_attempts >= eff_max)
                if quarantined:
                    conn.execute(
                        "UPDATE telegram_updates "
                        "SET status = 'quarantined', delivery_attempts = ?, "
                        "lease_owner = NULL, lease_expires_at = NULL "
                        "WHERE update_id = ?",
                        (new_attempts, update_id),
                    )
                    self._prune_telegram_updates(conn, now=now_dt)
                else:
                    conn.execute(
                        "UPDATE telegram_updates SET delivery_attempts = ? WHERE update_id = ?",
                        (new_attempts, update_id),
                    )
                conn.execute("COMMIT;")
                return (new_attempts, quarantined)

            conn.execute("COMMIT;")
            return (cur_attempts, False)
        except Exception:
            if conn.in_transaction:
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
        chat_id: int | str | None = None,
        sender_user_id: int | str | None = None,
        chat_type: str | None = None,
        update_kind: str | None = None,
    ) -> None:
        now_dt = datetime.now(UTC)
        now_iso = now_dt.isoformat()
        clean_reply = scrub_persisted_pii(reply_text) if reply_text else ""
        in_chat = str(chat_id) if chat_id is not None else None
        in_sender = str(sender_user_id) if sender_user_id is not None else None
        in_chat_type = (
            chat_type.strip().lower() if isinstance(chat_type, str) and chat_type.strip() else None
        )
        in_kind = update_kind.strip() if isinstance(update_kind, str) and update_kind.strip() else None
        with self._session() as conn:
            if owner_id is not None:
                conn.execute(
                    """
                    UPDATE telegram_updates
                    SET status = 'completed',
                        case_id = ?,
                        reply_text = ?,
                        lease_expires_at = NULL,
                        created_at = ?,
                        scrubbed = 1
                    WHERE update_id = ? AND lease_owner = ? AND status = 'processing'
                    """,
                    (case_id, clean_reply, now_iso, update_id, owner_id),
                )
            else:
                conn.execute(
                    """
                    INSERT INTO telegram_updates (
                        update_id, status, lease_owner, lease_expires_at,
                        case_id, reply_text, created_at,
                        chat_id, sender_user_id, chat_type, update_kind,
                        scrubbed, delivery_attempts
                    )
                    VALUES (?, 'completed', NULL, NULL, ?, ?, ?, ?, ?, ?, ?, 1, 0)
                    ON CONFLICT(update_id) DO UPDATE SET
                        status = 'completed',
                        lease_owner = NULL,
                        lease_expires_at = NULL,
                        case_id = excluded.case_id,
                        reply_text = excluded.reply_text,
                        created_at = excluded.created_at,
                        scrubbed = 1,
                        chat_id = COALESCE(excluded.chat_id, telegram_updates.chat_id),
                        sender_user_id = COALESCE(
                            excluded.sender_user_id, telegram_updates.sender_user_id
                        ),
                        chat_type = COALESCE(excluded.chat_type, telegram_updates.chat_type),
                        update_kind = COALESCE(?, telegram_updates.update_kind)
                    """,
                    (
                        update_id,
                        case_id,
                        clean_reply,
                        now_iso,
                        in_chat,
                        in_sender,
                        in_chat_type,
                        in_kind or "message",
                        in_kind,
                    ),
                )
            self._prune_telegram_updates(conn, now=now_dt)

    def is_receipt_replayed(
        self,
        dhash_hex: str | None,
        bank: str | None,
        ref_code: str | None,
        *,
        now: datetime | None = None,
    ) -> bool:
        now_dt = now or datetime.now(UTC)
        cutoff_iso = (now_dt - timedelta(days=self._receipt_ttl_days)).isoformat()
        with self._session() as conn:
            return self._is_receipt_replayed_conn(
                conn, dhash_hex, bank, ref_code, cutoff_iso=cutoff_iso
            )

    @staticmethod
    def _expand_domain_candidates(domains: list[str]) -> list[str]:
        primary_exact_and_apex: list[str] = []
        intermediate_tiers: list[list[str]] = [
            [] for _ in range(max(0, MAX_DOMAIN_PARENT_LEVELS - 1))
        ]
        tail_window = MAX_DOMAIN_PARENT_LEVELS + 3
        for raw in domains:
            host = _canonical_domain_host(raw)
            if not host:
                continue
            primary_exact_and_apex.append(host)
            labels = [lbl for lbl in host.split(".") if lbl]
            tail = labels[-tail_window:]
            start_idx = 0 if len(labels) > len(tail) else 1
            valid_parents = [
                ".".join(tail[start:])
                for start in range(start_idx, len(tail) - 1)
                if ".".join(tail[start:]) not in _MULTI_PART_PUBLIC_SUFFIXES
            ]
            ordered_parents = list(reversed(valid_parents[-MAX_DOMAIN_PARENT_LEVELS:]))
            if ordered_parents:
                primary_exact_and_apex.append(ordered_parents[0])
                for tier_idx, parent in enumerate(ordered_parents[1:]):
                    intermediate_tiers[tier_idx].append(parent)
        candidates: list[str] = []
        seen: set[str] = set()
        for group in (primary_exact_and_apex, *intermediate_tiers):
            for item in group:
                if item not in seen:
                    seen.add(item)
                    candidates.append(item)
        return candidates

    def _bounded_lookup_hashes(self, iocs: ExtractedIOCs) -> list[str]:
        def _take_unique(ioc_type: str, values: Sequence[str], limit: int) -> list[str]:
            seen: set[str] = set()
            picked: list[str] = []
            for val in values:
                h = self._hash_ioc(ioc_type, val)
                if h not in seen:
                    seen.add(h)
                    picked.append(h)
                    if len(picked) >= limit:
                        break
            return picked

        domain_cands = self._expand_domain_candidates(iocs.domains)
        phones = _take_unique("phone", iocs.phones, MAX_LOOKUP_PHONE_HASHES)
        accounts = _take_unique("bank_account", iocs.bank_accounts, MAX_LOOKUP_ACCOUNT_HASHES)
        cross_hashes: list[str] = []
        cross_seen: set[str] = set()
        for acct in iocs.bank_accounts:
            norm_acct = normalize_ioc_value("bank_account", acct)
            if _VN_PHONE_SHAPE_RE.fullmatch(norm_acct):
                h = self._hash_ioc("phone", norm_acct)
                if h not in cross_seen:
                    cross_seen.add(h)
                    cross_hashes.append(h)
                    if len(cross_hashes) >= MAX_LOOKUP_CROSS_HASHES:
                        break
        if len(cross_hashes) < MAX_LOOKUP_CROSS_HASHES:
            for ph in iocs.phones:
                norm_ph = normalize_ioc_value("phone", ph)
                if norm_ph:
                    h = self._hash_ioc("bank_account", norm_ph)
                    if h not in cross_seen:
                        cross_seen.add(h)
                        cross_hashes.append(h)
                        if len(cross_hashes) >= MAX_LOOKUP_CROSS_HASHES:
                            break
        domains = _take_unique("domain", domain_cands, MAX_LOOKUP_DOMAIN_HASHES)
        return list(dict.fromkeys([*phones, *accounts, *cross_hashes, *domains]))[
            :MAX_LOOKUP_IOC_HASHES
        ]

    def count_ioc_hits(self, iocs: ExtractedIOCs) -> int:
        hashes = self._bounded_lookup_hashes(iocs)
        if not hashes:
            return 0
        total = 0
        with self._session() as conn:
            for chunk in _iter_chunks(hashes):
                placeholders = ",".join("?" for _ in chunk)
                sql = (
                    f"SELECT COALESCE(SUM(hit_count), 0) AS total "  # noqa: S608
                    f"FROM ioc_sightings WHERE ioc_hash IN ({placeholders})"
                )
                row = conn.execute(sql, tuple(chunk)).fetchone()
                total += int(row["total"]) if row else 0
        return total

    def match_active_block_rules(
        self,
        iocs: ExtractedIOCs,
        now: datetime | None = None,
    ) -> list[BlockRule]:
        hashes = self._bounded_lookup_hashes(iocs)
        if not hashes:
            return []
        now_iso = (now or datetime.now(UTC)).isoformat()
        matched: dict[str, BlockRule] = {}
        with self._session() as conn:
            for chunk in _iter_chunks(hashes):
                placeholders = ",".join("?" for _ in chunk)
                rows = conn.execute(
                    f"""
                    SELECT rule_id, ioc_type, masked_value, reason, created_at, expires_at
                    FROM block_rules
                    WHERE ioc_hash IN ({placeholders}) AND expires_at > ?
                    """,  # noqa: S608
                    (*chunk, now_iso),
                ).fetchall()
                for r in rows:
                    rid = str(r["rule_id"])
                    if rid not in matched:
                        matched[rid] = BlockRule(
                            rule_id=rid,
                            ioc_type=r["ioc_type"],
                            masked_value=str(r["masked_value"]),
                            reason=str(r["reason"]),
                            created_at=str(r["created_at"]),
                            expires_at=str(r["expires_at"]),
                            active=True,
                        )
        return list(matched.values())

    def find_campaign_titles_for_hashes(
        self,
        ioc_hashes: Sequence[str],
        limit: int = 2,
    ) -> list[str]:
        """Return matching campaign titles ordered by case_count DESC via indexed primary-hash lookup."""
        clean_hashes = list(dict.fromkeys(h.strip().lower() for h in ioc_hashes if h and h.strip()))
        if not clean_hashes or limit <= 0:
            return []
        matched: dict[str, tuple[int, str]] = {}
        with self._session() as conn:
            for chunk in _iter_chunks(clean_hashes):
                placeholders = ",".join("?" for _ in chunk)
                rows = conn.execute(
                    f"SELECT campaign_id, title_vi, case_count FROM campaigns "  # noqa: S608
                    f"WHERE primary_ioc_hash IN ({placeholders}) "
                    f"ORDER BY case_count DESC LIMIT ?",
                    (*chunk, limit),
                ).fetchall()
                for row in rows:
                    cid = str(row["campaign_id"])
                    cnt = int(row["case_count"])
                    title = str(row["title_vi"])
                    prev = matched.get(cid)
                    if prev is None or cnt > prev[0]:
                        matched[cid] = (cnt, title)
        ordered = sorted(matched.values(), key=lambda item: (-item[0], item[1]))
        return [title for _, title in ordered[:limit]]

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
            canonical = (
                _canonical_domain_host(raw_value)
                if ioc_type == "domain"
                else normalize_ioc_value(ioc_type, raw_value)
            )
            if not canonical:
                raise ValueError("Invalid or empty IOC value.")
            target_hash = self._hash_ioc(ioc_type, canonical)
            resolved_type: IocType = ioc_type
            resolved_mask = mask_ioc(ioc_type, canonical)
        elif ioc_hash and ioc_hash.strip():
            target_hash = ioc_hash.strip().lower()
            resolved_type = ioc_type
            resolved_mask = ""
        else:
            raise ValueError("Either raw_value or ioc_hash is required.")

        scrubbed_reason = scrub_persisted_pii(
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
            if self._is_protected_ioc_conn(
                conn,
                resolved_type,
                raw_value=raw_value if has_raw else None,
                ioc_hash=target_hash,
            ):
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
                if resolved_type != ioc_type and self._is_protected_ioc_conn(
                    conn, resolved_type, ioc_hash=target_hash
                ):
                    raise ProtectedDemoIocError(
                        "Tên miền hoặc tài khoản này thuộc danh sách chính thức được bảo vệ, "
                        "không thể thêm vào danh sách chặn."
                    )

            conn.execute(
                """
                INSERT INTO block_rules
                (rule_id, ioc_hash, ioc_type, masked_value, reason, created_at, expires_at, label_ver)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ioc_hash) DO UPDATE SET
                    rule_id = excluded.rule_id,
                    masked_value = excluded.masked_value,
                    reason = excluded.reason,
                    created_at = excluded.created_at,
                    expires_at = excluded.expires_at,
                    label_ver = excluded.label_ver
                """,
                (
                    rule_id,
                    target_hash,
                    resolved_type,
                    resolved_mask,
                    scrubbed_reason,
                    created_iso,
                    expires_iso,
                    CURRENT_RADAR_LABEL_VER,
                ),
            )
            persisted = conn.execute(
                "SELECT rule_id, ioc_type, masked_value, reason, created_at, expires_at "
                "FROM block_rules WHERE ioc_hash = ?",
                (target_hash,),
            ).fetchone()

        self._invalidate_radar_cache()
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
            revoked = bool(cur.rowcount and cur.rowcount > 0)
        self._invalidate_radar_cache()
        return revoked

    def reset_transient_rules(self) -> int:
        """Clear transient /radar block rules without erasing receipt-replay forensic history."""
        with self._session() as conn:
            cur = conn.execute("DELETE FROM block_rules")
            cleared = int(cur.rowcount or 0)
        self._invalidate_radar_cache()
        return cleared

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
        clean_detail = scrub_persisted_pii(detail.strip())[:300]
        clean_target = scrub_persisted_pii(masked_target) if masked_target else None
        clean_rule_id = sanitize_rule_id(rule_id)
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
                    clean_rule_id,
                    clean_detail,
                    ip_hash,
                ),
            )
            conn.execute(
                """
                DELETE FROM radar_audit_logs
                WHERE action != 'auth_failed'
                  AND audit_id NOT IN (
                    SELECT audit_id FROM radar_audit_logs
                    WHERE action != 'auth_failed'
                    ORDER BY created_at DESC LIMIT 200
                )
                """
            )
            conn.execute(
                """
                DELETE FROM radar_audit_logs
                WHERE action = 'auth_failed'
                  AND audit_id NOT IN (
                    SELECT audit_id FROM radar_audit_logs
                    WHERE action = 'auth_failed'
                    ORDER BY created_at DESC LIMIT 50
                )
                """
            )
        self._invalidate_radar_cache()
        return RadarAuditEvent(
            audit_id=audit_id,
            created_at=created_at,
            action=action,
            outcome=outcome,
            ioc_type=ioc_type,
            masked_target=clean_target,
            rule_id=clean_rule_id,
            detail=clean_detail,
        )

    def get_radar_graph(self, now: datetime | None = None) -> RadarGraphResponse:
        use_cache = now is None
        now_iso = (now or datetime.now(UTC)).isoformat()
        ver_before = 0
        if use_cache:
            with self._radar_cache_lock:
                ver_before = self._radar_cache_ver
                entry = self._radar_cache
                if entry is not None:
                    cached_mono, cached_ver, earliest_exp, cached_resp = entry
                    if (
                        cached_ver == ver_before
                        and (time.monotonic() - cached_mono) < RADAR_CACHE_TTL_SEC
                        and (earliest_exp is None or now_iso < earliest_exp)
                    ):
                        return cached_resp.model_copy(deep=True)

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
                """
                SELECT s.*
                FROM ioc_sightings s
                LEFT JOIN block_rules b ON b.ioc_hash = s.ioc_hash AND b.expires_at > ?
                ORDER BY
                    CASE WHEN b.rule_id IS NOT NULL THEN 1 ELSE 0 END DESC,
                    CASE
                        WHEN s.campaign_id IS NOT NULL
                          OR EXISTS (
                              SELECT 1 FROM campaigns c WHERE c.primary_ioc_hash = s.ioc_hash
                          )
                        THEN 1 ELSE 0
                    END DESC,
                    s.hit_count DESC
                LIMIT 60
                """,
                (now_iso,),
            ).fetchall()
            total_sightings_row = conn.execute(
                "SELECT COUNT(*) AS cnt, "
                "COALESCE(SUM(CASE WHEN is_demo = 1 THEN 1 ELSE 0 END), 0) AS demo_cnt "
                "FROM ioc_sightings"
            ).fetchone()
            edge_rows = conn.execute(
                """
                SELECT * FROM ioc_edges
                ORDER BY
                    CASE
                        WHEN relation = 'primary_ioc' THEN 0
                        WHEN relation = 'associated_ioc' THEN 1
                        ELSE 2
                    END ASC,
                    source_id ASC,
                    target_id ASC
                LIMIT 120
                """
            ).fetchall()
            case_cnt_row = conn.execute(
                "SELECT COUNT(*) AS c FROM cases WHERE contributes_to_radar = 1 AND is_demo = 0"
            ).fetchone()
            auth_fail_rows = conn.execute(
                """
                SELECT audit_id, created_at, action, outcome, ioc_type, masked_target, rule_id, detail
                FROM radar_audit_logs
                WHERE action = 'auth_failed'
                ORDER BY created_at DESC LIMIT 5
                """
            ).fetchall()
            admin_audit_rows = conn.execute(
                """
                SELECT audit_id, created_at, action, outcome, ioc_type, masked_target, rule_id, detail
                FROM radar_audit_logs
                WHERE action != 'auth_failed'
                ORDER BY created_at DESC LIMIT 20
                """
            ).fetchall()
            selected_auth = list(auth_fail_rows[:5])
            remaining_slots = max(0, 20 - len(selected_auth))
            audit_rows = sorted(
                [*selected_auth, *admin_audit_rows[:remaining_slots]],
                key=lambda row: str(row["created_at"]),
                reverse=True,
            )

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
                rule_id=sanitize_rule_id(str(a["rule_id"])) if a["rule_id"] else None,
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

        response = RadarGraphResponse(
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
        if use_cache:
            exp_list = [r.expires_at for r in active_rules if r.expires_at]
            next_earliest_exp: str | None = min(exp_list) if exp_list else None
            with self._radar_cache_lock:
                if self._radar_cache_ver == ver_before:
                    self._radar_cache = (
                        time.monotonic(),
                        ver_before,
                        next_earliest_exp,
                        response,
                    )
        return response.model_copy(deep=True) if use_cache else response
