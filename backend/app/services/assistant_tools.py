"""Controlled read-only, ref-only verification tools and pre-tool router for VeriShield Assistant."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
from collections.abc import AsyncIterator
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.config import Settings
from app.core.url_authority import extract_strict_ascii_host, has_disallowed_url_backslash
from app.db.repository import CaseRepository
from app.schemas import AnalysisReport, ExtractedIOCs, IocType
from app.schemas.assistant import AssistantCitation
from app.services import assistant_vault as av
from app.services.action_copilot import MERCHANT_HONESTY_BANNER
from app.services.assistant_rag import AssistantKnowledgeRetriever
from app.services.ioc_extractor import hash_ioc, mask_ioc, scrub_free_text_pii
from app.services.url_inspector import _is_official_domain, _load_brand_rules, inspect_url
from app.services.vietqr_parser import VALID_VIETQR_AMOUNT_RE, parse_qr_payload

logger = logging.getLogger(__name__)
MAX_PRE_TOOLS_PER_TURN, MAX_URL_CHECKS_PER_TURN = 3, 2
MAX_TOOL_OUTPUT_CHARS, URL_TOOL_TIMEOUT_SEC = 1800, 6.0
_IOC_DISC: Final[str] = "Không trùng danh sách chặn không đồng nghĩa giao dịch an toàn."
_REASON_DOM_RE: Final[re.Pattern[str]] = re.compile(r"Tên miền '([^']+)'")
_SAFE_MASK_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9*._-]{1,40}$")
_UNTRUSTED_SECS: Final[frozenset[str]] = frozenset({"ocr_excerpt", "signals", "summary"})
_LABELS: Final[dict[str, tuple[str, str, str]]] = {
    "check_url_safety": ("Đang kiểm tra link...", "Đã kiểm tra đường dẫn", "Đã chặn đường dẫn rủi ro"),
    "inspect_vietqr_payload": ("Đang kiểm tra VietQR...", "Đã xác minh VietQR", "Cảnh báo VietQR lạ"),
    "lookup_ioc_reputation": ("Đang đối chiếu IOC...", "Đã đối chiếu cảnh báo", "Trùng quy tắc chặn"),
}
class _StrictArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
class CheckUrlSafetyArgs(_StrictArgs):
    url_ref_id: str = Field(..., pattern=r"^URL_REF_\d+$")
class InspectVietQrArgs(_StrictArgs):
    vietqr_ref_id: str = Field(..., pattern=r"^VIETQR_REF_\d+$")
class LookupIocArgs(_StrictArgs):
    entity_ref_id: str = Field(..., pattern=r"^(?:PHONE|ACCT|URL)_REF_\d+$")
class GetCaseEvidenceDetailArgs(_StrictArgs):
    section: Literal["summary", "signals", "ocr_excerpt", "vietqr", "urls", "receipt"]
class SearchFraudKnowledgeArgs(_StrictArgs):
    query: str = Field(..., min_length=2, max_length=200)
    top_k: int = Field(default=3, ge=1, le=5)
_SCHEMAS: Final[dict[str, type[BaseModel]]] = {
    "check_url_safety": CheckUrlSafetyArgs, "inspect_vietqr_payload": InspectVietQrArgs,
    "lookup_ioc_reputation": LookupIocArgs, "get_case_evidence_detail": GetCaseEvidenceDetailArgs,
    "search_fraud_knowledge": SearchFraudKnowledgeArgs}
ALLOWED_ASSISTANT_TOOLS: Final[frozenset[str]] = frozenset(_SCHEMAS)
def _eg(text: str, *, off: bool = True, refs: bool = True, lim: int = MAX_TOOL_OUTPUT_CHARS) -> str:
    return av.sanitize_llm_egress_text(
        text, preserve_official_bare_domains=off, preserve_strict_vault_refs=refs)[:lim]
def _host(raw: str | None) -> str:
    return "" if (not raw or has_disallowed_url_backslash(raw)) else (extract_strict_ascii_host(raw) or "")
def _is_off(h: str) -> bool:
    asc = "" if (not h or has_disallowed_url_backslash(h)) else (
        extract_strict_ascii_host(h if "://" in h else f"https://{h}") or "")
    return bool(asc) and any(_is_official_domain(asc, b["official_domains"]) for b in _load_brand_rules())
def _ref(v: av.RequestEntityVault, rid: str, exp: av.VaultEntityType) -> av.VaultEntity | None:
    return ent if ((ent := v.get(rid)) is not None and ent.entity_type == exp) else None
def _mopt(t: IocType, val: str | None) -> str:
    s = (val or "").strip()
    return ("N/A" if not s else s if ("****" in s and _SAFE_MASK_RE.fullmatch(s)
            and sum(c.isdigit() for c in s) <= 6) else mask_ioc(t, s))
def _vnd(amt: str | None) -> str:
    h, *t = (amt or "").split(".", 1)
    g = f"{int(h):,}".replace(",", ".") if h.isdigit() else h
    return f"{g}.{t[0]} VND" if t else (f"{g} VND" if amt else "N/A")
def _idna_vars(h: str) -> list[str]:
    out = [h]
    for enc, dec in (("ascii", "idna"), ("idna", "ascii")):
        with contextlib.suppress(UnicodeError):
            out.append(h.encode(enc).decode(dec))
    return list(dict.fromkeys(x for x in out if x))
def _mask_reason_dom(m: re.Match[str]) -> str:
    dom = asc = re.sub(r"[\u3002\uff0e\uff61]", ".", m.group(1).strip()).rstrip(".")
    with contextlib.suppress(UnicodeError):
        asc = dom.encode("idna").decode("ascii")
    lbl = dom if (dom.isascii() and _is_off(asc.lower())) else mask_ioc("domain", asc.lower())
    return f"Tên miền '{lbl}'"
def _mask_report_domains(raw: str, rep: AnalysisReport) -> str:
    out = _REASON_DOM_RE.sub(_mask_reason_dom, raw)
    for h in sorted({v for u in rep.url_findings for d in (u.domain, u.normalized_ascii_domain)
                     if d for v in _idna_vars(d)}, key=len, reverse=True):
        out = re.sub(re.escape(h), _mopt("domain", h), out, flags=re.IGNORECASE)
    return out
async def _inspect_safe(raw_url: str, live: bool) -> Any | None:
    try:
        return await asyncio.wait_for(inspect_url(raw_url, enable_network=live), URL_TOOL_TIMEOUT_SEC)
    except Exception:
        with contextlib.suppress(Exception):
            return await inspect_url(raw_url, enable_network=False) if live else None
        return None
async def _run_url(a: CheckUrlSafetyArgs, v: av.RequestEntityVault, cfg: Settings) -> dict[str, Any]:
    if (ent := _ref(v, a.url_ref_id, "url")) is None:
        return {"ok": False, "error_code": "REF_NOT_IN_CURRENT_TURN"}
    if (f := await _inspect_safe(ent.raw_value, cfg.enable_live_network_checks)) is None:
        return {"ok": False, "error_code": "URL_INSPECT_ERROR"}
    bad_bs = has_disallowed_url_backslash(ent.raw_value) or has_disallowed_url_backslash(f.final_url or "")
    raw_h, fh = _host(ent.raw_value), _host(f.final_url)
    host = "" if bad_bs else (f.normalized_ascii_domain or f.domain or raw_h)
    md = ent.masked_preview if bad_bs else mask_ioc("domain", host or ent.raw_value)
    raw_hs = [u for h in (f.domain, f.normalized_ascii_domain, fh) if h and (bad_bs or not _is_off(h))
              for u in _idna_vars(h)]
    sigs: list[str] = []
    for r in f.reasons[:4]:
        r = _REASON_DOM_RE.sub(_mask_reason_dom, r)
        for h in raw_hs:
            r = re.sub(re.escape(h), md, r, flags=re.IGNORECASE)
        sigs += [sig] if (sig := _eg(r, lim=220)) else []
    is_off = (not bad_bs and not f.is_blocked_ssrf and bool(raw_h) and _is_off(raw_h)
              and _is_off(host) and (_is_off(fh) if f.final_url else True))
    fin_fb = f"url_{hash_ioc('domain', f.final_url)[:4]}***" if f.final_url else None
    return {
        "ok": True, "ref_id": a.url_ref_id, "masked_domain": md, "verdict_signals": sigs,
        "masked_final_domain": (mask_ioc("domain", fh) if fh else fin_fb) if f.final_url else None,
        "risk_points": f.risk_points, "ssrf_blocked": f.is_blocked_ssrf, "is_official_brand": is_off,
        "spoofed_brand": _eg(f.spoofed_brand, lim=60) if f.spoofed_brand else None}
def _run_vietqr(a: InspectVietQrArgs, v: av.RequestEntityVault, text: str) -> dict[str, Any]:
    if (ent := _ref(v, a.vietqr_ref_id, "vietqr")) is None:
        return {"ok": False, "error_code": "REF_NOT_IN_CURRENT_TURN"}
    info, evs = parse_qr_payload(ent.raw_value, accompanying_text=text)
    accts, raw_a = ([info.account_number] if info.account_number else None), (info.account_number or "")
    raw_n = scrub_free_text_pii(info.note, known_accounts=accts) if info.note else ""
    amt = info.amount.strip() if info.amount else None
    ok_amt = bool(amt and VALID_VIETQR_AMOUNT_RE.fullmatch(amt) and amt != raw_a.strip())
    return {
        "ok": True, "ref_id": a.vietqr_ref_id, "bank_bin": info.bank_bin, "bank_name": info.bank_name,
        "is_valid_crc": bool(info.crc_valid and info.tlv_valid and info.kind == "VALID_VIETQR"),
        "masked_account": mask_ioc("bank_account", raw_a) if raw_a else None,
        "amount": amt if ok_amt else None,
        "purpose_redacted": _eg(raw_n, off=False, lim=140) if raw_n else None,
        "anomalies": [_eg(scrub_free_text_pii(e.title, known_accounts=accts), lim=180) for e in evs[:4]]}
def _run_ioc(a: LookupIocArgs, v: av.RequestEntityVault, repo: CaseRepository) -> dict[str, Any]:
    rid = a.entity_ref_id
    exp: Literal["phone", "bank_account", "url"] = (
        "phone" if rid.startswith("PHONE_") else "bank_account" if rid.startswith("ACCT_") else "url")
    if (ent := _ref(v, rid, exp)) is None:
        return {"ok": False, "error_code": "REF_NOT_IN_CURRENT_TURN"}
    it: IocType = "domain" if exp == "url" else exp
    tgt = _host(ent.raw_value) if exp == "url" else ent.raw_value
    iocs = (ExtractedIOCs(phones=[tgt]) if exp == "phone" else ExtractedIOCs(bank_accounts=[tgt])
            if exp == "bank_account" else ExtractedIOCs(domains=[tgt] if tgt else []))
    cands = CaseRepository._expand_domain_candidates([tgt]) if (exp == "url" and tgt) else [tgt]
    hashes = {repo.hash_ioc_value(it, c) for c in cands if c}
    hits, rules = repo.count_ioc_hits(iocs), repo.match_active_block_rules(iocs)
    camps = repo.find_campaign_titles_for_hashes(list(hashes), limit=2) if (hits > 0 and hashes) else []
    msg = (f"Trùng quy tắc chặn ({rules[0].reason}); ghi nhận {hits} lượt cộng đồng." if rules
           else f"Ghi nhận {hits} lượt cảnh báo.{f' Chiến dịch: {', '.join(camps)}.' if camps else ''}"
           if hits > 0 else f"Chưa ghi nhận cảnh báo hay quy tắc chặn nội bộ. {_IOC_DISC}")
    return {
        "ok": True, "ref_id": rid, "entity_type": ent.entity_type,
        "masked_preview": ent.masked_preview if exp == "url" else mask_ioc(it, ent.raw_value),
        "known_sightings": hits, "is_blocked": bool(rules), "risk_summary": _eg(msg, lim=300)}
def _run_case(a: GetCaseEvidenceDetailArgs, rep: AnalysisReport | None) -> dict[str, Any]:
    if rep is None:
        return {"ok": False, "error_code": "NO_ACTIVE_CASE"}
    sec, rl, im, st = a.section, rep.receipt_logic, rep.image_forensics, rep.receipt_verification_status
    if sec == "summary":
        raw = _mask_report_domains(f"{rep.verdict} ({rep.risk_score}/100, {st}). {rep.summary_vi}", rep)
    elif sec == "signals":
        joined = " | ".join(f"{e.severity}: {e.title} — {e.detail}" for e in rep.evidence[:5])
        raw = _mask_report_domains(joined, rep) if joined else "Không có."
    elif sec == "ocr_excerpt":
        imgs = [x.ocr_text for x in (im, *rep.image_forensics_list) if x and x.ocr_text]
        raw = " ".join(dict.fromkeys(imgs)) or "Không có văn bản OCR."
    elif sec == "vietqr":
        vqr = [f"{v.kind}(crc={v.crc_valid}, bank={v.bank_name or 'N/A'}, "
               f"acct={_mopt('bank_account', v.account_number)})" for v in rep.vietqr_findings[:3]]
        raw = "; ".join(vqr) or "Không có VietQR."
    elif sec == "urls":
        urls = [f"{_mopt('domain', u.domain or u.url)}(risk={u.risk_points}, ssrf={u.is_blocked_ssrf})"
                for u in rep.url_findings[:3]]
        raw = "; ".join(urls) or "Không có URL."
    else:
        warn = rep.mode == "merchant" or rl is not None or st != "NOT_APPLICABLE"
        p = [f"status={st}", *([f"tamper={im.tamper_score}, editing_sw={im.editing_software_detected}"]
             if im else []), *([f"bank={rl.bank_detected or 'N/A'}, replayed={rl.is_replayed}"]
             if rl else []), *([MERCHANT_HONESTY_BANNER] if warn else [])]
        raw = ". ".join(p)
    clean = av.sanitize_untrusted_delimiters(raw, preserve_strict_vault_refs=False)
    return {"ok": True, "section": sec, "detail": _eg(clean, off=sec not in _UNTRUSTED_SECS, refs=False)}
async def execute_controlled_tool(
    tool_name: str, raw_args: dict[str, Any], *, vault: av.RequestEntityVault,
    report: AnalysisReport | None, repo: CaseRepository, retriever: AssistantKnowledgeRetriever,
    settings: Settings, accompanying_text: str = "",
) -> dict[str, Any]:
    """Validate allowlist + strict ref-only schema and execute read-only verification tool."""
    if tool_name not in ALLOWED_ASSISTANT_TOOLS:
        return {"ok": False, "error_code": "TOOL_NOT_ALLOWED"}
    try:
        p = _SCHEMAS[tool_name].model_validate(raw_args)
    except ValidationError:
        return {"ok": False, "error_code": "INVALID_TOOL_ARGS"}
    if isinstance(p, CheckUrlSafetyArgs):
        return await _run_url(p, vault, settings)
    if isinstance(p, InspectVietQrArgs):
        return _run_vietqr(p, vault, accompanying_text)
    if isinstance(p, LookupIocArgs):
        return _run_ioc(p, vault, repo)
    if isinstance(p, GetCaseEvidenceDetailArgs):
        return _run_case(p, report)
    assert isinstance(p, SearchFraudKnowledgeArgs)
    res = retriever.search(_eg(p.query, lim=200), top_k=p.top_k)
    items = [{"chunk_id": c.chunk_id, "title": _eg(c.title, lim=120), "excerpt": _eg(c.content, lim=240)}
             for c in res.chunks[: p.top_k]]
    return {"ok": True, "in_domain": res.in_domain, "items": items}
def format_tool_summary(tool_name: str, r: dict[str, Any]) -> str:
    """Format tool output as concise text passed through the unified egress chokepoint (<=1800 chars)."""
    if not r.get("ok"):
        return _eg(f"{tool_name}: lỗi ({r.get('error_code', 'ERROR')})")
    if tool_name == "check_url_safety":
        st = "CHẶN_SSRF" if r["ssrf_blocked"] else (
            "CHÍNH_THỨC" if r["is_official_brand"] else f"risk={r['risk_points']}/100")
        raw = f"{tool_name} {r['ref_id']} ({r['masked_domain']}): {st}. {'; '.join(r['verdict_signals'])}"
    elif tool_name == "inspect_vietqr_payload":
        raw = (f"{tool_name} {r['ref_id']}: crc={r['is_valid_crc']}, bank={r['bank_name'] or 'N/A'} "
               f"(BIN {r['bank_bin'] or 'N/A'}), stk={r['masked_account'] or 'N/A'}, "
               f"amount={_vnd(r.get('amount'))}. {'; '.join(r.get('anomalies') or [])}")
    elif tool_name == "lookup_ioc_reputation":
        raw = (f"{tool_name} {r['ref_id']} ({r['masked_preview']}): sightings={r['known_sightings']}, "
               f"blocked={r['is_blocked']}. {r['risk_summary']}")
    else:
        raw = (f"{tool_name} ({r['section']}): {r['detail']}" if tool_name == "get_case_evidence_detail"
               else " | ".join(f"{it['title']}: {it['excerpt']}" for it in r.get("items") or []))
    return _eg(raw.strip(), lim=MAX_TOOL_OUTPUT_CHARS)
async def iter_pre_tools_for_vault(
    *, vault: av.RequestEntityVault, report: AnalysisReport | None, repo: CaseRepository,
    retriever: AssistantKnowledgeRetriever, settings: Settings, accompanying_text: str = "",
    max_url_checks: int = MAX_URL_CHECKS_PER_TURN,
) -> AsyncIterator[tuple[dict[str, Any] | None, str | None, AssistantCitation | None]]:
    """Run budgeted pre-LLM verification tools over current turn's vault, streaming live tool_status."""
    plan, url_n, rem = list[tuple[str, dict[str, Any], str]](), 0, MAX_TOOL_OUTPUT_CHARS
    url_cap = max(0, max_url_checks)
    for it in vault.list_public_refs():
        if len(plan) >= MAX_PRE_TOOLS_PER_TURN:
            break
        rid, et = it["ref_id"], it["entity_type"]
        if et == "url" and url_n < url_cap:
            url_n, plan = url_n + 1, [*plan, ("check_url_safety", {"url_ref_id": rid}, rid)]
        elif et != "url":
            t, k = (("inspect_vietqr_payload", "vietqr_ref_id") if et == "vietqr"
                    else ("lookup_ioc_reputation", "entity_ref_id"))
            plan.append((t, {k: rid}, rid))
    for tname, raw_args, rid in plan:
        run_l, done_l, blk_l = _LABELS[tname]
        yield {"tool": tname, "state": "running", "label": run_l}, None, None
        try:
            res = await execute_controlled_tool(
                tname, raw_args, vault=vault, report=report, repo=repo,
                retriever=retriever, settings=settings, accompanying_text=accompanying_text)
        except Exception:
            logger.exception("Pre-tool %s failed unexpectedly.", tname)
            res = {"ok": False, "error_code": "TOOL_EXECUTION_ERROR"}
        vq_bad = tname == "inspect_vietqr_payload" and (
            not res.get("is_valid_crc") or bool(res.get("anomalies")))
        blk = (not res.get("ok")) or bool(res.get("ssrf_blocked")) or bool(res.get("is_blocked")) or vq_bad
        summary = format_tool_summary(tname, res)[:rem]
        rem, lbl = max(0, rem - len(summary)), (blk_l if blk else done_l)
        cit = AssistantCitation(id=f"TOOL:{tname}:{rid}", source_type="tool", title=lbl)
        yield {"tool": tname, "state": "blocked" if blk else "done", "label": lbl}, summary, cit
async def run_pre_tools_for_vault(
    *, vault: av.RequestEntityVault, report: AnalysisReport | None, repo: CaseRepository,
    retriever: AssistantKnowledgeRetriever, settings: Settings, accompanying_text: str = "",
    max_url_checks: int = MAX_URL_CHECKS_PER_TURN,
) -> tuple[list[dict[str, Any]], list[str], list[AssistantCitation]]:
    """Collect all pre-tool status events, bounded sanitized summaries, and tool citations."""
    ev, sm, ct = list[dict[str, Any]](), list[str](), list[AssistantCitation]()
    async for tev, s, cit in iter_pre_tools_for_vault(
        vault=vault, report=report, repo=repo, retriever=retriever, settings=settings,
        accompanying_text=accompanying_text, max_url_checks=max_url_checks):
        ev, sm, ct = ev + ([tev] if tev else []), sm + ([s] if s else []), ct + ([cit] if cit else [])
    return ev, sm, ct
