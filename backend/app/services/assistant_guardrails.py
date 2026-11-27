"""3-tier pre-emission output safety gate and <think> stream filter for VeriShield Assistant."""

from __future__ import annotations

import re
import unicodedata

from app.schemas.analysis import AnalysisReport
from app.services import assistant_guardrail_patterns as gp
from app.services.assistant_guardrail_patterns import (
    MAX_TIER2_SENTENCE_CHARS,
    MERCHANT_BALANCE_WARNING_VI,
    OutputTier,
)
from app.services.assistant_rag import RetrievedChunk
from app.services.guardrails import normalize_guardrail_text
from app.services.knowledge_base import normalize_vi_search
from app.services.receipt_validator import build_trusted_merchant_summary as _merchant_summary

__all__ = [
    "MAX_TIER2_SENTENCE_CHARS", "MERCHANT_BALANCE_WARNING_VI", "OutputTier",
    "ThinkStreamFilter", "Tier2SentenceGate", "build_degraded_rag_reply",
    "build_tier0_deterministic_reply", "check_policy_violations",
    "classify_output_tier", "is_merchant_or_receipt_report", "validate_full_reply",
]


class ThinkStreamFilter:
    """Stateful chunk-boundary stripper for nested/attributed <think>...</think> blocks."""

    def __init__(self) -> None:
        self._buf, self._depth = "", 0

    def feed(self, chunk: str) -> str:
        self._buf, out = self._buf + chunk, []
        while self._buf:
            if (pos := self._buf.find("<")) != 0:
                out.append(self._buf[: None if pos == -1 else pos] if self._depth == 0 else "")
                self._buf = "" if pos == -1 else self._buf[pos:]
                if pos == -1:
                    break
            low = self._buf.lower()
            if (gt := low.find(">")) != -1 and (
                gp.THINK_OPEN_RE.fullmatch(tag := low[: gt + 1]) or gp.THINK_CLOSE_RE.fullmatch(tag)
            ):
                self._depth = self._depth + 1 if tag[1] != "/" else max(0, self._depth - 1)
                self._buf = self._buf[gt + 1 :]
                continue
            if gt == -1 and gp.PARTIAL_THINK_RE.fullmatch(low):
                break
            out.append("<" if self._depth == 0 else "")
            self._buf = self._buf[1:]
        return "".join(out)

    def flush(self) -> str:
        rem, self._buf, self._depth = (self._buf if self._depth == 0 else ""), "", 0
        return rem


def is_merchant_or_receipt_report(report: AnalysisReport | None) -> bool:
    """Return True if report belongs to merchant mode or carries receipt forensics."""
    return report is not None and (
        report.mode == "merchant" or str(report.receipt_verification_status) in gp.RECEIPT_STATUSES
        or (report.receipt_logic is not None and report.receipt_logic.is_receipt_candidate))


def classify_output_tier(
    *, message: str, report: AnalysisReport | None, turn_injection_detected: bool,
) -> OutputTier:
    """Route each turn to Tier 0 (deterministic), Tier 1 (buffered), or Tier 2 (sentence-gated)."""
    folded = normalize_vi_search(normalize_guardrail_text(message)[0])
    merchant, t0 = is_merchant_or_receipt_report(report), bool(gp.TIER0_RE.search(folded))
    return 0 if (merchant and not turn_injection_detected and t0) else (
        1 if (merchant or turn_injection_detected or t0 or gp.TIER1_RE.search(folded)
              or (report and (report.verdict == "SAFE" or report.prompt_injection_detected))) else 2)


def _extract_hotlines(text: str) -> set[str]:
    scan, out = gp.MD_EMPH_RE.sub("", unicodedata.normalize("NFKC", text)), set[str]()
    for m in gp.HOTLINE_RE.finditer(scan):
        raw = m.group(0)
        if not (gp.DATE_RE.match(raw) or gp.CURR_RE.match(scan[m.end() :])):
            d = re.sub(r"\D", "", raw)
            if d.startswith("84") and (len(d) in (11, 12) or (d.startswith("840") and len(d) == 13)):
                d = "0" + d[2 + d.startswith("840") :]
            if not d.startswith("02") or 10 <= len(d) <= 11:
                out.add(d)
    return out
def _is_negated(lp: str, *, allow_verify_words: bool = True, next_text: str = "") -> bool:
    seg = gp.PIVOT_RE.split(lp)[-1].strip()
    if not (negs := list(gp.NEG_TOK_RE.finditer(seg))):
        return False
    neg_tok, a = negs[-1].group(0), seg[negs[-1].end() :].split()
    if len(a) > 5 or not all(w in gp.NEG_BRIDGE for w in a):
        return False
    toks = [*a, *next_text.split()[:1]]
    if "phai" in toks and "xac" in toks and toks.index("phai") < toks.index("xac"):
        return False
    can_verify = allow_verify_words and neg_tok in gp.NEG_DECL_TOKS
    return can_verify or not any(w in gp.NEG_VERIFY_WORDS for w in toks)
def _handover_ok(fc: str, start: int, end: int) -> bool:
    return not (gp.NEG_BAL_RE.search(fc) and any(t in fc for t in gp.BAL_TARGETS)) and (
        bool(gp.BAL_COND_RE.search(fc[end:].split(",", 1)[0]))
        or (bool(gp.BAL_COND_RE.search(fc[:start])) and not gp.CAUSAL_RE.search(fc[:start])))
def _settle_ok(fc: str, m: re.Match[str]) -> bool:
    lp, ls, txt = fc[: m.start()], fc[m.end() :], m.group(0)
    slp, sls = gp.PIVOT_RE.split(lp)[-1].strip(), gp.PIVOT_RE.split(ls)[0].strip()
    lo_vic = bool(gp.SETTLE_VICTIM_LO_RE.search(slp))
    pre_ok = (txt.startswith("tien ") and not txt.startswith("tien da ")
              and lp.rstrip().endswith(gp.SETTLE_PRE_VERBS)
              and not gp.SETTLE_CUSTOMER_RE.search(slp)
              and (lo_vic or (not gp.SETTLE_PAST_ACTION_RE.search(slp)
                              and not gp.SETTLE_DONE_SUFFIX_RE.search(sls))))
    imp_ok = bool(gp.IMP_ASK_RE.search(slp) and not gp.CLAIM_SUBJ_RE.search(slp)
                  and gp.CLOSE_CHUA_RE.search(sls))
    return (_is_negated(lp, next_text=txt) or pre_ok or imp_ok
            or (bool(gp.GUIDE_TOPIC_RE.search(slp)) and "roi" not in sls.split()[:4])
            or (" chi " in f" {slp} " and (_handover_ok(fc, *m.span()) or bool(gp.PRE_BAL_RE.search(slp))))
            or (txt.startswith("da nhan") and bool(gp.FRAUD_LOSS_RE.search(slp))))
def _unsafe_act_ok(fc: str, m: re.Match[str]) -> bool:
    lp, seg = fc[: m.start()], gp.PIVOT_RE.split(fc[: m.start()])[-1].strip()
    return _is_negated(lp) or (not gp.ADVICE_MOD_RE.search(m.group(0)) and not gp.PRE_ADVICE_RE.search(seg)
                               and bool(gp.DESC_FRAME_RE.search(seg)))
def _norm_policy(s: str) -> str:
    return normalize_vi_search(re.sub(r"[()]", " ", re.sub(r"[*_`]", "", s)))
def _scan_policy_violations(nfc: str, rag_chunks: list[RetrievedChunk]) -> tuple[list[str], bool]:
    violations, neg_bal_hit = list[str](), False
    for fc in filter(None, map(_norm_policy, gp.CLAUSE_RE.split(nfc))):
        if any(not _settle_ok(fc, m) for m in gp.SETTLE_RE.finditer(fc)) or any(
            not _is_negated(fc[: m.start()], allow_verify_words=False)
            and not _handover_ok(fc, m.start(), m.end()) for m in gp.HANDOVER_RE.finditer(fc)
        ):
            violations.append("RECEIPT_SETTLEMENT_CLAIM")
        if any(not _is_negated(fc[: m.start()], allow_verify_words=False)
               for m in gp.ABS_SAFE_RE.finditer(fc)):
            violations.append("ABSOLUTE_SAFETY_CLAIM")
        if any(not _unsafe_act_ok(fc, m) for m in gp.UNSAFE_ACT_RE.finditer(fc)):
            violations.append("UNSAFE_ACTION_ADVICE")
        if gp.NEG_BAL_RE.search(fc) and any(t in fc for t in gp.BAL_TARGETS):
            neg_bal_hit, violations = True, [*violations, "UNSAFE_ACTION_ADVICE"]
    grounded = {"113"}.union(*(_extract_hotlines(f"{c.title} {c.content}") for c in rag_chunks))
    if any(num not in grounded for num in _extract_hotlines(nfc)):
        violations.append("UNGROUNDED_HOTLINE")
    return list(dict.fromkeys(violations)), neg_bal_hit
def check_policy_violations(
    text: str, *, rag_chunks: list[RetrievedChunk] | None = None,
) -> list[str]:
    """Pure non-recursive policy check (clause + hotline gates only, never invokes fallbacks)."""
    nfc, _ = normalize_guardrail_text(text)
    return _scan_policy_violations(nfc, list(rag_chunks or []))[0] if nfc.strip() else []
def _safe_frag(raw: str, rag_chunks: list[RetrievedChunk], max_chars: int = 180) -> str:
    clean = re.sub(r"\s+", " ", raw).strip()[:max_chars]
    return clean if (clean and not check_policy_violations(clean, rag_chunks=rag_chunks)) else ""
def _safe_merchant_summary(rep: AnalysisReport, chunks: list[RetrievedChunk]) -> str:
    raw = _merchant_summary(rep.summary_vi, rep.mode, rep.receipt_verification_status)
    return _safe_frag(raw, chunks, 320) or gp.MERCHANT_SAFE_FALLBACK_SUMMARY_VI
def build_tier0_deterministic_reply(
    report: AnalysisReport | None, rag_chunks: list[RetrievedChunk],
) -> tuple[str, dict[str, str]]:
    """Build 0-LLM deterministic merchant/receipt verdict with mandatory balance check."""
    lines = [f"**Cảnh báo xác minh biên lai:** {MERCHANT_BALANCE_WARNING_VI}"]
    if report is not None:
        raw_r = [*(report.receipt_logic.reasons[:2] if report.receipt_logic else []),
                 *(report.image_forensics.reasons[:2] if report.image_forensics else [])]
        safe_r = list(dict.fromkeys(sr for r in raw_r if (sr := _safe_frag(r, rag_chunks, 180))))
        st = report.receipt_verification_status
        lines.extend([
            f"- **Trạng thái hồ sơ:** `{report.verdict}` ({report.risk_score}/100) · `{st}`.",
            f"- **Đánh giá xác thực:** {_safe_merchant_summary(report, rag_chunks)}",
            *(f"- **Dấu hiệu kỹ thuật:** {r}" for r in safe_r)])
    lines.extend([gp.TIER0_ACTION_LINE_VI,
                  *([f"- **Tài liệu tham khảo:** {rag_chunks[0].title}."] if rag_chunks else [])])
    return "\n".join(lines), {"code": "MERCHANT_BALANCE_REQUIRED", "message": MERCHANT_BALANCE_WARNING_VI}
def build_degraded_rag_reply(
    report: AnalysisReport | None, rag_chunks: list[RetrievedChunk], *, message: str,
) -> str:
    """Build deterministic Vietnamese fallback grounded strictly in report + top RAG chunks."""
    _ = message
    lines, merchant = list[str](), is_merchant_or_receipt_report(report)
    if report is not None:
        if merchant:
            body = _safe_merchant_summary(report, rag_chunks)
        elif report.verdict == "SAFE":
            body = gp.DEGRADED_SAFE_BODY_VI
        else:
            safe_sum = _safe_frag(report.summary_vi, rag_chunks, max_chars=260)
            body = (f"{safe_sum or 'Hồ sơ cần thận trọng.'} Lưu ý: Kết quả không đảm bảo "
                    "an toàn tuyệt đối; hãy tự xác minh qua kênh chính thức.")
        steps = [s for x in report.actions.urgent_steps[:2] if (s := _safe_frag(x, rag_chunks, 220))]
        lines.extend([f"**Tóm tắt hồ sơ (`{report.verdict}`, {report.risk_score}/100):**", body])
        lines.extend(f"- {s}" for s in steps)
    if rag_chunks:
        lines.append("**Hướng dẫn xác minh & ứng phó từ kho tri thức:**")
        lines.extend(f"- **{c.title}:** {c.content}" for c in rag_chunks[:2])
    if merchant or not lines:
        lines.append(MERCHANT_BALANCE_WARNING_VI if merchant else gp.DEGRADED_GENERIC_TAIL_VI)
    return "\n".join(lines)
def _fallback_for(report: AnalysisReport | None, chunks: list[RetrievedChunk], merchant: bool) -> str:
    return (build_tier0_deterministic_reply(report, chunks)[0]
            if (merchant or is_merchant_or_receipt_report(report))
            else build_degraded_rag_reply(report, chunks, message=""))


def validate_full_reply(
    *, draft_text: str, report: AnalysisReport | None, rag_chunks: list[RetrievedChunk],
    require_balance_check: bool, require_epistemic_limit: bool,
) -> tuple[bool, list[str], str]:
    """Run 5-layer defense-in-depth validation and fail closed to deterministic safe fallback."""
    nfc, _ = normalize_guardrail_text(draft_text)
    if not nfc.strip():
        return False, ["EMPTY_REPLY"], _fallback_for(report, rag_chunks, require_balance_check)
    violations, neg_bal_hit = _scan_policy_violations(nfc, rag_chunks)
    folded = _norm_policy(nfc)
    if require_balance_check and (neg_bal_hit or not (
        any(v in folded for v in gp.CHECK_VERBS) and any(t in folded for t in gp.BAL_TARGETS)
    )):
        violations.append("MISSING_BALANCE_CHECK")
    if require_epistemic_limit and not any(c in folded for c in gp.EPISTEMIC_CUES):
        violations.append("MISSING_EPISTEMIC_LIMIT")
    deduped = list(dict.fromkeys(violations))
    return (False, deduped, _fallback_for(report, rag_chunks, require_balance_check)) if deduped else (
        True, [], nfc)


class Tier2SentenceGate:
    """Sentence-gated streaming validator that promotes long/sensitive sentences to Tier 1."""

    def __init__(self, *, report: AnalysisReport | None = None,
                 rag_chunks: list[RetrievedChunk] | None = None,
                 max_sentence_chars: int = MAX_TIER2_SENTENCE_CHARS) -> None:
        self._report, self._rag_chunks = report, list(rag_chunks or [])
        self._max_chars, self._buffer, self.emitted_prefix = max_sentence_chars, "", ""
        self.promoted_to_tier1, self.blocked, self.violation_codes = False, False, list[str]()

    @property
    def buffered_remainder(self) -> str:
        return self._buffer

    def feed(self, chunk: str) -> list[str]:
        if not chunk or self.blocked:
            return []
        self._buffer, emitted = self._buffer + chunk, list[str]()
        while not self.promoted_to_tier1 and (m := gp.BOUNDARY_RE.search(self._buffer)):
            cand, rest = self._buffer[: m.end()], self._buffer[m.end() :]
            if not cand.strip():
                self._buffer, emitted = rest, ([*emitted, cand] if self.emitted_prefix else emitted)
                self.emitted_prefix += cand if self.emitted_prefix else ""
                continue
            if gp.TIER2_ESC_RE.search(normalize_vi_search(cand)):
                self.promoted_to_tier1 = True
                return emitted
            ok, codes, _ = validate_full_reply(
                draft_text=self.emitted_prefix + cand, report=self._report,
                rag_chunks=self._rag_chunks, require_balance_check=False, require_epistemic_limit=False)
            if not ok:
                self.blocked, self.promoted_to_tier1, self.violation_codes = True, True, codes
                return emitted
            self.emitted_prefix, self._buffer, emitted = self.emitted_prefix + cand, rest, [*emitted, cand]
        self.promoted_to_tier1 = self.promoted_to_tier1 or len(self._buffer) > self._max_chars
        return emitted

    def finalize(self) -> tuple[bool, list[str], str, dict[str, str] | None]:
        full_text, req_bal = self.emitted_prefix + self._buffer, is_merchant_or_receipt_report(self._report)
        ok, codes, safe = validate_full_reply(
            draft_text=full_text, report=self._report,
            rag_chunks=self._rag_chunks, require_balance_check=req_bal, require_epistemic_limit=False)
        if self.blocked or not ok:
            self.blocked, self._buffer = True, ""
            self.violation_codes = list(dict.fromkeys([*self.violation_codes, *codes]))
            out = _fallback_for(self._report, self._rag_chunks, req_bal) if ok else safe
            c = "MERCHANT_BALANCE_REQUIRED" if req_bal else "FAIL_CLOSED_FALLBACK"
            msg = MERCHANT_BALANCE_WARNING_VI if req_bal else gp.FAIL_CLOSED_MSG_VI
            return False, self.violation_codes, out, {"code": c, "message": msg}
        rem, self.emitted_prefix, self._buffer = self._buffer, full_text, ""
        return True, [], rem, None
