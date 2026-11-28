"""Context-aware follow-up suggestion generator with normalization & semantic deduplication."""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable, Sequence

from app.schemas import AnalysisReport
from app.schemas.assistant import AssistantHistoryTurn, AssistantQuickIntent
from app.services import assistant_followup_catalog as cat
from app.services import assistant_guardrails as ag
from app.services.assistant_rag import RetrievedChunk


def normalize_followup_text(text: str) -> str:
    """Normalize Vietnamese question text: NFC, lowercase, strip diacritics, punctuation & fillers."""
    if not text:
        return ""
    mapped = unicodedata.normalize("NFC", text).lower().replace("đ", "d")
    stripped = "".join(
        ch for ch in unicodedata.normalize("NFD", mapped) if unicodedata.category(ch) != "Mn"
    )
    cleaned = cat.PUNCT_RE.sub(" ", cat.MD_NOISE_RE.sub(" ", stripped))
    compact = cat.WS_RE.sub(" ", cleaned).strip()
    return cat.PREFIX_RE.sub("", compact).strip()


def extract_followup_intents(text: str) -> set[str]:
    """Identify canonical fraud/verification intent buckets expressed in a Vietnamese question."""
    norm = normalize_followup_text(text)
    return {intent for intent, pat in cat.INTENT_PATTERNS if pat.search(norm)} if norm else set()


def extract_semantic_concepts(text: str) -> set[str]:
    """Extract canonical domain concepts for paraphrase-aware semantic deduplication."""
    norm = normalize_followup_text(text)
    return {concept for concept, pat in cat.CONCEPT_RULES if pat.search(norm)} if norm else set()


def _content_tokens(norm_text: str) -> set[str]:
    return {tok for tok in norm_text.split() if len(tok) >= 2 and tok not in cat.STOPWORDS}


def is_duplicate_question(
    candidate: str,
    asked_texts: Sequence[str],
    *,
    candidate_intent: str | None = None,
    covered_intents: frozenset[str] = frozenset(),
) -> bool:
    """Return True if candidate matches any asked question exactly or semantically."""
    norm_cand = normalize_followup_text(candidate)
    if not norm_cand:
        return True
    cand_intents = extract_followup_intents(norm_cand)
    if candidate_intent:
        cand_intents.add(candidate_intent)
    if cand_intents & covered_intents:
        return True

    cand_concepts = extract_semantic_concepts(norm_cand)
    cand_tokens = _content_tokens(norm_cand)

    for asked in asked_texts:
        norm_asked = normalize_followup_text(asked)
        if not norm_asked:
            continue
        if norm_cand == norm_asked:
            return True
        if len(norm_cand) >= 12 and len(norm_asked) >= 12 and (
            norm_cand in norm_asked or norm_asked in norm_cand
        ):
            return True
        if cand_intents & extract_followup_intents(norm_asked):
            return True
        asked_concepts = extract_semantic_concepts(norm_asked)
        if cand_concepts and asked_concepts:
            shared_c = len(cand_concepts & asked_concepts)
            min_c = min(len(cand_concepts), len(asked_concepts))
            union_c = len(cand_concepts | asked_concepts)
            if shared_c >= 2 and (shared_c / min_c >= 0.65 or shared_c / union_c >= 0.50):
                return True
        asked_tokens = _content_tokens(norm_asked)
        if cand_tokens and asked_tokens:
            shared_t = len(cand_tokens & asked_tokens)
            min_t = min(len(cand_tokens), len(asked_tokens))
            union_t = len(cand_tokens | asked_tokens)
            if shared_t >= 3 and (shared_t / min_t >= 0.72 or shared_t / union_t >= 0.58):
                return True
    return False


def _profile_for_report(report: AnalysisReport | None) -> str:
    if ag.is_merchant_or_receipt_report(report):
        return "merchant"
    if report is None:
        return "general"
    return "high" if report.verdict in ("CRITICAL_SCAM", "HIGH_RISK") else "low"


def _dynamic_boosts(
    report: AnalysisReport | None,
    current_intents: set[str],
    rag_chunks: Sequence[RetrievedChunk],
    all_user_norm: str,
) -> tuple[dict[str, int], set[str]]:
    """Return (priority_boosts, explicitly_triggered_cross_profile_intents)."""
    boosts: dict[str, int] = {}
    triggered: set[str] = set()
    for cur in current_intents:
        for idx, nxt in enumerate(cat.NEXT_STEP_BOOSTS.get(cur, ())):
            boosts[nxt] = boosts.get(nxt, 0) + (24 - idx * 5)
    if report is not None:
        if report.url_findings:
            boosts["verify_domain_url"] = boosts.get("verify_domain_url", 0) + 22
            triggered.add("verify_domain_url")
        if report.vietqr_findings:
            boosts["verify_vietqr_bin"] = boosts.get("verify_vietqr_bin", 0) + 24
            triggered.add("verify_vietqr_bin")
        if report.in_active_call:
            boosts["active_call_handling"] = boosts.get("active_call_handling", 0) + 32
        if report.image_forensics or (report.receipt_logic and report.receipt_logic.is_receipt_candidate):
            boosts["explain_forensics"] = boosts.get("explain_forensics", 0) + 16
        pb_text = " ".join(report.matched_playbooks).lower()
        if any(k in pb_text for k in ("apk", "vneid", "evn", "tax", "biometric")):
            boosts["incident_apk_malware"] = boosts.get("incident_apk_malware", 0) + 18
    rag_ids = " ".join(c.chunk_id for c in rag_chunks).lower()
    if "cccd" in rag_ids or "cccd" in all_user_norm or "1414" in all_user_norm:
        boosts["incident_cccd_ekyc"] = boosts.get("incident_cccd_ekyc", 0) + 30
        triggered.add("incident_cccd_ekyc")
    if "zalo" in rag_ids or "hijack" in rag_ids or "zalo" in all_user_norm:
        boosts["incident_social_hijack"] = boosts.get("incident_social_hijack", 0) + 28
        triggered.add("incident_social_hijack")
    return boosts, triggered


def generate_followup_suggestions(
    *,
    report: AnalysisReport | None,
    current_message: str,
    history: Sequence[AssistantHistoryTurn] = (),
    reply_text: str = "",
    quick_intent: AssistantQuickIntent | None = None,
    rag_chunks: Sequence[RetrievedChunk] = (),
    extra_covered_intents: Iterable[str] = (),
    max_suggestions: int = 3,
) -> list[str]:
    """Generate 0..3 practical, context-aware, history-deduplicated follow-up questions."""
    _ = reply_text
    profile = _profile_for_report(report)
    asked_texts = [t.content for t in history if t.role == "user" and t.content.strip()]
    if current_message.strip():
        asked_texts.append(current_message)

    covered: set[str] = set(extra_covered_intents)
    if quick_intent and quick_intent in cat.QUICK_INTENT_MAP:
        covered.add(cat.QUICK_INTENT_MAP[quick_intent])
    for txt in asked_texts:
        covered.update(extract_followup_intents(txt))

    current_intents = extract_followup_intents(current_message)
    all_user_norm = " ".join(normalize_followup_text(t) for t in asked_texts)
    boosts, triggered = _dynamic_boosts(report, current_intents, rag_chunks, all_user_norm)

    scored: list[tuple[int, cat.FollowupItem]] = []
    for item in cat.CATALOG:
        in_profile = profile in item.profiles
        if not in_profile and item.intent not in triggered:
            continue
        boost = boosts.get(item.intent, 0)
        if item.intent == "active_call_handling" and not (report and report.in_active_call):
            continue
        has_forensics = bool(
            report
            and (
                report.image_forensics
                or (report.receipt_logic and report.receipt_logic.is_receipt_candidate)
            )
        )
        if item.intent == "explain_forensics" and not has_forensics:
            continue
        if is_duplicate_question(
            item.text, asked_texts, candidate_intent=item.intent, covered_intents=frozenset(covered)
        ):
            continue
        scored.append((item.base_priority + boost, item))

    scored.sort(key=lambda pair: pair[0], reverse=True)
    selected: list[str] = []
    selected_intents: set[str] = set()
    limit = max(0, min(3, max_suggestions))
    for _score, item in scored:
        if len(selected) >= limit:
            break
        if item.intent in selected_intents:
            continue
        if is_duplicate_question(
            item.text, selected, candidate_intent=item.intent, covered_intents=frozenset(selected_intents)
        ):
            continue
        selected.append(item.text)
        selected_intents.add(item.intent)
    return selected
