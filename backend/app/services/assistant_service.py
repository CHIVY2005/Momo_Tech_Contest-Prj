"""Orchestration service for VeriShield AI Assistant ('Trợ lý VeriShield')."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
from collections import OrderedDict
from collections.abc import AsyncGenerator, Awaitable, Callable
from typing import Any, Final

from fastapi import HTTPException

from app.config import Settings
from app.db.repository import CaseRepository
from app.schemas import AnalysisReport
from app.schemas.assistant import AssistantChatRequest, AssistantCitation
from app.services import assistant_guardrails as ag
from app.services import assistant_slots as _slots
from app.services.assistant_context import build_assistant_prompt
from app.services.assistant_followups import generate_followup_suggestions
from app.services.assistant_llm import AssistantLlmUnavailableError, stream_assistant_llm
from app.services.assistant_rag import AssistantKnowledgeRetriever, RetrievedChunk
from app.services.assistant_tools import iter_pre_tools_for_vault
from app.services.assistant_vault import RequestEntityVault
from app.services.guardrails import detect_prompt_injection, normalize_guardrail_text
from app.services.knowledge_base import normalize_vi_search
from app.services.scam_classifier import ScamClassifier

logger = logging.getLogger(__name__)
MAX_CONCURRENT_STREAMS: Final[int] = _slots.MAX_CONCURRENT_STREAMS
SEMAPHORE_ACQUIRE_TIMEOUT_SEC: Final[float] = _slots.SEMAPHORE_ACQUIRE_TIMEOUT_SEC
MAX_TURNS_PER_CASE: Final[int] = 20
TURN_LRU_MAX_CASES: Final[int] = 1024
STREAM_TOTAL_TIMEOUT_SEC: Final[float] = 45.0
PROMPT_INJECTION_ONNX_THRESHOLD: Final[float] = 0.55
_NON_SCAM: Final[frozenset[str]] = frozenset({"LEGIT_NORMAL", "SAFE_ADVISORY", "PROMPT_INJECTION"})
_FORGED_HIST: Final[frozenset[str]] = frozenset(
    {"RECEIPT_SETTLEMENT_CLAIM", "ABSOLUTE_SAFETY_CLAIM", "UNSAFE_ACTION_ADVICE"}
)
_OOD_REFUSAL_VI: Final[str] = (
    "Trợ lý VeriShield chỉ chuyên hỗ trợ phòng chống lừa đảo trực tuyến, giải thích kết quả "
    "phân tích, hướng dẫn ứng phó sự cố tài chính và cách xác minh giao dịch, đường dẫn hoặc "
    "mã VietQR. Mình không hỗ trợ chủ đề ngoài phạm vi an toàn giao dịch này. "
    "Nếu bạn nghi ngờ tin nhắn, cuộc gọi, biên lai hoặc đường dẫn lạ, hãy chia sẻ để mình hỗ trợ nhé."
)
_EPISTEMIC_ASK_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:\ban toan\b.{0,25}\b(?:khong|chua)\b|(?:co (?:nen|the) )?(?:chuyen|nop) (?:tien|khoan)"
    r"|(?:co )?(?:tin duoc|uy tin|dam bao|that) khong|chac chan an toan)"
)
_MERCHANT_NOTICE: Final[dict[str, str]] = {
    "code": "MERCHANT_BALANCE_REQUIRED", "message": ag.MERCHANT_BALANCE_WARNING_VI,
}
ToolRunner = Callable[
    [AssistantChatRequest, RequestEntityVault, AnalysisReport | None],
    Awaitable[tuple[list[dict[str, Any]], list[str], list[AssistantCitation]]],
]
def _has_indirect_or_forged_injection(req: AssistantChatRequest, rep: AnalysisReport | None) -> bool:
    for turn in req.history:
        if detect_prompt_injection(*normalize_guardrail_text(turn.content))[0]:
            return True
        if turn.role == "assistant":
            _, codes, _ = ag.validate_full_reply(
                draft_text=turn.content, report=None, rag_chunks=[],
                require_balance_check=False, require_epistemic_limit=False,
            )
            if any(c in _FORGED_HIST for c in codes):
                return True
    if rep is None:
        return False
    texts = [
        *(im.ocr_text for im in (rep.image_forensics, *rep.image_forensics_list) if im),
        *(ev.detail for ev in rep.evidence[:6]),
        *(ev.snippet for ev in rep.evidence[:6] if ev.snippet),
        *rep.manipulation_tactics[:4], *([rep.transcript] if rep.transcript else []),
    ]
    return any(t and detect_prompt_injection(*normalize_guardrail_text(t))[0] for t in texts)
def _sse(event: str, data: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
def _done(degraded: bool, tier: int, followups: list[str]) -> str:
    return _sse("done", {"degraded_mode": degraded, "output_tier": tier, "suggested_followups": followups})
def _rate_headers(retry_after: str) -> dict[str, str]:
    return {"Retry-After": retry_after, "Cache-Control": "no-store", "Vary": "X-Case-Access-Token"}
def _build_citations(
    report: AnalysisReport | None, chunks: list[RetrievedChunk], tool_cits: list[AssistantCitation]
) -> list[dict[str, Any]]:
    cit = AssistantCitation
    case_c = [cit(id="CASE", source_type="case", title=f"Hồ sơ ({report.verdict})")] if report else []
    kb_c = [cit(id=f"KB:{c.chunk_id}", source_type="kb", title=c.title) for c in chunks]
    return [item.model_dump() for item in (*case_c, *kb_c, *tool_cits)]

class AssistantService:
    """Context-aware fraud assistant reusing the pipeline's single ONNX classifier session."""
    def __init__(
        self, settings: Settings, repo: CaseRepository,
        retriever: AssistantKnowledgeRetriever, classifier: ScamClassifier,
    ) -> None:
        self.settings, self.repo, self.retriever, self.classifier = settings, repo, retriever, classifier
        self._slots = _slots.AssistantSlotManager()
        self._semaphore, self._case_turns = self._slots.global_semaphore, OrderedDict[str, int]()
    def check_and_reserve_case_turn(self, case_id: str | None) -> None:
        if not case_id:
            return
        if (count := self._case_turns.get(case_id, 0)) >= MAX_TURNS_PER_CASE:
            self._case_turns.move_to_end(case_id)
            raise HTTPException(429, "Hồ sơ đã đạt giới hạn 20 lượt.", headers=_rate_headers("60"))
        if case_id not in self._case_turns and len(self._case_turns) >= TURN_LRU_MAX_CASES:
            self._case_turns.popitem(last=False)
        self._case_turns[case_id] = count + 1
        self._case_turns.move_to_end(case_id)
    async def acquire_stream_slot(
        self, *, authenticated: bool = True, client_ip: str | None = None
    ) -> Callable[[], None]:
        return await self._slots.acquire(authenticated=authenticated, client_ip=client_ip)
    def release_stream_slot(self) -> None:
        self._semaphore.release()
    async def stream_chat(
        self, request: AssistantChatRequest, *, report: AnalysisReport | None,
        tool_runner: ToolRunner | None = None,
    ) -> AsyncGenerator[str, None]:
        try:
            inner = self._stream_chat_inner(request, report=report, tool_runner=tool_runner)
            async with contextlib.aclosing(inner):
                async for frame in inner:
                    yield frame
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            yield _sse("error", {"code": "STREAM_TIMEOUT", "message": "Hết thời gian xử lý. Thử lại sau."})
        except Exception:
            logger.exception("Unhandled error during assistant SSE stream.")
            err = {"code": "ASSISTANT_ERROR", "message": "Trợ lý gặp sự cố tạm thời. Vui lòng thử lại sau."}
            yield _sse("error", err)
    async def _stream_chat_inner(
        self, request: AssistantChatRequest, *, report: AnalysisReport | None,
        tool_runner: ToolRunner | None,
    ) -> AsyncGenerator[str, None]:
        deadline, req_msg = asyncio.get_running_loop().time() + STREAM_TOTAL_TIMEOUT_SEC, request.message
        safe_msg, vault = RequestEntityVault.extract_from_message(req_msg)
        async with asyncio.timeout_at(deadline):
            clf, q_emb = await asyncio.to_thread(self.classifier.predict_and_encode, safe_msg)
        norm_msg, had_invis = normalize_guardrail_text(req_msg)
        heur_inj = detect_prompt_injection(norm_msg, had_invisible=had_invis)[0]
        onnx_inj = bool(clf.available and clf.injection_probability >= PROMPT_INJECTION_ONNX_THRESHOLD)
        turn_inj = heur_inj or onnx_inj or _has_indirect_or_forged_injection(request, report)
        is_merchant = ag.is_merchant_or_receipt_report(report)
        hint = (
            report.matched_playbooks[0] if (report and report.matched_playbooks)
            else "merchant" if is_merchant
            else clf.predicted_label if (clf.available and clf.predicted_label not in _NON_SCAM) else None
        )
        rag_query, rag_emb = safe_msg, q_emb
        if report is not None and len(safe_msg.strip()) < 35:
            ctx_hint = (
                ["biên lai chuyển khoản người bán kiểm tra số dư"] if is_merchant
                else ["dấu hiệu lừa đảo"] if report.verdict in ("HIGH_RISK", "CRITICAL_SCAM") else []
            )
            if extra := [*report.matched_playbooks[:2], *ctx_hint]:
                rag_query = f"{safe_msg} {' '.join(extra)}".strip()
                async with asyncio.timeout_at(deadline):
                    rag_emb = await asyncio.to_thread(self.classifier.encode_text, rag_query)
        rag = self.retriever.search(rag_query, query_embedding=rag_emb, scam_type_hint=hint, top_k=4)
        yield _sse("status", {"phase": "retrieving", "label": "Đang đối chiếu hồ sơ và kho tri thức..."})

        def _fups(reply_text: str, extra: tuple[str, ...] = ()) -> list[str]:
            return generate_followup_suggestions(
                report=report, current_message=req_msg, history=request.history,
                reply_text=reply_text, quick_intent=request.quick_intent,
                rag_chunks=rag.chunks, extra_covered_intents=extra,
            )

        if report is None and not rag.in_domain and not vault.list_public_refs():
            yield _sse("delta", {"text": _OOD_REFUSAL_VI})
            yield _done(False, 0, _fups(_OOD_REFUSAL_VI))
            return
        tool_summaries, tool_cits = None, list[AssistantCitation]()
        if tool_runner is not None:
            async with asyncio.timeout_at(deadline):
                t_events, tool_summaries, tool_cits = await tool_runner(request, vault, report)
            for tev in t_events:
                yield _sse("tool_status", tev)
        elif vault.list_public_refs():
            lbl = "Đang xác minh thực thể bằng công cụ an toàn..."
            yield _sse("status", {"phase": "verifying", "label": lbl})
            tool_summaries = []
            async with asyncio.timeout_at(deadline):
                async for pre_ev, summary, cit in iter_pre_tools_for_vault(
                    vault=vault, report=report, repo=self.repo, retriever=self.retriever,
                    settings=self.settings, accompanying_text=req_msg,
                    max_url_checks=1 if report is None else 2,
                ):
                    if pre_ev is not None:
                        yield _sse("tool_status", pre_ev)
                    tool_summaries += [summary] if summary else []
                    tool_cits += [cit] if cit is not None else []
        yield _sse("citation", {"items": _build_citations(report, rag.chunks, tool_cits)})

        tier = ag.classify_output_tier(message=req_msg, report=report, turn_injection_detected=turn_inj)
        if tier == 0:
            reply_text, notice = ag.build_tier0_deterministic_reply(report, rag.chunks)
            yield _sse("safety_notice", notice)
            yield _sse("delta", {"text": reply_text})
            yield _done(False, 0, _fups(reply_text, extra=("merchant_handover",)))
            return
        sys_inst, prompt = build_assistant_prompt(
            message=safe_msg, vault=vault, report=report, rag_chunks=rag.chunks,
            history=request.history, quick_intent=request.quick_intent, tool_summaries=tool_summaries,
        )
        llm_stream = stream_assistant_llm(self.settings, system_instruction=sys_inst, user_prompt=prompt)
        if tier == 1:
            asked_ep = not is_merchant and bool(_EPISTEMIC_ASK_RE.search(normalize_vi_search(norm_msg)))
            req_ep = bool((report and report.verdict == "SAFE") or asked_ep)
            yield _sse("status", {"phase": "thinking", "label": "Đang tổng hợp và kiểm duyệt phản hồi..."})
            pieces: list[str] = []
            try:
                async with asyncio.timeout_at(deadline), contextlib.aclosing(llm_stream):
                    async for piece in llm_stream:
                        pieces.append(piece)
            except (AssistantLlmUnavailableError, TimeoutError):
                yield _sse("status", {"phase": "fallback", "label": "Đang dùng hướng dẫn dự phòng..."})
                if is_merchant:
                    yield _sse("safety_notice", _MERCHANT_NOTICE)
                fb = ag.build_degraded_rag_reply(report, rag.chunks, message=req_msg)
                yield _sse("delta", {"text": fb})
                yield _done(True, 1, _fups(fb))
                return
            ok, _codes, safe_text = ag.validate_full_reply(
                draft_text="".join(pieces), report=report, rag_chunks=rag.chunks,
                require_balance_check=is_merchant, require_epistemic_limit=req_ep,
            )
            if not ok:
                msg = (
                    f"Đã chuyển sang hướng dẫn an toàn. {ag.MERCHANT_BALANCE_WARNING_VI}"
                    if is_merchant else "Phản hồi đã được kiểm duyệt và thay bằng hướng dẫn an toàn."
                )
                yield _sse("safety_notice", {"code": "FAIL_CLOSED_FALLBACK", "message": msg})
            elif is_merchant:
                yield _sse("safety_notice", _MERCHANT_NOTICE)
            yield _sse("delta", {"text": safe_text})
            yield _done(not ok, 1, _fups(safe_text))
            return
        yield _sse("status", {"phase": "thinking", "label": "Đang phân tích và đối chiếu dữ liệu..."})
        gate, emitted = ag.Tier2SentenceGate(report=report, rag_chunks=rag.chunks), False
        try:
            async with asyncio.timeout_at(deadline), contextlib.aclosing(llm_stream):
                async for piece in llm_stream:
                    for approved in gate.feed(piece):
                        emitted = True
                        yield _sse("delta", {"text": approved})
                    if gate.blocked:
                        break
        except (AssistantLlmUnavailableError, TimeoutError):
            yield _sse("status", {"phase": "fallback", "label": "Đang dùng kho tri thức cục bộ..."})
            fb_reply = gate.emitted_prefix
            if not emitted:
                fb_reply = ag.build_degraded_rag_reply(report, rag.chunks, message=req_msg)
                yield _sse("delta", {"text": fb_reply})
            yield _done(True, 2, _fups(fb_reply))
            return
        ok, _codes, tail, t2_notice = gate.finalize()
        if not ok and t2_notice is not None:
            yield _sse("safety_notice", t2_notice)
        if tail:
            yield _sse("delta", {"text": f"\n\n{tail}" if (not ok and emitted) else tail})
        yield _done(not ok, 2, _fups(f"{gate.emitted_prefix}{tail}"))
