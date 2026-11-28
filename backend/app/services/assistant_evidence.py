"""Upload guards & SSE runner for Phase-3 ephemeral supplementary evidence."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import logging
from collections.abc import AsyncIterator
from typing import Any, Final

from fastapi import HTTPException, UploadFile
from pydantic import BaseModel, ConfigDict, Field

from app.config import Settings
from app.core.security import InvalidMediaError, UploadTooLargeError, validate_upload_bytes
from app.schemas import AnalysisReport
from app.schemas.assistant import AssistantChatRequest, AssistantCitation
from app.services import assistant_guardrails as ag
from app.services.assistant_followups import generate_followup_suggestions
from app.services.assistant_rag import RetrievedChunk
from app.services.assistant_service import AssistantService
from app.services.assistant_stage import (
    DEFAULT_STAGE_MAX_ENTRIES,
    DEFAULT_STAGE_TTL_SECONDS,
    MAX_DRAFTS_PER_CASE,
    MAX_DRAFTS_PER_OWNER,
    EphemeralEvidenceStage,
    StagedEvidenceDraft,
)
from app.services.pipeline import AnalysisPipeline, MediaItem

logger = logging.getLogger(__name__)
EVIDENCE_STREAM_TOTAL_TIMEOUT_SEC: Final[float] = 60.0
PRIVATE_EVIDENCE_HEADERS: Final[dict[str, str]] = {
    "Cache-Control": "no-store", "Vary": "X-Case-Access-Token",
}
_LOCAL_PRIVACY_NOTE_VI: Final[str] = (
    "Bằng chứng bổ sung vừa được xử lý hoàn toàn cục bộ ở chế độ riêng tư (không gửi ảnh/ghi âm "
    "tới dịch vụ AI bên ngoài và chưa ghi vào cơ sở dữ liệu). Bạn có thể bấm nút lưu trên thẻ kết "
    "quả trong vòng 15 phút nếu cần lưu hồ sơ bổ sung & tải báo cáo PDF."
)
_REPLAY_NEUTRAL_NOTE_VI: Final[str] = (
    "Lưu ý về dấu hiệu trùng lặp: Ảnh biên lai hoặc mã giao dịch này trùng với dữ liệu đã được ghi "
    "nhận trước đó — bao gồm trường hợp bạn tải lại cùng bức ảnh từ hồ sơ ban đầu. Hãy kiểm tra "
    "trực tiếp biến động số dư thực tế trên ứng dụng ngân hàng hoặc loa Soundbox."
)

__all__ = [
    "DEFAULT_STAGE_MAX_ENTRIES", "DEFAULT_STAGE_TTL_SECONDS", "EVIDENCE_STREAM_TOTAL_TIMEOUT_SEC",
    "MAX_DRAFTS_PER_CASE", "MAX_DRAFTS_PER_OWNER", "PRIVATE_EVIDENCE_HEADERS",
    "EphemeralEvidenceStage", "PersistEvidenceRequest", "StagedEvidenceDraft",
    "build_local_evidence_explanation", "format_sse_frame", "parse_bool_form",
    "prepare_evidence_uploads", "stream_ephemeral_evidence",
]


class PersistEvidenceRequest(BaseModel):
    """Strict request payload for POST /api/v1/assistant/evidence/{draft_id}/persist."""

    model_config = ConfigDict(extra="forbid")
    case_id: str = Field(..., min_length=1, max_length=80)
    contribute_to_radar: bool = False


def format_sse_frame(event: str, data: dict[str, Any]) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def parse_bool_form(raw: str | bool) -> bool:
    return raw if isinstance(raw, bool) else raw.strip().lower() in ("1", "true", "yes", "on")


async def prepare_evidence_uploads(
    *, settings: Settings, raw_message: str, image: UploadFile | None, audio: UploadFile | None
) -> tuple[list[MediaItem], list[MediaItem]]:
    """Validate optional supplementary image/audio uploads and message synchronously."""
    if len(raw_message) > 1500:
        msg = "Nội dung câu hỏi vượt quá độ dài tối đa 1.500 ký tự."
        raise HTTPException(400, msg, headers=PRIVATE_EVIDENCE_HEADERS)
    if image is not None and audio is not None:
        msg = "Chỉ hỗ trợ đính kèm tối đa 1 hình ảnh hoặc 1 tệp ghi âm mỗi lượt."
        raise HTTPException(400, msg, headers=PRIVATE_EVIDENCE_HEADERS)
    img_items: list[MediaItem] = []
    aud_items: list[MediaItem] = []
    total_bytes = 0
    try:
        for upload, is_img, def_name, def_mime, target in (
            (image, True, "evidence.jpg", "image/jpeg", img_items),
            (audio, False, "evidence.wav", "audio/wav", aud_items),
        ):
            if upload is None:
                continue
            data = await upload.read(settings.max_upload_bytes + 1)
            total_bytes += len(data)
            if len(data) > settings.max_upload_bytes or total_bytes > settings.max_upload_bytes:
                raise UploadTooLargeError("Tệp đính kèm vượt quá dung lượng tối đa 10 MB.")
            mime = upload.content_type or def_mime
            await asyncio.to_thread(
                validate_upload_bytes, data, settings.max_upload_bytes,
                "image" if is_img else "audio", mime,
            )
            target.append((data, upload.filename or def_name, mime))
    except UploadTooLargeError as exc:
        raise HTTPException(413, str(exc), headers=PRIVATE_EVIDENCE_HEADERS) from exc
    except InvalidMediaError as exc:
        raise HTTPException(400, str(exc), headers=PRIVATE_EVIDENCE_HEADERS) from exc
    if not raw_message and not img_items and not aud_items:
        msg = "Vui lòng nhập nội dung hoặc đính kèm ít nhất một hình ảnh hay tệp ghi âm."
        raise HTTPException(400, msg, headers=PRIVATE_EVIDENCE_HEADERS)
    return img_items, aud_items


def build_local_evidence_explanation(
    report: AnalysisReport, rag_chunks: list[RetrievedChunk], *, message: str
) -> tuple[str, dict[str, str] | None, int, list[str]]:
    """Build deterministic local-only Vietnamese explanation with zero external LLM calls."""
    if ag.is_merchant_or_receipt_report(report):
        base_reply, notice = ag.build_tier0_deterministic_reply(report, rag_chunks)
        output_tier = 0
    else:
        base_reply = ag.build_degraded_rag_reply(report, rag_chunks, message=message)
        notice, output_tier = None, 1
    parts = [base_reply]
    highlights = [
        item for ev in report.evidence[:3]
        if (item := " ".join(ev.detail.split())[:180]) and item not in base_reply
        and not ag.check_policy_violations(item, rag_chunks=rag_chunks)
    ]
    if highlights:
        bullet_block = "\n".join(f"- {item}" for item in dict.fromkeys(highlights))
        parts.append(f"**Dấu hiệu nổi bật từ bằng chứng bổ sung:**\n{bullet_block}")
    if report.receipt_verification_status == "REPLAYED_RECEIPT":
        parts.append(_REPLAY_NEUTRAL_NOTE_VI)
    parts.append(_LOCAL_PRIVACY_NOTE_VI)
    full_reply = "\n\n".join(parts)
    followups = generate_followup_suggestions(
        report=report, current_message=message, reply_text=full_reply, rag_chunks=rag_chunks,
    )
    return full_reply, notice, output_tier, followups


async def stream_ephemeral_evidence(
    *, pipeline: AnalysisPipeline, service: AssistantService,
    evidence_stage: EphemeralEvidenceStage, parent_case_id: str, parent_report: AnalysisReport,
    parent_is_demo: bool, raw_msg: str, img_items: list[MediaItem], aud_items: list[MediaItem],
    allow_external: bool, owner_key: str | None = None, media_prevalidated: bool = False,
) -> AsyncIterator[str]:
    """Run ephemeral supplementary evidence pipeline & stream SSE under a bounded 60s timeout."""
    try:
        async with asyncio.timeout(EVIDENCE_STREAM_TOTAL_TIMEOUT_SEC):
            lbl = ("Đang phân tích bằng chứng bổ sung..." if allow_external
                   else "Đang phân tích bằng chứng bổ sung ở chế độ riêng tư cục bộ...")
            yield format_sse_frame("status", {"phase": "retrieving", "label": lbl})
            ephemeral_kwargs: dict[str, Any] = {
                "mode": parent_report.mode, "text": raw_msg,
                "image_items": img_items or None, "audio_items": aud_items or None,
                "allow_external_media_ai": allow_external, "is_demo": parent_is_demo,
            }
            if media_prevalidated:
                params = inspect.signature(pipeline.run_ephemeral).parameters
                if "media_prevalidated" in params or any(
                    p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()
                ):
                    ephemeral_kwargs["media_prevalidated"] = True
            bundle = await pipeline.run_ephemeral(**ephemeral_kwargs)
            draft = evidence_stage.stage(
                parent_case_id=parent_case_id, parent_is_demo=parent_is_demo,
                bundle=bundle, allow_external_media_ai=allow_external, owner_key=owner_key,
            )
            staged = bundle.staged_redacted_report
            yield format_sse_frame("evidence_report", {
                "draft_id": draft.draft_id, "can_contribute_radar": not parent_is_demo,
                "risk_score": staged.risk_score, "verdict": staged.verdict,
                "receipt_verification_status": staged.receipt_verification_status,
                "summary_vi": staged.summary_vi,
            })
            if not allow_external:
                rag_q = raw_msg or staged.summary_vi or "biên lai chuyển khoản dấu hiệu lừa đảo"
                q_emb = await asyncio.to_thread(service.classifier.encode_text, rag_q)
                hint = staged.matched_playbooks[0] if staged.matched_playbooks else None
                rag = service.retriever.search(rag_q, query_embedding=q_emb, scam_type_hint=hint, top_k=3)
                cit = AssistantCitation
                cits = [
                    cit(id="CASE", source_type="case", title=f"Bằng chứng ({staged.verdict})"),
                    *(cit(id=f"KB:{c.chunk_id}", source_type="kb", title=c.title) for c in rag.chunks),
                ]
                yield format_sse_frame("citation", {"items": [c.model_dump() for c in cits]})
                reply, notice, tier, fups = build_local_evidence_explanation(
                    staged, rag.chunks, message=raw_msg
                )
                if notice is not None:
                    yield format_sse_frame("safety_notice", notice)
                yield format_sse_frame("delta", {"text": reply})
                done_p = {"degraded_mode": False, "output_tier": tier, "suggested_followups": fups}
                yield format_sse_frame("done", done_p)
                return
            synth_msg = raw_msg or "Giải thích kết quả phân tích bằng chứng bổ sung và bước cần làm."
            synth_req = AssistantChatRequest(case_id=None, message=synth_msg[:1500], history=[])
            async with contextlib.aclosing(service.stream_chat(synth_req, report=staged)) as chat_iter:
                async for frame in chat_iter:
                    yield frame
    except asyncio.CancelledError:
        raise
    except TimeoutError:
        err = {"code": "STREAM_TIMEOUT", "message": "Quá thời gian xử lý bằng chứng. Thử lại sau."}
        yield format_sse_frame("error", err)
    except Exception:
        logger.exception("Unhandled error during supplementary evidence stream.")
        msg = "Không thể phân tích bằng chứng bổ sung lúc này. Vui lòng thử lại."
        yield format_sse_frame("error", {"code": "EVIDENCE_ANALYSIS_ERROR", "message": msg})
