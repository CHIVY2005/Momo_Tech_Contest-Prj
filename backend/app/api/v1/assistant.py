"""SSE streaming & Phase-3 ephemeral supplementary evidence endpoints for VeriShield Assistant."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Annotated, Any, Final

from fastapi import APIRouter, File, Form, Header, HTTPException, Request, Response, UploadFile
from fastapi.responses import StreamingResponse
from starlette.types import Receive, Scope, Send

from app.api.v1.cases import verify_web_case_access
from app.config import Settings
from app.core.case_tokens import generate_case_id, issue_case_access_token
from app.db.repository import CaseRepository
from app.schemas import AnalysisReport
from app.schemas.assistant import AssistantChatRequest
from app.services.assistant_evidence import (
    EVIDENCE_STREAM_TOTAL_TIMEOUT_SEC,
    PRIVATE_EVIDENCE_HEADERS,
    EphemeralEvidenceStage,
    PersistEvidenceRequest,
    parse_bool_form,
    prepare_evidence_uploads,
    stream_ephemeral_evidence,
)
from app.services.assistant_service import STREAM_TOTAL_TIMEOUT_SEC, AssistantService
from app.services.pipeline import AnalysisPipeline

router = APIRouter(tags=["assistant"])
_SSE_HEADERS: Final[dict[str, str]] = {
    "Cache-Control": "no-store, no-cache",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
    "Vary": "X-Case-Access-Token",
}


def _client_ip(request: Request) -> str:
    return str(request.client.host) if request.client else "local"


def _consume_task_result(task: asyncio.Task[Any]) -> None:
    if not task.cancelled():
        with contextlib.suppress(BaseException):
            task.exception()


async def _await_coro(aw: Awaitable[Any]) -> None:
    await aw


async def _cancel_and_drain(task: asyncio.Task[Any], grace_sec: float = 2.0) -> None:
    if not task.done():
        task.cancel()
    with contextlib.suppress(asyncio.CancelledError, Exception):
        await asyncio.wait_for(asyncio.shield(task), timeout=grace_sec)
    if not task.done():
        task.cancel()
        task.add_done_callback(_consume_task_result)


class _SlotGuardedStreamingResponse(StreamingResponse):
    """StreamingResponse guaranteeing outer timeout, async-generator close & idempotent release."""

    def __init__(
        self,
        content: AsyncIterator[str],
        *,
        on_finish: Callable[[], None],
        headers: dict[str, str] | None = None,
        media_type: str | None = None,
        outer_timeout_sec: float = STREAM_TOTAL_TIMEOUT_SEC + 10.0,
    ) -> None:
        super().__init__(content, headers=headers, media_type=media_type)
        self._on_finish = on_finish
        self._outer_timeout_sec = max(0.05, float(outer_timeout_sec))

    async def _aclose_body_iterator(self) -> None:
        aclose_fn = getattr(self.body_iterator, "aclose", None)
        if not callable(aclose_fn):
            return
        try:
            res = aclose_fn()
        except (RuntimeError, GeneratorExit):
            return
        if not inspect.isawaitable(res):
            return
        close_task = asyncio.create_task(_await_coro(res))
        try:
            await asyncio.wait_for(asyncio.shield(close_task), timeout=2.0)
        except (RuntimeError, GeneratorExit):
            return
        except TimeoutError:
            close_task.cancel()
            close_task.add_done_callback(_consume_task_result)
        except BaseException:
            if not close_task.done():
                close_task.cancel()
                close_task.add_done_callback(_consume_task_result)
            raise

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        stream_task = asyncio.create_task(super().__call__(scope, receive, send))
        try:
            try:
                await asyncio.wait_for(asyncio.shield(stream_task), timeout=self._outer_timeout_sec)
            except TimeoutError:
                await _cancel_and_drain(stream_task, grace_sec=2.0)
            except BaseException:
                if not stream_task.done():
                    await _cancel_and_drain(stream_task, grace_sec=2.0)
                raise
        finally:
            try:
                if stream_task.done():
                    await self._aclose_body_iterator()
            finally:
                self._on_finish()


def _guarded_sse_response(
    service: AssistantService,
    stream_iter: AsyncIterator[str],
    release_once: Callable[[], None],
    *,
    outer_timeout_sec: float = STREAM_TOTAL_TIMEOUT_SEC + 10.0,
) -> StreamingResponse:
    _ = service
    return _SlotGuardedStreamingResponse(
        stream_iter,
        on_finish=release_once,
        media_type="text/event-stream",
        headers=_SSE_HEADERS,
        outer_timeout_sec=outer_timeout_sec,
    )


@router.post("/assistant/chat/stream")
async def post_assistant_chat_stream(
    payload: AssistantChatRequest,
    request: Request,
    x_case_access_token: Annotated[str | None, Header(alias="X-Case-Access-Token")] = None,
) -> StreamingResponse:
    """Authenticate case access, enforce turn/concurrency caps, and stream grounded SSE chat."""
    service: AssistantService = request.app.state.assistant_service
    repo: CaseRepository = request.app.state.repo
    secret: str = request.app.state.case_token_secret

    case_id = payload.case_id.strip() if payload.case_id and payload.case_id.strip() else None
    report: AnalysisReport | None = None
    if case_id is not None:
        report = verify_web_case_access(case_id, x_case_access_token, repo, secret).report

    client_ip = _client_ip(request)
    release_slot = await service.acquire_stream_slot(
        authenticated=(case_id is not None),
        client_ip=client_ip,
    )
    try:
        service.check_and_reserve_case_turn(case_id)
        return _guarded_sse_response(
            service,
            service.stream_chat(payload, report=report),
            release_slot,
        )
    except BaseException:
        release_slot()
        raise


@router.post("/assistant/chat/evidence/stream")
async def post_assistant_evidence_stream(
    request: Request,
    case_id: Annotated[str, Form(...)],
    message: Annotated[str, Form()] = "",
    allow_external_media_ai: Annotated[str, Form()] = "false",
    image: Annotated[UploadFile | None, File()] = None,
    audio: Annotated[UploadFile | None, File()] = None,
    x_case_access_token: Annotated[str | None, Header(alias="X-Case-Access-Token")] = None,
) -> StreamingResponse:
    """Analyze supplementary evidence ephemerally (local-only by default, 0 DB writes)."""
    service: AssistantService = request.app.state.assistant_service
    pipeline: AnalysisPipeline = request.app.state.pipeline
    evidence_stage: EphemeralEvidenceStage = request.app.state.evidence_stage
    settings: Settings = request.app.state.settings
    repo: CaseRepository = request.app.state.repo
    secret: str = request.app.state.case_token_secret

    clean_case_id = case_id.strip()
    parent_record = verify_web_case_access(clean_case_id, x_case_access_token, repo, secret)
    raw_msg = message.strip()
    img_items, aud_items = await prepare_evidence_uploads(
        settings=settings, raw_message=raw_msg, image=image, audio=audio
    )
    allow_external = parse_bool_form(allow_external_media_ai)

    client_ip = _client_ip(request)
    release_slot = await service.acquire_stream_slot(
        authenticated=True,
        client_ip=client_ip,
    )
    try:
        service.check_and_reserve_case_turn(clean_case_id)
        ev_stream = stream_ephemeral_evidence(
            pipeline=pipeline,
            service=service,
            evidence_stage=evidence_stage,
            parent_case_id=clean_case_id,
            parent_report=parent_record.report,
            parent_is_demo=parent_record.is_demo,
            raw_msg=raw_msg,
            img_items=img_items,
            aud_items=aud_items,
            allow_external=allow_external,
            owner_key=client_ip,
            media_prevalidated=True,
        )
        return _guarded_sse_response(
            service,
            ev_stream,
            release_slot,
            outer_timeout_sec=EVIDENCE_STREAM_TOTAL_TIMEOUT_SEC + 10.0,
        )
    except BaseException:
        release_slot()
        raise


@router.post("/assistant/evidence/{draft_id}/persist")
async def post_assistant_evidence_persist(
    draft_id: str,
    payload: PersistEvidenceRequest,
    request: Request,
    response: Response,
    x_case_access_token: Annotated[str | None, Header(alias="X-Case-Access-Token")] = None,
) -> dict[str, Any]:
    """Atomically persist a staged supplementary draft and issue a dedicated child case token."""
    repo: CaseRepository = request.app.state.repo
    secret: str = request.app.state.case_token_secret
    evidence_stage: EphemeralEvidenceStage = request.app.state.evidence_stage

    clean_case_id = payload.case_id.strip()
    parent_record = verify_web_case_access(clean_case_id, x_case_access_token, repo, secret)
    draft = evidence_stage.pop_for_parent(draft_id, clean_case_id)
    if draft is None:
        raise HTTPException(
            status_code=404,
            detail="Bản phân tích tạm thời không tồn tại, đã hết hạn (15 phút) hoặc đã được lưu.",
            headers=PRIVATE_EVIDENCE_HEADERS,
        )

    is_demo_parent = parent_record.is_demo or draft.parent_is_demo
    effective_radar = False if is_demo_parent else bool(payload.contribute_to_radar)
    child_case_id = generate_case_id()
    repo.save_staged_report(
        draft.staged_redacted_report,
        child_case_id=child_case_id,
        parent_case_id=clean_case_id,
        prehashed_iocs=draft.prehashed_iocs,
        replay_fingerprints=draft.replay_fingerprints,
        contribute_to_radar=effective_radar,
        is_demo=is_demo_parent,
    )
    child_token, expires_at = issue_case_access_token(
        child_case_id, secret, parent_case_id=clean_case_id
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Vary"] = "X-Case-Access-Token"
    return {
        "child_case_id": child_case_id,
        "child_case_access_token": child_token,
        "expires_at": expires_at,
        "contributed_to_radar": effective_radar,
        "parent_case_id": clean_case_id,
    }
