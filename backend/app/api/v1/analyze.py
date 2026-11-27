"""Synchronous and SSE streaming multimodal scam-analysis endpoints."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import StreamingResponse

from app.config import Settings
from app.core.case_tokens import issue_case_access_token
from app.core.security import InvalidMediaError, UploadTooLargeError, validate_upload_bytes
from app.schemas import AnalysisReport, AnalyzeMode
from app.services.pipeline import AnalysisPipeline, MediaItem, UnknownDemoError

logger = logging.getLogger(__name__)
router = APIRouter(tags=["analyze"])

MAX_ANALYZE_TEXT_CHARS = 8_000
MAX_ANALYZE_URL_CHARS = 2_048
MAX_EXPECTED_MERCHANT_ACCOUNT_CHARS = 64
SSE_STREAM_TIMEOUT_SEC = 120.0


def _sse_error_frame(code: str, message: str) -> str:
    payload = json.dumps({"code": code, "message": message}, ensure_ascii=False)
    return f"event: error\ndata: {payload}\n\n"


async def _read_bounded_upload(upload: UploadFile, max_bytes: int) -> bytes:
    # Read at most max_bytes + 1 so chunked uploads without Content-Length cannot OOM RAM
    data = await upload.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise UploadTooLargeError("Tệp tải lên vượt quá dung lượng tối đa 10 MB.")
    return data


def _parse_bool_form(raw: str | bool) -> bool:
    if isinstance(raw, bool):
        return raw
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _collect_uploads(
    single: UploadFile | None,
    plural: list[UploadFile] | None,
) -> list[UploadFile]:
    out: list[UploadFile] = []
    if single is not None:
        out.append(single)
    if plural:
        out.extend(plural)
    return out


async def _prepare_inputs(
    pipeline: AnalysisPipeline,
    settings: Settings,
    demo_id: str | None,
    text: str,
    url: str | None,
    image: UploadFile | None,
    audio: UploadFile | None,
    images: list[UploadFile] | None = None,
    audios: list[UploadFile] | None = None,
    expected_merchant_account: str | None = None,
) -> tuple[list[MediaItem], list[MediaItem]]:
    if len(text) > MAX_ANALYZE_TEXT_CHARS:
        msg = f"Nội dung văn bản vượt quá giới hạn tối đa {MAX_ANALYZE_TEXT_CHARS} ký tự."
        raise HTTPException(400, msg)
    if url is not None and len(url) > MAX_ANALYZE_URL_CHARS:
        raise HTTPException(400, f"Đường dẫn vượt quá giới hạn tối đa {MAX_ANALYZE_URL_CHARS} ký tự.")
    if expected_merchant_account and len(expected_merchant_account) > MAX_EXPECTED_MERCHANT_ACCOUNT_CHARS:
        msg = f"Số tài khoản cửa hàng vượt quá giới hạn tối đa {MAX_EXPECTED_MERCHANT_ACCOUNT_CHARS} ký tự."
        raise HTTPException(400, msg)

    has_demo = bool(demo_id and demo_id.strip())
    valid_demos = {d.demo_id for d in pipeline.list_demos()}
    if has_demo and demo_id is not None and demo_id.strip() not in valid_demos:
        raise HTTPException(404, "Không tìm thấy tình huống mẫu được yêu cầu.")

    raw_images, raw_audios = _collect_uploads(image, images), _collect_uploads(audio, audios)
    if len(raw_images) > settings.max_images_per_request:
        msg = f"Chỉ hỗ trợ tối đa {settings.max_images_per_request} hình ảnh mỗi lần kiểm tra."
        raise HTTPException(400, msg)
    if len(raw_audios) > settings.max_audios_per_request:
        msg = f"Chỉ hỗ trợ tối đa {settings.max_audios_per_request} tệp ghi âm mỗi lần kiểm tra."
        raise HTTPException(400, msg)

    img_items: list[MediaItem] = []
    aud_items: list[MediaItem] = []
    raw_img_buffers: list[MediaItem] = []
    raw_aud_buffers: list[MediaItem] = []
    total_bytes = 0
    total_limit = 2 * settings.max_upload_bytes

    try:
        for uploads, target, prefix, ext, mime_def in (
            (raw_images, raw_img_buffers, "upload", "jpg", "image/jpeg"),
            (raw_audios, raw_aud_buffers, "call", "wav", "audio/wav"),
        ):
            for idx, up in enumerate(uploads, start=1):
                data = await _read_bounded_upload(up, settings.max_upload_bytes)
                total_bytes += len(data)
                if total_bytes > total_limit:
                    raise UploadTooLargeError("Tổng dung lượng các tệp tải lên vượt quá 20 MB.")
                target.append(
                    (data, up.filename or f"{prefix}_{idx}.{ext}", up.content_type or mime_def)
                )

        for data, filename, declared_mime in raw_img_buffers:
            await asyncio.to_thread(
                validate_upload_bytes, data, max_bytes=settings.max_upload_bytes,
                kind="image", declared_mime=declared_mime,
            )
            img_items.append((data, filename, declared_mime))

        for data, filename, declared_mime in raw_aud_buffers:
            await asyncio.to_thread(
                validate_upload_bytes, data, max_bytes=settings.max_upload_bytes,
                kind="audio", declared_mime=declared_mime,
            )
            aud_items.append((data, filename, declared_mime))
    except UploadTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except InvalidMediaError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    has_any_input = (
        has_demo or bool(text.strip()) or bool(url and url.strip()) or bool(img_items) or bool(aud_items)
    )
    if not has_any_input:
        raise HTTPException(
            status_code=400,
            detail=(
                "Vui lòng nhập nội dung tin nhắn, đường dẫn hoặc tải lên ít nhất một hình ảnh hay "
                "tệp ghi âm để kiểm tra."
            ),
        )
    return img_items, aud_items


@router.post("/analyze", response_model=AnalysisReport)
async def post_analyze(
    request: Request,
    response: Response,
    mode: Annotated[AnalyzeMode, Form()] = "personal",
    text: Annotated[str, Form()] = "",
    url: Annotated[str | None, Form()] = None,
    demo_id: Annotated[str | None, Form()] = None,
    in_active_call: Annotated[str, Form()] = "false",
    is_simulation: Annotated[str, Form()] = "false",
    transfer_amount: Annotated[int | None, Form()] = None,
    expected_merchant_account: Annotated[str | None, Form()] = None,
    image: Annotated[UploadFile | None, File()] = None,
    audio: Annotated[UploadFile | None, File()] = None,
    images: Annotated[list[UploadFile] | None, File()] = None,
    audios: Annotated[list[UploadFile] | None, File()] = None,
) -> AnalysisReport:
    pipeline: AnalysisPipeline = request.app.state.pipeline
    settings: Settings = request.app.state.settings
    img_items, aud_items = await _prepare_inputs(
        pipeline, settings, demo_id, text, url, image, audio,
        images=images, audios=audios, expected_merchant_account=expected_merchant_account,
    )
    simulation_mode = _parse_bool_form(is_simulation)
    try:
        report = await pipeline.run(
            mode=mode, text=text, url=url,
            image_items=img_items or None, audio_items=aud_items or None,
            demo_id=demo_id, in_active_call=_parse_bool_form(in_active_call),
            is_simulation=simulation_mode, transfer_amount=transfer_amount,
            expected_merchant_account=expected_merchant_account,
            media_prevalidated=True,
        )
    except UnknownDemoError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if not simulation_mode:
        token, _expires_at = issue_case_access_token(
            report.case_id, request.app.state.case_token_secret
        )
        response.headers["X-Case-Access-Token"] = token
        response.headers["Cache-Control"] = "no-store"
    return report


@router.post("/analyze/stream")
async def post_analyze_stream(
    request: Request,
    mode: Annotated[AnalyzeMode, Form()] = "personal",
    text: Annotated[str, Form()] = "",
    url: Annotated[str | None, Form()] = None,
    demo_id: Annotated[str | None, Form()] = None,
    in_active_call: Annotated[str, Form()] = "false",
    is_simulation: Annotated[str, Form()] = "false",
    transfer_amount: Annotated[int | None, Form()] = None,
    expected_merchant_account: Annotated[str | None, Form()] = None,
    image: Annotated[UploadFile | None, File()] = None,
    audio: Annotated[UploadFile | None, File()] = None,
    images: Annotated[list[UploadFile] | None, File()] = None,
    audios: Annotated[list[UploadFile] | None, File()] = None,
) -> StreamingResponse:
    pipeline: AnalysisPipeline = request.app.state.pipeline
    settings: Settings = request.app.state.settings
    case_token_secret: str = request.app.state.case_token_secret
    img_items, aud_items = await _prepare_inputs(
        pipeline, settings, demo_id, text, url, image, audio,
        images=images, audios=audios, expected_merchant_account=expected_merchant_account,
    )
    active_call = _parse_bool_form(in_active_call)
    simulation_mode = _parse_bool_form(is_simulation)

    async def _sse_generator() -> AsyncIterator[str]:
        emitted_case_id: str | None = None
        stream_iter = pipeline.stream(
            mode=mode, text=text, url=url,
            image_items=img_items or None, audio_items=aud_items or None,
            demo_id=demo_id, in_active_call=active_call,
            is_simulation=simulation_mode, transfer_amount=transfer_amount,
            expected_merchant_account=expected_merchant_account,
            media_prevalidated=True,
        )
        try:
            async with asyncio.timeout(SSE_STREAM_TIMEOUT_SEC), contextlib.aclosing(stream_iter):
                async for ev in stream_iter:
                    payload = json.dumps(ev["data"], ensure_ascii=False)
                    yield f"event: {ev['event']}\ndata: {payload}\n\n"
                    if ev["event"] == "result" and isinstance(ev["data"], dict):
                        raw_cid = ev["data"].get("case_id")
                        if isinstance(raw_cid, str) and raw_cid.strip():
                            emitted_case_id = raw_cid.strip()
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            yield _sse_error_frame(
                "ANALYSIS_TIMEOUT",
                "Quá trình phân tích vượt quá thời gian cho phép. Vui lòng thử lại.",
            )
            return
        except Exception:
            logger.exception("Unhandled error during /analyze/stream SSE execution")
            yield _sse_error_frame(
                "ANALYSIS_ERROR",
                "Không thể hoàn tất phân tích lúc này. Vui lòng thử lại sau.",
            )
            return
        if not simulation_mode and emitted_case_id:
            token, expires_at = issue_case_access_token(emitted_case_id, case_token_secret)
            session_payload = json.dumps(
                {"case_id": emitted_case_id, "case_access_token": token, "expires_at": expires_at},
                ensure_ascii=False,
            )
            yield f"event: session\ndata: {session_payload}\n\n"

    return StreamingResponse(
        _sse_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-store, no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
