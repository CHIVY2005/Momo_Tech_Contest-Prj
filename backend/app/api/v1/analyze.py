"""Synchronous and SSE streaming multimodal scam-analysis endpoints."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse

from app.config import Settings
from app.core.security import InvalidMediaError, UploadTooLargeError, validate_upload_bytes
from app.schemas import AnalysisReport, AnalyzeMode
from app.services.pipeline import AnalysisPipeline, MediaItem, UnknownDemoError

router = APIRouter(tags=["analyze"])


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
) -> tuple[list[MediaItem], list[MediaItem]]:
    has_demo = bool(demo_id and demo_id.strip())
    valid_demos = {d.demo_id for d in pipeline.list_demos()}
    if has_demo and demo_id is not None and demo_id.strip() not in valid_demos:
        raise HTTPException(status_code=404, detail="Không tìm thấy tình huống mẫu được yêu cầu.")

    raw_images = _collect_uploads(image, images)
    raw_audios = _collect_uploads(audio, audios)

    if len(raw_images) > settings.max_images_per_request:
        raise HTTPException(
            status_code=400,
            detail=f"Chỉ hỗ trợ tối đa {settings.max_images_per_request} hình ảnh mỗi lần kiểm tra.",
        )
    if len(raw_audios) > settings.max_audios_per_request:
        raise HTTPException(
            status_code=400,
            detail=f"Chỉ hỗ trợ tối đa {settings.max_audios_per_request} tệp ghi âm mỗi lần kiểm tra.",
        )

    img_items: list[MediaItem] = []
    aud_items: list[MediaItem] = []
    raw_img_buffers: list[tuple[bytes, str, str]] = []
    raw_aud_buffers: list[tuple[bytes, str, str]] = []
    total_bytes = 0
    total_limit = 2 * settings.max_upload_bytes

    try:
        for idx, up in enumerate(raw_images, start=1):
            data = await _read_bounded_upload(up, settings.max_upload_bytes)
            total_bytes += len(data)
            if total_bytes > total_limit:
                raise UploadTooLargeError("Tổng dung lượng các tệp tải lên vượt quá 20 MB.")
            raw_img_buffers.append(
                (data, up.filename or f"upload_{idx}.jpg", up.content_type or "image/jpeg")
            )

        for idx, up in enumerate(raw_audios, start=1):
            data = await _read_bounded_upload(up, settings.max_upload_bytes)
            total_bytes += len(data)
            if total_bytes > total_limit:
                raise UploadTooLargeError("Tổng dung lượng các tệp tải lên vượt quá 20 MB.")
            raw_aud_buffers.append(
                (data, up.filename or f"call_{idx}.wav", up.content_type or "audio/wav")
            )

        for data, filename, declared_mime in raw_img_buffers:
            validate_upload_bytes(
                data,
                max_bytes=settings.max_upload_bytes,
                kind="image",
                declared_mime=declared_mime,
            )
            img_items.append((data, filename, declared_mime))

        for data, filename, declared_mime in raw_aud_buffers:
            validate_upload_bytes(
                data,
                max_bytes=settings.max_upload_bytes,
                kind="audio",
                declared_mime=declared_mime,
            )
            aud_items.append((data, filename, declared_mime))
    except UploadTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except InvalidMediaError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if (
        not has_demo
        and not text.strip()
        and not (url and url.strip())
        and not img_items
        and not aud_items
    ):
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
        pipeline,
        settings,
        demo_id,
        text,
        url,
        image,
        audio,
        images=images,
        audios=audios,
    )
    try:
        return await pipeline.run(
            mode=mode,
            text=text,
            url=url,
            image_items=img_items or None,
            audio_items=aud_items or None,
            demo_id=demo_id,
            in_active_call=_parse_bool_form(in_active_call),
            is_simulation=_parse_bool_form(is_simulation),
            transfer_amount=transfer_amount,
            expected_merchant_account=expected_merchant_account,
        )
    except UnknownDemoError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


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
    img_items, aud_items = await _prepare_inputs(
        pipeline,
        settings,
        demo_id,
        text,
        url,
        image,
        audio,
        images=images,
        audios=audios,
    )
    active_call = _parse_bool_form(in_active_call)
    simulation_mode = _parse_bool_form(is_simulation)

    async def _sse_generator() -> AsyncIterator[str]:
        async for ev in pipeline.stream(
            mode=mode,
            text=text,
            url=url,
            image_items=img_items or None,
            audio_items=aud_items or None,
            demo_id=demo_id,
            in_active_call=active_call,
            is_simulation=simulation_mode,
            transfer_amount=transfer_amount,
            expected_merchant_account=expected_merchant_account,
        ):
            payload = json.dumps(ev["data"], ensure_ascii=False)
            yield f"event: {ev['event']}\ndata: {payload}\n\n"

    return StreamingResponse(
        _sse_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
