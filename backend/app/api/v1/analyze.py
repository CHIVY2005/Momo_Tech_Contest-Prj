"""Synchronous and SSE streaming multimodal scam-analysis endpoints."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse

from app.core.security import InvalidMediaError, UploadTooLargeError, validate_upload_bytes
from app.schemas import AnalysisReport, AnalyzeMode
from app.services.pipeline import AnalysisPipeline, UnknownDemoError

router = APIRouter(tags=["analyze"])


async def _read_bounded_upload(upload: UploadFile | None, max_bytes: int) -> bytes | None:
    if upload is None:
        return None
    # Read at most max_bytes + 1 so chunked uploads without Content-Length cannot OOM RAM
    data = await upload.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise UploadTooLargeError(
            f"Uploaded file '{upload.filename}' exceeds limit of {max_bytes} bytes."
        )
    return data


def _parse_bool_form(raw: str | bool) -> bool:
    if isinstance(raw, bool):
        return raw
    return raw.strip().lower() in ("1", "true", "yes", "on")


async def _prepare_inputs(
    pipeline: AnalysisPipeline,
    max_bytes: int,
    demo_id: str | None,
    image: UploadFile | None,
    audio: UploadFile | None,
) -> tuple[bytes | None, str, str, bytes | None, str, str]:
    if demo_id and demo_id.strip() and demo_id.strip() not in {d.demo_id for d in pipeline.list_demos()}:
        raise HTTPException(status_code=404, detail=f"Unknown demo_id: {demo_id}")

    try:
        img_bytes = await _read_bounded_upload(image, max_bytes)
        if img_bytes is not None:
            validate_upload_bytes(img_bytes, max_bytes=max_bytes, kind="image")

        aud_bytes = await _read_bounded_upload(audio, max_bytes)
        if aud_bytes is not None:
            validate_upload_bytes(aud_bytes, max_bytes=max_bytes, kind="audio")
    except UploadTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except InvalidMediaError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    img_name = (image.filename if image and image.filename else "upload.jpg")
    img_mime = (image.content_type if image and image.content_type else "image/jpeg")
    aud_name = (audio.filename if audio and audio.filename else "call.wav")
    aud_mime = (audio.content_type if audio and audio.content_type else "audio/wav")
    return img_bytes, img_name, img_mime, aud_bytes, aud_name, aud_mime


@router.post("/analyze", response_model=AnalysisReport)
async def post_analyze(
    request: Request,
    mode: Annotated[AnalyzeMode, Form()] = "personal",
    text: Annotated[str, Form()] = "",
    url: Annotated[str | None, Form()] = None,
    demo_id: Annotated[str | None, Form()] = None,
    in_active_call: Annotated[str, Form()] = "false",
    transfer_amount: Annotated[int | None, Form()] = None,
    expected_merchant_account: Annotated[str | None, Form()] = None,
    image: Annotated[UploadFile | None, File()] = None,
    audio: Annotated[UploadFile | None, File()] = None,
) -> AnalysisReport:
    pipeline: AnalysisPipeline = request.app.state.pipeline
    settings = request.app.state.settings
    img_bytes, img_name, img_mime, aud_bytes, aud_name, aud_mime = await _prepare_inputs(
        pipeline,
        settings.max_upload_bytes,
        demo_id,
        image,
        audio,
    )
    try:
        return await pipeline.run(
            mode=mode,
            text=text,
            url=url,
            image_bytes=img_bytes,
            image_filename=img_name,
            image_mime=img_mime,
            audio_bytes=aud_bytes,
            audio_filename=aud_name,
            audio_mime=aud_mime,
            demo_id=demo_id,
            in_active_call=_parse_bool_form(in_active_call),
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
    transfer_amount: Annotated[int | None, Form()] = None,
    expected_merchant_account: Annotated[str | None, Form()] = None,
    image: Annotated[UploadFile | None, File()] = None,
    audio: Annotated[UploadFile | None, File()] = None,
) -> StreamingResponse:
    pipeline: AnalysisPipeline = request.app.state.pipeline
    settings = request.app.state.settings
    img_bytes, img_name, img_mime, aud_bytes, aud_name, aud_mime = await _prepare_inputs(
        pipeline,
        settings.max_upload_bytes,
        demo_id,
        image,
        audio,
    )
    active_call = _parse_bool_form(in_active_call)

    async def _sse_generator() -> AsyncIterator[str]:
        async for ev in pipeline.stream(
            mode=mode,
            text=text,
            url=url,
            image_bytes=img_bytes,
            image_filename=img_name,
            image_mime=img_mime,
            audio_bytes=aud_bytes,
            audio_filename=aud_name,
            audio_mime=aud_mime,
            demo_id=demo_id,
            in_active_call=active_call,
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
