"""Health check and 1-Click Demo scenario routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from app.db.repository import CaseRepository
from app.schemas import DemoScenario
from app.services.local_stt import is_local_stt_ready

router = APIRouter(tags=["system"])


@router.get("/health")
async def get_health(request: Request) -> dict[str, Any]:
    pipeline = request.app.state.pipeline
    settings = request.app.state.settings
    repo: CaseRepository = request.app.state.repo
    stt_ready = is_local_stt_ready(settings.enable_local_stt)
    ocr_orch = getattr(pipeline, "ocr_orchestrator", None)
    ocr_ready = (
        bool(ocr_orch.is_local_ready()) if ocr_orch is not None else settings.enable_local_ocr
    )
    raw_tg_url = settings.telegram_bot_url.strip()
    safe_tg_url = raw_tg_url if raw_tg_url.startswith("https://t.me/") else None
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.app_version,
        "sqlite_wal_ready": repo.is_wal_ready(),
        "onnx_classifier_loaded": pipeline.classifier.is_available,
        "local_ocr_enabled": settings.enable_local_ocr,
        "local_ocr_ready": ocr_ready,
        "ocr_provider": ocr_orch.primary_name if ocr_orch is not None else settings.ocr_provider,
        "local_stt_enabled": stt_ready,
        "local_stt_ready": stt_ready,
        "gemini_configured": bool(
            settings.gemini_api_key.strip() or settings.gemini_backup_api_key.strip()
        ),
        "llm_provider": settings.resolved_llm_provider,
        "llm_model": settings.gemini_model,
        "llm_base_url_configured": bool(settings.gemini_base_url.strip()),
        "telegram_bot_configured": bool(settings.telegram_bot_token.strip()),
        "telegram_bot_url": safe_tg_url,
        "playbooks_count": len(pipeline.kb.playbooks),
    }


@router.get("/demos", response_model=list[DemoScenario])
async def get_demos(request: Request) -> list[DemoScenario]:
    pipeline = request.app.state.pipeline
    demos: list[DemoScenario] = pipeline.list_demos()
    return demos
