"""Health check and 1-Click Demo scenario routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from app.schemas import DemoScenario

router = APIRouter(tags=["system"])


@router.get("/health")
async def get_health(request: Request) -> dict[str, Any]:
    pipeline = request.app.state.pipeline
    settings = request.app.state.settings
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.app_version,
        "onnx_classifier_loaded": pipeline.classifier.is_available,
        "gemini_configured": bool(settings.gemini_api_key.strip()),
        "playbooks_count": len(pipeline.kb.playbooks),
    }


@router.get("/demos", response_model=list[DemoScenario])
async def get_demos(request: Request) -> list[DemoScenario]:
    pipeline = request.app.state.pipeline
    demos: list[DemoScenario] = pipeline.list_demos()
    return demos
