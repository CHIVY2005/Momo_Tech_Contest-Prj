"""Telegram 1-Tap Forward Bot webhook endpoint."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request

from app.core.security import verify_secret
from app.services.telegram_bot import TelegramDeliveryError, handle_telegram_update

router = APIRouter(prefix="/bot", tags=["telegram"])


@router.post("/telegram")
async def post_telegram_webhook(
    update: dict[str, Any],
    request: Request,
    x_telegram_bot_api_secret_token: str | None = Header(default=None),
) -> dict[str, Any]:
    settings = request.app.state.settings
    if not verify_secret(x_telegram_bot_api_secret_token, settings.telegram_webhook_secret):
        raise HTTPException(status_code=403, detail="Invalid Telegram webhook secret token.")

    pipeline = request.app.state.pipeline
    try:
        return await handle_telegram_update(update=update, pipeline=pipeline, settings=settings)
    except TelegramDeliveryError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
