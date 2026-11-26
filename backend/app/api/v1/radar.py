"""Closed-loop Fintech Fraud Ops (/radar) graph, 1-click block rules, and demo reset."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request

from app.core.security import verify_secret
from app.db.repository import CaseRepository, ProtectedDemoIocError
from app.schemas import (
    BlockRule,
    CreateBlockRuleRequest,
    RadarGraphResponse,
    ResetBlockRulesRequest,
)

router = APIRouter(prefix="/radar", tags=["radar"])


@router.get("/graph", response_model=RadarGraphResponse)
async def get_radar_graph(request: Request) -> RadarGraphResponse:
    repo: CaseRepository = request.app.state.repo
    return repo.get_radar_graph()


@router.post("/block-rules", response_model=BlockRule)
async def post_block_rule(body: CreateBlockRuleRequest, request: Request) -> BlockRule:
    settings = request.app.state.settings
    if not verify_secret(body.analyst_pin, settings.analyst_pin):
        raise HTTPException(status_code=403, detail="Mã PIN chuyên viên không hợp lệ.")

    repo: CaseRepository = request.app.state.repo
    try:
        return repo.add_block_rule(
            ioc_type=body.ioc_type,
            reason=body.reason,
            raw_value=body.value,
            ioc_hash=body.ioc_hash,
            masked_value=body.masked_value,
            ttl_minutes=body.ttl_minutes,
        )
    except ProtectedDemoIocError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/block-rules/{rule_id}/revoke")
async def post_revoke_block_rule(
    rule_id: str,
    body: ResetBlockRulesRequest,
    request: Request,
) -> dict[str, Any]:
    settings = request.app.state.settings
    if not verify_secret(body.analyst_pin, settings.analyst_pin):
        raise HTTPException(status_code=403, detail="Mã PIN chuyên viên không hợp lệ.")

    repo: CaseRepository = request.app.state.repo
    revoked = repo.revoke_block_rule(rule_id)
    return {"ok": True, "rule_id": rule_id, "revoked": revoked}


@router.post("/block-rules/reset")
async def post_reset_block_rules(
    body: ResetBlockRulesRequest,
    request: Request,
) -> dict[str, Any]:
    settings = request.app.state.settings
    if not verify_secret(body.analyst_pin, settings.analyst_pin):
        raise HTTPException(status_code=403, detail="Mã PIN chuyên viên không hợp lệ.")

    repo: CaseRepository = request.app.state.repo
    cleared = repo.reset_transient_rules()
    return {"ok": True, "cleared_rules": cleared}
