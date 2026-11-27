"""Closed-loop Fintech Fraud Ops (/radar) graph, block rules, audit logs, and demo reset."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from app.core.security import verify_secret
from app.db.repository import CaseRepository, ProtectedDemoIocError, sanitize_rule_id
from app.schemas import (
    BlockRule,
    CreateBlockRuleRequest,
    RadarGraphResponse,
    ResetBlockRulesRequest,
)
from app.services.ioc_extractor import mask_ioc

logger = logging.getLogger("verishield.radar.audit")
router = APIRouter(prefix="/radar", tags=["radar"])


def _client_ip(request: Request) -> str:
    return str(request.client.host) if request.client else "unknown"


@router.get("/graph", response_model=RadarGraphResponse)
async def get_radar_graph(request: Request) -> RadarGraphResponse:
    repo: CaseRepository = request.app.state.repo
    return await asyncio.to_thread(repo.get_radar_graph)


@router.post("/block-rules", response_model=BlockRule)
async def post_block_rule(body: CreateBlockRuleRequest, request: Request) -> BlockRule:
    settings = request.app.state.settings
    repo: CaseRepository = request.app.state.repo
    ip = _client_ip(request)
    target_preview = (
        mask_ioc(body.ioc_type, body.value)
        if body.value and body.value.strip()
        else (f"{body.ioc_hash[:6]}****" if body.ioc_hash else None)
    )
    if not verify_secret(body.analyst_pin, settings.analyst_pin):
        repo.record_audit_log(
            action="auth_failed",
            outcome="denied",
            ioc_type=body.ioc_type,
            masked_target=target_preview,
            detail="Xác thực quản trị viên thất bại khi tạo quy tắc chặn.",
            client_ip=ip,
        )
        logger.warning("radar_audit action=auth_failed op=create_rule outcome=denied")
        raise HTTPException(
            status_code=403,
            detail="Mã PIN xác thực không đúng. Vui lòng kiểm tra lại.",
        )

    try:
        rule = repo.add_block_rule(
            ioc_type=body.ioc_type,
            reason=body.reason,
            raw_value=body.value,
            ioc_hash=body.ioc_hash,
            masked_value=body.masked_value,
            ttl_minutes=body.ttl_minutes,
        )
    except ProtectedDemoIocError as exc:
        repo.record_audit_log(
            action="protected_ioc_blocked",
            outcome="denied",
            ioc_type=body.ioc_type,
            masked_target=target_preview,
            detail="Từ chối tạo quy tắc đối với thực thể thuộc danh sách chính thức được bảo vệ.",
            client_ip=ip,
        )
        logger.warning("radar_audit action=protected_ioc_blocked outcome=denied")
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="Giá trị IOC không hợp lệ hoặc không đúng định dạng.",
        ) from exc

    repo.record_audit_log(
        action="create_rule",
        outcome="allowed",
        ioc_type=rule.ioc_type,
        masked_target=rule.masked_value,
        rule_id=rule.rule_id,
        detail=f"Áp dụng quy tắc chặn tạm thời cho {rule.masked_value}.",
        client_ip=ip,
    )
    logger.info(
        "radar_audit action=create_rule outcome=allowed rule_id=%s ioc_type=%s",
        rule.rule_id,
        rule.ioc_type,
    )
    return rule


@router.post("/block-rules/{rule_id}/revoke")
async def post_revoke_block_rule(
    rule_id: str,
    body: ResetBlockRulesRequest,
    request: Request,
) -> dict[str, Any]:
    settings = request.app.state.settings
    repo: CaseRepository = request.app.state.repo
    ip = _client_ip(request)
    safe_rule_id = sanitize_rule_id(rule_id)
    if not verify_secret(body.analyst_pin, settings.analyst_pin):
        repo.record_audit_log(
            action="auth_failed",
            outcome="denied",
            rule_id=safe_rule_id,
            detail="Xác thực quản trị viên thất bại khi thu hồi quy tắc chặn.",
            client_ip=ip,
        )
        logger.warning("radar_audit action=auth_failed op=revoke_rule outcome=denied")
        raise HTTPException(
            status_code=403,
            detail="Mã PIN xác thực không đúng. Vui lòng kiểm tra lại.",
        )

    revoked_rule = repo.get_block_rule(safe_rule_id) if safe_rule_id is not None else None
    revoked = repo.revoke_block_rule(safe_rule_id) if safe_rule_id is not None else False
    repo.record_audit_log(
        action="revoke_rule",
        outcome="allowed",
        ioc_type=revoked_rule.ioc_type if revoked_rule else None,
        masked_target=revoked_rule.masked_value if revoked_rule else None,
        rule_id=safe_rule_id,
        detail=(
            f"Thu hồi quy tắc chặn đối với {revoked_rule.masked_value}."
            if revoked and revoked_rule
            else "Yêu cầu thu hồi quy tắc không còn tồn tại hoặc đã hết hạn."
        ),
        client_ip=ip,
    )
    logger.info(
        "radar_audit action=revoke_rule outcome=allowed rule_id=%s revoked=%s",
        safe_rule_id or "invalid",
        revoked,
    )
    return {"ok": True, "rule_id": safe_rule_id, "revoked": revoked}


@router.post("/block-rules/reset")
async def post_reset_block_rules(
    body: ResetBlockRulesRequest,
    request: Request,
) -> dict[str, Any]:
    settings = request.app.state.settings
    repo: CaseRepository = request.app.state.repo
    ip = _client_ip(request)
    if not verify_secret(body.analyst_pin, settings.analyst_pin):
        repo.record_audit_log(
            action="auth_failed",
            outcome="denied",
            detail="Xác thực quản trị viên thất bại khi đặt lại quy tắc mẫu.",
            client_ip=ip,
        )
        logger.warning("radar_audit action=auth_failed op=reset_rules outcome=denied")
        raise HTTPException(
            status_code=403,
            detail="Mã PIN xác thực không đúng. Vui lòng kiểm tra lại.",
        )

    cleared = repo.reset_transient_rules()
    repo.record_audit_log(
        action="reset_rules",
        outcome="allowed",
        detail=f"Đặt lại quy tắc tạm thời (đã thu hồi {cleared} quy tắc).",
        client_ip=ip,
    )
    logger.info("radar_audit action=reset_rules outcome=allowed cleared=%d", cleared)
    return {"ok": True, "cleared_rules": cleared}
