"""Case lookup and Vietnamese PDF incident-report download endpoints with unified access control."""

from __future__ import annotations

from collections import OrderedDict
from typing import Annotated, Final

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response

from app.core.case_tokens import verify_case_access_token
from app.core.media_executors import MediaExecutorBusyError, run_pdf_bounded
from app.db.repository import CaseRepository, StoredCaseRecord
from app.schemas import AnalysisReport
from app.services.report_pdf import generate_incident_pdf

router = APIRouter(tags=["cases"])

_CASE_ACCESS_DENIED_DETAIL: Final[str] = "Phiên truy cập hồ sơ không hợp lệ hoặc đã hết hạn."
_PDF_BUSY_DETAIL: Final[str] = "Hệ thống tạo báo cáo PDF đang bận. Vui lòng thử lại sau ít giây."
_PDF_CACHE_MAX_ENTRIES: Final[int] = 16
_PDF_RENDER_TIMEOUT_SEC: Final[float] = 15.0
_PRIVATE_CASE_HEADERS: Final[dict[str, str]] = {
    "Cache-Control": "no-store",
    "Vary": "X-Case-Access-Token",
}


def verify_web_case_access(
    case_id: str,
    token: str | None,
    repo: CaseRepository,
    secret: str,
) -> StoredCaseRecord:
    """Verify web HMAC case token before DB lookup and enforce owner_channel == 'web_token'."""
    claims = verify_case_access_token(token, case_id, secret)
    if claims is None:
        raise HTTPException(
            status_code=403,
            detail=_CASE_ACCESS_DENIED_DETAIL,
            headers=_PRIVATE_CASE_HEADERS,
        )
    record = repo.get_report_with_owner(case_id)
    if record is None or record.owner_channel != "web_token":
        raise HTTPException(
            status_code=403,
            detail=_CASE_ACCESS_DENIED_DETAIL,
            headers=_PRIVATE_CASE_HEADERS,
        )
    return record


def require_case_access(
    case_id: str,
    request: Request,
    x_case_access_token: Annotated[
        str | None,
        Header(alias="X-Case-Access-Token"),
    ] = None,
) -> StoredCaseRecord:
    """FastAPI dependency enforcing X-Case-Access-Token on web case endpoints."""
    repo: CaseRepository = request.app.state.repo
    secret: str = request.app.state.case_token_secret
    return verify_web_case_access(case_id, x_case_access_token, repo, secret)


@router.get("/cases/{case_id}", response_model=AnalysisReport)
async def get_case(
    response: Response,
    record: Annotated[StoredCaseRecord, Depends(require_case_access)],
) -> AnalysisReport:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Vary"] = "X-Case-Access-Token"
    return record.report


@router.get("/cases/{case_id}/report.pdf")
async def get_case_pdf(
    request: Request,
    record: Annotated[StoredCaseRecord, Depends(require_case_access)],
) -> Response:
    report = record.report
    cache: OrderedDict[tuple[str, str, int, str], bytes] | None = getattr(
        request.app.state, "pdf_cache", None
    )
    if cache is None:
        cache = OrderedDict()
        request.app.state.pdf_cache = cache

    cache_key = (report.case_id, report.created_at, report.risk_score, report.verdict)
    pdf_bytes = cache.get(cache_key)
    if pdf_bytes is not None:
        cache.move_to_end(cache_key)
    else:
        try:
            pdf_bytes = await run_pdf_bounded(
                generate_incident_pdf,
                report,
                already_redacted=True,
                timeout_sec=_PDF_RENDER_TIMEOUT_SEC,
            )
        except (MediaExecutorBusyError, TimeoutError) as exc:
            raise HTTPException(
                status_code=503,
                detail=_PDF_BUSY_DETAIL,
                headers={
                    "Retry-After": "2",
                    "Cache-Control": "no-store",
                    "Vary": "X-Case-Access-Token",
                },
            ) from exc
        cache[cache_key] = pdf_bytes
        cache.move_to_end(cache_key)
        while len(cache) > _PDF_CACHE_MAX_ENTRIES:
            cache.popitem(last=False)

    safe_filename = "".join(ch for ch in report.case_id if ch.isalnum() or ch in ("_", "-")) or "report"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="VeriShield_{safe_filename}.pdf"',
            "Cache-Control": "no-store",
            "Vary": "X-Case-Access-Token",
        },
    )
