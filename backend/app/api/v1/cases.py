"""Case lookup and Vietnamese PDF incident-report download endpoints."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException, Request, Response

from app.db.repository import CaseRepository
from app.schemas import AnalysisReport
from app.services.report_pdf import generate_incident_pdf

router = APIRouter(tags=["cases"])


@router.get("/cases/{case_id}", response_model=AnalysisReport)
async def get_case(case_id: str, request: Request) -> AnalysisReport:
    repo: CaseRepository = request.app.state.repo
    report = repo.get_report(case_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    return report


@router.get("/cases/{case_id}/report.pdf")
async def get_case_pdf(case_id: str, request: Request) -> Response:
    repo: CaseRepository = request.app.state.repo
    report = repo.get_report(case_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Case not found.")
    pdf_bytes = await asyncio.to_thread(generate_incident_pdf, report)
    safe_filename = "".join(ch for ch in case_id if ch.isalnum() or ch in ("_", "-")) or "report"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="VeriShield_{safe_filename}.pdf"',
        },
    )
