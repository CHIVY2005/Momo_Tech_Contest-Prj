"""Unicode Vietnamese PDF incident-report generator using fpdf2 + DejaVuSans.ttf."""

from __future__ import annotations

from pathlib import Path

from fpdf import FPDF

from app.db.repository import redact_report_pii
from app.schemas import AnalysisReport


def _font_path() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "fonts" / "DejaVuSans.ttf"


def generate_incident_pdf(report: AnalysisReport) -> bytes:
    """Render a PII-redacted Vietnamese cyber-fraud incident report as PDF bytes."""
    safe = redact_report_pii(report)

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.add_page()

    ttf = _font_path()
    pdf.add_font("DejaVu", style="", fname=str(ttf))
    pdf.set_font("DejaVu", size=15)

    # Header
    pdf.set_fill_color(15, 23, 42)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(
        w=0,
        h=12,
        text="  VERISHIELD AI — HỒ SƠ GHI NHẬN & TỐ GIÁC DẤU HIỆU LỪA ĐẢO SỐ",
        new_x="LMARGIN",
        new_y="NEXT",
        fill=True,
    )
    pdf.ln(4)

    pdf.set_text_color(15, 23, 42)
    pdf.set_font("DejaVu", size=10)
    call_label = "CÓ" if safe.in_active_call else "KHÔNG"
    conf_pct = round(safe.confidence * 100)
    meta_lines = [
        f"Mã hồ sơ (Case ID): {safe.case_id}   |   Thời điểm lập: {safe.created_at}",
        f"Chế độ kiểm tra: {safe.mode}   |   Trạng thái cuộc gọi (in_active_call): {call_label}",
        (
            f"Mức phán quyết: {safe.verdict}   |   Điểm rủi ro hiệu chuẩn: "
            f"{safe.risk_score}/100 (Độ tin cậy: {conf_pct}%)"
        ),
    ]
    if safe.receipt_verification_status != "NOT_APPLICABLE":
        meta_lines.append(f"Trạng thái kiểm chứng biên lai: {safe.receipt_verification_status}")

    for line in meta_lines:
        pdf.multi_cell(w=0, h=6, text=line, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # Section 1: Summary
    pdf.set_font("DejaVu", size=12)
    pdf.cell(w=0, h=8, text="1. Tóm tắt Kết luận Điều tra", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("DejaVu", size=10)
    pdf.multi_cell(w=0, h=6, text=safe.summary_vi, new_x="LMARGIN", new_y="NEXT")
    if safe.actions.merchant_balance_warning:
        pdf.ln(1)
        pdf.multi_cell(
            w=0,
            h=6,
            text=safe.actions.merchant_balance_warning,
            new_x="LMARGIN",
            new_y="NEXT",
        )
    pdf.ln(3)

    # Section 2: Matched Playbooks & IOCs (Masked)
    pdf.set_font("DejaVu", size=12)
    pdf.cell(
        w=0,
        h=8,
        text="2. Kịch bản Nhận diện & Thực thể Liên quan (Đã Ẩn danh PII)",
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.set_font("DejaVu", size=10)
    pbs = ", ".join(safe.matched_playbooks) if safe.matched_playbooks else "Chưa khớp mẫu cố định"
    pdf.multi_cell(w=0, h=6, text=f"• Kịch bản: {pbs}", new_x="LMARGIN", new_y="NEXT")
    if safe.iocs.phones:
        pdf.multi_cell(
            w=0,
            h=6,
            text=f"• Số điện thoại nghi vấn: {', '.join(safe.iocs.phones)}",
            new_x="LMARGIN",
            new_y="NEXT",
        )
    if safe.iocs.bank_accounts:
        pdf.multi_cell(
            w=0,
            h=6,
            text=f"• Tài khoản nhận nghi vấn: {', '.join(safe.iocs.bank_accounts)}",
            new_x="LMARGIN",
            new_y="NEXT",
        )
    if safe.iocs.domains:
        pdf.multi_cell(
            w=0,
            h=6,
            text=f"• Tên miền liên quan: {', '.join(safe.iocs.domains)}",
            new_x="LMARGIN",
            new_y="NEXT",
        )
    pdf.ln(3)

    # Section 3: Technical Evidence
    pdf.set_font("DejaVu", size=12)
    pdf.cell(w=0, h=8, text="3. Bằng chứng Kỹ thuật & Pháp y Số", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("DejaVu", size=10)
    if safe.evidence:
        for ev in safe.evidence[:8]:
            pdf.multi_cell(
                w=0,
                h=6,
                text=f"• [{ev.severity} | {ev.source}] {ev.title}: {ev.detail}",
                new_x="LMARGIN",
                new_y="NEXT",
            )
    else:
        pdf.multi_cell(
            w=0,
            h=6,
            text="• Không ghi nhận cảnh báo kỹ thuật nghiêm trọng.",
            new_x="LMARGIN",
            new_y="NEXT",
        )
    pdf.ln(3)

    # Section 4: Recommended Urgent Actions
    pdf.set_font("DejaVu", size=12)
    pdf.cell(
        w=0,
        h=8,
        text="4. Hướng dẫn Xử lý Khẩn cấp & Trình báo",
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.set_font("DejaVu", size=10)
    for step in safe.actions.urgent_steps:
        pdf.multi_cell(w=0, h=6, text=f"• {step}", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)
    pdf.set_font("DejaVu", size=8)
    pdf.set_text_color(100, 116, 139)
    pdf.multi_cell(
        w=0,
        h=5,
        text=(
            "Tài liệu được trích xuất tự động bởi hệ thống VeriShield AI phục vụ lưu trữ bằng chứng "
            "và hỗ trợ trình báo cơ quan Công an gần nhất hoặc qua ứng dụng VNeID."
        ),
        new_x="LMARGIN",
        new_y="NEXT",
    )

    return bytes(pdf.output())
