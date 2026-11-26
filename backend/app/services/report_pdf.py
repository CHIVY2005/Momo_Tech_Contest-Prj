"""Unicode Vietnamese PDF incident-report generator using fpdf2 + DejaVuSans.ttf."""

from __future__ import annotations

from pathlib import Path

from fpdf import FPDF

from app.db.repository import redact_report_pii
from app.schemas import AnalysisReport

_VERDICT_VI: dict[str, str] = {
    "SAFE": "Chưa phát hiện dấu hiệu bất thường",
    "SUSPICIOUS": "Cần thận trọng — nên xác minh thêm",
    "HIGH_RISK": "Cảnh báo rủi ro cao — tạm dừng giao dịch",
    "CRITICAL_SCAM": "Cảnh báo rủi ro rất cao — có nhiều dấu hiệu lừa đảo",
}
_MODE_VI: dict[str, str] = {
    "personal": "Tin nhắn và đường dẫn",
    "merchant": "Xác minh thanh toán",
    "wallet_transfer": "Trước khi chuyển tiền",
}
_RECEIPT_STATUS_VI: dict[str, str] = {
    "UNVERIFIED_SCREENSHOT": "Chưa thể xác nhận tiền đã vào tài khoản từ ảnh chụp",
    "BENEFICIARY_MISMATCH": "Thông tin người nhận không khớp",
    "TAMPER_OR_LOGIC_ANOMALY": "Ảnh biên lai có dấu hiệu chỉnh sửa hoặc sai lệch thông tin",
    "REPLAYED_RECEIPT": "Ảnh biên lai đã từng xuất hiện trước đó",
}
_SEVERITY_VI: dict[str, str] = {
    "CRITICAL": "Rất nghiêm trọng",
    "HIGH": "Nghiêm trọng",
    "MEDIUM": "Cần lưu ý",
    "LOW": "Thấp",
    "INFO": "Thông tin bổ sung",
}
_SOURCE_VI: dict[str, str] = {
    "image_forensics": "Phân tích tính xác thực của hình ảnh",
    "vietqr_parser": "Kiểm tra mã QR chuyển khoản",
    "url_inspector": "Kiểm tra đường dẫn trang web",
    "phishing_sandbox": "Kiểm tra trang web trong môi trường cách ly",
    "receipt_validator": "Đối chiếu biên lai chuyển khoản",
    "fraud_ops_radar": "Danh sách chặn rủi ro hệ thống",
    "guardrails": "Kiểm tra an toàn nội dung",
    "ocr_engine": "Trích xuất văn bản từ hình ảnh (OCR)",
    "gemini_vision": "Phân tích ngữ cảnh AI",
    "pipeline": "Hệ thống tổng hợp",
}


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
    pdf.set_font("DejaVu", size=14)

    # Header
    pdf.set_fill_color(15, 23, 42)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(
        w=0,
        h=12,
        text="  VeriShield AI — Báo cáo bằng chứng và hỗ trợ trình báo dấu hiệu lừa đảo",
        new_x="LMARGIN",
        new_y="NEXT",
        fill=True,
    )
    pdf.ln(4)

    pdf.set_text_color(15, 23, 42)
    pdf.set_font("DejaVu", size=10)
    call_label = "Có" if safe.in_active_call else "Không"
    conf_pct = round(safe.confidence * 100)
    mode_label = _MODE_VI.get(safe.mode, safe.mode)
    verdict_label = _VERDICT_VI.get(safe.verdict, safe.verdict)
    meta_lines = [
        f"Mã hồ sơ: {safe.case_id}   |   Thời điểm lập: {safe.created_at}",
        f"Chế độ kiểm tra: {mode_label}   |   Đang nghe điện thoại khi chuyển tiền: {call_label}",
        (
            f"Đánh giá rủi ro: {verdict_label}   |   Mức độ rủi ro: "
            f"{safe.risk_score}/100 (Mức độ chắc chắn: {conf_pct}%)"
        ),
    ]
    if safe.receipt_verification_status != "NOT_APPLICABLE":
        rcpt_label = _RECEIPT_STATUS_VI.get(
            safe.receipt_verification_status,
            safe.receipt_verification_status,
        )
        meta_lines.append(f"Trạng thái kiểm tra biên lai: {rcpt_label}")

    for line in meta_lines:
        pdf.multi_cell(w=0, h=6, text=line, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)

    # Section 1: Summary
    pdf.set_font("DejaVu", size=12)
    pdf.cell(w=0, h=8, text="1. Tóm tắt kết quả kiểm tra", new_x="LMARGIN", new_y="NEXT")
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
        text="2. Kịch bản tương tự và thông tin liên quan (đã che giấu thông tin cá nhân)",
        new_x="LMARGIN",
        new_y="NEXT",
    )
    pdf.set_font("DejaVu", size=10)
    pbs = (
        ", ".join(safe.matched_playbooks)
        if safe.matched_playbooks
        else "Chưa trùng khớp kịch bản cụ thể"
    )
    pdf.multi_cell(w=0, h=6, text=f"• Kịch bản tương tự: {pbs}", new_x="LMARGIN", new_y="NEXT")
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
            text=f"• Số tài khoản nhận nghi vấn: {', '.join(safe.iocs.bank_accounts)}",
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

    # Section 3: Digital Evidence
    pdf.set_font("DejaVu", size=12)
    pdf.cell(w=0, h=8, text="3. Chi tiết phân tích bằng chứng số", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("DejaVu", size=10)
    if safe.evidence:
        for ev in safe.evidence[:8]:
            sev_label = _SEVERITY_VI.get(ev.severity, ev.severity)
            src_label = _SOURCE_VI.get(ev.source, "Hệ thống kiểm tra")
            pdf.multi_cell(
                w=0,
                h=6,
                text=f"• [{sev_label} | {src_label}] {ev.title}: {ev.detail}",
                new_x="LMARGIN",
                new_y="NEXT",
            )
    else:
        pdf.multi_cell(
            w=0,
            h=6,
            text="• Chưa ghi nhận dấu hiệu bất thường nghiêm trọng.",
            new_x="LMARGIN",
            new_y="NEXT",
        )
    pdf.ln(3)

    # Section 4: Recommended Urgent Actions
    pdf.set_font("DejaVu", size=12)
    pdf.cell(
        w=0,
        h=8,
        text="4. Hướng dẫn xử lý và trình báo",
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
            "Tài liệu được tạo tự động bởi hệ thống VeriShield AI nhằm hỗ trợ lưu trữ bằng chứng "
            "và trình báo cơ quan Công an gần nhất hoặc qua ứng dụng VNeID. Kết quả chỉ mang tính "
            "tham khảo, không thay thế việc xác minh chính thức từ ngân hàng hoặc cơ quan chức năng."
        ),
        new_x="LMARGIN",
        new_y="NEXT",
    )

    return bytes(pdf.output())
