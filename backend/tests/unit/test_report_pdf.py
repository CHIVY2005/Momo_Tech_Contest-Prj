import io

from pypdf import PdfReader

from app.schemas import AnalysisReport
from app.services.report_pdf import generate_incident_pdf


def test_pdf_generator_embeds_readable_vietnamese_unicode_and_redacts_raw_pii(
    sample_report: AnalysisReport,
) -> None:
    pdf_bytes = generate_incident_pdf(sample_report)
    assert pdf_bytes[:5] == b"%PDF-"
    assert len(pdf_bytes) > 2500

    reader = PdfReader(io.BytesIO(pdf_bytes))
    assert len(reader.pages) >= 1
    extracted = "\n".join(page.extract_text() or "" for page in reader.pages)

    assert "VeriShield AI" in extracted
    assert "CRITICAL_SCAM" in extracted
    assert "Công an" in extracted
    # Raw phone/account from unredacted caller must still be masked inside exported PDF
    assert "0912345678" not in extracted
    assert "190384756201" not in extracted
