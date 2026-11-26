import sys
import zipfile
from pathlib import Path

from pypdf import PdfReader

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.package_submission import build_clean_source_zip  # noqa: E402

DIST_DIR = REPO_ROOT / "submission" / "dist"


def test_rendered_pdfs_and_templates_respect_strict_contest_page_limits() -> None:
    slides_tpl = (REPO_ROOT / "submission" / "slides" / "index.html").read_text(encoding="utf-8")
    guide_tpl = (REPO_ROOT / "submission" / "guide" / "index.html").read_text(encoding="utf-8")
    assert slides_tpl.count('<section class="slide">') == 10
    assert guide_tpl.count('<div class="page">') == 1

    slides_pdf = DIST_DIR / "VeriShield_AI_Slides_10p.pdf"
    guide_pdf = DIST_DIR / "VeriShield_AI_UserGuide_1p.pdf"
    if slides_pdf.exists() and guide_pdf.exists():
        assert slides_pdf.read_bytes()[:5] == b"%PDF-"
        assert guide_pdf.read_bytes()[:5] == b"%PDF-"
        assert len(PdfReader(str(slides_pdf)).pages) == 10
        assert len(PdfReader(str(guide_pdf)).pages) == 1


def _assert_clean_archive(zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = set(zf.namelist())

    required_entries = {
        "README.md",
        "AGENTS.md",
        "docker-compose.yml",
        "backend/.env.example",
        "backend/app/main.py",
        "backend/app/data/models/scam_e5_int8.onnx",
        "frontend/package.json",
        "frontend/src/app/page.tsx",
        "frontend/src/app/radar/page.tsx",
        "training/train_export_e5_onnx.py",
        "evaluation/dataset_vn_benchmark.json",
        "evaluation/results.json",
    }
    for req in required_entries:
        assert req in names, f"Required file {req} missing from {zip_path}"

    forbidden_substrings = (
        "node_modules/",
        ".venv/",
        ".next/",
        "__pycache__/",
        ".superpowers/",
        "submission/dist/",
        ".db",
    )
    for entry in names:
        lower = entry.lower()
        for bad in forbidden_substrings:
            assert bad not in lower, f"Forbidden artifact {entry} leaked into {zip_path}!"

        basename = entry.rsplit("/", maxsplit=1)[-1].lower()
        if basename.startswith(".env"):
            assert basename in (
                ".env.example",
                ".env.prod.example",
            ), f"Secret dotenv file {entry} leaked into {zip_path}!"


def test_source_zip_contains_required_modules_and_zero_secrets_or_bloat(tmp_path: Path) -> None:
    fresh_zip = build_clean_source_zip(tmp_path / "verishield-clean-check.zip")
    _assert_clean_archive(fresh_zip)

    if (DIST_DIR / "verishield-ai-source.zip").exists():
        _assert_clean_archive(DIST_DIR / "verishield-ai-source.zip")
