"""Render print-calibrated 10-page Slides PDF & 1-page A4 User Guide PDF with real empirical metrics."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import cv2
from playwright.sync_api import Browser, Playwright, sync_playwright
from pypdf import PdfReader

REPO_ROOT = Path(__file__).resolve().parents[1]
SUBMISSION_DIR = REPO_ROOT / "submission"
DIST_DIR = SUBMISSION_DIR / "dist"


def build_qr_svg(url: str) -> str:
    """Encode URL into a crisp, genuinely scannable inline SVG QR code via OpenCV."""
    encoder = cv2.QRCodeEncoder_create()
    mat = encoder.encode(url)
    rows, cols = mat.shape
    quiet = 2
    total = rows + quiet * 2
    rects: list[str] = []
    for r in range(rows):
        for c in range(cols):
            if int(mat[r, c]) == 0:
                rects.append(f'<rect x="{c + quiet}" y="{r + quiet}" width="1" height="1"/>')
    body = "".join(rects)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total} {total}" '
        f'shape-rendering="crispEdges">'
        f'<rect width="{total}" height="{total}" fill="#ffffff"/>'
        f'<g fill="#090e1a">{body}</g></svg>'
    )


def _load_replacements(base_url: str) -> dict[str, str]:
    results_path = REPO_ROOT / "evaluation" / "results.json"
    train_metrics_path = REPO_ROOT / "backend" / "app" / "data" / "models" / "training_metrics.json"

    results: dict[str, Any] = json.loads(results_path.read_text(encoding="utf-8"))
    train_metrics: dict[str, Any] = json.loads(train_metrics_path.read_text(encoding="utf-8"))

    cm = results["classification_metrics"]
    lat = results["latency_ms"]
    health = results["api_health"]
    models_obs: dict[str, int] = results.get("actual_models_observed") or {}

    live_ok = int(health.get("live_llm_success_count", 0))
    total_cases = int(results.get("dataset_size", 40))
    if live_ok <= 0 or not models_obs:
        raise RuntimeError(
            "Refusing to render contest PDFs without verified live LLM "
            "benchmark observations in evaluation/results.json."
        )
    primary_model = max(models_obs.items(), key=lambda kv: kv[1])[0]

    clean_url = base_url.rstrip("/")
    return {
        "{{F1_SCORE}}": f"{cm['f1']:.4f}",
        "{{PRECISION}}": f"{cm['precision'] * 100:.1f}%",
        "{{RECALL}}": f"{cm['recall'] * 100:.1f}%",
        "{{ADV_FPR}}": f"{cm['safety_advisory_fpr'] * 100:.1f}%",
        "{{ADV_CLEAN_RATE}}": f"{(1.0 - float(cm['safety_advisory_fpr'])) * 100:.1f}%",
        "{{INJ_BLOCK}}": f"{cm['prompt_injection_block_rate'] * 100:.1f}%",
        "{{INJ_FLAG}}": (
            f"{cm.get('prompt_injection_flag_rate', cm['prompt_injection_block_rate']) * 100:.1f}%"
        ),
        "{{FAKE_BILL_CATCH}}": f"{cm['fake_bill_catch_rate'] * 100:.1f}%",
        "{{LIVE_SUCCESS_COUNT}}": str(live_ok),
        "{{TOTAL_CASES}}": str(total_cases),
        "{{TERMINAL_ERRORS}}": str(
            health.get("terminal_error_count", health.get("api_error_count", 0))
        ),
        "{{ONNX_SIZE_MB}}": f"{train_metrics['onnx_size_mb']:.2f}",
        "{{PRUNED_VOCAB}}": f"{int(train_metrics['pruned_vocab_size']):,}",
        "{{ONNX_P50_MS}}": str(lat["onnx_p50_ms"]),
        "{{ONNX_P95_MS}}": str(lat["onnx_p95_ms"]),
        "{{E2E_P50_S}}": f"{lat['e2e_p50_ms'] / 1000.0:.2f}",
        "{{ACTUAL_LLM_MODEL}}": str(primary_model),
        "{{QR_SVG_MAIN}}": build_qr_svg(clean_url),
        "{{QR_SVG_RADAR}}": build_qr_svg(f"{clean_url}/radar"),
    }


def _launch_browser(pw: Playwright) -> Browser:
    last_err: Exception | None = None
    for channel in ("msedge", "chrome", None):
        try:
            if channel:
                return pw.chromium.launch(channel=channel, headless=True)
            return pw.chromium.launch(headless=True)
        except Exception as exc:
            last_err = exc
    raise RuntimeError("No headless Chromium/Edge/Chrome browser available.") from last_err


def render_all_pdfs(base_url: str = "https://verishield.joiboi.app") -> tuple[Path, Path]:
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    replacements = _load_replacements(base_url)

    slides_html = (SUBMISSION_DIR / "slides" / "index.html").read_text(encoding="utf-8")
    guide_html = (SUBMISSION_DIR / "guide" / "index.html").read_text(encoding="utf-8")
    for key, val in replacements.items():
        slides_html = slides_html.replace(key, val)
        guide_html = guide_html.replace(key, val)

    slides_out = DIST_DIR / "VeriShield_AI_Slides_10p.pdf"
    guide_out = DIST_DIR / "VeriShield_AI_UserGuide_1p.pdf"

    with sync_playwright() as pw:
        browser = _launch_browser(pw)
        try:
            slide_page = browser.new_page(viewport={"width": 1280, "height": 720})
            slide_page.set_content(slides_html, wait_until="load")
            slide_page.pdf(
                path=str(slides_out),
                width="1280px",
                height="720px",
                print_background=True,
                margin={"top": "0px", "right": "0px", "bottom": "0px", "left": "0px"},
            )
            slide_page.close()

            guide_page = browser.new_page(viewport={"width": 794, "height": 1123})
            guide_page.set_content(guide_html, wait_until="load")
            guide_page.pdf(
                path=str(guide_out),
                format="A4",
                print_background=True,
                margin={"top": "0px", "right": "0px", "bottom": "0px", "left": "0px"},
            )
            guide_page.close()
        finally:
            browser.close()

    slides_pages = len(PdfReader(str(slides_out)).pages)
    guide_pages = len(PdfReader(str(guide_out)).pages)
    if slides_pages != 10:
        raise RuntimeError(f"Slides PDF must be exactly 10 pages, got {slides_pages}")
    if guide_pages != 1:
        raise RuntimeError(f"User Guide PDF must be exactly 1 page, got {guide_pages}")

    print(f"==> Rendered {slides_out.name} ({slides_pages} pages)")
    print(f"==> Rendered {guide_out.name} ({guide_pages} page)")
    return slides_out, guide_out


if __name__ == "__main__":
    render_all_pdfs()
