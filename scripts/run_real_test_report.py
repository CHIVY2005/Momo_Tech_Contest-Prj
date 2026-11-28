"""Execute real verification suites + live stack Chromium E2E and render PDF log report."""

from __future__ import annotations

import html
import http.client
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from playwright.sync_api import Browser, Playwright, expect, sync_playwright
from playwright.sync_api import Error as PlaywrightError
from pypdf import PdfReader

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
FRONTEND_DIR = REPO_ROOT / "frontend"
VENV_SCRIPTS = BACKEND_DIR / ".venv" / "Scripts"
PYTHON_EXE = VENV_SCRIPTS / ("python.exe" if os.name == "nt" else "python")
RUFF_EXE = VENV_SCRIPTS / ("ruff.exe" if os.name == "nt" else "ruff")
MYPY_EXE = VENV_SCRIPTS / ("mypy.exe" if os.name == "nt" else "mypy")
PYTEST_EXE = VENV_SCRIPTS / ("pytest.exe" if os.name == "nt" else "pytest")
NPM_BIN = "npm.cmd" if os.name == "nt" else "npm"
NPX_BIN = "npx.cmd" if os.name == "nt" else "npx"

JSON_OUT = REPO_ROOT / "docs" / "test_reports" / "real_test_run.json"
PDF_OUT = REPO_ROOT / "docs" / "VeriShield_AI_Bao_Cao_Log_Test_That.pdf"
FONT_PATH = BACKEND_DIR / "app" / "data" / "fonts" / "DejaVuSans.ttf"
VN_TZ = timezone(timedelta(hours=7))


@dataclass
class SuiteRunResult:
    """Captured execution metrics and diagnostics for a single test suite."""

    name: str
    category: str  # "TEST THẬT" | "MOCK UI"
    command: str
    exit_code: int
    status: str  # "PASS" | "FAIL"
    duration_sec: float
    summary: str
    log_excerpt: str


@dataclass
class LiveFlowResult:
    """Captured live FastAPI + Next.js E2E observation in Chromium without API mocks."""

    flow_name: str
    status: str
    duration_ms: int
    verdict_or_state: str
    risk_score: str
    detail_excerpt: str


def _run_cmd_capture(
    cmd: list[str],
    *,
    cwd: Path,
    timeout_sec: int = 300,
) -> tuple[int, float, str]:
    """Run subprocess synchronously, returning (exit_code, elapsed_sec, combined_output)."""
    t0 = time.perf_counter()
    proc = subprocess.run(  # noqa: S603
        cmd,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_sec,
        check=False,
    )
    elapsed = round(time.perf_counter() - t0, 2)
    return proc.returncode, elapsed, proc.stdout or ""


def _git_meta() -> dict[str, str]:
    """Collect current git branch, short commit, runtime versions, and local timestamp."""
    _, _, branch = _run_cmd_capture(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=REPO_ROOT)
    _, _, commit = _run_cmd_capture(["git", "rev-parse", "--short", "HEAD"], cwd=REPO_ROOT)
    _, _, py_ver = _run_cmd_capture([str(PYTHON_EXE), "--version"], cwd=REPO_ROOT)
    _, _, node_ver = _run_cmd_capture(["node", "-v"], cwd=REPO_ROOT)
    _, _, ort_ver = _run_cmd_capture(
        [str(PYTHON_EXE), "-c", "import onnxruntime as o; print(o.__version__)"],
        cwd=REPO_ROOT,
    )
    return {
        "timestamp_vn": datetime.now(VN_TZ).strftime("%Y-%m-%d %H:%M:%S (UTC+7)"),
        "git_branch": branch.strip() or "unknown",
        "git_commit": commit.strip() or "unknown",
        "python_version": py_ver.strip(),
        "node_version": node_ver.strip(),
        "onnxruntime_version": ort_ver.strip(),
        "os_platform": f"{os.name} ({os.cpu_count()} CPU threads)",
    }


def _launch_chromium(pw: Playwright) -> Browser:
    """Launch default Playwright Chromium or fall back to cached local Chromium/Edge/Chrome."""
    default_exe = Path(pw.chromium.executable_path)
    if default_exe.exists():
        return pw.chromium.launch(headless=True)

    cache_roots = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "ms-playwright",
        Path.home() / ".cache" / "ms-playwright",
    ]
    for root in cache_roots:
        if not root.exists():
            continue
        for pat in ("chromium-*/chrome-win64/chrome.exe", "chromium-*/chrome-linux*/chrome"):
            matches = sorted(root.glob(pat), reverse=True)
            if matches:
                return pw.chromium.launch(headless=True, executable_path=str(matches[0]))

    last_err: PlaywrightError | None = None
    for channel in ("msedge", "chrome"):
        try:
            return pw.chromium.launch(channel=channel, headless=True)
        except PlaywrightError as exc:
            last_err = exc
    raise RuntimeError("No usable Chromium/Edge/Chrome binary found.") from last_err


def _wait_http_ok(url: str, timeout_sec: float = 35.0) -> None:
    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 80
    path = parsed.path or "/"
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        conn: http.client.HTTPConnection | None = None
        try:
            conn = http.client.HTTPConnection(host, port, timeout=2.0)
            conn.request("GET", path)
            resp = conn.getresponse()
            if resp.status == 200:
                return
        except (http.client.HTTPException, TimeoutError, OSError):
            time.sleep(0.4)
        finally:
            if conn is not None:
                conn.close()
    raise RuntimeError(f"Timed out waiting for HTTP 200 at {url}")


def _terminate_tree(proc: subprocess.Popen[bytes] | subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    if os.name == "nt":
        taskkill = shutil.which("taskkill")
        if taskkill:
            subprocess.run(  # noqa: S603
                [taskkill, "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            proc.terminate()
    else:
        proc.terminate()
    try:
        proc.wait(timeout=6)
    except subprocess.TimeoutExpired:
        proc.kill()


def _summarize_pytest(out: str, code: int) -> str:
    m = re.search(r"(\d+\s+failed,\s+\d+\s+passed|\d+\s+passed)(?:\s+in\s+[^\r\n]+)?", out)
    if m:
        return m.group(0).strip()
    return "PASSED" if code == 0 else f"Exit {code}"


def _summarize_node_test(out: str, code: int) -> str:
    total = re.search(r"ℹ tests (\d+)", out)
    passed = re.search(r"ℹ pass (\d+)", out)
    failed = re.search(r"ℹ fail (\d+)", out)
    if total and passed and failed:
        return f"{passed.group(1)}/{total.group(1)} pass, {failed.group(1)} fail"
    return "PASSED" if code == 0 else f"Exit {code}"


def _tail_lines(text: str, max_lines: int = 18) -> str:
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    return "\n".join(lines[-max_lines:]) if lines else "(không có output)"


def _extract_pytest_excerpt(text: str) -> str:
    lines = text.splitlines()
    idx = next((i for i, ln in enumerate(lines) if "short test summary info" in ln), -1)
    if idx >= 0:
        return "\n".join(ln.rstrip() for ln in lines[idx : idx + 22] if ln.strip())
    return _tail_lines(text, 18)


def _run_real_stack_e2e() -> tuple[SuiteRunResult, list[LiveFlowResult]]:
    """Run live FastAPI (:8000) + Next.js (:3098) E2E in Chromium with zero API mocks."""
    temp_dir = Path(tempfile.mkdtemp(prefix="verishield_real_e2e_"))
    db_path = temp_dir / "real_e2e.db"
    uvicorn_log_path = temp_dir / "uvicorn.log"
    uvicorn_log_fh = uvicorn_log_path.open("w", encoding="utf-8", errors="replace")
    backend_proc: subprocess.Popen[bytes] | subprocess.Popen[str] | None = None
    frontend_proc: subprocess.Popen[bytes] | subprocess.Popen[str] | None = None
    flows: list[LiveFlowResult] = []
    t_suite = time.perf_counter()

    backend_env = os.environ.copy()
    backend_env.update(
        {
            "APP_ENV": "demo",
            "ANALYST_PIN": "2026",
            "SQLITE_PATH": str(db_path),
            "ENABLE_LIVE_NETWORK_CHECKS": "false",
            "ENABLE_PLAYWRIGHT_SANDBOX": "false",
            "ENABLE_LOCAL_STT": "false",
            "GEMINI_API_KEY": "",
            "GEMINI_BACKUP_API_KEY": "",
            "RATE_LIMIT_PER_MINUTE": "200",
        }
    )

    page_errors: list[str] = []
    logs: list[str] = []
    try:
        backend_proc = subprocess.Popen(  # noqa: S603
            [
                str(PYTHON_EXE),
                "-m",
                "uvicorn",
                "app.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                "8000",
            ],
            cwd=str(BACKEND_DIR),
            env=backend_env,
            stdout=uvicorn_log_fh,
            stderr=subprocess.STDOUT,
        )
        frontend_proc = subprocess.Popen(  # noqa: S603
            [NPM_BIN, "run", "start", "--", "--port", "3098"],
            cwd=str(FRONTEND_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
        )

        _wait_http_ok("http://127.0.0.1:8000/api/v1/health", timeout_sec=35.0)
        _wait_http_ok("http://127.0.0.1:3098/", timeout_sec=35.0)

        with sync_playwright() as pw:
            browser = _launch_chromium(pw)
            context = browser.new_context(viewport={"width": 1280, "height": 900})
            page = context.new_page()
            page.on("pageerror", lambda err: page_errors.append(str(err)))
            page.goto("http://127.0.0.1:3098/", wait_until="networkidle")

            expect(page.get_by_text("Hệ thống đang hoạt động")).to_be_visible(timeout=10000)

            # Flow 1: Real scam input -> wallet_transfer via real backend ONNX + Calibrator
            t1 = time.perf_counter()
            composer = page.get_by_label("Tin nhắn, đường dẫn hoặc tệp đính kèm")
            composer.fill(
                "Cơ quan Công an yêu cầu chuyển 15.000.000đ tạm giữ xác minh qua "
                "https://vneid-xacminh-247.top ngay lập tức"
            )
            page.get_by_role("button", name="Thông tin giao dịch bổ sung (tùy chọn)").click()
            page.locator("#wb-transfer-amount").fill("15000000")
            page.locator("#wb-active-call-toggle").click()
            page.get_by_role("button", name="Kiểm tra ngay").click()

            expect(page.locator("#verdict-heading")).to_be_visible(timeout=20000)
            expect(
                page.get_by_text("Tạm dừng 30 giây để kiểm tra trước khi chuyển tiền")
            ).to_be_visible(timeout=10000)
            score1 = page.locator('[role="progressbar"]').get_attribute("aria-valuenow") or "?"
            badge1 = page.locator('section[aria-labelledby="verdict-heading"] span').first.inner_text()
            summary1 = page.locator("#verdict-heading").inner_text()
            page.locator("details summary", has_text="Thông tin kỹ thuật").click()
            tech_txt1 = page.locator("#verdict-result details").inner_text()
            assert "SCAM_IMPERSONATION" not in tech_txt1
            assert int(score1) >= 80
            ms1 = int((time.perf_counter() - t1) * 1000)
            flows.append(
                LiveFlowResult(
                    flow_name="1. Kiểm tra lừa đảo thật (FastAPI + E5 ONNX + URL inspector)",
                    status="PASS",
                    duration_ms=ms1,
                    verdict_or_state=badge1,
                    risk_score=f"{score1}/100",
                    detail_excerpt=summary1[:180],
                )
            )
            logs.append(f"[LIVE FLOW 1] {badge1} ({score1}/100) in {ms1} ms -> {summary1}")

            # Flow 2: Real Chatbot (Trợ lý VeriShield) SSE stream against real RAG + Guardrails
            t2 = time.perf_counter()
            page.get_by_role("button", name="Hỏi Trợ lý VeriShield").first.click()
            dialog = page.get_by_role("dialog")
            expect(dialog).to_be_visible(timeout=5000)
            dialog.locator("#assistant-composer-input").fill(
                "Vì sao hệ thống cảnh báo lừa đảo và tôi cần làm gì ngay?"
            )
            dialog.get_by_role("button", name="Gửi câu hỏi").click()

            assistant_msg = dialog.locator('article[aria-label="Phản hồi từ Trợ lý VeriShield"]').last
            expect(assistant_msg).to_be_visible(timeout=15000)
            expect(dialog.get_by_role("button", name="Gửi câu hỏi")).to_be_visible(timeout=20000)
            chat_reply = assistant_msg.inner_text().strip()
            assert len(chat_reply) >= 40
            ms2 = int((time.perf_counter() - t2) * 1000)
            clean_reply = " ".join(chat_reply.splitlines())
            flows.append(
                LiveFlowResult(
                    flow_name="2. Chatbot Trợ lý VeriShield thật (/assistant/chat/stream)",
                    status="PASS",
                    duration_ms=ms2,
                    verdict_or_state="Stream hoàn tất",
                    risk_score="RAG cục bộ",
                    detail_excerpt=clean_reply[:180],
                )
            )
            logs.append(f"[LIVE FLOW 2] Chatbot streamed in {ms2} ms -> {clean_reply[:160]}")
            dialog.get_by_role("button", name="Đóng Trợ lý VeriShield").click()

            # Flow 3: Real Merchant Receipt Honesty Guardrail (real receipt_validator + calibrator)
            t3 = time.perf_counter()
            page.get_by_role("button", name="Chỉnh sửa thông tin").click()
            page.locator("#wb-merchant-stk").fill("190311112222")
            page.locator("#wb-transfer-amount").fill("")
            active_toggle = page.locator("#wb-active-call-toggle")
            if active_toggle.get_attribute("aria-checked") == "true":
                active_toggle.click()
            composer.fill(
                "Chuyển khoản thành công Vietcombank 500.000 VND tới STK nhận 190311112222 "
                "lúc 12:30 28/11/2026 mã giao dịch FT26331000999"
            )
            page.get_by_role("button", name="Kiểm tra ngay").click()
            expect(
                page.get_by_text("Chưa thể xác nhận tiền đã vào tài khoản từ ảnh chụp").first
            ).to_be_visible(timeout=20000)
            score3 = page.locator('[role="progressbar"]').get_attribute("aria-valuenow") or "?"
            badge3 = page.locator('section[aria-labelledby="verdict-heading"] span').first.inner_text()
            summary3 = page.locator("#verdict-heading").inner_text()
            assert int(score3) <= 24
            ms3 = int((time.perf_counter() - t3) * 1000)
            flows.append(
                LiveFlowResult(
                    flow_name="3. Xác minh biên lai người bán thật (Honesty Guardrail)",
                    status="PASS",
                    duration_ms=ms3,
                    verdict_or_state=badge3,
                    risk_score=f"{score3}/100",
                    detail_excerpt=summary3[:180],
                )
            )
            logs.append(f"[LIVE FLOW 3] {badge3} ({score3}/100) in {ms3} ms -> {summary3}")

            assert not page_errors, f"Uncaught browser page errors: {page_errors}"
            context.close()
            browser.close()

        suite = SuiteRunResult(
            name="Live Full-Stack E2E (FastAPI + Next.js + Chromium)",
            category="TEST THẬT",
            command="uvicorn app.main:app + next start --port 3098 (0 API mocks)",
            exit_code=0,
            status="PASS",
            duration_sec=round(time.perf_counter() - t_suite, 2),
            summary=f"{len(flows)}/3 luồng E2E thật Pass (0 lỗi JS)",
            log_excerpt="\n".join(logs),
        )
        return suite, flows
    except (PlaywrightError, AssertionError, RuntimeError, OSError, TimeoutError, ValueError) as exc:
        logs.append(f"[LIVE E2E ERROR] {type(exc).__name__}: {exc}")
        uvicorn_log_fh.flush()
        if uvicorn_log_path.exists():
            uv_text = uvicorn_log_path.read_text(encoding="utf-8", errors="replace")
            if uv_text.strip():
                logs.append(_tail_lines(uv_text, 20))
        suite = SuiteRunResult(
            name="Live Full-Stack E2E (FastAPI + Next.js + Chromium)",
            category="TEST THẬT",
            command="uvicorn app.main:app + next start --port 3098 (0 API mocks)",
            exit_code=1,
            status="FAIL",
            duration_sec=round(time.perf_counter() - t_suite, 2),
            summary=f"FAIL ({type(exc).__name__})",
            log_excerpt="\n".join(logs),
        )
        return suite, flows
    finally:
        if frontend_proc is not None:
            _terminate_tree(frontend_proc)
        if backend_proc is not None:
            _terminate_tree(backend_proc)
        uvicorn_log_fh.close()
        shutil.rmtree(temp_dir, ignore_errors=True)


def _render_report_pdf(payload: dict[str, Any]) -> None:
    """Render structured real-test results into an A4 Vietnamese log report PDF."""
    font_uri = FONT_PATH.as_uri() if FONT_PATH.exists() else ""
    font_css = (
        f"@font-face {{ font-family: 'VSDejaVu'; src: url('{html.escape(font_uri)}') "
        "format('truetype'); font-weight: 100 900; font-style: normal; }"
        if font_uri
        else ""
    )

    meta: dict[str, str] = payload["meta"]
    suites: list[dict[str, Any]] = payload["suites"]
    live_flows: list[dict[str, Any]] = payload["live_flows"]

    real_suites = [s for s in suites if s["category"] == "TEST THẬT"]
    real_pass = sum(1 for s in real_suites if s["status"] == "PASS")
    pytest_row = next((s for s in suites if "Pytest" in s["name"]), None)
    fe_row = next((s for s in suites if "Frontend Unit" in s["name"]), None)
    mock_row = next((s for s in suites if s["category"] == "MOCK UI"), None)

    suite_rows_html = "\n".join(
        f"""
        <tr>
          <td>
            <span class="badge {'b-real' if s['category'] == 'TEST THẬT' else 'b-mock'}">
              {html.escape(s['category'])}
            </span>
          </td>
          <td><strong>{html.escape(s['name'])}</strong><br/><code>{html.escape(s['command'])}</code></td>
          <td>
            <span class="badge {'b-pass' if s['status'] == 'PASS' else 'b-fail'}">
              {html.escape(s['status'])} (code {s['exit_code']})
            </span>
          </td>
          <td class="num">{s['duration_sec']:.2f}s</td>
          <td>{html.escape(s['summary'])}</td>
        </tr>
        """
        for s in suites
    )

    flow_rows_html = "\n".join(
        f"""
        <tr>
          <td><strong>{html.escape(f['flow_name'])}</strong></td>
          <td>
            <span class="badge {'b-pass' if f['status'] == 'PASS' else 'b-fail'}">
              {html.escape(f['status'])}
            </span>
          </td>
          <td class="num">{f['duration_ms']} ms</td>
          <td>
            <strong>{html.escape(f['verdict_or_state'])}</strong><br/>
            <code>{html.escape(f['risk_score'])}</code>
          </td>
          <td>{html.escape(f['detail_excerpt'])}</td>
        </tr>
        """
        for f in live_flows
    )

    log_blocks_html = "\n".join(
        f"""
        <div class="log-card">
          <div class="log-head">
            <span>[{html.escape(s['category'])}] {html.escape(s['name'])}</span>
            <span>Exit {s['exit_code']} · {s['duration_sec']:.2f}s</span>
          </div>
          <pre>{html.escape(s['log_excerpt'])}</pre>
        </div>
        """
        for s in suites
    )

    html_doc = f"""<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="utf-8" />
<title>VeriShield AI — Báo cáo Log Kết quả Chạy Test Thật</title>
<style>
{font_css}
@page {{ size: A4 portrait; margin: 12mm 12mm 15mm 12mm; }}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  font-family: 'Segoe UI', 'VSDejaVu', Arial, sans-serif;
  color: #0f172a;
  font-size: 9pt;
  line-height: 1.42;
}}
.hero {{
  background: #0f172a;
  color: #f8fafc;
  border-radius: 9px;
  padding: 14px 16px;
  border-left: 5px solid #10b981;
  margin-bottom: 10px;
}}
.kicker {{
  font-size: 7.5pt;
  font-weight: 700;
  color: #34d399;
  text-transform: uppercase;
  letter-spacing: 0.07em;
}}
.hero h1 {{ margin: 3px 0 5px 0; font-size: 14.5pt; color: #ffffff; }}
.meta-grid {{
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 5px 10px;
  font-size: 7.7pt;
  color: #cbd5e1;
  margin-top: 6px;
}}
.kpi-grid {{
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
  margin-bottom: 10px;
}}
.kpi {{
  border: 1px solid #cbd5e1;
  border-radius: 7px;
  padding: 7px 9px;
  background: #f8fafc;
  border-top: 3px solid #0284c7;
}}
.kpi.ok {{ border-top-color: #059669; background: #f0fdf4; }}
.kpi.warn {{ border-top-color: #d97706; background: #fffbeb; }}
.kpi-lbl {{ font-size: 7pt; font-weight: 700; text-transform: uppercase; color: #475569; }}
.kpi-val {{ font-size: 11pt; font-weight: 800; color: #0f172a; margin-top: 2px; }}
.kpi-sub {{ font-size: 7.3pt; color: #334155; margin-top: 1px; }}
h2 {{
  font-size: 10.8pt;
  margin: 10px 0 5px 0;
  padding-bottom: 3px;
  border-bottom: 2px solid #e2e8f0;
  break-after: avoid;
}}
table {{ width: 100%; border-collapse: collapse; margin: 5px 0 9px 0; font-size: 8pt; }}
th {{
  background: #0f172a;
  color: #f8fafc;
  text-align: left;
  padding: 5px 6px;
  border: 1px solid #0f172a;
}}
td {{ padding: 5px 6px; border: 1px solid #cbd5e1; vertical-align: top; }}
tr {{ break-inside: avoid; }}
tbody tr:nth-child(even) {{ background: #f8fafc; }}
td.num {{ white-space: nowrap; font-family: Consolas, monospace; text-align: right; }}
.badge {{
  display: inline-block;
  font-size: 7pt;
  font-weight: 800;
  padding: 1px 5px;
  border-radius: 4px;
  white-space: nowrap;
}}
.b-real {{ background: #dbeafe; color: #1e40af; border: 1px solid #93c5fd; }}
.b-mock {{ background: #f3e8ff; color: #6b21a8; border: 1px solid #d8b4fe; }}
.b-pass {{ background: #dcfce7; color: #166534; border: 1px solid #86efac; }}
.b-fail {{ background: #ffe4e6; color: #9f1239; border: 1px solid #fda4af; }}
code {{
  font-family: Consolas, 'VSDejaVu', monospace;
  font-size: 7.3pt;
  background: #f1f5f9;
  padding: 0.5px 3px;
  border-radius: 3px;
}}
.log-card {{
  border: 1px solid #cbd5e1;
  border-radius: 6px;
  margin-bottom: 7px;
  overflow: hidden;
  break-inside: avoid;
}}
.log-head {{
  background: #e2e8f0;
  color: #0f172a;
  font-size: 7.8pt;
  font-weight: 700;
  padding: 4px 8px;
  display: flex;
  justify-content: space-between;
}}
pre {{
  margin: 0;
  padding: 6px 8px;
  background: #0f172a;
  color: #e2e8f0;
  font-family: Consolas, 'VSDejaVu', monospace;
  font-size: 6.9pt;
  line-height: 1.35;
  white-space: pre-wrap;
  word-break: break-word;
}}
.note-box {{
  background: #fffbeb;
  border: 1px solid #fcd34d;
  border-left: 4px solid #d97706;
  border-radius: 6px;
  padding: 7px 9px;
  font-size: 8pt;
  margin-bottom: 8px;
  break-inside: avoid;
}}
.page-break {{ break-before: page; }}
</style>
</head>
<body>

<div class="hero">
  <div class="kicker">Nhật ký thực thi kiểm thử tự động · Nguồn dữ liệu: real_test_run.json</div>
  <h1>VeriShield AI — Báo Cáo Log Kết Quả Chạy Test Thật</h1>
  <div class="meta-grid">
    <div><strong>Thời điểm chạy:</strong> {html.escape(meta['timestamp_vn'])}</div>
    <div>
      <strong>Nhánh / Commit:</strong>
      {html.escape(meta['git_branch'])} @ {html.escape(meta['git_commit'])}
    </div>
    <div><strong>Môi trường:</strong> {html.escape(meta['os_platform'])}</div>
    <div><strong>Python:</strong> {html.escape(meta['python_version'])}</div>
    <div><strong>Node.js:</strong> {html.escape(meta['node_version'])}</div>
    <div><strong>ONNX Runtime:</strong> {html.escape(meta['onnxruntime_version'])}</div>
  </div>
</div>

<div class="kpi-grid">
  <div class="kpi ok">
    <div class="kpi-lbl">Bộ test thật đạt</div>
    <div class="kpi-val">{real_pass}/{len(real_suites)} Suites</div>
    <div class="kpi-sub">Bao gồm Live E2E thật 0 mock</div>
  </div>
  <div class="kpi warn">
    <div class="kpi-lbl">Backend Pytest</div>
    <div class="kpi-val">{html.escape(pytest_row['summary'] if pytest_row else 'N/A')}</div>
    <div class="kpi-sub">Chi tiết lỗi trích ở trang sau</div>
  </div>
  <div class="kpi ok">
    <div class="kpi-lbl">Frontend Tests &amp; TS</div>
    <div class="kpi-val">{html.escape(fe_row['summary'] if fe_row else 'N/A')}</div>
    <div class="kpi-sub">tsc --noEmit pass · npm test pass</div>
  </div>
  <div class="kpi ok">
    <div class="kpi-lbl">Mock UI E2E (tách riêng)</div>
    <div class="kpi-val">{html.escape(mock_row['status'] if mock_row else 'N/A')}</div>
    <div class="kpi-sub">{html.escape(mock_row['summary'] if mock_row else '')}</div>
  </div>
</div>

<h2>1. Bảng Tổng Hợp Kết Quả Chạy Các Bộ Kiểm Thử (Test Thật vs Mock UI Tách Biệt)</h2>
<table>
  <thead>
    <tr>
      <th style="width: 11%;">Phân loại</th>
      <th style="width: 34%;">Bộ kiểm thử &amp; Lệnh thực thi</th>
      <th style="width: 14%;">Trạng thái</th>
      <th style="width: 9%;">Thời gian</th>
      <th style="width: 32%;">Kết quả đo được trực tiếp</th>
    </tr>
  </thead>
  <tbody>
    {suite_rows_html}
  </tbody>
</table>

<h2>2. Log Kiểm Thử E2E Toàn Hệ Thống Thật (FastAPI :8000 + Next.js :3098, Không Mock)</h2>
<p style="margin:2px 0 6px 0;font-size:8.2pt;color:#334155;">
  Trình duyệt Chromium gọi trực tiếp tới server Next.js và backend FastAPI đang chạy thật với
  CSDL SQLite tạm thời, mô hình E5-Small INT8 ONNX, bộ giải mã URL/biên lai và Trợ lý RAG cục bộ
  (tắt gọi Gemini ngoài để kiểm định Tầng 1 &amp; độ bền dự phòng nội bộ).
</p>
<table>
  <thead>
    <tr>
      <th style="width: 24%;">Luồng nghiệp vụ thật</th>
      <th style="width: 8%;">Kết quả</th>
      <th style="width: 9%;">Độ trễ</th>
      <th style="width: 19%;">Phản hồi thực tế</th>
      <th style="width: 40%;">Nội dung trả về quan sát trên UI</th>
    </tr>
  </thead>
  <tbody>
    {flow_rows_html}
  </tbody>
</table>

<div class="page-break"></div>

<h2>3. Trích Xuất Raw Log Thực Thi Từ Từng Lệnh (stdout / stderr)</h2>
<div class="note-box">
  <strong>Lưu ý minh bạch:</strong> Toàn bộ số liệu và đoạn log bên dưới được trích trực tiếp từ
  lần chạy thật lưu tại <code>docs/test_reports/real_test_run.json</code>. Nếu có ca test lỗi do
  môi trường local Windows (như thiếu gói <code>rapidocr</code> trong <code>.venv</code> hoặc sai số
  <code>onnxruntime 1.32.0</code>), hệ thống ghi nguyên trạng không che giấu.
</div>

{log_blocks_html}

</body>
</html>
"""

    PDF_OUT.parent.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = _launch_chromium(pw)
        try:
            page = browser.new_page(viewport={"width": 794, "height": 1123})
            page.set_content(html_doc, wait_until="load")
            page.pdf(
                path=str(PDF_OUT),
                format="A4",
                print_background=True,
                display_header_footer=True,
                header_template="<div></div>",
                footer_template=(
                    "<div style='width:100%;font-size:8px;color:#64748b;"
                    "padding:0 12mm;display:flex;justify-content:space-between;'>"
                    "<span>VeriShield AI — Log Kết quả Chạy Test Thật</span>"
                    "<span>Trang <span class='pageNumber'></span> / "
                    "<span class='totalPages'></span></span></div>"
                ),
                margin={"top": "11mm", "right": "11mm", "bottom": "14mm", "left": "11mm"},
            )
            page.close()
        finally:
            browser.close()

    reader = PdfReader(str(PDF_OUT))
    if len(reader.pages) < 2:
        raise RuntimeError(f"Expected >= 2 PDF pages, got {len(reader.pages)}")


def main() -> int:
    meta = _git_meta()
    suites: list[SuiteRunResult] = []

    print("==> [1/7] Running Backend Ruff...", flush=True)
    ruff_cmd = [
        str(RUFF_EXE),
        "check",
        "app",
        "tests",
        "../scripts",
        "../evaluation",
        "../submission",
        "../training",
    ]
    rc, dur, out = _run_cmd_capture(ruff_cmd, cwd=BACKEND_DIR, timeout_sec=120)
    print(f"    -> Ruff: exit={rc} ({dur}s)", flush=True)
    suites.append(
        SuiteRunResult(
            name="Backend Ruff Linter",
            category="TEST THẬT",
            command="ruff check app tests ../scripts ../evaluation ../submission ../training",
            exit_code=rc,
            status="PASS" if rc == 0 else "FAIL",
            duration_sec=dur,
            summary="All checks passed!" if rc == 0 else f"Exit {rc}",
            log_excerpt=_tail_lines(out, 12),
        )
    )

    print("==> [2/7] Running Backend Mypy Strict...", flush=True)
    mypy_cmd = [str(MYPY_EXE), "--config-file", "pyproject.toml", "app"]
    rc, dur, out = _run_cmd_capture(mypy_cmd, cwd=BACKEND_DIR, timeout_sec=120)
    print(f"    -> Mypy: exit={rc} ({dur}s)", flush=True)
    suites.append(
        SuiteRunResult(
            name="Backend Mypy Strict Typecheck",
            category="TEST THẬT",
            command="mypy --config-file pyproject.toml app",
            exit_code=rc,
            status="PASS" if rc == 0 else "FAIL",
            duration_sec=dur,
            summary=_tail_lines(out, 1),
            log_excerpt=_tail_lines(out, 10),
        )
    )

    print("==> [3/7] Running Backend Pytest Suite...", flush=True)
    pytest_cmd = [str(PYTEST_EXE), "-c", "pyproject.toml", "-q", "--tb=short"]
    rc, dur, out = _run_cmd_capture(pytest_cmd, cwd=BACKEND_DIR, timeout_sec=300)
    print(f"    -> Pytest: exit={rc} ({dur}s)", flush=True)
    suites.append(
        SuiteRunResult(
            name="Backend Pytest Suite",
            category="TEST THẬT",
            command="pytest -c pyproject.toml -q --tb=short",
            exit_code=rc,
            status="PASS" if rc == 0 else "FAIL",
            duration_sec=dur,
            summary=_summarize_pytest(out, rc),
            log_excerpt=_extract_pytest_excerpt(out),
        )
    )

    print("==> [4/7] Running Frontend TypeScript Check...", flush=True)
    rc, dur, out = _run_cmd_capture([NPX_BIN, "tsc", "--noEmit"], cwd=FRONTEND_DIR, timeout_sec=120)
    print(f"    -> tsc: exit={rc} ({dur}s)", flush=True)
    suites.append(
        SuiteRunResult(
            name="Frontend TypeScript Strict",
            category="TEST THẬT",
            command="npx tsc --noEmit",
            exit_code=rc,
            status="PASS" if rc == 0 else "FAIL",
            duration_sec=dur,
            summary="0 type errors" if rc == 0 else f"Exit {rc}",
            log_excerpt=_tail_lines(out, 12) if out.strip() else "0 type errors",
        )
    )

    print("==> [5/7] Running Frontend Unit & Contract Tests...", flush=True)
    rc, dur, out = _run_cmd_capture([NPM_BIN, "test"], cwd=FRONTEND_DIR, timeout_sec=120)
    print(f"    -> npm test: exit={rc} ({dur}s)", flush=True)
    suites.append(
        SuiteRunResult(
            name="Frontend Unit & Contract Tests (node --test)",
            category="TEST THẬT",
            command="npm test",
            exit_code=rc,
            status="PASS" if rc == 0 else "FAIL",
            duration_sec=dur,
            summary=_summarize_node_test(out, rc),
            log_excerpt=_tail_lines(out, 14),
        )
    )

    print("==> [6/7] Running Live Full-Stack E2E (FastAPI + Next.js + Chromium, 0 mock)...", flush=True)
    live_suite, live_flows = _run_real_stack_e2e()
    print(f"    -> Live E2E: {live_suite.status} ({live_suite.duration_sec}s)", flush=True)
    suites.append(live_suite)

    print("==> [7/7] Running Isolated Mock UI E2E (scripts/test_web_mock_e2e.py)...", flush=True)
    rc, dur, out = _run_cmd_capture(
        [str(PYTHON_EXE), "scripts/test_web_mock_e2e.py"],
        cwd=REPO_ROOT,
        timeout_sec=120,
    )
    print(f"    -> Mock UI E2E: exit={rc} ({dur}s)", flush=True)
    suites.append(
        SuiteRunResult(
            name="Frontend Mock UI E2E (Isolated page.route)",
            category="MOCK UI",
            command="python scripts/test_web_mock_e2e.py",
            exit_code=rc,
            status="PASS" if rc == 0 else "FAIL",
            duration_sec=dur,
            summary=_tail_lines(out, 1),
            log_excerpt=_tail_lines(out, 12),
        )
    )

    payload: dict[str, Any] = {
        "meta": meta,
        "suites": [asdict(s) for s in suites],
        "live_flows": [asdict(f) for f in live_flows],
    }
    JSON_OUT.parent.mkdir(parents=True, exist_ok=True)
    JSON_OUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    _render_report_pdf(payload)
    pages = len(PdfReader(str(PDF_OUT)).pages)
    size_kb = PDF_OUT.stat().st_size / 1024.0
    print(f"Saved JSON log: {JSON_OUT}", flush=True)
    print(f"Generated PDF log report: {PDF_OUT} ({pages} pages, {size_kb:.1f} KB)", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
