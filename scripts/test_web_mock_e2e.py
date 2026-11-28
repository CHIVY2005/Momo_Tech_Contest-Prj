"""End-to-end Playwright mock verification for web input workbench and chatbot flows."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import shutil
import struct
import subprocess
import sys
import time
import zlib
from email.parser import BytesParser
from email.policy import default as email_default_policy
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from playwright.sync_api import (
    Browser,
    Page,
    Playwright,
    Route,
    expect,
    sync_playwright,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIR = REPO_ROOT / "frontend"


def _make_tiny_png() -> bytes:
    """Create a minimal valid 1x1 PNG image without external dependencies."""

    def chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack("!I", len(data)) + tag + data + struct.pack("!I", crc)

    ihdr = struct.pack("!IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\xaa\x00")
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _parse_multipart(content_type: str, body: bytes) -> tuple[dict[str, list[str]], list[str]]:
    """Extract text form fields and uploaded filenames from a multipart/form-data payload."""
    fields: dict[str, list[str]] = {}
    filenames: list[str] = []
    header = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode()
    msg = BytesParser(policy=email_default_policy).parsebytes(header + body)
    if not msg.is_multipart():
        return fields, filenames
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        filename = part.get_filename()
        if filename:
            filenames.append(filename)
            continue
        payload = part.get_payload(decode=True)
        val = payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else ""
        fields.setdefault(str(name), []).append(val)
    return fields, filenames


def _build_scam_report() -> dict[str, Any]:
    return {
        "case_id": "vs_e2e_wallet_scam_0123456789abcdef",
        "created_at": "2026-11-28T05:15:00Z",
        "mode": "wallet_transfer",
        "in_active_call": True,
        "risk_score": 88,
        "verdict": "CRITICAL_SCAM",
        "confidence": 0.94,
        "degraded_mode": False,
        "safety_advisory_detected": False,
        "prompt_injection_detected": False,
        "active_block_rule_hit": False,
        "receipt_verification_status": "NOT_APPLICABLE",
        "summary_vi": (
            "Cảnh báo rủi ro rất cao: nội dung giả danh công an gọi điện thúc ép chuyển tiền "
            "qua đường dẫn giả mạo."
        ),
        "transcript": None,
        "classifier": {
            "available": True,
            "predicted_label": "SCAM_IMPERSONATION",
            "scam_probability": 0.96,
            "advisory_probability": 0.01,
            "injection_probability": 0.0,
            "class_probabilities": {"SCAM_IMPERSONATION": 0.96},
            "latency_ms": 11,
        },
        "matched_playbooks": ["Giả danh Công an / Yêu cầu chuyển tiền tạm giữ"],
        "manipulation_tactics": ["Đe dọa pháp lý khẩn cấp", "Thúc ép giữ bí mật cuộc gọi"],
        "highlighted_phrases": ["chuyển 15.000.000", "tạm giữ xác minh"],
        "iocs": {
            "phones": ["091****678"],
            "bank_accounts": ["8800****56"],
            "urls": ["https://dichvucong-giamao.top/xac-minh"],
            "domains": ["dichvucong-giamao.top"],
            "brands": [],
        },
        "vietqr_findings": [],
        "url_findings": [
            {
                "url": "https://dichvucong-giamao.top/xac-minh",
                "domain": "dichvucong-giamao.top",
                "normalized_ascii_domain": "dichvucong-giamao.top",
                "final_url": "https://dichvucong-giamao.top/xac-minh",
                "redirect_hops": 0,
                "is_blocked_ssrf": False,
                "is_idn_homoglyph": False,
                "spoofed_brand": None,
                "urlhaus_listed": False,
                "risk_points": 68,
                "reasons": ["Tên miền giả mạo cổng dịch vụ công."],
            }
        ],
        "sandbox": None,
        "image_forensics": None,
        "image_forensics_list": [],
        "receipt_logic": None,
        "evidence": [
            {
                "source": "url_inspector",
                "severity": "CRITICAL",
                "title": "Phát hiện rủi ro từ đường dẫn trang web",
                "detail": "Tên miền có dấu hiệu giả mạo cơ quan chức năng.",
                "snippet": "https://dichvucong-giamao.top/xac-minh",
            }
        ],
        "actions": {
            "counter_replies": [
                "Tôi sẽ tự liên hệ công an địa phương hoặc tổng đài chính thức, không chuyển tiền."
            ],
            "family_shield_message": (
                "[Cảnh báo từ VeriShield AI] Cả nhà cảnh giác thủ đoạn giả danh công an gọi điện "
                "thúc chuyển tiền (mức rủi ro 88/100)."
            ),
            "urgent_steps": [
                "Ngắt cuộc gọi ngay và không cung cấp mã OTP.",
                (
                    "Tải báo cáo bằng chứng PDF để lưu lại thông tin khi cần trình báo "
                    "cơ quan công an."
                ),
            ],
            "merchant_balance_warning": None,
            "pre_transfer": {
                "should_hold_transfer": True,
                "cooling_off_seconds": 30,
                "triggered_by_active_call": True,
                "blocked_by_ops_rule": False,
                "warning_headline": (
                    "Tạm dừng để kiểm tra 30 giây — hãy bình tĩnh xác minh lại khi đang nghe "
                    "cuộc gọi thúc ép chuyển tiền"
                ),
                "verification_questions": [
                    "Người yêu cầu chuyển tiền có đang giục gấp hoặc yêu cầu giữ bí mật không?",
                    "Bạn đã gọi lại bằng số điện thoại chính thống để kiểm chứng chưa?",
                ],
            },
        },
        "trace": [],
        "community_hits": 0,
        "llm_provider": "gemini",
        "llm_model": "gemini-2.5-flash",
        "llm_latency_ms": 380,
    }


def _build_merchant_report() -> dict[str, Any]:
    return {
        "case_id": "vs_e2e_merchant_safe_0123456789abcd",
        "created_at": "2026-11-28T05:16:00Z",
        "mode": "merchant",
        "in_active_call": False,
        "risk_score": 12,
        "verdict": "SAFE",
        "confidence": 0.91,
        "degraded_mode": False,
        "safety_advisory_detected": False,
        "prompt_injection_detected": False,
        "active_block_rule_hit": False,
        "receipt_verification_status": "UNVERIFIED_SCREENSHOT",
        "summary_vi": (
            "Ảnh chụp biên lai chưa ghi nhận dấu hiệu chỉnh sửa, nhưng hệ thống không thể xác "
            "nhận tiền đã vào tài khoản chỉ từ ảnh chụp. Chỉ giao hàng sau khi kiểm tra trực "
            "tiếp biến động số dư trên ứng dụng ngân hàng hoặc loa thông báo nhận tiền."
        ),
        "transcript": None,
        "classifier": {
            "available": True,
            "predicted_label": "SAFE_NORMAL",
            "scam_probability": 0.04,
            "advisory_probability": 0.03,
            "injection_probability": 0.0,
            "class_probabilities": {"SAFE_NORMAL": 0.93},
            "latency_ms": 9,
        },
        "matched_playbooks": [],
        "manipulation_tactics": [],
        "highlighted_phrases": [],
        "iocs": {
            "phones": [],
            "bank_accounts": ["19****22"],
            "urls": [],
            "domains": [],
            "brands": ["Techcombank"],
        },
        "vietqr_findings": [],
        "url_findings": [],
        "sandbox": None,
        "image_forensics": None,
        "image_forensics_list": [],
        "receipt_logic": {
            "is_receipt_candidate": True,
            "bank_detected": "Techcombank",
            "reference_code": "FT26331000123",
            "reference_valid": True,
            "timestamp_checked": True,
            "timestamp_anomaly": False,
            "amount_checked": True,
            "amount_format_anomaly": False,
            "geometry_checked": True,
            "geometry_anomaly": False,
            "beneficiary_checked": True,
            "beneficiary_mismatch": False,
            "extracted_recipient_account": "19****22",
            "replay_checked": True,
            "is_replayed": False,
            "verification_status": "UNVERIFIED_SCREENSHOT",
            "logic_risk_points": 0,
            "reasons": [],
        },
        "evidence": [],
        "actions": {
            "counter_replies": [],
            "family_shield_message": "",
            "urgent_steps": [
                "Kiểm tra trực tiếp biến động số dư trước khi giao hàng cho khách."
            ],
            "merchant_balance_warning": (
                "Lưu ý bắt buộc cho người bán: Ảnh chụp màn hình biên lai không phải bằng chứng "
                "tiền đã vào tài khoản. Chỉ giao hàng sau khi kiểm tra trực tiếp biến động số dư "
                "trên ứng dụng ngân hàng hoặc loa thông báo nhận tiền."
            ),
            "pre_transfer": {
                "should_hold_transfer": False,
                "cooling_off_seconds": 0,
                "triggered_by_active_call": False,
                "blocked_by_ops_rule": False,
                "warning_headline": "",
                "verification_questions": [],
            },
        },
        "trace": [],
        "community_hits": 0,
        "llm_provider": "gemini",
        "llm_model": "gemini-2.5-flash",
        "llm_latency_ms": 290,
    }


def _sse_bytes(events: list[tuple[str, dict[str, Any]]]) -> bytes:
    frames = "".join(
        f"event: {ev}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n" for ev, data in events
    )
    return frames.encode("utf-8")


def _wait_for_http_ready(url: str, timeout_s: float = 30.0) -> None:
    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 80
    path = parsed.path or "/"
    deadline = time.monotonic() + timeout_s
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
    raise RuntimeError(f"Timed out waiting for server at {url}")


def _terminate_process_tree(proc: subprocess.Popen[bytes] | subprocess.Popen[str]) -> None:
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
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


def _install_api_mocks(page: Page, state: dict[str, Any]) -> None:
    def handle_route(route: Route) -> None:
        req = route.request
        path = urlparse(req.url).path

        if path == "/api/v1/health":
            route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps(
                    {
                        "status": "ok",
                        "service": "verishield-api",
                        "version": "2.0.0",
                        "onnx_classifier_loaded": True,
                        "gemini_configured": True,
                        "playbooks_count": 20,
                    }
                ),
            )
            return

        if path == "/api/v1/demos":
            route.fulfill(status=200, content_type="application/json", body="[]")
            return

        if path == "/api/v1/analyze/stream":
            ctype = req.headers.get("content-type", "")
            raw_body = req.post_data_buffer or b""
            fields, filenames = _parse_multipart(ctype, raw_body)
            state["analyze_requests"].append({"fields": fields, "filenames": filenames})

            req_mode = (fields.get("mode") or ["personal"])[0]
            if req_mode == "merchant":
                report = _build_merchant_report()
                token = "tok_e2e_merchant_safe_12"  # noqa: S105
            else:
                report = _build_scam_report()
                token = "tok_e2e_wallet_scam_88"  # noqa: S105

            sse = _sse_bytes(
                [
                    (
                        "trace",
                        {
                            "step_id": "media_forensics",
                            "title": "Phân tích tính xác thực của hình ảnh, mã QR và ghi âm",
                            "status": "done",
                            "detail": "Đã kiểm tra dữ liệu đính kèm.",
                            "duration_ms": 12,
                        },
                    ),
                    (
                        "trace",
                        {
                            "step_id": "cyber_guardrails",
                            "title": "Kiểm tra đường dẫn đáng ngờ và danh sách chặn",
                            "status": "warning" if req_mode != "merchant" else "done",
                            "detail": "Đã kiểm tra đường dẫn và dấu hiệu.",
                            "duration_ms": 21,
                        },
                    ),
                    (
                        "trace",
                        {
                            "step_id": "onnx_and_kb",
                            "title": "Đối chiếu nội dung với các kịch bản lừa đảo phổ biến",
                            "status": "done",
                            "detail": "Đã phân loại ngữ cảnh.",
                            "duration_ms": 11,
                        },
                    ),
                    (
                        "trace",
                        {
                            "step_id": "multimodal_calibration",
                            "title": "Tổng hợp bằng chứng và đánh giá mức độ rủi ro",
                            "status": "done",
                            "detail": f"Mức độ rủi ro: {report['risk_score']}/100",
                            "duration_ms": 290,
                        },
                    ),
                    (
                        "session",
                        {
                            "case_id": report["case_id"],
                            "case_access_token": token,
                            "expires_at": "2026-11-28T07:15:00Z",
                        },
                    ),
                    ("result", report),
                ]
            )
            route.fulfill(status=200, content_type="text/event-stream; charset=utf-8", body=sse)
            return

        if path == "/api/v1/assistant/chat/stream":
            payload = json.loads(req.post_data or "{}")
            token = req.headers.get("x-case-access-token")
            state["chat_requests"].append({"token": token, "payload": payload})
            turn_idx = len(state["chat_requests"])
            sse = _sse_bytes(
                [
                    ("status", {"phase": "retrieving", "label": "Đang đối chiếu hồ sơ..."}),
                    (
                        "tool_status",
                        {
                            "tool": "check_url_safety",
                            "state": "done",
                            "label": "Đã kiểm tra đường dẫn an toàn",
                        },
                    ),
                    (
                        "safety_notice",
                        {
                            "code": "OFFICIAL_VERIFY_ONLY",
                            "message": "Luôn tự xác minh qua kênh chính thức trước khi chuyển tiền.",
                        },
                    ),
                    (
                        "delta",
                        {
                            "text": (
                                f"### Phản hồi lượt {turn_idx}\n"
                                "- **Tuyệt đối không chuyển tiền tạm giữ** qua cuộc gọi.\n"
                                "- Ngắt máy ngay và đối chiếu qua tổng đài chính thức."
                            )
                        },
                    ),
                    (
                        "citation",
                        {
                            "items": [
                                {
                                    "id": "KB:sop_impersonation",
                                    "source_type": "kb",
                                    "title": "Quy trình ứng phó giả danh công an",
                                }
                            ]
                        },
                    ),
                    (
                        "done",
                        {
                            "degraded_mode": False,
                            "output_tier": 1,
                            "suggested_followups": ["Cách báo cáo số tài khoản đáng ngờ?"],
                        },
                    ),
                ]
            )
            route.fulfill(status=200, content_type="text/event-stream; charset=utf-8", body=sse)
            return

        if path == "/api/v1/assistant/chat/evidence/stream":
            ctype = req.headers.get("content-type", "")
            raw_body = req.post_data_buffer or b""
            fields, filenames = _parse_multipart(ctype, raw_body)
            state["evidence_requests"].append(
                {
                    "token": req.headers.get("x-case-access-token"),
                    "fields": fields,
                    "filenames": filenames,
                }
            )
            sse = _sse_bytes(
                [
                    (
                        "status",
                        {"phase": "verifying", "label": "Đang phân tích cục bộ bằng chứng bổ sung..."},
                    ),
                    (
                        "evidence_report",
                        {
                            "draft_id": "drf_e2e_extra_99",
                            "can_contribute_radar": True,
                            "risk_score": 84,
                            "verdict": "CRITICAL_SCAM",
                            "receipt_verification_status": "NOT_APPLICABLE",
                            "summary_vi": "Ảnh bổ sung chứa nội dung yêu cầu chuyển khoản khẩn cấp.",
                        },
                    ),
                    (
                        "delta",
                        {"text": "Bằng chứng bổ sung đã được xử lý hoàn toàn cục bộ trên máy chủ."},
                    ),
                    (
                        "done",
                        {"degraded_mode": False, "output_tier": 0, "suggested_followups": []},
                    ),
                ]
            )
            route.fulfill(status=200, content_type="text/event-stream; charset=utf-8", body=sse)
            return

        if path == "/api/v1/assistant/evidence/drf_e2e_extra_99/persist":
            payload = json.loads(req.post_data or "{}")
            state["persist_requests"].append(
                {"token": req.headers.get("x-case-access-token"), "payload": payload}
            )
            route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps(
                    {
                        "child_case_id": "vs_child_e2e_99",
                        "child_case_access_token": "tok_child_e2e_99",
                        "expires_at": "2026-11-28T07:15:00Z",
                        "contributed_to_radar": bool(payload.get("contribute_to_radar", False)),
                        "parent_case_id": payload.get("case_id", ""),
                    }
                ),
            )
            return

        if path.endswith("/report.pdf"):
            state["pdf_requests"].append(
                {"path": path, "token": req.headers.get("x-case-access-token")}
            )
            route.fulfill(
                status=200,
                headers={
                    "Content-Type": "application/pdf",
                    "Content-Disposition": 'attachment; filename="VeriShield_vs_child_e2e_99.pdf"',
                },
                body=b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n",
            )
            return

        route.abort()

    page.route("**/api/v1/**", handle_route)


def _launch_chromium(pw: Playwright) -> Browser:
    """Launch default Playwright Chromium or fall back to a cached local Playwright binary."""
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
    return pw.chromium.launch(headless=True)


def run_browser_e2e(base_url: str) -> None:
    """Execute interactive input-workbench and chatbot mock scenarios in Chromium."""
    state: dict[str, Any] = {
        "analyze_requests": [],
        "chat_requests": [],
        "evidence_requests": [],
        "persist_requests": [],
        "pdf_requests": [],
    }
    tiny_png = _make_tiny_png()
    page_errors: list[str] = []

    with sync_playwright() as pw:
        browser = _launch_chromium(pw)
        context = browser.new_context(viewport={"width": 1280, "height": 900}, accept_downloads=True)
        page = context.new_page()
        page.on("pageerror", lambda err: page_errors.append(str(err)))
        _install_api_mocks(page, state)

        page.goto(base_url, wait_until="networkidle")

        # Scenario 1: Input workbench scam flow (text + URL + PNG + extra fields -> wallet_transfer)
        composer = page.get_by_label("Tin nhắn, đường dẫn hoặc tệp đính kèm")
        composer.fill(
            "Công an yêu cầu chuyển 15.000.000đ qua https://dichvucong-giamao.top/xac-minh ngay"
        )
        expect(page.get_by_text("Tự phát hiện 1 đường dẫn:")).to_be_visible()

        img_input = page.locator('input[aria-label="Chọn hình ảnh đính kèm"]')
        img_input.set_input_files(
            {"name": "mock-scam-bill.png", "mimeType": "image/png", "buffer": tiny_png}
        )
        expect(page.get_by_text("mock-scam-bill.png")).to_be_visible()

        page.get_by_role("button", name="Thông tin giao dịch bổ sung (tùy chọn)").click()
        amount_input = page.locator("#wb-transfer-amount")
        amount_input.fill("15000000")
        expect(amount_input).to_have_value("15.000.000")
        page.locator("#wb-active-call-toggle").click()

        page.get_by_role("button", name="Kiểm tra ngay").click()

        expect(page.locator("#verdict-heading")).to_contain_text("giả danh công an")
        expect(
            page.get_by_text("Cảnh báo rủi ro rất cao — có nhiều dấu hiệu lừa đảo")
        ).to_be_visible()
        expect(page.get_by_text("Độ tin cậy")).to_be_visible()
        expect(page.get_by_text("0–24 · Thấp")).to_be_visible()
        expect(page.get_by_text("80–100 · Rất cao")).to_be_visible()
        expect(
            page.get_by_text("Tạm dừng 30 giây để kiểm tra trước khi chuyển tiền")
        ).to_be_visible()
        expect(
            page.get_by_text("Đã ghi nhận dấu hiệu đáng ngờ vào hệ thống giám sát")
        ).to_be_visible()

        page.locator("details summary", has_text="Thông tin kỹ thuật").click()
        expect(
            page.get_by_text("Giả mạo cơ quan nhà nước, công an hoặc ngân hàng")
        ).to_be_visible()
        assert "SCAM_IMPERSONATION" not in page.locator("#verdict-result").inner_text()

        assert len(state["analyze_requests"]) == 1
        req1 = state["analyze_requests"][0]
        assert req1["fields"]["mode"] == ["wallet_transfer"]
        assert req1["fields"]["transfer_amount"] == ["15000000"]
        assert req1["fields"]["in_active_call"] == ["true"]
        assert "mock-scam-bill.png" in req1["filenames"]
        print("[PASS] Scenario 1: Input workbench -> wallet_transfer mock result")

        # Scenario 2: Chatbot multi-turn Q&A, follow-up, local evidence upload, persist & PDF
        page.get_by_role("button", name="Hỏi Trợ lý VeriShield").first.click()
        dialog = page.get_by_role("dialog")
        expect(dialog).to_be_visible()
        expect(dialog.get_by_text("88/100").first).to_be_visible()

        chat_input = dialog.locator("#assistant-composer-input")
        chat_input.fill("Vì sao cảnh báo rủi ro rất cao?")
        dialog.get_by_role("button", name="Gửi câu hỏi").click()

        expect(dialog.get_by_text("Phản hồi lượt 1")).to_be_visible()
        expect(dialog.get_by_text("Tuyệt đối không chuyển tiền tạm giữ")).to_be_visible()
        expect(dialog.get_by_text("Quy trình ứng phó giả danh công an")).to_be_visible()

        followup_btn = dialog.get_by_role("button", name="Cách báo cáo số tài khoản đáng ngờ?")
        expect(followup_btn).to_be_visible()
        followup_btn.click()

        expect(dialog.get_by_text("Phản hồi lượt 2")).to_be_visible()
        assert len(state["chat_requests"]) == 2
        assert state["chat_requests"][0]["token"] == "tok_e2e_wallet_scam_88"  # noqa: S105
        assert len(state["chat_requests"][1]["payload"]["history"]) == 2

        ev_input = dialog.locator('input[aria-label="Chọn ảnh hoặc tệp ghi âm bổ sung"]')
        ev_input.set_input_files(
            {"name": "extra-evidence.png", "mimeType": "image/png", "buffer": tiny_png}
        )
        opt_in = dialog.locator("#assistant-external-media-optin")
        expect(opt_in).not_to_be_checked()
        chat_input.fill("Kiểm tra thêm ảnh này giúp tôi")
        dialog.get_by_role("button", name="Gửi câu hỏi").click()

        expect(dialog.get_by_text("Chưa lưu vào hệ thống — chỉ tạm giữ 15 phút")).to_be_visible()
        assert len(state["evidence_requests"]) == 1
        assert state["evidence_requests"][0]["fields"]["allow_external_media_ai"] == ["false"]
        assert "extra-evidence.png" in state["evidence_requests"][0]["filenames"]

        with page.expect_download() as download_info:
            dialog.get_by_role("button", name="Lưu hồ sơ bổ sung & tải PDF").click()
        download = download_info.value
        assert "VeriShield_vs_child_e2e_99.pdf" in download.suggested_filename
        expect(dialog.get_by_text("Đã lưu hồ sơ bổ sung")).to_be_visible()
        assert len(state["persist_requests"]) == 1
        assert len(state["pdf_requests"]) == 1

        dialog.get_by_role("button", name="Xóa hội thoại").click()
        expect(dialog.get_by_text("Xin chào, mình là Trợ lý VeriShield.")).to_be_visible()
        dialog.get_by_role("button", name="Đóng Trợ lý VeriShield").click()
        expect(dialog).to_be_hidden()
        print("[PASS] Scenario 2: Chatbot multi-turn, local evidence, persist & PDF download")

        # Scenario 3: Merchant SAFE receipt flow + Merchant Honesty Guardrail
        page.get_by_role("button", name="Chỉnh sửa thông tin").click()
        page.locator("#wb-merchant-stk").fill("190311112222")
        page.locator("#wb-transfer-amount").fill("")
        page.locator("#wb-active-call-toggle").click()
        composer.fill("Khách gửi ảnh biên lai chuyển khoản Techcombank FT26331000123")
        page.get_by_role("button", name="Kiểm tra ngay").click()

        expect(page.get_by_text("Chưa phát hiện dấu hiệu bất thường")).to_be_visible()
        expect(
            page.get_by_text("Chưa thể xác nhận tiền đã vào tài khoản từ ảnh chụp").first
        ).to_be_visible()
        expect(page.get_by_text("Đã lưu hồ sơ kiểm tra ẩn thông tin cá nhân")).to_be_visible()

        req2 = state["analyze_requests"][1]
        assert req2["fields"]["mode"] == ["merchant"]
        assert req2["fields"]["expected_merchant_account"] == ["190311112222"]

        page.get_by_role("button", name="Hỏi Trợ lý VeriShield").first.click()
        expect(dialog.get_by_test_id("merchant-honesty-banner")).to_be_visible()
        dialog.get_by_role("button", name="Đóng Trợ lý VeriShield").click()
        print("[PASS] Scenario 3: Merchant SAFE flow + Honesty Guardrail in dashboard & chatbot")

        # Scenario 4: Invalid attachment validation notice in composer
        page.get_by_role("button", name="Chỉnh sửa thông tin").click()
        page.locator('input[aria-label="Chọn hình ảnh đính kèm"]').set_input_files(
            {"name": "bad.svg", "mimeType": "image/svg+xml", "buffer": b"<svg></svg>"}
        )
        err_alert = page.locator('[role="alert"]', has_text="chưa được hỗ trợ")
        expect(err_alert).to_be_visible()
        expect(err_alert).to_contain_text("WebM")
        print("[PASS] Scenario 4: Invalid SVG attachment rejected with Vietnamese WebM error")

        assert not page_errors, f"Uncaught page errors detected: {page_errors}"
        context.close()
        browser.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run mocked Playwright E2E tests for web UI.")
    parser.add_argument("--base-url", default="", help="Optional running frontend URL.")
    parser.add_argument("--port", type=int, default=3099, help="Port for temporary next start.")
    args = parser.parse_args()

    proc: subprocess.Popen[bytes] | None = None
    try:
        if args.base_url.strip():
            target_url = args.base_url.strip().rstrip("/") + "/"
        else:
            npm_bin = "npm.cmd" if os.name == "nt" else "npm"
            proc = subprocess.Popen(  # noqa: S603
                [npm_bin, "run", "start", "--", "--port", str(args.port)],
                cwd=str(FRONTEND_DIR),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
            )
            target_url = f"http://127.0.0.1:{args.port}/"
            _wait_for_http_ready(target_url, timeout_s=30.0)

        run_browser_e2e(target_url)
        print("ALL WEB MOCK E2E SCENARIOS PASSED!")
        return 0
    finally:
        if proc is not None:
            _terminate_process_tree(proc)


if __name__ == "__main__":
    sys.exit(main())
