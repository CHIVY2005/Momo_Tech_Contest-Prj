"""Unit tests for VeriShield AI multimodal Telegram Bot (commands, /demo, /call, HTML & callbacks)."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from PIL import Image

from app.config import Settings
from app.db.repository import CaseRepository
from app.main import create_app
from app.services.pipeline import AnalysisPipeline
from app.services.telegram_bot import _deliver_telegram_message, handle_telegram_update
from app.services.telegram_media import (
    TELEGRAM_MAX_TEXT_LEN,
    TelegramMediaFetchError,
    build_verdict_inline_keyboard,
    download_telegram_file,
    extract_telegram_attachment,
    truncate_telegram_text,
)


def _make_png_bytes(width: int = 120, height: int = 120) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (width, height), color=(18, 28, 48)).save(buf, format="PNG")
    return buf.getvalue()


def _make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    params: dict[str, Any] = {
        "_env_file": None,
        "sqlite_path": str(tmp_path / "tg_unit.db"),
        "gemini_api_key": "",
        "gemini_backup_api_key": "",
        "telegram_bot_token": "999888:SYNTHETIC_BOT_TOKEN",
        "telegram_webhook_secret": "tg_unit_secret_999",
        "public_base_url": "https://verishield.joiboi.app",
        "enable_live_network_checks": False,
        "enable_playwright_sandbox": False,
        "enable_local_ocr": False,
        "enable_local_stt": False,
        "max_upload_bytes": 1024 * 1024,
    }
    params.update(overrides)
    return Settings(**params)


@pytest.mark.asyncio
async def test_telegram_slash_commands_skip_pipeline_and_emit_clean_html(tmp_path: Path) -> None:
    cfg = _make_settings(tmp_path)
    repo = CaseRepository(cfg.sqlite_path)
    repo.init_db()
    pipe = AnalysisPipeline(settings=cfg, repo=repo)
    sent_bodies: list[dict[str, Any]] = []

    def _capture(request: httpx.Request) -> httpx.Response:
        sent_bodies.append(json.loads(request.content.decode("utf-8")))
        return httpx.Response(200, json={"ok": True, "result": {"message_id": len(sent_bodies)}})

    with respx.mock(assert_all_called=False) as router:
        router.post("https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/sendMessage").mock(
            side_effect=_capture
        )

        res_start = await handle_telegram_update(
            {"update_id": 101, "message": {"chat": {"id": 5001}, "text": "/start@verishieldvnbot"}},
            pipe,
            cfg,
        )
        res_help = await handle_telegram_update(
            {"update_id": 102, "message": {"chat": {"id": 5001}, "text": "/help"}},
            pipe,
            cfg,
        )
        res_bill = await handle_telegram_update(
            {"update_id": 103, "message": {"chat": {"id": 5001}, "text": "/bill"}},
            pipe,
            cfg,
        )
        res_call = await handle_telegram_update(
            {"update_id": 104, "message": {"chat": {"id": 5001}, "text": "/call"}},
            pipe,
            cfg,
        )
        res_demo = await handle_telegram_update(
            {"update_id": 105, "message": {"chat": {"id": 5001}, "text": "/demo"}},
            pipe,
            cfg,
        )

    assert len(sent_bodies) == 5
    for res in (res_start, res_help, res_bill, res_call, res_demo):
        assert "case_id" not in res
        assert "`" not in res["reply_text"]  # No raw markdown backticks in HTML mode

    assert "Chào mừng" in res_start["reply_text"]
    assert "Hướng dẫn sử dụng" in res_help["reply_text"]
    assert "<code>/bill 190311112222</code>" in res_bill["reply_text"]
    assert "/call" in res_call["reply_text"]

    # /start and /demo attach 5 1-Click Demo inline buttons
    start_kb = sent_bodies[0]["reply_markup"]["inline_keyboard"]
    demo_kb = sent_bodies[4]["reply_markup"]["inline_keyboard"]
    assert len(start_kb) == 5
    assert len(demo_kb) == 5
    assert demo_kb[0][0]["callback_data"].startswith("demo:")
    assert sent_bodies[0]["parse_mode"] == "HTML"
    # Slash guidance commands must never pollute the Fraud Ops graph with junk cases
    assert repo.get_radar_graph().stats["total_cases"] == 0


@pytest.mark.asyncio
async def test_telegram_demo_callback_and_call_command_run_full_pipeline(tmp_path: Path) -> None:
    cfg = _make_settings(tmp_path)
    repo = CaseRepository(cfg.sqlite_path)
    repo.init_db()
    pipe = AnalysisPipeline(settings=cfg, repo=repo)
    sent_bodies: list[dict[str, Any]] = []

    def _capture(request: httpx.Request) -> httpx.Response:
        sent_bodies.append(json.loads(request.content.decode("utf-8")))
        return httpx.Response(200, json={"ok": True, "result": {"message_id": len(sent_bodies)}})

    with respx.mock(assert_all_called=False) as router:
        ack_route = router.post(
            "https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/answerCallbackQuery"
        ).mock(return_value=httpx.Response(200, json={"ok": True, "result": True}))
        router.post("https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/sendChatAction").mock(
            return_value=httpx.Response(200, json={"ok": True, "result": True})
        )
        router.post("https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/sendMessage").mock(
            side_effect=_capture
        )

        # 1. Tap 1-Click Demo inline button (callback_query -> demo_zalo_fake_bill)
        cb_res = await handle_telegram_update(
            {
                "update_id": 150,
                "callback_query": {
                    "id": "cbq_77",
                    "data": "demo:demo_zalo_fake_bill",
                    "message": {"chat": {"id": 6001}},
                },
            },
            pipe,
            cfg,
        )
        assert ack_route.called is True
        assert cb_res["ok"] is True and cb_res["delivered"] is True
        assert cb_res["case_id"].startswith("vs_")
        assert "⚠️" in cb_res["reply_text"]
        assert f"<code>{cb_res['case_id']}</code>" in cb_res["reply_text"]

        # 2. /demo 1 numeric shortcut
        num_res = await handle_telegram_update(
            {"update_id": 151, "message": {"chat": {"id": 6001}, "text": "/demo 1"}},
            pipe,
            cfg,
        )
        assert num_res["delivered"] is True and num_res["risk_score"] >= 55

        # 3. /call active-call wallet_transfer coercion with HTML special chars
        call_res = await handle_telegram_update(
            {
                "update_id": 152,
                "message": {
                    "chat": {"id": 6001},
                    "text": (
                        "/call <script>& Công an điều tra yêu cầu chuyển gấp 15.000.000 VND "
                        "vào STK 999888777666 và giữ máy bí mật"
                    ),
                },
            },
            pipe,
            cfg,
        )
        assert call_res["delivered"] is True
        assert call_res["risk_score"] >= 55
        assert "Tạm dừng để kiểm tra 30 giây" in call_res["reply_text"]
        assert "<script>" not in call_res["reply_text"]


@pytest.mark.asyncio
async def test_telegram_photo_with_bill_command_downloads_media_and_sends_pdf_keyboard(
    tmp_path: Path,
) -> None:
    cfg = _make_settings(tmp_path)
    repo = CaseRepository(cfg.sqlite_path)
    repo.init_db()
    pipe = AnalysisPipeline(settings=cfg, repo=repo)
    png_bytes = _make_png_bytes()
    captured_send_bodies: list[dict[str, Any]] = []

    def _capture_send(request: httpx.Request) -> httpx.Response:
        captured_send_bodies.append(json.loads(request.content.decode("utf-8")))
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 42}})

    with respx.mock(assert_all_called=False) as router:
        router.post("https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/sendChatAction").mock(
            return_value=httpx.Response(500, json={"ok": False})
        )
        router.get("https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/getFile").mock(
            return_value=httpx.Response(
                200,
                json={
                    "ok": True,
                    "result": {
                        "file_id": "PHOTO_HI_RES",
                        "file_size": len(png_bytes),
                        "file_path": "photos/file_77.png",
                    },
                },
            )
        )
        router.get(
            "https://api.telegram.org/file/bot999888:SYNTHETIC_BOT_TOKEN/photos/file_77.png"
        ).mock(return_value=httpx.Response(200, content=png_bytes))
        router.post("https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/sendMessage").mock(
            side_effect=_capture_send
        )

        res = await handle_telegram_update(
            {
                "update_id": 201,
                "message": {
                    "chat": {"id": 8801},
                    "caption": "/bill 190311112222 Khách gửi biên lai chuyển 5.000.000 VND",
                    "photo": [
                        {"file_id": "PHOTO_THUMB", "file_size": 500},
                        {"file_id": "PHOTO_HI_RES", "file_size": len(png_bytes)},
                    ],
                },
            },
            pipe,
            cfg,
        )

    assert res["ok"] is True
    assert res["delivered"] is True
    assert res["case_id"].startswith("vs_")
    assert "⚠️" in res["reply_text"]
    assert len(captured_send_bodies) == 1
    sent = captured_send_bodies[0]
    keyboard = sent["reply_markup"]["inline_keyboard"]
    expected_pdf = f"https://verishield.joiboi.app/api/v1/cases/{res['case_id']}/report.pdf"
    assert keyboard[0][0]["url"] == expected_pdf


@pytest.mark.asyncio
async def test_telegram_oversize_corrupt_and_html_parse_fallback(tmp_path: Path) -> None:
    cfg = _make_settings(tmp_path, max_upload_bytes=2048)
    repo = CaseRepository(cfg.sqlite_path)
    repo.init_db()
    pipe = AnalysisPipeline(settings=cfg, repo=repo)

    with respx.mock(assert_all_called=False) as router:
        router.post("https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/sendChatAction").mock(
            return_value=httpx.Response(200, json={"ok": True, "result": True})
        )
        router.post("https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/sendMessage").mock(
            return_value=httpx.Response(200, json={"ok": True, "result": {"message_id": 2}})
        )

        # 1. Declared oversize voice note -> polite 10 MB guidance
        res_big = await handle_telegram_update(
            {
                "update_id": 301,
                "message": {
                    "chat": {"id": 8802},
                    "voice": {"file_id": "BIG_VOICE", "file_size": 99_999, "mime_type": "audio/ogg"},
                },
            },
            pipe,
            cfg,
        )
        assert res_big["delivered"] is True
        assert "10 MB" in res_big["reply_text"]
        assert "case_id" not in res_big

        # 2. Corrupt image bytes downloaded -> friendly format error instead of HTTP 500
        router.get("https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/getFile").mock(
            return_value=httpx.Response(
                200,
                json={
                    "ok": True,
                    "result": {
                        "file_id": "BAD_IMG",
                        "file_size": 16,
                        "file_path": "photos/bad.jpg",
                    },
                },
            )
        )
        router.get("https://api.telegram.org/file/bot999888:SYNTHETIC_BOT_TOKEN/photos/bad.jpg").mock(
            return_value=httpx.Response(200, content=b"not-a-valid-image")
        )
        res_bad = await handle_telegram_update(
            {
                "update_id": 302,
                "message": {
                    "chat": {"id": 8802},
                    "photo": [{"file_id": "BAD_IMG", "file_size": 16}],
                },
            },
            pipe,
            cfg,
        )
        assert res_bad["delivered"] is True
        assert "lỗi định dạng" in res_bad["reply_text"]

    # 3. HTML parse_entities 400 automatically retries cleanly as plain text
    calls: list[dict[str, Any]] = []

    def _html_then_plain(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        calls.append(body)
        if body.get("parse_mode") == "HTML":
            return httpx.Response(
                400,
                json={"ok": False, "description": "Bad Request: can't parse entities"},
            )
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 99}})

    with respx.mock(assert_all_called=False) as router:
        router.post("https://api.telegram.org/botTOK/sendMessage").mock(side_effect=_html_then_plain)
        await _deliver_telegram_message("TOK", 123, "<b>Test</b> fallback")
    assert len(calls) == 2
    assert calls[0].get("parse_mode") == "HTML"
    assert "parse_mode" not in calls[1]
    assert calls[1]["text"] == "Test fallback"


@pytest.mark.asyncio
async def test_telegram_media_guards_path_traversal_truncation_and_health_url(tmp_path: Path) -> None:
    with respx.mock(assert_all_called=False) as router:
        router.get("https://api.telegram.org/botTOK/getFile").mock(
            return_value=httpx.Response(
                200,
                json={"ok": True, "result": {"file_id": "X", "file_path": "../../etc/passwd"}},
            )
        )
        with pytest.raises(TelegramMediaFetchError):
            await download_telegram_file("TOK", "X", max_bytes=4096)

    img_att = extract_telegram_attachment(
        {"document": {"file_id": "D1", "file_name": "receipt.png", "mime_type": "image/png"}},
        max_bytes=10_000,
    )
    assert img_att is not None and img_att.kind == "image"
    txt_doc = {"document": {"file_id": "D2", "file_name": "notes.txt"}}
    assert extract_telegram_attachment(txt_doc, 10_000) is None

    long_out = truncate_telegram_text("A" * 5000)
    assert len(long_out) <= TELEGRAM_MAX_TEXT_LEN
    assert build_verdict_inline_keyboard("vs_1", "http://insecure.local") is None
    assert build_verdict_inline_keyboard("vs_1", "https://verishield.joiboi.app") is not None

    ok_client = TestClient(
        create_app(
            _make_settings(
                tmp_path,
                app_env="demo",
                analyst_pin="2026",
                telegram_bot_url="https://t.me/verishieldvnbot",
            )
        )
    )
    h_ok = ok_client.get("/api/v1/health").json()
    assert h_ok["telegram_bot_configured"] is True
    assert h_ok["telegram_bot_url"] == "https://t.me/verishieldvnbot"

    bad_client = TestClient(
        create_app(
            _make_settings(
                tmp_path,
                sqlite_path=str(tmp_path / "bad_url.db"),
                app_env="demo",
                analyst_pin="2026",
                telegram_bot_url="javascript:alert(1)",
            )
        )
    )
    assert bad_client.get("/api/v1/health").json()["telegram_bot_url"] is None
