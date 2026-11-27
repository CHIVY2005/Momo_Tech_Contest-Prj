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
from app.core.case_tokens import hash_telegram_private_owner
from app.db.repository import CaseRepository
from app.main import create_app
from app.services.pipeline import AnalysisPipeline
from app.services.telegram_bot import _deliver_telegram_message, handle_telegram_update
from app.services.telegram_formatting import validate_telegram_update_envelope
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
    for res, sent in zip((res_start, res_help, res_bill, res_call, res_demo), sent_bodies, strict=True):
        assert "case_id" not in res
        assert "reply_text" not in res
        assert "`" not in sent["text"]  # No raw markdown backticks in HTML mode

    assert "Chào mừng" in sent_bodies[0]["text"]
    assert "Hướng dẫn sử dụng" in sent_bodies[1]["text"]
    assert "<code>/bill 190311112222</code>" in sent_bodies[2]["text"]
    assert "/call" in sent_bodies[3]["text"]

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
        assert "reply_text" not in cb_res
        assert cb_res["case_id"].startswith("vs_")
        assert "⚠️" in sent_bodies[0]["text"]
        assert f"<code>{cb_res['case_id']}</code>" in sent_bodies[0]["text"]

        # 2. /demo 1 numeric shortcut
        num_res = await handle_telegram_update(
            {"update_id": 151, "message": {"chat": {"id": 6001}, "text": "/demo 1"}},
            pipe,
            cfg,
        )
        assert num_res["delivered"] is True and num_res["risk_score"] >= 55
        assert "reply_text" not in num_res

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
        assert "reply_text" not in call_res
        assert call_res["risk_score"] >= 55
        assert "Tạm dừng để kiểm tra 30 giây" in sent_bodies[2]["text"]
        assert "<script>" not in sent_bodies[2]["text"]


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
                    "chat": {"id": 8801, "type": "private"},
                    "from": {"id": 8801},
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
    assert "reply_text" not in res
    assert res["case_id"].startswith("vs_")
    assert len(captured_send_bodies) == 1
    sent = captured_send_bodies[0]
    assert "⚠️" in sent["text"]
    keyboard = sent["reply_markup"]["inline_keyboard"]
    assert keyboard[0][0]["callback_data"] == f"pdf:{res['case_id']}"
    assert "url" not in keyboard[0][0]
    assert "/report.pdf" not in json.dumps(sent, ensure_ascii=False)

    stored = repo.get_report_with_owner(res["case_id"])
    assert stored is not None
    assert stored.owner_channel == "telegram_private"
    assert stored.owner_chat_hash == hash_telegram_private_owner(8801, 8801, pipe.case_token_secret)


@pytest.mark.asyncio
async def test_telegram_oversize_corrupt_and_html_parse_fallback(tmp_path: Path) -> None:
    cfg = _make_settings(tmp_path, max_upload_bytes=2048)
    repo = CaseRepository(cfg.sqlite_path)
    repo.init_db()
    pipe = AnalysisPipeline(settings=cfg, repo=repo)

    sent_err_bodies: list[dict[str, Any]] = []

    def _cap_err(request: httpx.Request) -> httpx.Response:
        sent_err_bodies.append(json.loads(request.content.decode("utf-8")))
        return httpx.Response(200, json={"ok": True, "result": {"message_id": len(sent_err_bodies)}})

    with respx.mock(assert_all_called=False) as router:
        router.post("https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/sendChatAction").mock(
            return_value=httpx.Response(200, json={"ok": True, "result": True})
        )
        router.post("https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/sendMessage").mock(
            side_effect=_cap_err
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
        assert "reply_text" not in res_big
        assert "10 MB" in sent_err_bodies[0]["text"]
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
        assert "reply_text" not in res_bad
        assert "lỗi định dạng" in sent_err_bodies[1]["text"]

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
    assert build_verdict_inline_keyboard("vs_1", "http://insecure.local", allow_pdf_callback=False) is None
    kb_insecure_private = build_verdict_inline_keyboard(
        "vs_1", "http://insecure.local", allow_pdf_callback=True
    )
    assert kb_insecure_private is not None
    assert kb_insecure_private["inline_keyboard"] == [
        [{"text": "📄 Nhận báo cáo bằng chứng (PDF)", "callback_data": "pdf:vs_1"}]
    ]
    kb_https_private = build_verdict_inline_keyboard("vs_1", "https://verishield.joiboi.app")
    assert kb_https_private is not None
    assert kb_https_private["inline_keyboard"][0][0]["callback_data"] == "pdf:vs_1"
    assert "/report.pdf" not in json.dumps(kb_https_private, ensure_ascii=False)
    kb_https_group = build_verdict_inline_keyboard(
        "vs_1", "https://verishield.joiboi.app", allow_pdf_callback=False
    )
    assert kb_https_group is not None
    assert "pdf:" not in json.dumps(kb_https_group, ensure_ascii=False)

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


@pytest.mark.asyncio
async def test_telegram_private_pdf_callback_delivery_and_deduplication(tmp_path: Path) -> None:
    cfg = _make_settings(tmp_path)
    repo = CaseRepository(cfg.sqlite_path)
    repo.init_db()
    pipe = AnalysisPipeline(settings=cfg, repo=repo)

    # Verify TelegramEnvelope extracts cb["from"]["id"] and NEVER cb["message"]["from"]["id"]
    env = validate_telegram_update_envelope(
        {
            "update_id": 400,
            "callback_query": {
                "id": "cb_env_1",
                "from": {"id": 7001},
                "data": "pdf:vs_abc",
                "message": {
                    "from": {"id": 999888, "is_bot": True},
                    "chat": {"id": 7001, "type": "private"},
                },
            },
        }
    )
    assert env.chat_type == "private"
    assert env.sender_user_id == 7001

    ack_calls: list[dict[str, Any]] = []
    doc_calls: list[bytes] = []
    send_msg_calls: list[dict[str, Any]] = []

    def _cap_ack(request: httpx.Request) -> httpx.Response:
        ack_calls.append(json.loads(request.content.decode("utf-8")))
        return httpx.Response(200, json={"ok": True, "result": True})

    def _cap_doc(request: httpx.Request) -> httpx.Response:
        doc_calls.append(request.content)
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 500}})

    def _cap_msg(request: httpx.Request) -> httpx.Response:
        send_msg_calls.append(json.loads(request.content.decode("utf-8")))
        return httpx.Response(200, json={"ok": True, "result": {"message_id": len(send_msg_calls)}})

    with respx.mock(assert_all_called=False) as router:
        router.post("https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/sendChatAction").mock(
            return_value=httpx.Response(200, json={"ok": True, "result": True})
        )
        router.post("https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/sendMessage").mock(
            side_effect=_cap_msg
        )
        router.post("https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/answerCallbackQuery").mock(
            side_effect=_cap_ack
        )
        router.post("https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/sendDocument").mock(
            side_effect=_cap_doc
        )

        # 1. Private chat analysis saves owner_channel="telegram_private" + callback_data="pdf:{case_id}"
        verdict_res = await handle_telegram_update(
            {
                "update_id": 401,
                "message": {
                    "chat": {"id": 7001, "type": "private"},
                    "from": {"id": 7001},
                    "text": "NAPAS thông báo đổi điểm thưởng tại https://napas-qua.top/login",
                },
            },
            pipe,
            cfg,
        )
        case_id = verdict_res["case_id"]
        assert len(send_msg_calls) == 1
        first_btn = send_msg_calls[0]["reply_markup"]["inline_keyboard"][0][0]
        assert first_btn["callback_data"] == f"pdf:{case_id}"
        assert "/report.pdf" not in json.dumps(send_msg_calls[0], ensure_ascii=False)

        # 2. Private owner taps pdf:{case_id} -> sendDocument called once, zero sendMessage, clean ack
        pdf_cb = {
            "update_id": 402,
            "callback_query": {
                "id": "cb_pdf_ok",
                "from": {"id": 7001},
                "data": f"pdf:{case_id}",
                "message": {
                    "from": {"id": 999888, "is_bot": True},
                    "chat": {"id": 7001, "type": "private"},
                },
            },
        }
        pdf_res = await handle_telegram_update(pdf_cb, pipe, cfg)
        assert pdf_res["ok"] is True
        assert pdf_res["delivered"] is True
        assert pdf_res["pdf_sent"] is True
        assert len(send_msg_calls) == 1  # ZERO sendMessage calls on pdf callback!
        assert len(doc_calls) == 1
        assert b"%PDF-" in doc_calls[0]
        assert f"verishield-{case_id}.pdf".encode() in doc_calls[0]
        assert len(ack_calls) == 1
        assert ack_calls[0]["callback_query_id"] == "cb_pdf_ok"
        assert ack_calls[0].get("show_alert") is not True
        assert "đang kiểm tra" not in ack_calls[0].get("text", "").lower()

        # 3. Webhook retry with same update_id must NOT send duplicate PDF document
        dup_res = await handle_telegram_update(pdf_cb, pipe, cfg)
        assert dup_res["ok"] is True
        assert dup_res.get("duplicate") is True
        assert len(doc_calls) == 1


@pytest.mark.asyncio
async def test_telegram_pdf_callback_fails_closed_for_group_wrong_user_and_cross_channel(
    tmp_path: Path,
) -> None:
    cfg = _make_settings(tmp_path)
    repo = CaseRepository(cfg.sqlite_path)
    repo.init_db()
    pipe = AnalysisPipeline(settings=cfg, repo=repo)

    # Seed one private Telegram case, one web_token case, and one legacy_locked case
    private_report = await pipe.run(
        text="Kiểm tra liên kết https://napas-fake.top",
        owner_channel="telegram_private",
        owner_chat_hash=hash_telegram_private_owner(7100, 7100, pipe.case_token_secret),
    )
    web_report = await pipe.run(
        text="Kiểm tra web case https://vneid-fake.top",
        owner_channel="web_token",
    )
    legacy_report = await pipe.run(
        text="Kiểm tra legacy case https://bank-fake.top",
        owner_channel="legacy_locked",
    )

    attack_payloads: list[tuple[str, dict[str, Any]]] = [
        (
            "wrong_sender_even_when_message_from_matches_owner",
            {
                "update_id": 501,
                "callback_query": {
                    "id": "cb_att_1",
                    "from": {"id": 9999},
                    "data": f"pdf:{private_report.case_id}",
                    "message": {
                        "from": {"id": 7100},
                        "chat": {"id": 7100, "type": "private"},
                    },
                },
            },
        ),
        (
            "group_chat",
            {
                "update_id": 502,
                "callback_query": {
                    "id": "cb_att_2",
                    "from": {"id": 7100},
                    "data": f"pdf:{private_report.case_id}",
                    "message": {"chat": {"id": -1001, "type": "group"}},
                },
            },
        ),
        (
            "supergroup_chat",
            {
                "update_id": 503,
                "callback_query": {
                    "id": "cb_att_3",
                    "from": {"id": 7100},
                    "data": f"pdf:{private_report.case_id}",
                    "message": {"chat": {"id": -1002, "type": "supergroup"}},
                },
            },
        ),
        (
            "channel_chat",
            {
                "update_id": 504,
                "callback_query": {
                    "id": "cb_att_4",
                    "from": {"id": 7100},
                    "data": f"pdf:{private_report.case_id}",
                    "message": {"chat": {"id": -1003, "type": "channel"}},
                },
            },
        ),
        (
            "missing_chat_type",
            {
                "update_id": 505,
                "callback_query": {
                    "id": "cb_att_5",
                    "from": {"id": 7100},
                    "data": f"pdf:{private_report.case_id}",
                    "message": {"chat": {"id": 7100}},
                },
            },
        ),
        (
            "missing_sender_from",
            {
                "update_id": 506,
                "callback_query": {
                    "id": "cb_att_6",
                    "data": f"pdf:{private_report.case_id}",
                    "message": {"chat": {"id": 7100, "type": "private"}},
                },
            },
        ),
        (
            "web_owned_case",
            {
                "update_id": 507,
                "callback_query": {
                    "id": "cb_att_7",
                    "from": {"id": 7100},
                    "data": f"pdf:{web_report.case_id}",
                    "message": {"chat": {"id": 7100, "type": "private"}},
                },
            },
        ),
        (
            "legacy_locked_case",
            {
                "update_id": 508,
                "callback_query": {
                    "id": "cb_att_8",
                    "from": {"id": 7100},
                    "data": f"pdf:{legacy_report.case_id}",
                    "message": {"chat": {"id": 7100, "type": "private"}},
                },
            },
        ),
        (
            "nonexistent_case",
            {
                "update_id": 509,
                "callback_query": {
                    "id": "cb_att_9",
                    "from": {"id": 7100},
                    "data": "pdf:vs_00000000000000000000000000000000",
                    "message": {"chat": {"id": 7100, "type": "private"}},
                },
            },
        ),
    ]

    with respx.mock(assert_all_called=False) as router:
        ack_calls: list[dict[str, Any]] = []
        doc_route = router.post(
            "https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/sendDocument"
        ).mock(return_value=httpx.Response(200, json={"ok": True, "result": {"message_id": 1}}))
        msg_route = router.post(
            "https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/sendMessage"
        ).mock(return_value=httpx.Response(200, json={"ok": True, "result": {"message_id": 1}}))
        router.post("https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/answerCallbackQuery").mock(
            side_effect=lambda req: (
                ack_calls.append(json.loads(req.content.decode("utf-8"))),
                httpx.Response(200, json={"ok": True, "result": True}),
            )[1]
        )

        for label, payload in attack_payloads:
            before_acks = len(ack_calls)
            res = await handle_telegram_update(payload, pipe, cfg)
            assert res["ok"] is True, label
            assert res["delivered"] is False, label
            assert res.get("pdf_sent") is False, label
            assert doc_route.call_count == 0, f"sendDocument leaked on {label}"
            assert msg_route.call_count == 0, f"sendMessage leaked on {label}"
            assert len(ack_calls) == before_acks + 1, f"Expected single alert ack on {label}"
            assert ack_calls[-1].get("show_alert") is True, f"Expected show_alert=True on {label}"
            assert "đang kiểm tra" not in ack_calls[-1].get("text", "").lower(), label


@pytest.mark.asyncio
async def test_telegram_group_analysis_locks_case_omits_pdf_button_and_webhook_wires_secret(
    tmp_path: Path,
) -> None:
    cfg = _make_settings(tmp_path)
    app = create_app(cfg)
    client = TestClient(app)
    repo = app.state.repo
    sent_messages: list[dict[str, Any]] = []
    doc_uploads: list[bytes] = []

    def _cap_msg(request: httpx.Request) -> httpx.Response:
        sent_messages.append(json.loads(request.content.decode("utf-8")))
        return httpx.Response(200, json={"ok": True, "result": {"message_id": len(sent_messages)}})

    def _cap_doc(request: httpx.Request) -> httpx.Response:
        doc_uploads.append(request.content)
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 999}})

    with respx.mock(assert_all_called=False) as router:
        router.post("https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/sendChatAction").mock(
            return_value=httpx.Response(200, json={"ok": True, "result": True})
        )
        router.post("https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/sendMessage").mock(
            side_effect=_cap_msg
        )
        router.post("https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/answerCallbackQuery").mock(
            return_value=httpx.Response(200, json={"ok": True, "result": True})
        )
        router.post("https://api.telegram.org/bot999888:SYNTHETIC_BOT_TOKEN/sendDocument").mock(
            side_effect=_cap_doc
        )

        # 1. Group chat message -> telegram_group_locked, no pdf callback button, includes 1-1 note
        grp_resp = client.post(
            "/api/v1/bot/telegram",
            headers={"X-Telegram-Bot-Api-Secret-Token": "tg_unit_secret_999"},
            json={
                "update_id": 601,
                "message": {
                    "chat": {"id": -100555, "type": "supergroup"},
                    "from": {"id": 4242},
                    "text": "Kiểm tra link https://napas-group-test.top",
                },
            },
        )
        assert grp_resp.status_code == 200
        assert "reply_text" not in grp_resp.json()
        grp_case_id = grp_resp.json()["case_id"]
        grp_record = repo.get_report_with_owner(grp_case_id)
        assert grp_record is not None
        assert grp_record.owner_channel == "telegram_group_locked"
        assert grp_record.owner_chat_hash is None
        assert "1-1" in sent_messages[0]["text"]
        assert "pdf:" not in json.dumps(sent_messages[0], ensure_ascii=False)
        assert "/report.pdf" not in json.dumps(sent_messages[0], ensure_ascii=False)

        # 2. Private chat webhook -> app.state.case_token_secret wired consistently end-to-end
        priv_resp = client.post(
            "/api/v1/bot/telegram",
            headers={"X-Telegram-Bot-Api-Secret-Token": "tg_unit_secret_999"},
            json={
                "update_id": 602,
                "message": {
                    "chat": {"id": 4242, "type": "private"},
                    "from": {"id": 4242},
                    "text": "Kiểm tra link riêng tư https://napas-private-test.top",
                },
            },
        )
        assert priv_resp.status_code == 200
        priv_case_id = priv_resp.json()["case_id"]
        cb_resp = client.post(
            "/api/v1/bot/telegram",
            headers={"X-Telegram-Bot-Api-Secret-Token": "tg_unit_secret_999"},
            json={
                "update_id": 603,
                "callback_query": {
                    "id": "cb_webhook_ok",
                    "from": {"id": 4242},
                    "data": f"pdf:{priv_case_id}",
                    "message": {
                        "from": {"id": 999888, "is_bot": True},
                        "chat": {"id": 4242, "type": "private"},
                    },
                },
            },
        )
        assert cb_resp.status_code == 200
        assert cb_resp.json()["pdf_sent"] is True
        assert len(doc_uploads) == 1
        assert b"%PDF-" in doc_uploads[0]
