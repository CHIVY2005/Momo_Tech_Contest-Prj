"""Telegram command parsing, safe HTML verdict formatting & inline keyboard builders."""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from typing import Any, Final

from app.schemas import AnalysisReport, AnalyzeMode, DemoScenario

TELEGRAM_MAX_TEXT_LEN: Final[int] = 4000

_CMD_RE = re.compile(r"^/([a-zA-Z0-9_]+)(?:@[a-zA-Z0-9_]+)?(?:\s+(.*))?$", re.DOTALL)
_ACCOUNT_ARG_RE = re.compile(r"^[A-Za-z0-9]{6,20}$")
_MERCHANT_HINT_RE = re.compile(
    r"(?:biên\s*lai|bien\s*lai|fake\s*bill|chuyển\s*khoản|"
    r"chuyen\s*khoan|chủ\s*shop|chu\s*shop|quầy\s*thu\s*ngân)",
    re.IGNORECASE,
)

TELEGRAM_WELCOME_TEXT: Final[str] = (
    "🛡 <b>Chào mừng đến với VeriShield AI — Trợ lý kiểm tra lừa đảo một chạm</b>\n\n"
    "Bạn có thể gửi hoặc chuyển tiếp trực tiếp vào đây:\n"
    "• <b>Tin nhắn hoặc đường dẫn:</b> Tin nhắn SMS, Zalo, đường dẫn nghi giả mạo\n"
    "• <b>Ảnh biên lai hoặc mã VietQR:</b> Phân tích tính xác thực của hình ảnh và kiểm tra mã QR\n"
    "• <b>Ghi âm cuộc gọi:</b> Chuyển lời thoại sang văn bản và phát hiện dấu hiệu giả mạo\n\n"
    "⚡ <b>Lệnh nhanh:</b>\n"
    "• /demo — Thử ngay 5 tình huống mẫu chỉ với một chạm\n"
    "• /bill <code>190311112222</code> — Gửi kèm ảnh biên lai để đối chiếu số tài khoản cửa hàng\n"
    "• /call <i>nội dung</i> — Bật cảnh báo khi đang nghe điện thoại (tạm dừng để kiểm tra 30 giây)\n"
    "• /help — Xem hướng dẫn gửi tin nhắn, ảnh và tệp ghi âm (tối đa 10 MB)\n\n"
    "👇 <i>Hoặc chọn một tình huống mẫu bên dưới để kiểm tra ngay:</i>"
)

TELEGRAM_HELP_TEXT: Final[str] = (
    "📘 <b>Hướng dẫn sử dụng VeriShield AI trên Telegram</b>\n\n"
    "1️⃣ <b>Tin nhắn hoặc đường dẫn:</b> Gửi hoặc chuyển tiếp trực tiếp nội dung vào khung chat.\n"
    "2️⃣ <b>Ảnh biên lai hoặc mã VietQR:</b> Gửi ảnh chụp hoặc tệp ảnh (JPG, PNG, WebP — tối đa 10 MB).\n"
    "3️⃣ <b>Dành cho người bán:</b> Gửi ảnh biên lai kèm chú thích "
    "<code>/bill 190311112222</code> (thay bằng số tài khoản nhận tiền của cửa hàng).\n"
    "4️⃣ <b>Khi đang nghe điện thoại lạ:</b> Gửi <code>/call nội dung cuộc gọi</code> "
    "để tăng mức cảnh báo rủi ro và bật tạm dừng để kiểm tra 30 giây.\n"
    "5️⃣ <b>Tệp ghi âm cuộc gọi:</b> Gửi tin nhắn thoại hoặc tệp .mp3, .wav, .m4a (tối đa 10 MB).\n"
    "6️⃣ <b>Thử tình huống mẫu:</b> Gõ /demo hoặc <code>/demo 1</code> đến <code>/demo 5</code>.\n\n"
    "⚠️ <i>Lưu ý: Ảnh chụp biên lai không phải bằng chứng tiền đã vào tài khoản. "
    "Luôn kiểm tra trực tiếp biến động số dư trên ứng dụng ngân hàng hoặc loa thông báo "
    "trước khi giao hàng.</i>"
)


@dataclass(frozen=True, slots=True)
class TelegramEnvelope:
    """Validated incoming Telegram webhook envelope (message or callback_query)."""

    update_id: int | None
    msg: dict[str, Any] | None
    chat_id: int | str | None
    raw_text: str
    callback_query_id: str | None = None
    callback_data: str | None = None


@dataclass(frozen=True, slots=True)
class ParsedTelegramCommand:
    """Result of parsing a Telegram slash command or normal message."""

    direct_reply: str | None
    mode: AnalyzeMode
    expected_stk: str | None
    cleaned_text: str
    in_active_call: bool = False
    demo_selector: str | None = None
    attach_demo_keyboard: bool = False


def validate_telegram_update_envelope(update: dict[str, Any]) -> TelegramEnvelope:
    """Validate Telegram webhook JSON for message, edited_message, or callback_query."""
    if not isinstance(update, dict):
        raise ValueError("Telegram update must be a JSON object.")

    raw_uid = update.get("update_id")
    if raw_uid is not None and (
        isinstance(raw_uid, bool)
        or not isinstance(raw_uid, int)
        or raw_uid < 0
        or raw_uid > 9_223_372_036_854_775_807
    ):
        raise ValueError("Telegram update_id must be a valid 64-bit non-negative integer.")
    update_id: int | None = raw_uid

    for field_name in ("message", "edited_message", "callback_query"):
        if (
            field_name in update
            and update[field_name] is not None
            and not isinstance(update[field_name], dict)
        ):
            raise ValueError(f"Telegram field '{field_name}' must be a JSON object.")

    cb = update.get("callback_query")
    if isinstance(cb, dict):
        cb_id = cb.get("id")
        cb_data = cb.get("data")
        cb_msg = cb.get("message")
        if cb_id is not None and not isinstance(cb_id, str):
            raise ValueError("Telegram callback_query.id must be a string.")
        if cb_data is not None and not isinstance(cb_data, str):
            raise ValueError("Telegram callback_query.data must be a string.")
        if cb_msg is not None and not isinstance(cb_msg, dict):
            raise ValueError("Telegram callback_query.message must be a JSON object.")
        chat = cb_msg.get("chat") if isinstance(cb_msg, dict) else None
        if chat is not None and not isinstance(chat, dict):
            raise ValueError("Telegram callback_query.message.chat must be a JSON object.")
        chat_id = chat.get("id") if isinstance(chat, dict) else None
        if chat_id is not None and (isinstance(chat_id, bool) or not isinstance(chat_id, (int, str))):
            raise ValueError("Telegram chat.id must be an integer or string.")
        return TelegramEnvelope(
            update_id=update_id,
            msg=cb_msg if isinstance(cb_msg, dict) else None,
            chat_id=chat_id,
            raw_text="",
            callback_query_id=cb_id,
            callback_data=(cb_data or "").strip(),
        )

    msg = update.get("message") or update.get("edited_message")
    if msg is None:
        return TelegramEnvelope(update_id=update_id, msg=None, chat_id=None, raw_text="")

    chat = msg.get("chat")
    if chat is not None and not isinstance(chat, dict):
        raise ValueError("Telegram message.chat must be a JSON object.")
    chat_id = chat.get("id") if isinstance(chat, dict) else None
    if chat_id is not None and (isinstance(chat_id, bool) or not isinstance(chat_id, (int, str))):
        raise ValueError("Telegram chat.id must be an integer or string.")

    raw_text_field = msg.get("text") if msg.get("text") is not None else msg.get("caption")
    if raw_text_field is not None and not isinstance(raw_text_field, str):
        raise ValueError("Telegram text/caption must be a string.")
    return TelegramEnvelope(
        update_id=update_id,
        msg=msg,
        chat_id=chat_id,
        raw_text=(raw_text_field or "").strip(),
    )


def truncate_telegram_text(text: str, max_len: int = TELEGRAM_MAX_TEXT_LEN) -> str:
    """Ensure plain text fits safely below Telegram's 4096-character message ceiling."""
    if len(text) <= max_len:
        return text
    suffix = "\n… (xem đầy đủ bằng chứng trong báo cáo PDF hoặc trang web VeriShield AI)"
    keep = max(64, max_len - len(suffix))
    return text[:keep].rstrip() + suffix


def _join_html_lines_bounded(lines: list[str], max_len: int = TELEGRAM_MAX_TEXT_LEN) -> str:
    """Join complete HTML lines without ever slicing inside an HTML tag or entity."""
    out: list[str] = []
    total = 0
    for line in lines:
        sep = 2 if out else 0
        if total + sep + len(line) > max_len:
            break
        out.append(line)
        total += sep + len(line)
    return "\n\n".join(out)


def _esc(raw: str, max_chars: int = 420) -> str:
    cleaned = raw.strip()
    if len(cleaned) > max_chars:
        cleaned = cleaned[: max_chars - 1].rstrip() + "…"
    return html.escape(cleaned, quote=False)


def build_demo_inline_keyboard(demos: list[DemoScenario]) -> dict[str, Any] | None:
    """Build 1-tap callback keyboard listing canonical VeriShield AI demo scenarios."""
    if not demos:
        return None
    rows: list[list[dict[str, str]]] = []
    for idx, demo in enumerate(demos[:5], start=1):
        icon = "🟢" if demo.expected_verdict == "SAFE" else "🧪"
        label = f"{icon} {idx}. {demo.title_vi}"
        if len(label) > 54:
            label = label[:53].rstrip() + "…"
        rows.append([{"text": label, "callback_data": f"demo:{demo.demo_id}"}])
    return {"inline_keyboard": rows}


def build_verdict_inline_keyboard(case_id: str, public_base_url: str) -> dict[str, Any] | None:
    """Build InlineKeyboardMarkup with PDF evidence download & web links for HTTPS deployments."""
    base = public_base_url.strip().rstrip("/")
    if not base.startswith("https://"):
        return None
    return {
        "inline_keyboard": [
            [
                {
                    "text": "📄 Tải báo cáo bằng chứng (PDF)",
                    "url": f"{base}/api/v1/cases/{case_id}/report.pdf",
                }
            ],
            [
                {"text": "🛡 Mở trang web VeriShield AI", "url": f"{base}/"},
                {"text": "📡 Trung tâm giám sát gian lận", "url": f"{base}/radar"},
            ],
        ]
    }


def parse_telegram_command(raw_text: str, has_attachment: bool) -> ParsedTelegramCommand:
    """Parse /start, /help, /demo, /bill, /call commands cleanly."""
    match = _CMD_RE.match(raw_text)
    if not match:
        mode: AnalyzeMode = (
            "merchant" if has_attachment and _MERCHANT_HINT_RE.search(raw_text) else "personal"
        )
        return ParsedTelegramCommand(None, mode, None, raw_text)

    cmd = match.group(1).lower()
    arg_text = (match.group(2) or "").strip()

    if cmd == "start" and not has_attachment:
        return ParsedTelegramCommand(
            TELEGRAM_WELCOME_TEXT, "personal", None, "", attach_demo_keyboard=True
        )
    if cmd == "help" and not has_attachment:
        return ParsedTelegramCommand(TELEGRAM_HELP_TEXT, "personal", None, "")
    if cmd == "demo":
        if not arg_text:
            return ParsedTelegramCommand(
                "🧪 <b>5 tình huống mẫu kiểm tra một chạm</b>\n\n"
                "Chọn trực tiếp một nút bên dưới (hoặc gõ <code>/demo 1</code> đến <code>/demo 5</code>) "
                "để xem cách hệ thống phân tích và cảnh báo ngay trên Telegram:",
                "personal",
                None,
                "",
                attach_demo_keyboard=True,
            )
        return ParsedTelegramCommand(None, "personal", None, "", demo_selector=arg_text.split()[0])
    if cmd == "call":
        if not has_attachment and not arg_text:
            return ParsedTelegramCommand(
                "📞 <b>Kiểm tra khi đang nghe điện thoại (/call)</b>\n"
                "Hãy gửi <code>/call nội dung người gọi đang yêu cầu</code> "
                "(hoặc gửi kèm tệp ghi âm) để tăng mức cảnh báo rủi ro và bật "
                "tạm dừng để kiểm tra 30 giây.",
                "wallet_transfer",
                None,
                "",
                in_active_call=True,
            )
        return ParsedTelegramCommand(None, "wallet_transfer", None, arg_text, in_active_call=True)
    if cmd == "bill":
        expected_stk: str | None = None
        remaining = arg_text
        if arg_text:
            parts = arg_text.split(None, 1)
            first = parts[0]
            if _ACCOUNT_ARG_RE.match(first) and sum(ch.isdigit() for ch in first) >= 6:
                expected_stk = first
                remaining = parts[1].strip() if len(parts) > 1 else ""
        if not has_attachment and not remaining:
            return ParsedTelegramCommand(
                "🏪 <b>Kiểm tra biên lai cho người bán (/bill)</b>\n"
                "Hãy gửi ảnh biên lai chuyển khoản hoặc mã VietQR kèm chú thích "
                "<code>/bill 190311112222</code> (thay bằng số tài khoản nhận tiền của cửa hàng).",
                "merchant",
                expected_stk,
                "",
            )
        return ParsedTelegramCommand(None, "merchant", expected_stk, remaining)

    return ParsedTelegramCommand(None, "personal", None, arg_text or raw_text)


def format_telegram_verdict_reply(report: AnalysisReport) -> str:
    """Format safe HTML Vietnamese safety verdict, 30s shield & counter-reply for Telegram."""
    badge_map = {
        "SAFE": "🟢 Chưa phát hiện dấu hiệu bất thường",
        "SUSPICIOUS": "🟡 Cần thận trọng — nên xác minh thêm",
        "HIGH_RISK": "🟠 Cảnh báo rủi ro cao — tạm dừng giao dịch",
        "CRITICAL_SCAM": "🔴 Cảnh báo rủi ro rất cao — có nhiều dấu hiệu lừa đảo",
    }
    lines = [
        f"🛡 <b>VeriShield AI</b> | <b>{badge_map[report.verdict]} ({report.risk_score}/100)</b>",
        f"📌 <b>Tóm tắt:</b> {_esc(report.summary_vi, 650)}",
    ]
    if report.matched_playbooks:
        pbs = ", ".join(_esc(pb, 90) for pb in report.matched_playbooks[:2])
        lines.append(f"🎯 <b>Kịch bản tương tự:</b> {pbs}")
    if any(q.receive_scam_detected for q in report.vietqr_findings):
        lines.append(
            "🚨 <b>Bẫy quét mã VietQR:</b> Mã QR này là lệnh chuyển tiền đi, "
            "không thể quét để nhận tiền hoàn hay nhận thưởng."
        )
    if any(q.beneficiary_mismatch for q in report.vietqr_findings):
        lines.append(
            "🚨 <b>Lệch tài khoản nhận:</b> Số tài khoản trong mã VietQR không khớp với "
            "số tài khoản của cửa hàng."
        )
    pre = report.actions.pre_transfer
    if pre.should_hold_transfer:
        hold_line = (
            f"⏱ <b>Ngăn chặn lừa đảo trước khi chuyển tiền "
            f"(Tạm dừng để kiểm tra {pre.cooling_off_seconds} giây):</b> "
            f"{_esc(pre.warning_headline, 240)}"
        )
        if pre.verification_questions:
            hold_line += f"\n• <i>Tự kiểm tra nhanh:</i> {_esc(pre.verification_questions[0], 180)}"
        lines.append(hold_line)
    if report.transcript:
        lines.append(f'🎙 <b>Nội dung từ ghi âm:</b> <i>"{_esc(report.transcript, 200)}"</i>')
    if report.actions.merchant_balance_warning:
        lines.append(
            f"⚠️ <b>Lưu ý cho người bán:</b> {_esc(report.actions.merchant_balance_warning, 320)}"
        )
    if report.actions.counter_replies:
        lines.append(f'💬 <b>Gợi ý câu trả lời:</b> "{_esc(report.actions.counter_replies[0], 260)}"')
    if report.actions.urgent_steps:
        lines.append(f"✅ <b>Việc cần làm ngay:</b> {_esc(report.actions.urgent_steps[0], 260)}")
    lines.append(
        f"ℹ️ <i>Kết quả chỉ mang tính tham khảo. Mã hồ sơ:</i> "
        f"<code>{_esc(report.case_id, 64)}</code>"
    )
    return _join_html_lines_bounded(lines)
