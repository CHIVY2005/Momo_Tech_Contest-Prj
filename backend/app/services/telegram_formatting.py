"""Telegram command parsing, verdict formatting, inline keyboards & 4096-char ceiling helpers."""

from __future__ import annotations

import re
from typing import Any, Final

from app.schemas import AnalysisReport, AnalyzeMode

TELEGRAM_MAX_TEXT_LEN: Final[int] = 4000

_CMD_RE = re.compile(r"^/([a-zA-Z0-9_]+)(?:@[a-zA-Z0-9_]+)?(?:\s+(.*))?$", re.DOTALL)
_ACCOUNT_ARG_RE = re.compile(r"^[A-Za-z0-9]{6,20}$")
_MERCHANT_HINT_RE = re.compile(
    r"(?:biên\s*lai|bien\s*lai|fake\s*bill|chuyển\s*khoản|"
    r"chuyen\s*khoan|chủ\s*shop|chu\s*shop|quầy\s*thu\s*ngân)",
    re.IGNORECASE,
)

TELEGRAM_WELCOME_TEXT: Final[str] = (
    "🛡 Chào mừng bạn đến với VeriShield AI — Trợ lý Chống Lừa đảo 1-Chạm!\n\n"
    "Bạn có thể gửi hoặc chuyển tiếp (Forward) trực tiếp vào đây:\n"
    "• Tin nhắn SMS / Zalo / đường link đáng ngờ\n"
    "• Ảnh chụp biên lai chuyển khoản (soi pháp y ELA + đối chiếu nghiệp vụ)\n"
    "• Ảnh mã VietQR (giải mã EMVCo CRC-16, phát hiện bẫy 'quét để nhận tiền')\n"
    "• Ghi âm / tin nhắn thoại cuộc gọi nghi mạo danh (gỡ băng & phát hiện kịch bản)\n\n"
    "🏪 Mẹo cho Chủ cửa hàng:\n"
    "Gửi ảnh biên lai kèm chú thích: /bill <STK cửa hàng> để đối chiếu tài khoản thụ hưởng.\n"
    "Gõ /help để xem chi tiết giới hạn tệp (tối đa 10 MB)."
)

TELEGRAM_HELP_TEXT: Final[str] = (
    "📘 Hướng dẫn sử dụng VeriShield AI Bot:\n\n"
    "1️⃣ Kiểm tra tin nhắn / link: Chuyển tiếp trực tiếp văn bản hoặc URL vào khung chat.\n"
    "2️⃣ Kiểm tra ảnh Fake Bill / VietQR: Gửi ảnh (Photo hoặc File ảnh ≤ 10 MB).\n"
    "3️⃣ Chế độ Chủ cửa hàng: Gửi ảnh biên lai kèm chú thích `/bill 190311112222`.\n"
    "4️⃣ Kiểm tra cuộc gọi đáng ngờ: Gửi Voice hoặc file ghi âm (.mp3/.wav/.m4a ≤ 10 MB).\n\n"
    "⚠️ Lưu ý: Ảnh chụp màn hình biên lai KHÔNG phải bằng chứng tiền đã vào tài khoản — "
    "luôn kiểm tra ứng dụng ngân hàng hoặc Loa thông báo thực tế trước khi giao hàng."
)


def validate_telegram_update_envelope(
    update: dict[str, Any],
) -> tuple[int | None, dict[str, Any] | None, int | str | None, str]:
    """Validate Telegram webhook JSON envelope; return (update_id, msg, chat_id, raw_text)."""
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

    for field_name in ("message", "edited_message"):
        if (
            field_name in update
            and update[field_name] is not None
            and not isinstance(update[field_name], dict)
        ):
            raise ValueError(f"Telegram field '{field_name}' must be a JSON object.")

    msg = update.get("message") or update.get("edited_message")
    if msg is None:
        return update_id, None, None, ""

    chat = msg.get("chat")
    if chat is not None and not isinstance(chat, dict):
        raise ValueError("Telegram message.chat must be a JSON object.")
    chat_id = chat.get("id") if isinstance(chat, dict) else None
    if chat_id is not None and (isinstance(chat_id, bool) or not isinstance(chat_id, (int, str))):
        raise ValueError("Telegram chat.id must be an integer or string.")

    raw_text_field = msg.get("text") if msg.get("text") is not None else msg.get("caption")
    if raw_text_field is not None and not isinstance(raw_text_field, str):
        raise ValueError("Telegram text/caption must be a string.")
    return update_id, msg, chat_id, (raw_text_field or "").strip()


def truncate_telegram_text(text: str, max_len: int = TELEGRAM_MAX_TEXT_LEN) -> str:
    """Ensure outbound Telegram reply fits safely below Telegram's 4096-character limit."""
    if len(text) <= max_len:
        return text
    suffix = "\n… (xem đầy đủ bằng chứng trong Hồ sơ PDF hoặc VeriShield Web)"
    keep = max(64, max_len - len(suffix))
    return text[:keep].rstrip() + suffix


def build_verdict_inline_keyboard(case_id: str, public_base_url: str) -> dict[str, Any] | None:
    """Build InlineKeyboardMarkup with PDF evidence download & web links for HTTPS deployments."""
    base = public_base_url.strip().rstrip("/")
    if not base.startswith("https://"):
        return None
    return {
        "inline_keyboard": [
            [
                {
                    "text": "📄 Tải Hồ sơ Tố giác PDF",
                    "url": f"{base}/api/v1/cases/{case_id}/report.pdf",
                }
            ],
            [
                {"text": "🛡 Mở VeriShield Web", "url": f"{base}/"},
                {"text": "📡 Fraud Ops Radar", "url": f"{base}/radar"},
            ],
        ]
    }


def parse_telegram_command(
    raw_text: str,
    has_attachment: bool,
) -> tuple[str | None, AnalyzeMode, str | None, str]:
    """Parse /start, /help, /bill; return (direct_reply, mode, expected_stk, cleaned_text)."""
    match = _CMD_RE.match(raw_text)
    if not match:
        mode: AnalyzeMode = (
            "merchant" if has_attachment and _MERCHANT_HINT_RE.search(raw_text) else "personal"
        )
        return None, mode, None, raw_text

    cmd = match.group(1).lower()
    arg_text = (match.group(2) or "").strip()

    if cmd == "start" and not has_attachment:
        return TELEGRAM_WELCOME_TEXT, "personal", None, ""
    if cmd == "help" and not has_attachment:
        return TELEGRAM_HELP_TEXT, "personal", None, ""
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
            return (
                "🏪 Chế độ Kiểm tra Biên lai Chủ cửa hàng:\n"
                "Hãy gửi ảnh biên lai chuyển khoản hoặc mã VietQR kèm chú thích "
                "`/bill <STK nhận tiền của shop>` (ví dụ: `/bill 190311112222`).",
                "merchant",
                expected_stk,
                "",
            )
        return None, "merchant", expected_stk, remaining

    return None, "personal", None, arg_text or raw_text


def format_telegram_verdict_reply(report: AnalysisReport) -> str:
    """Format concise Vietnamese safety verdict & counter-reply for Telegram chat."""
    badge_map = {
        "SAFE": "🟢 ÍT RỦI RO",
        "SUSPICIOUS": "🟡 NGHI VẤN — CẦN KIỂM CHỨNG",
        "HIGH_RISK": "🟠 RỦI RO CAO — TẠM DỪNG GIAO DỊCH",
        "CRITICAL_SCAM": "🔴 CẢNH BÁO ĐỎ — DẤU HIỆU LỪA ĐẢO RÕ RỆT",
    }
    lines = [
        f"🛡 VeriShield AI | {badge_map[report.verdict]} ({report.risk_score}/100)",
        f"📌 Tóm tắt: {report.summary_vi}",
    ]
    if report.matched_playbooks:
        lines.append(f"🎯 Kịch bản khớp: {', '.join(report.matched_playbooks[:2])}")
    if any(q.receive_scam_detected for q in report.vietqr_findings):
        lines.append(
            "🚨 Bẫy quét VietQR: Mã QR này là LỆNH CHUYỂN TIỀN ĐI — "
            "tuyệt đối không quét để 'nhận hoàn tiền'!"
        )
    if any(q.beneficiary_mismatch for q in report.vietqr_findings):
        lines.append("🚨 Tráo mã QR: Tài khoản trong mã VietQR KHÔNG KHỚP với STK cửa hàng!")
    if report.transcript:
        snippet = report.transcript.strip()
        if len(snippet) > 180:
            snippet = snippet[:177] + "…"
        lines.append(f'🎙 Gỡ băng lời thoại: "{snippet}"')
    if report.actions.merchant_balance_warning:
        lines.append(f"⚠️ {report.actions.merchant_balance_warning}")
    if report.actions.counter_replies:
        lines.append(f'💬 Gợi ý phản hồi: "{report.actions.counter_replies[0]}"')
    if report.actions.urgent_steps:
        lines.append(f"✅ Việc cần làm ngay: {report.actions.urgent_steps[0]}")
    lines.append(f"🆔 Mã hồ sơ: {report.case_id}")
    return truncate_telegram_text("\n\n".join(lines))
