"""Configure VeriShield AI Telegram Bot menu commands & authenticated HTTPS webhook in 1 shot.

Reads TELEGRAM_BOT_TOKEN, TELEGRAM_WEBHOOK_SECRET, and PUBLIC_BASE_URL from environment
or from deploy/.env.prod (never prints secrets).
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path

BOT_COMMANDS = [
    {"command": "start", "description": "Giới thiệu và thử nhanh 5 tình huống mẫu một chạm"},
    {"command": "demo", "description": "Thử 5 tình huống lừa đảo mẫu (biên lai giả, VietQR, giả công an)"},
    {"command": "bill", "description": "Người bán kiểm tra ảnh biên lai: /bill <số tài khoản>"},
    {"command": "call", "description": "Kiểm tra khi đang nghe điện thoại lạ (tạm dừng 30 giây)"},
    {"command": "help", "description": "Hướng dẫn gửi tin nhắn, ảnh và tệp ghi âm (tối đa 10 MB)"},
]


def _load_env(env_path: Path) -> dict[str, str]:
    values = dict(os.environ)
    if env_path.exists():
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            if key and not values.get(key):
                values[key] = val.strip().strip('"').strip("'")
    return values


def _tg_post(token: str, method: str, payload: dict[str, object]) -> dict[str, object]:
    url = f"https://api.telegram.org/bot{token}/{method}"
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))  # type: ignore[no-any-return]


def _tg_get(token: str, method: str) -> dict[str, object]:
    url = f"https://api.telegram.org/bot{token}/{method}"
    with urllib.request.urlopen(url, timeout=15) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8"))  # type: ignore[no-any-return]


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    env_file = Path(sys.argv[1]) if len(sys.argv) > 1 else repo_root / "deploy" / ".env.prod"
    env = _load_env(env_file)

    token = env.get("TELEGRAM_BOT_TOKEN", "").strip()
    secret = env.get("TELEGRAM_WEBHOOK_SECRET", "").strip()
    public_base = env.get("PUBLIC_BASE_URL", "https://verishield.joiboi.app").strip().rstrip("/")

    if not token:
        print("ERROR: TELEGRAM_BOT_TOKEN is not configured.", file=sys.stderr)
        return 1
    if not secret:
        print("ERROR: TELEGRAM_WEBHOOK_SECRET is not configured.", file=sys.stderr)
        return 1
    if not public_base.startswith("https://"):
        print("ERROR: PUBLIC_BASE_URL must start with https://", file=sys.stderr)
        return 1

    webhook_url = f"{public_base}/api/v1/bot/telegram"
    cmd_res = _tg_post(token, "setMyCommands", {"commands": BOT_COMMANDS})
    wh_res = _tg_post(
        token,
        "setWebhook",
        {
            "url": webhook_url,
            "secret_token": secret,
            "allowed_updates": ["message", "edited_message", "callback_query"],
            "drop_pending_updates": True,
        },
    )
    info = _tg_get(token, "getWebhookInfo").get("result", {})
    cmds = _tg_get(token, "getMyCommands").get("result", [])

    print(
        json.dumps(
            {
                "setMyCommands_ok": cmd_res.get("ok"),
                "setWebhook_ok": wh_res.get("ok"),
                "webhook_info": info,
                "registered_commands": cmds,
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0 if (cmd_res.get("ok") is True and wh_res.get("ok") is True) else 2


if __name__ == "__main__":
    raise SystemExit(main())
