#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${REPO_ROOT}/deploy/.env.prod"

if [[ ! -f "${ENV_FILE}" ]]; then
    echo "ERROR: Missing ${ENV_FILE}. Copy deploy/.env.prod.example to deploy/.env.prod and set secrets."
    exit 1
fi

# Parse target domain safely without executing .env.prod as shell code
TARGET_DOMAIN="$(python3 - "${ENV_FILE}" <<'PY'
import sys
from pathlib import Path

domain = "verishield.joiboi.app"
for raw in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, v = line.split("=", 1)
    if k.strip() == "DOMAIN" and v.strip():
        domain = v.strip().strip('"').strip("'")
print(domain)
PY
)"

cd "${REPO_ROOT}"
echo "==> [VeriShield Deploy] Building & launching production stack..."
docker compose --env-file "${ENV_FILE}" -f docker-compose.yml -f docker-compose.prod.yml up -d --build --remove-orphans

echo "==> [VeriShield Deploy] Probing HTTPS API (/api/v1/health) and Frontend (/, /radar) on https://${TARGET_DOMAIN} ..."
healthy=0
for attempt in $(seq 1 20); do
    if curl -fsS --max-time 10 "https://${TARGET_DOMAIN}/api/v1/health" >/dev/null 2>&1 \
        && curl -fsS --max-time 10 "https://${TARGET_DOMAIN}/" | grep -q "VeriShield AI" \
        && curl -fsS --max-time 10 "https://${TARGET_DOMAIN}/radar" >/dev/null 2>&1; then
        echo "    API + Frontend HTTPS probes OK on attempt ${attempt}!"
        healthy=1
        break
    fi
    sleep 3
done

if [[ "${healthy}" -ne 1 ]]; then
    echo "ERROR: HTTPS readiness probes failed after 20 attempts on https://${TARGET_DOMAIN}"
    exit 1
fi

# Register Telegram webhook inside Python so bot token & webhook secret never appear in process argv
python3 - "${ENV_FILE}" "${TARGET_DOMAIN}" <<'PY'
import json
import sys
import urllib.request
from pathlib import Path

env_map: dict[str, str] = {}
for raw in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, v = line.split("=", 1)
    env_map[k.strip()] = v.strip().strip('"').strip("'")

bot_token = env_map.get("TELEGRAM_BOT_TOKEN", "")
webhook_secret = env_map.get("TELEGRAM_WEBHOOK_SECRET", "")
target_domain = sys.argv[2]

if bot_token and webhook_secret:
    print("==> [VeriShield Deploy] Registering Telegram 1-Tap Bot Webhook...")
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{bot_token}/setWebhook",
        data=json.dumps(
            {
                "url": f"https://{target_domain}/api/v1/bot/telegram",
                "secret_token": webhook_secret,
            }
        ).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
        body = json.loads(resp.read().decode("utf-8"))
        if not body.get("ok"):
            raise SystemExit(f"ERROR: Telegram setWebhook returned ok=false: {body.get('description')}")
    print("    Telegram webhook registered cleanly.")
PY

echo "==> [VeriShield Deploy] Deployment complete: https://${TARGET_DOMAIN}"
