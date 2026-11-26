#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${REPO_ROOT}/deploy/.env.prod"

if [[ ! -f "${ENV_FILE}" ]]; then
    echo "ERROR: Missing ${ENV_FILE}. Copy deploy/.env.prod.example to deploy/.env.prod and set secrets."
    exit 1
fi

cd "${REPO_ROOT}"
echo "==> [VeriShield Deploy] Building & launching production stack..."
docker compose --env-file "${ENV_FILE}" -f docker-compose.yml -f docker-compose.prod.yml up -d --build --remove-orphans

set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

TARGET_DOMAIN="${DOMAIN:-verishield.joiboi.app}"
echo "==> [VeriShield Deploy] Waiting for HTTPS health check on https://${TARGET_DOMAIN}/api/v1/health ..."
healthy=0
for attempt in $(seq 1 20); do
    if curl -fsS "https://${TARGET_DOMAIN}/api/v1/health" >/dev/null 2>&1; then
        echo "    Health check OK on attempt ${attempt}!"
        healthy=1
        break
    fi
    sleep 3
done

if [[ "${healthy}" -ne 1 ]]; then
    echo "ERROR: HTTPS health check failed after 20 attempts on https://${TARGET_DOMAIN}/api/v1/health"
    exit 1
fi

if [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_WEBHOOK_SECRET:-}" ]]; then
    echo "==> [VeriShield Deploy] Registering Telegram 1-Tap Bot Webhook..."
    curl -fsS -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/setWebhook" \
        -H "Content-Type: application/json" \
        -d "{\"url\":\"https://${TARGET_DOMAIN}/api/v1/bot/telegram\",\"secret_token\":\"${TELEGRAM_WEBHOOK_SECRET}\"}"
    echo ""
fi

echo "==> [VeriShield Deploy] Deployment complete: https://${TARGET_DOMAIN}"
