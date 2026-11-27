"""128-bit case IDs and HMAC-SHA256 case access tokens for unified Web & Telegram isolation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from datetime import UTC, datetime
from typing import Any, Final, Literal

from app.config import Settings

CaseOwnerChannel = Literal[
    "web_token",
    "telegram_private",
    "telegram_group_locked",
    "legacy_locked",
]

_MIN_TOKEN_TTL_SECONDS: Final[int] = 60


def generate_case_id() -> str:
    """Generate a 128-bit opaque case identifier (35 ASCII chars: 'vs_' + 32 hex)."""
    return f"vs_{secrets.token_hex(16)}"


def resolve_case_token_secret(settings: Settings) -> str:
    """Resolve the HMAC signing secret for case access tokens and Telegram private-owner hashes."""
    explicit_token_secret = settings.case_token_secret.strip()
    if settings.app_env == "production":
        if len(explicit_token_secret) < 32:
            raise ValueError(
                "APP_ENV=production requires an explicit CASE_TOKEN_SECRET (>= 32 chars)."
            )
        return explicit_token_secret
    if explicit_token_secret:
        return explicit_token_secret
    return secrets.token_hex(32)


def _sign_b64_payload(payload_b64: str, secret: str) -> str:
    return hmac.new(
        secret.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256
    ).hexdigest()


def issue_case_access_token(
    case_id: str,
    secret: str,
    *,
    ttl_seconds: int = 7200,
    parent_case_id: str | None = None,
    now: int | None = None,
) -> tuple[str, str]:
    """Issue a compact HMAC-SHA256 web case access token and its UTC ISO expiry timestamp."""
    if not case_id.strip() or not secret.strip():
        raise ValueError("case_id and secret must be non-empty.")
    ts_now = int(time.time()) if now is None else int(now)
    exp = ts_now + max(_MIN_TOKEN_TTL_SECONDS, int(ttl_seconds))
    payload: dict[str, Any] = {
        "v": 1,
        "cid": case_id,
        "ch": "web",
        "scope": "case_access",
        "exp": exp,
    }
    if parent_case_id:
        payload["pcid"] = parent_case_id
    raw_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(raw_json).rstrip(b"=").decode("ascii")
    sig = _sign_b64_payload(payload_b64, secret)
    return f"{payload_b64}.{sig}", datetime.fromtimestamp(exp, tz=UTC).isoformat()


def verify_case_access_token(
    token: str | None,
    expected_case_id: str,
    secret: str,
    *,
    now: int | None = None,
) -> dict[str, Any] | None:
    """Verify a web case access token in constant time; return decoded claims or None."""
    if not token or not expected_case_id.strip() or not secret.strip():
        return None
    parts = token.strip().split(".")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None
    payload_b64, provided_sig = parts
    try:
        expected_sig_bytes = _sign_b64_payload(payload_b64, secret).encode("ascii")
        provided_sig_bytes = provided_sig.encode("ascii")
    except UnicodeEncodeError:
        return None
    if not hmac.compare_digest(provided_sig_bytes, expected_sig_bytes):
        return None
    try:
        padded = payload_b64 + ("=" * (-len(payload_b64) % 4))
        decoded: object = json.loads(
            base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        )
    except Exception:
        return None
    if not isinstance(decoded, dict):
        return None
    version = decoded.get("v")
    exp = decoded.get("exp")
    if (
        isinstance(version, bool)
        or version != 1
        or decoded.get("cid") != expected_case_id
        or decoded.get("ch") != "web"
        or decoded.get("scope") != "case_access"
        or isinstance(exp, bool)
        or not isinstance(exp, int)
    ):
        return None
    ts_now = int(time.time()) if now is None else int(now)
    return decoded if exp > ts_now else None


def hash_telegram_private_owner(
    chat_id: int | str,
    sender_user_id: int | str,
    secret: str,
) -> str:
    """Compute a keyed HMAC-SHA256 binding a private Telegram case to its chat and sender."""
    if not secret.strip():
        raise ValueError("secret must be non-empty.")
    message = f"tg_private:{chat_id}:{sender_user_id}".encode()
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
