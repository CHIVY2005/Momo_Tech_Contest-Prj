"""Smoke-test live CPA (OpenAI-compatible) or Google GenAI structured JSON output using backend/.env."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.config import get_settings  # noqa: E402
from app.services.ai_orchestrator import build_isolated_prompt  # noqa: E402
from app.services.llm_client import execute_llm_call  # noqa: E402


async def _run_smoke_check() -> int:
    get_settings.cache_clear()
    cfg = get_settings()
    has_primary = bool(cfg.gemini_api_key.strip())
    has_backup = bool(cfg.gemini_backup_api_key.strip())

    print("==> [VeriShield LLM Connection Check]")
    print(f"    Provider         : {cfg.resolved_llm_provider}")
    print(f"    Base URL         : {cfg.gemini_base_url or '(official Google GenAI)'}")
    print(f"    Configured Model : {cfg.gemini_model}")
    print(f"    Primary Key Set  : {has_primary} | Backup Key Set: {has_backup}")

    if not (has_primary or has_backup):
        print("ERROR: No API key configured in backend/.env (GEMINI_API_KEY is empty).")
        return 1

    prompt = build_isolated_prompt(
        user_text=(
            "[NAPAS] Thong bao: Diem thuong the cua quy khach sap het han. "
            "Truy cap https://napas-diemthuong-247.top de nhan tien hoan."
        ),
        mode="personal",
        tier1_notes=["Tên miền .top giả mạo thương hiệu NAPAS"],
        matched_playbooks=[
            {
                "name_vi": "SMS giả mạo NAPAS / Ngân hàng đổi điểm thưởng",
                "red_flags": ["Gửi đường link tên miền lạ yêu cầu nhập thông tin thẻ & OTP"],
            }
        ],
        trusted_signals=["URL_BRAND_SPOOF_DETECTED"],
    )

    outcome = await execute_llm_call(settings=cfg, prompt=prompt)
    if outcome.parsed is None:
        print(
            f"FAILED: error_code={outcome.error_code} | attempts={outcome.attempts} | "
            f"latency_ms={outcome.latency_ms}"
        )
        return 1

    print(
        f"SUCCESS: actual_model={outcome.actual_model} | latency_ms={outcome.latency_ms}ms | "
        f"attempts={outcome.attempts} | used_backup_key={outcome.used_backup_key}"
    )
    print(json.dumps(outcome.parsed.model_dump(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_run_smoke_check()))
