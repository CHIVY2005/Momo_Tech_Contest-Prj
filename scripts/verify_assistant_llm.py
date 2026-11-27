"""Live & offline smoke verifier for VeriShield Assistant dual-protocol streaming LLM adapters."""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.config import Settings, get_settings  # noqa: E402
from app.services.assistant_context import ASSISTANT_SYSTEM_INSTRUCTION  # noqa: E402
from app.services.assistant_guardrails import ThinkStreamFilter  # noqa: E402
from app.services.assistant_llm import (  # noqa: E402
    AssistantLlmUnavailableError,
    apply_final_wire_egress_chokepoint,
    stream_assistant_llm,
)
from app.services.vietqr_parser import build_vietqr_test_payload  # noqa: E402


async def _verify_offline_invariants() -> None:
    raw_qr = build_vietqr_test_payload("970436", "1903667788901", "500000", "Hoan tien")
    dirty_prompt = (
        "[GROUNDED_KB_CONTEXT]\n"
        "Đối chiếu tại vietcombank.com.vn hoặc canhbao.khonggianmang.vn.\n\n"
        "<UNTRUSTED_USER_CONTENT>\n"
        f"Link: https://evil.top/a?k=1 | IPv6: http://[::ffff:127.0.0.1]/ | Int: http://2130706433/\n"
        f"QR: {raw_qr} | Email: a@example.com | CCCD: 079203012345 | SĐT: 0912345678 | OTP: 482910\n"
        "</UNTRUSTED_USER_CONTENT>"
    )
    scrubbed = apply_final_wire_egress_chokepoint(dirty_prompt)
    prefix, rest = scrubbed.split("<UNTRUSTED_USER_CONTENT>", 1)
    assert "vietcombank.com.vn" in prefix and "canhbao.khonggianmang.vn" in prefix
    leaks = ("evil.top", "::ffff:127.0.0.1", "2130706433", raw_qr, "a@example.com", "0912345678", "482910")
    for leaked in leaks:
        assert leaked not in rest, f"Chokepoint failed to redact {leaked!r}"

    fail_closed = apply_final_wire_egress_chokepoint("vietcombank.com.vn 0912345678")
    assert "vietcombank.com.vn" not in fail_closed and "0912345678" not in fail_closed

    filt = ThinkStreamFilter()
    filtered = "".join(filt.feed(p) for p in ("<th", "ink>hidden</th", "ink>visible")) + filt.flush()
    assert filtered == "visible"

    offline_cfg = Settings(_env_file=None, gemini_api_key="", gemini_backup_api_key="")
    try:
        async for _ in stream_assistant_llm(
            offline_cfg,
            system_instruction="sys",
            user_prompt="<UNTRUSTED_USER_CONTENT>\nhello\n</UNTRUSTED_USER_CONTENT>",
        ):
            pass
    except AssistantLlmUnavailableError as exc:
        assert exc.error_code == "NO_API_KEY"
    else:
        raise AssertionError("Expected AssistantLlmUnavailableError when keys are missing.")


async def _probe_provider(cfg: Settings, provider: str) -> bool:
    probe_cfg = cfg.model_copy(update={"llm_provider": provider})
    if provider == "openai_compatible" and not probe_cfg.gemini_base_url.strip():
        print(f"    [{provider}] SKIPPED (GEMINI_BASE_URL is empty).")
        return True
    prompt = (
        "[GROUNDED_KB_CONTEXT]\n"
        "[KB:ver_official] Chỉ xác minh trên vietcombank.com.vn hoặc canhbao.khonggianmang.vn.\n\n"
        "<UNTRUSTED_USER_CONTENT>\n"
        "[CURRENT_USER_MESSAGE]\n"
        "Tôi nhận được tin nhắn yêu cầu nhập mã OTP để nhận thưởng, cần làm gì?\n"
        "</UNTRUSTED_USER_CONTENT>"
    )
    t0 = time.perf_counter()
    ttft_ms: int | None = None
    chunks: list[str] = []
    try:
        async for piece in stream_assistant_llm(
            probe_cfg,
            system_instruction=ASSISTANT_SYSTEM_INSTRUCTION,
            user_prompt=prompt,
            max_output_tokens=220,
            timeout_sec=20.0,
        ):
            if ttft_ms is None:
                ttft_ms = int((time.perf_counter() - t0) * 1000)
            chunks.append(piece)
    except AssistantLlmUnavailableError as exc:
        print(f"    [{provider}] FALLBACK_TRIGGERED: error_code={exc.error_code}")
        return False

    full = "".join(chunks)
    total_ms = int((time.perf_counter() - t0) * 1000)
    has_think = "<think" in full.lower() or "</think" in full.lower()
    print(
        f"    [{provider}] OK: chunks={len(chunks)} | chars={len(full)} | "
        f"ttft_ms={ttft_ms}ms | total_ms={total_ms}ms | think_leaked={has_think}"
    )
    return bool(full.strip()) and not has_think


async def _run(provider_arg: str) -> int:
    print("==> [VeriShield Assistant LLM Verification]")
    await _verify_offline_invariants()
    print("    Offline checks (wire chokepoint, <think> filter, missing-key fallback): PASSED")

    get_settings.cache_clear()
    cfg = get_settings()
    has_key = bool(cfg.gemini_api_key.strip() or cfg.gemini_backup_api_key.strip())
    print(
        f"    Resolved Provider: {cfg.resolved_llm_provider} | "
        f"Model: {cfg.gemini_model} | Key Configured: {has_key}"
    )
    if not has_key:
        print("    Live streaming probe SKIPPED (no GEMINI_API_KEY configured). Exiting cleanly.")
        return 0

    targets = (
        ["openai_compatible", "google_genai"]
        if provider_arg == "both"
        else [cfg.resolved_llm_provider if provider_arg == "auto" else provider_arg]
    )
    all_ok = True
    for prov in targets:
        ok = await _probe_provider(cfg, prov)
        all_ok = all_ok and ok
    return 0 if all_ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify VeriShield Assistant streaming LLM adapters.")
    parser.add_argument(
        "--provider",
        choices=("auto", "openai_compatible", "google_genai", "both"),
        default="auto",
    )
    args = parser.parse_args()
    return asyncio.run(_run(args.provider))


if __name__ == "__main__":
    raise SystemExit(main())
