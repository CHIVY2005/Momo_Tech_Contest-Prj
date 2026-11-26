import httpx
import pytest
import respx

from app.config import Settings
from app.schemas import ExtractedIOCs
from app.services.ai_orchestrator import run_gemini_reasoning
from app.services.guardrails import GuardrailResult
from app.services.llm_client import normalize_openai_chat_url, parse_structured_llm_json


def test_settings_provider_resolution_and_url_normalization() -> None:
    cpa_cfg = Settings(
        _env_file=None,
        llm_provider="auto",
        gemini_base_url="https://cpa.joiboi.app/v1/",
        gemini_model="gemini-2.5-flash",
        gemini_api_key="test_key_a",
    )
    assert cpa_cfg.resolved_llm_provider == "openai_compatible"
    assert normalize_openai_chat_url(cpa_cfg.gemini_base_url) == (
        "https://cpa.joiboi.app/v1/chat/completions"
    )
    assert normalize_openai_chat_url("https://cpa.joiboi.app") == (
        "https://cpa.joiboi.app/v1/chat/completions"
    )

    official_cfg = Settings(
        _env_file=None,
        llm_provider="auto",
        gemini_base_url="",
        gemini_api_key="official_key",
    )
    assert official_cfg.resolved_llm_provider == "google_genai"


def test_parse_structured_llm_json_handles_fences_thinking_blocks_and_null_lists() -> None:
    raw_response = (
        "<think>Analyzing Vietnamese phishing indicators...</think>\n"
        "Kết quả JSON:\n"
        "```json\n"
        "{\n"
        '  "ai_risk_score": 91,\n'
        '  "summary_vi": "Cảnh báo tin nhắn giả mạo NAPAS lừa đánh cắp OTP.",\n'
        '  "transcript": null,\n'
        '  "manipulation_tactics": ["Gây áp lực hết hạn điểm thưởng"],\n'
        '  "highlighted_phrases": null,\n'
        '  "counter_replies": ["Tôi chỉ kiểm tra trên ứng dụng ngân hàng chính thức."],\n'
        '  "family_alert": null,\n'
        '  "bill_visual_anomalies": null\n'
        "}\n"
        "```"
    )
    parsed = parse_structured_llm_json(raw_response)
    assert parsed.ai_risk_score == 91
    assert "NAPAS" in parsed.summary_vi
    assert parsed.highlighted_phrases == []
    assert parsed.bill_visual_anomalies == []


@pytest.mark.asyncio
async def test_cpa_openai_compatible_retry_429_and_structured_json_telemetry() -> None:
    cfg = Settings(
        _env_file=None,
        llm_provider="openai_compatible",
        gemini_base_url="https://cpa.joiboi.app/v1",
        gemini_model="gemini-2.5-flash",
        gemini_api_key="cpa_primary_secret_123",
        llm_timeout_sec=5.0,
        llm_max_retries=2,
    )

    call_count = 0

    def _handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        assert request.headers.get("authorization") == "Bearer cpa_primary_secret_123"
        if call_count == 1:
            return httpx.Response(
                429,
                headers={"Retry-After": "0.02"},
                json={"error": {"message": "Rate limit exceeded"}},
            )
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl-cpa-01",
                "model": "cpa/gemini-2.5-flash-001",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": (
                                '{"ai_risk_score": 88, '
                                '"summary_vi": "Phát hiện giả danh Công an yêu cầu chuyển khoản.", '
                                '"manipulation_tactics": ["Thao túng nỗi sợ pháp lý"], '
                                '"counter_replies": ["Cơ quan Công an không làm việc qua Zalo."]}'
                            ),
                        },
                    }
                ],
            },
        )

    with respx.mock(assert_all_called=True) as router:
        router.post("https://cpa.joiboi.app/v1/chat/completions").mock(side_effect=_handler)
        res = await run_gemini_reasoning(
            settings=cfg,
            text="Tôi là cán bộ điều tra, yêu cầu chuyển 20 triệu để xác minh",
            mode="personal",
            guardrails=GuardrailResult(),
            classifier=None,
            iocs=ExtractedIOCs(),
            url_findings=[],
            vietqr_findings=[],
            image_forensics=None,
            receipt_logic=None,
            matched_playbooks=[],
        )

    assert call_count == 2
    assert res.degraded_mode is False
    assert res.ai_score == 88
    assert res.llm_provider == "openai_compatible"
    assert res.llm_model == "cpa/gemini-2.5-flash-001"
    assert res.llm_latency_ms is not None and res.llm_latency_ms >= 0
    assert res.llm_error is None


@pytest.mark.asyncio
async def test_cpa_400_response_format_compat_backup_failover_and_clean_degraded_error() -> None:
    cfg = Settings(
        _env_file=None,
        llm_provider="openai_compatible",
        gemini_base_url="https://cpa.joiboi.app/v1",
        gemini_model="custom-cpa-model",
        gemini_api_key="expired_primary_secret",
        gemini_backup_api_key="working_backup_secret",
        llm_timeout_sec=5.0,
        llm_max_retries=1,
    )

    seen_auth: list[str] = []

    def _failover_handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        seen_auth.append(auth)
        if auth == "Bearer expired_primary_secret":
            return httpx.Response(401, json={"error": {"message": "Invalid API key"}})
        body_text = request.content.decode("utf-8")
        if '"response_format"' in body_text:
            return httpx.Response(
                400,
                json={"error": {"message": "response_format is not supported by this model"}},
            )
        return httpx.Response(
            200,
            json={
                "model": "custom-cpa-model-v2",
                "choices": [
                    {
                        "message": {
                            "content": (
                                "```json\n"
                                '{"ai_risk_score": 12, "summary_vi": "Tin nhắn giao tiếp thông thường."}\n'
                                "```"
                            )
                        }
                    }
                ],
            },
        )

    with respx.mock(assert_all_called=True) as router:
        router.post("https://cpa.joiboi.app/v1/chat/completions").mock(
            side_effect=_failover_handler
        )
        ok_res = await run_gemini_reasoning(
            settings=cfg,
            text="Chiều nay 6h nhà mình ăn cơm nhé mẹ",
            mode="personal",
            guardrails=GuardrailResult(),
            classifier=None,
            iocs=ExtractedIOCs(),
            url_findings=[],
            vietqr_findings=[],
            image_forensics=None,
            receipt_logic=None,
            matched_playbooks=[],
        )

    assert ok_res.degraded_mode is False
    assert ok_res.ai_score == 12
    assert ok_res.llm_model == "custom-cpa-model-v2"
    assert "Bearer expired_primary_secret" in seen_auth
    assert "Bearer working_backup_secret" in seen_auth

    # Total outage falls back cleanly without leaking secrets
    with respx.mock(assert_all_called=True) as router:
        router.post("https://cpa.joiboi.app/v1/chat/completions").mock(
            return_value=httpx.Response(503, json={"error": {"message": "Upstream overloaded"}})
        )
        deg_res = await run_gemini_reasoning(
            settings=cfg,
            text="Kiểm tra tin nhắn",
            mode="personal",
            guardrails=GuardrailResult(),
            classifier=None,
            iocs=ExtractedIOCs(),
            url_findings=[],
            vietqr_findings=[],
            image_forensics=None,
            receipt_logic=None,
            matched_playbooks=[],
        )

    assert deg_res.degraded_mode is True
    assert deg_res.llm_error == "HTTP_503"
    assert "expired_primary_secret" not in (deg_res.llm_error or "")
    assert "working_backup_secret" not in (deg_res.llm_error or "")
