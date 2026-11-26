import sys
from pathlib import Path

import httpx
import pytest
import respx

from app.config import Settings

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from evaluation.run_benchmark import load_benchmark_cases, run_benchmark_suite  # noqa: E402


def test_benchmark_dataset_has_40_balanced_synthetic_vietnamese_cases() -> None:
    dataset_path = REPO_ROOT / "evaluation" / "dataset_vn_benchmark.json"
    cases = load_benchmark_cases(dataset_path)
    assert len(cases) == 40
    scam_count = sum(1 for c in cases if c.expected_is_scam)
    benign_count = sum(1 for c in cases if not c.expected_is_scam)
    assert scam_count >= 25
    assert benign_count >= 10
    categories = {c.category for c in cases}
    assert "safety_advisory" in categories
    assert "prompt_injection" in categories
    assert "fake_bill" in categories


@pytest.mark.asyncio
async def test_benchmark_runner_records_real_model_latency_and_errors_without_secret_leak(
    tmp_path: Path,
) -> None:
    dataset_path = REPO_ROOT / "evaluation" / "dataset_vn_benchmark.json"
    cases = load_benchmark_cases(dataset_path)[:3]

    cfg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "bench_test.db"),
        llm_provider="openai_compatible",
        gemini_base_url="https://cpa.joiboi.app/v1",
        gemini_model="gemini-2.5-flash",
        gemini_api_key="super_secret_do_not_leak",
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
        enable_local_ocr=False,
        enable_local_stt=False,
        llm_max_retries=0,
    )

    idx = 0

    def _mock_cpa(_req: httpx.Request) -> httpx.Response:
        nonlocal idx
        idx += 1
        if idx == 2:
            return httpx.Response(502, json={"error": {"message": "Bad Gateway"}})
        return httpx.Response(
            200,
            json={
                "model": "cpa/gemini-2.5-flash-live",
                "choices": [
                    {
                        "message": {
                            "content": (
                                '{"ai_risk_score": 90, '
                                '"summary_vi": "Phát hiện dấu hiệu lừa đảo rõ rệt."}'
                            )
                        }
                    }
                ],
            },
        )

    with respx.mock(assert_all_called=True) as router:
        router.post("https://cpa.joiboi.app/v1/chat/completions").mock(side_effect=_mock_cpa)
        summary = await run_benchmark_suite(cases=cases, settings=cfg, require_live_llm=False)

    serialized = str(summary)
    assert "super_secret_do_not_leak" not in serialized
    assert summary["actual_models_observed"] == {"cpa/gemini-2.5-flash-live": 2}
    assert summary["api_health"]["live_llm_success_count"] == 2
    assert summary["api_health"]["degraded_fallback_count"] == 1
    assert summary["api_health"]["api_error_count"] == 1
    assert summary["api_health"]["error_breakdown"] == {"HTTP_502": 1}
    assert len(summary["per_case_results"]) == 3


def test_gitignore_protects_backend_and_root_dotenv_files() -> None:
    gitignore_lines = {
        ln.strip()
        for ln in (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    }
    assert ".env" in gitignore_lines
    assert "backend/.env" in gitignore_lines
    assert "backend/.env.*" in gitignore_lines
    assert "!backend/.env.example" in gitignore_lines
