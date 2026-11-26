"""Live 40-case Vietnamese & Red-Team benchmark runner using real backend/.env configuration."""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import tempfile
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.config import Settings, get_settings  # noqa: E402
from app.db.repository import CaseRepository  # noqa: E402
from app.main import PROTECTED_SAFE_DEMO_IOCS  # noqa: E402
from app.schemas import AnalyzeMode  # noqa: E402
from app.services.pipeline import AnalysisPipeline  # noqa: E402


class BenchmarkCase(BaseModel):
    """Single labeled evaluation case from dataset_vn_benchmark.json."""

    case_id: str
    category: str
    mode: AnalyzeMode = "personal"
    in_active_call: bool = False
    transfer_amount: int | None = None
    expected_merchant_account: str | None = None
    image_filename: str | None = None
    audio_filename: str | None = None
    url: str | None = None
    text: str
    expected_is_scam: bool


def load_benchmark_cases(dataset_path: Path) -> list[BenchmarkCase]:
    raw = json.loads(dataset_path.read_text(encoding="utf-8"))
    return [BenchmarkCase.model_validate(item) for item in raw]


def _percentile(values: list[int], pct: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, round((pct / 100.0) * (len(ordered) - 1))))
    return int(ordered[idx])


async def run_benchmark_suite(
    cases: list[BenchmarkCase],
    settings: Settings,
    require_live_llm: bool = False,
    inter_case_delay_ms: int = 0,
) -> dict[str, Any]:
    """Run AnalysisPipeline across benchmark cases and record 100% real model/latency/error metrics."""
    has_primary = bool(settings.gemini_api_key.strip())
    has_backup = bool(settings.gemini_backup_api_key.strip())
    if require_live_llm and not (has_primary or has_backup):
        raise RuntimeError(
            "require_live_llm=True but neither GEMINI_API_KEY nor GEMINI_BACKUP_API_KEY "
            "is set in backend/.env."
        )

    demo_media_dir = BACKEND_DIR / "app" / "data" / "demo_media"
    seed_path = BACKEND_DIR / "app" / "data" / "seed_iocs.json"

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        run_cfg = settings.model_copy(
            update={
                "sqlite_path": str(Path(tmp_dir) / "benchmark_isolated.db"),
                "enable_playwright_sandbox": False,
            }
        )
        repo = CaseRepository(run_cfg.sqlite_path, default_ttl_minutes=run_cfg.block_rule_ttl_minutes)
        repo.init_db()
        repo.seed_if_empty(str(seed_path), protected_iocs=PROTECTED_SAFE_DEMO_IOCS)
        pipeline = AnalysisPipeline(settings=run_cfg, repo=repo)

        per_case: list[dict[str, Any]] = []
        e2e_latencies: list[int] = []
        llm_latencies: list[int] = []
        onnx_latencies: list[int] = []
        observed_models: Counter[str] = Counter()
        error_counter: Counter[str] = Counter()

        tp = fp = tn = fn = 0
        advisory_total = advisory_fp = 0
        injection_total = injection_blocked = 0
        fake_bill_total = fake_bill_caught = 0
        live_llm_success = 0
        degraded_count = 0

        for idx, case in enumerate(cases):
            img_bytes: bytes | None = None
            img_mime = "image/jpeg"
            if case.image_filename:
                img_path = demo_media_dir / case.image_filename
                img_bytes = img_path.read_bytes()
                img_mime = "image/png" if case.image_filename.endswith(".png") else "image/jpeg"

            aud_bytes: bytes | None = None
            if case.audio_filename:
                aud_bytes = (demo_media_dir / case.audio_filename).read_bytes()

            t0 = time.perf_counter()
            report = await pipeline.run(
                mode=case.mode,
                text=case.text,
                url=case.url,
                image_bytes=img_bytes,
                image_filename=case.image_filename or "upload.jpg",
                image_mime=img_mime,
                audio_bytes=aud_bytes,
                audio_filename=case.audio_filename or "call.wav",
                in_active_call=case.in_active_call,
                transfer_amount=case.transfer_amount,
                expected_merchant_account=case.expected_merchant_account,
            )
            e2e_ms = int((time.perf_counter() - t0) * 1000)
            e2e_latencies.append(e2e_ms)

            if report.classifier and report.classifier.available:
                onnx_latencies.append(report.classifier.latency_ms)

            if not report.degraded_mode and report.llm_model:
                live_llm_success += 1
                observed_models[report.llm_model] += 1
                if report.llm_latency_ms is not None:
                    llm_latencies.append(report.llm_latency_ms)
            else:
                degraded_count += 1
                if report.llm_error and report.llm_error != "NO_API_KEY":
                    error_counter[report.llm_error] += 1

            predicted_is_scam = report.verdict != "SAFE"
            passed = predicted_is_scam == case.expected_is_scam

            if case.expected_is_scam and predicted_is_scam:
                tp += 1
            elif not case.expected_is_scam and predicted_is_scam:
                fp += 1
            elif not case.expected_is_scam and not predicted_is_scam:
                tn += 1
            else:
                fn += 1

            if case.category == "safety_advisory":
                advisory_total += 1
                if predicted_is_scam:
                    advisory_fp += 1
            elif case.category == "prompt_injection":
                injection_total += 1
                if report.risk_score >= 70 and predicted_is_scam:
                    injection_blocked += 1
            elif case.category == "fake_bill":
                fake_bill_total += 1
                if predicted_is_scam:
                    fake_bill_caught += 1

            per_case.append(
                {
                    "case_id": case.case_id,
                    "category": case.category,
                    "mode": case.mode,
                    "expected_is_scam": case.expected_is_scam,
                    "predicted_verdict": report.verdict,
                    "predicted_is_scam": predicted_is_scam,
                    "risk_score": report.risk_score,
                    "passed": passed,
                    "receipt_verification_status": report.receipt_verification_status,
                    "llm_provider": report.llm_provider,
                    "actual_llm_model": report.llm_model,
                    "degraded_mode": report.degraded_mode,
                    "llm_error": report.llm_error,
                    "llm_latency_ms": report.llm_latency_ms,
                    "onnx_latency_ms": report.classifier.latency_ms if report.classifier else None,
                    "e2e_latency_ms": e2e_ms,
                }
            )

            if inter_case_delay_ms > 0 and idx + 1 < len(cases):
                await asyncio.sleep(inter_case_delay_ms / 1000.0)

        if require_live_llm and live_llm_success == 0:
            raise RuntimeError(
                f"Benchmark failed live-LLM requirement: 0/{len(cases)} calls succeeded. "
                f"Errors: {dict(error_counter)}"
            )

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / len(cases) if cases else 0.0

        return {
            "benchmark_timestamp_utc": datetime.now(UTC).isoformat(),
            "dataset_size": len(cases),
            "onnx_classifier_loaded": pipeline.classifier.is_available,
            "llm_config": {
                "provider": settings.resolved_llm_provider,
                "base_url": settings.gemini_base_url or None,
                "configured_model": settings.gemini_model,
                "timeout_sec": settings.llm_timeout_sec,
                "max_retries": settings.llm_max_retries,
                "has_primary_key": has_primary,
                "has_backup_key": has_backup,
            },
            "actual_models_observed": dict(observed_models),
            "api_health": {
                "live_llm_success_count": live_llm_success,
                "degraded_fallback_count": degraded_count,
                "api_error_count": int(sum(error_counter.values())),
                "error_breakdown": dict(error_counter),
            },
            "latency_ms": {
                "e2e_p50_ms": _percentile(e2e_latencies, 50),
                "e2e_p95_ms": _percentile(e2e_latencies, 95),
                "e2e_mean_ms": round(statistics.mean(e2e_latencies), 1) if e2e_latencies else 0.0,
                "llm_p50_ms": _percentile(llm_latencies, 50),
                "llm_p95_ms": _percentile(llm_latencies, 95),
                "onnx_p50_ms": _percentile(onnx_latencies, 50),
                "onnx_p95_ms": _percentile(onnx_latencies, 95),
            },
            "classification_metrics": {
                "total_cases": len(cases),
                "scam_cases": tp + fn,
                "benign_cases": tn + fp,
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
                "accuracy": round(accuracy, 4),
                "safety_advisory_fpr": round(advisory_fp / advisory_total, 4) if advisory_total else 0.0,
                "prompt_injection_block_rate": (
                    round(injection_blocked / injection_total, 4) if injection_total else 0.0
                ),
                "fake_bill_catch_rate": (
                    round(fake_bill_caught / fake_bill_total, 4) if fake_bill_total else 0.0
                ),
            },
            "per_case_results": per_case,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run VeriShield AI 40-case Vietnamese benchmark.")
    parser.add_argument(
        "--dataset",
        default=str(REPO_ROOT / "evaluation" / "dataset_vn_benchmark.json"),
        help="Path to benchmark dataset JSON.",
    )
    parser.add_argument(
        "--output",
        default=str(REPO_ROOT / "evaluation" / "results.json"),
        help="Path to write empirical results JSON.",
    )
    parser.add_argument(
        "--require-live-llm",
        action="store_true",
        help="Fail with non-zero exit code if API keys are missing or 0 live LLM calls succeed.",
    )
    parser.add_argument(
        "--delay-ms",
        type=int,
        default=150,
        help="Optional polite delay (ms) between cases to avoid proxy burst rate-limits.",
    )
    args = parser.parse_args()

    get_settings.cache_clear()
    cfg = get_settings()
    cases = load_benchmark_cases(Path(args.dataset))
    print(
        f"==> Running VeriShield Benchmark ({len(cases)} cases) | "
        f"provider={cfg.resolved_llm_provider} | base_url={cfg.gemini_base_url or 'official'} | "
        f"model={cfg.gemini_model}"
    )

    summary = asyncio.run(
        run_benchmark_suite(
            cases=cases,
            settings=cfg,
            require_live_llm=args.require_live_llm,
            inter_case_delay_ms=args.delay_ms,
        )
    )

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    cm = summary["classification_metrics"]
    ah = summary["api_health"]
    lat = summary["latency_ms"]
    print(f"==> Saved empirical benchmark report to: {out_path}")
    print(
        f"    Models observed: {summary['actual_models_observed']} | "
        f"Live LLM: {ah['live_llm_success_count']}/{summary['dataset_size']} | "
        f"API Errors: {ah['api_error_count']} {ah['error_breakdown']}"
    )
    print(
        f"    Precision={cm['precision']:.4f} | Recall={cm['recall']:.4f} | F1={cm['f1']:.4f} | "
        f"Advisory FPR={cm['safety_advisory_fpr']:.4f} | "
        f"Injection Block={cm['prompt_injection_block_rate']:.4f}"
    )
    print(
        f"    Latency P50/P95: E2E={lat['e2e_p50_ms']}/{lat['e2e_p95_ms']}ms | "
        f"LLM={lat['llm_p50_ms']}/{lat['llm_p95_ms']}ms | ONNX={lat['onnx_p50_ms']}/{lat['onnx_p95_ms']}ms"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
