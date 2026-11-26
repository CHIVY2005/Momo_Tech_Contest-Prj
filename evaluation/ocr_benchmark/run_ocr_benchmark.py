"""Subprocess-isolated empirical OCR benchmark comparing RapidOCR ONNX, MinerU Basic ONNX, and Gemini."""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import json
import os
import platform
import re
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

DEFAULT_OUT_DIR = Path(__file__).resolve().parent / "dataset"
RESULTS_PATH = Path(__file__).resolve().parent / "results.json"


def _get_peak_rss_mb() -> float:
    """Measure true OS-reported peak working-set / RSS memory of the current process in MB."""
    if sys.platform == "win32":
        class _ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = _ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        k32_get_mem = kernel32.K32GetProcessMemoryInfo
        k32_get_mem.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
        k32_get_mem.restype = ctypes.c_int
        handle = kernel32.GetCurrentProcess()
        if k32_get_mem(handle, ctypes.byref(counters), counters.cb):
            return round(counters.PeakWorkingSetSize / (1024 * 1024), 2)
        return 0.0

    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(usage / (1024 * 1024) if sys.platform == "darwin" else usage / 1024.0, 2)
    except Exception:
        return 0.0


def _run_worker_rapidocr(
    manifest: list[dict[str, Any]],
    dataset_dir: Path,
    variant: str,
    use_cls: bool,
) -> dict[str, Any]:
    from app.services.ocr.rapidocr_provider import RapidOcrOnnxProvider

    provider = RapidOcrOnnxProvider(
        variant=variant,
        allow_download=True,
        use_cls=use_cls,
        intra_op_num_threads=2,
    )
    # Warm-up model load once before per-image timing
    t_load0 = time.perf_counter()
    first_bytes = (dataset_dir / manifest[0]["filename"]).read_bytes()
    _ = provider.extract(first_bytes)
    cold_load_ms = round((time.perf_counter() - t_load0) * 1000.0, 2)

    t_wall0 = time.perf_counter()
    t_cpu0 = time.process_time()
    records: list[dict[str, Any]] = []
    for item in manifest:
        img_bytes = (dataset_dir / item["filename"]).read_bytes()
        mime = "image/jpeg" if item["filename"].endswith(".jpg") else "image/png"
        t0 = time.perf_counter()
        res = provider.extract(img_bytes, mime_type=mime)
        dt_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        records.append(
            {
                "sample_id": item["sample_id"],
                "category": item["category"],
                "status": res.status,
                "text": res.full_text,
                "mean_confidence": res.mean_confidence,
                "boxes_count": len(res.boxes),
                "latency_ms": dt_ms,
                "error_code": res.error_code,
            }
        )
    wall_s = max(1e-6, time.perf_counter() - t_wall0)
    cpu_s = max(0.0, time.process_time() - t_cpu0)
    cpu_cores = os.cpu_count() or 1
    return {
        "engine": f"rapidocr_{variant}{'_cls' if use_cls else ''}",
        "model_id": provider.model_id,
        "license": provider.license_name,
        "available": True,
        "cold_load_ms": cold_load_ms,
        "total_wall_sec": round(wall_s, 3),
        "total_cpu_sec": round(cpu_s, 3),
        "cpu_util_single_core_pct": round((cpu_s / wall_s) * 100.0, 1),
        "cpu_util_machine_pct": round((cpu_s / (wall_s * cpu_cores)) * 100.0, 1),
        "peak_rss_mb": _get_peak_rss_mb(),
        "records": records,
    }


def _run_worker_gemini(manifest: list[dict[str, Any]], dataset_dir: Path) -> dict[str, Any]:
    from app.config import get_settings
    from app.services.ocr.gemini_provider import extract_ocr_via_gemini

    settings = get_settings()
    if not (settings.gemini_api_key.strip() or settings.gemini_backup_api_key.strip()):
        return {
            "engine": "gemini_multimodal",
            "model_id": settings.gemini_model,
            "license": "Commercial API (Google Gemini / Configured Gateway)",
            "available": False,
            "error": "NO_API_KEY",
            "records": [],
        }

    async def _run_all() -> tuple[list[dict[str, Any]], float, float]:
        t_wall0 = time.perf_counter()
        t_cpu0 = time.process_time()
        recs: list[dict[str, Any]] = []
        for item in manifest:
            img_bytes = (dataset_dir / item["filename"]).read_bytes()
            mime = "image/jpeg" if item["filename"].endswith(".jpg") else "image/png"
            t0 = time.perf_counter()
            res = await extract_ocr_via_gemini(
                settings=settings,
                image_bytes=img_bytes,
                image_mime=mime,
                timeout_sec=25.0,
            )
            dt_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            recs.append(
                {
                    "sample_id": item["sample_id"],
                    "category": item["category"],
                    "status": res.status,
                    "text": res.full_text,
                    "mean_confidence": res.mean_confidence,
                    "boxes_count": 0,
                    "latency_ms": dt_ms,
                    "error_code": res.error_code,
                }
            )
        return recs, max(1e-6, time.perf_counter() - t_wall0), max(0.0, time.process_time() - t_cpu0)

    records, wall_s, cpu_s = asyncio.run(_run_all())
    cpu_cores = os.cpu_count() or 1
    return {
        "engine": "gemini_multimodal",
        "model_id": settings.gemini_model,
        "license": "Commercial API (Gemini Multimodal)",
        "available": True,
        "cold_load_ms": 0.0,
        "total_wall_sec": round(wall_s, 3),
        "total_cpu_sec": round(cpu_s, 3),
        "cpu_util_single_core_pct": round((cpu_s / wall_s) * 100.0, 1),
        "cpu_util_machine_pct": round((cpu_s / (wall_s * cpu_cores)) * 100.0, 1),
        "peak_rss_mb": _get_peak_rss_mb(),
        "records": records,
    }


def _run_worker_mineru(manifest: list[dict[str, Any]], dataset_dir: Path) -> dict[str, Any]:
    import importlib.metadata

    os.environ["MINERU_MODEL_ONNX_DEVICE"] = "cpu"
    try:
        import mineru
    except Exception as exc:
        return {
            "engine": "mineru_basic_onnx",
            "model_id": "mineru-v4-basic-onnx",
            "license": "LicenseRef-MinerU-Open-Source-License",
            "available": False,
            "error": f"IMPORT_FAILED: {type(exc).__name__}: {exc}",
            "records": [],
        }

    parse_fn: Any = getattr(mineru, "parse", None)
    try:
        mineru_ver = importlib.metadata.version("mineru")
    except Exception:
        mineru_ver = "4.x"

    def _parse_one(img_path: Path) -> tuple[str, str | None]:
        if not callable(parse_fn):
            return "", "MINERU_PARSE_MISSING"
        res = parse_fn(
            str(img_path),
            tier="basic",
            ocr_mode="ocr",
            image_analysis=False,
        )
        md_attr = getattr(res, "markdown", None)
        if callable(md_attr):
            md_val = md_attr()
        elif isinstance(md_attr, str):
            md_val = md_attr
        else:
            md_val = res if isinstance(res, str) else ""
        cleaned = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", str(md_val or "")).strip()
        # Strip leading markdown heading markers (# ) so markdown formatting does not distort CER
        lines = [ln.lstrip("#").strip() if ln.startswith("#") else ln for ln in cleaned.splitlines()]
        return "\n".join(ln for ln in lines if ln.strip()).strip(), None

    # Warm-up once
    t_load0 = time.perf_counter()
    try:
        _w_txt, _w_err = _parse_one(dataset_dir / manifest[0]["filename"])
    except Exception as exc:
        return {
            "engine": "mineru_basic_onnx",
            "model_id": f"mineru-{mineru_ver}-basic-onnx",
            "license": "LicenseRef-MinerU-Open-Source-License",
            "available": False,
            "error": f"WARMUP_FAILED: {type(exc).__name__}: {exc}",
            "records": [],
        }
    cold_load_ms = round((time.perf_counter() - t_load0) * 1000.0, 2)

    t_wall0 = time.perf_counter()
    t_cpu0 = time.process_time()
    records: list[dict[str, Any]] = []
    for item in manifest:
        img_path = dataset_dir / item["filename"]
        t0 = time.perf_counter()
        try:
            txt, err = _parse_one(img_path)
            status = "ok" if txt else ("error" if err else "empty")
        except Exception as exc:
            txt = ""
            err = f"{type(exc).__name__}: {exc}"
            status = "error"
        dt_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        records.append(
            {
                "sample_id": item["sample_id"],
                "category": item["category"],
                "status": status,
                "text": txt,
                "mean_confidence": 0.85 if txt else 0.0,
                "boxes_count": 0,
                "latency_ms": dt_ms,
                "error_code": err,
            }
        )
    wall_s = max(1e-6, time.perf_counter() - t_wall0)
    cpu_s = max(0.0, time.process_time() - t_cpu0)
    cpu_cores = os.cpu_count() or 1
    return {
        "engine": "mineru_basic_onnx",
        "model_id": f"mineru-{mineru_ver}-basic-onnx",
        "license": "LicenseRef-MinerU-Open-Source-License",
        "available": True,
        "cold_load_ms": cold_load_ms,
        "total_wall_sec": round(wall_s, 3),
        "total_cpu_sec": round(cpu_s, 3),
        "cpu_util_single_core_pct": round((cpu_s / wall_s) * 100.0, 1),
        "cpu_util_machine_pct": round((cpu_s / (wall_s * cpu_cores)) * 100.0, 1),
        "peak_rss_mb": _get_peak_rss_mb(),
        "records": records,
    }


def _evaluate_engine_output(
    raw: dict[str, Any],
    manifest: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compute CER, WER, entity F1, latency p50/p95, and downstream E5+Receipt classification metrics."""
    from app.services.guardrails import evaluate_guardrails
    from app.services.ioc_extractor import extract_iocs
    from app.services.receipt_validator import validate_receipt_logic
    from app.services.scam_classifier import ScamClassifier
    from app.services.url_inspector import _score_single_url
    from evaluation.ocr_benchmark.metrics import (
        compute_cer,
        compute_wer,
        extract_benchmark_entities,
        percentile,
        score_entity_extraction,
    )

    if not raw.get("available"):
        return raw

    classifier = ScamClassifier(str(BACKEND_DIR / "app" / "data" / "models"))
    manifest_map = {item["sample_id"]: item for item in manifest}

    cer_exact_all: list[float] = []
    cer_ascii_all: list[float] = []
    wer_all: list[float] = []
    latencies: list[float] = []
    ent_tp = ent_fp = ent_fn = 0.0
    scam_correct = 0
    receipt_tp = receipt_fp = receipt_fn = 0
    per_category: dict[str, dict[str, list[float]]] = {}
    ok_count = 0

    for rec in raw.get("records", []):
        gt = manifest_map[rec["sample_id"]]
        hyp = str(rec.get("text", "") or "")
        if rec.get("status") == "ok":
            ok_count += 1

        cer_ex = compute_cer(gt["ground_truth_text"], hyp, fold_ascii=False)
        cer_as = compute_cer(gt["ground_truth_text"], hyp, fold_ascii=True)
        wer = compute_wer(gt["ground_truth_text"], hyp)
        lat = float(rec.get("latency_ms", 0.0))

        cer_exact_all.append(cer_ex)
        cer_ascii_all.append(cer_as)
        wer_all.append(wer)
        latencies.append(lat)

        cat = gt["category"]
        cat_bucket = per_category.setdefault(
            cat,
            {"cer_exact": [], "cer_ascii": [], "wer": [], "latency_ms": []},
        )
        cat_bucket["cer_exact"].append(cer_ex)
        cat_bucket["cer_ascii"].append(cer_as)
        cat_bucket["wer"].append(wer)
        cat_bucket["latency_ms"].append(lat)

        pred_ents = extract_benchmark_entities(hyp, extract_iocs_fn=extract_iocs)
        ent_sc = score_entity_extraction(gt["entities"], pred_ents)
        ent_tp += ent_sc["tp"]
        ent_fp += ent_sc["fp"]
        ent_fn += ent_sc["fn"]

        # Downstream VeriShield Tier-1 scam classification + receipt validation impact
        guard = evaluate_guardrails(hyp)
        clf_out, _ = classifier.predict(hyp)
        rl = validate_receipt_logic(hyp)
        iocs = extract_iocs(hyp)
        url_risk = max((_score_single_url(u)[4] for u in iocs.urls), default=0)

        pred_is_receipt = rl.is_receipt_candidate
        if gt["expected_is_receipt"] and pred_is_receipt:
            receipt_tp += 1
        elif not gt["expected_is_receipt"] and pred_is_receipt:
            receipt_fp += 1
        elif gt["expected_is_receipt"] and not pred_is_receipt:
            receipt_fn += 1

        pred_is_scam = bool(
            (not guard.safety_advisory_detected)
            and (
                url_risk >= 40
                or rl.logic_risk_points >= 25
                or (clf_out.available and clf_out.scam_probability >= 0.50 and not pred_is_receipt)
            )
        )
        if pred_is_scam == bool(gt["expected_is_scam"]):
            scam_correct += 1

    ent_prec = ent_tp / (ent_tp + ent_fp) if (ent_tp + ent_fp) > 0 else 0.0
    ent_rec = ent_tp / (ent_tp + ent_fn) if (ent_tp + ent_fn) > 0 else 0.0
    ent_f1 = (2 * ent_prec * ent_rec / (ent_prec + ent_rec)) if (ent_prec + ent_rec) > 0 else 0.0
    rcpt_recall = receipt_tp / (receipt_tp + receipt_fn) if (receipt_tp + receipt_fn) > 0 else 0.0

    cat_summary = {
        cat: {
            "cer_exact_mean": round(sum(b["cer_exact"]) / len(b["cer_exact"]), 4),
            "cer_ascii_mean": round(sum(b["cer_ascii"]) / len(b["cer_ascii"]), 4),
            "wer_mean": round(sum(b["wer"]) / len(b["wer"]), 4),
            "latency_p50_ms": percentile(b["latency_ms"], 50),
        }
        for cat, b in per_category.items()
    }

    total_n = max(1, len(manifest))
    return {
        "engine": raw["engine"],
        "model_id": raw["model_id"],
        "license": raw["license"],
        "available": True,
        "samples_total": len(manifest),
        "samples_ok": ok_count,
        "cer_exact_mean": round(sum(cer_exact_all) / len(cer_exact_all), 4),
        "cer_ascii_mean": round(sum(cer_ascii_all) / len(cer_ascii_all), 4),
        "wer_mean": round(sum(wer_all) / len(wer_all), 4),
        "entity_precision": round(ent_prec, 4),
        "entity_recall": round(ent_rec, 4),
        "entity_f1": round(ent_f1, 4),
        "scam_classification_accuracy": round(scam_correct / total_n, 4),
        "receipt_detection_recall": round(rcpt_recall, 4),
        "receipt_false_positives": receipt_fp,
        "latency_p50_ms": percentile(latencies, 50),
        "latency_p95_ms": percentile(latencies, 95),
        "latency_mean_ms": round(sum(latencies) / len(latencies), 2),
        "cold_load_ms": raw["cold_load_ms"],
        "peak_rss_mb": raw["peak_rss_mb"],
        "cpu_util_single_core_pct": raw["cpu_util_single_core_pct"],
        "cpu_util_machine_pct": raw["cpu_util_machine_pct"],
        "per_category": cat_summary,
    }


def _invoke_subprocess_worker(python_exe: str, engine: str, dataset_dir: Path) -> dict[str, Any]:
    cmd = [
        python_exe,
        str(Path(__file__).resolve()),
        "--worker",
        engine,
        "--dataset-dir",
        str(dataset_dir),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900, check=False)  # noqa: S603
    marker = "__OCR_BENCH_JSON__"
    for line in reversed(proc.stdout.splitlines()):
        if line.startswith(marker):
            parsed: dict[str, Any] = json.loads(line[len(marker) :])
            return parsed
    return {
        "engine": engine,
        "available": False,
        "error": f"WORKER_FAILED(rc={proc.returncode}): {(proc.stderr or proc.stdout)[-400:].strip()}",
        "records": [],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Empirical Vietnamese OCR benchmark runner.")
    parser.add_argument("--worker", type=str, default=None, help="Internal subprocess engine worker.")
    parser.add_argument("--dataset-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--mineru-python", type=str, default="")
    parser.add_argument("--only-mineru", action="store_true")
    parser.add_argument("--skip-gemini", action="store_true")
    parser.add_argument("--output", type=Path, default=RESULTS_PATH)
    args = parser.parse_args()

    manifest_path = args.dataset_dir / "manifest.json"
    if args.worker:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if args.worker == "rapidocr_v4_ch":
            out = _run_worker_rapidocr(manifest, args.dataset_dir, "ppocrv4", False)
        elif args.worker == "rapidocr_v5_latin":
            out = _run_worker_rapidocr(manifest, args.dataset_dir, "ppocrv5_latin", False)
        elif args.worker == "rapidocr_v5_latin_cls":
            out = _run_worker_rapidocr(manifest, args.dataset_dir, "ppocrv5_latin", True)
        elif args.worker == "gemini_multimodal":
            out = _run_worker_gemini(manifest, args.dataset_dir)
        elif args.worker == "mineru_basic_onnx":
            out = _run_worker_mineru(manifest, args.dataset_dir)
        else:
            raise ValueError(f"Unknown worker: {args.worker}")
        print("__OCR_BENCH_JSON__" + json.dumps(out, ensure_ascii=False))
        return

    from evaluation.ocr_benchmark.generate_dataset import build_synthetic_dataset

    build_synthetic_dataset(args.dataset_dir)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    if args.only_mineru and args.mineru_python.strip():
        print("==> Running isolated benchmark worker: mineru_basic_onnx ...")
        raw = _invoke_subprocess_worker(args.mineru_python.strip(), "mineru_basic_onnx", args.dataset_dir)
        evaluated = _evaluate_engine_output(raw, manifest)
        if args.output.exists():
            existing = json.loads(args.output.read_text(encoding="utf-8"))
            existing_engines = [
                e for e in existing.get("engines", []) if e.get("engine") != "mineru_basic_onnx"
            ]
            existing_engines.append(evaluated)
            existing["engines"] = existing_engines
            existing["generated_at"] = datetime.now(UTC).isoformat()
            args.output.write_text(json.dumps(existing, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps(evaluated, ensure_ascii=False, indent=2))
        return

    engines_plan: list[tuple[str, str]] = [
        ("rapidocr_v4_ch", sys.executable),
        ("rapidocr_v5_latin", sys.executable),
        ("rapidocr_v5_latin_cls", sys.executable),
    ]
    if args.mineru_python.strip():
        engines_plan.append(("mineru_basic_onnx", args.mineru_python.strip()))
    if not args.skip_gemini:
        engines_plan.append(("gemini_multimodal", sys.executable))

    summaries: list[dict[str, Any]] = []
    for engine_name, py_exe in engines_plan:
        print(f"==> Running isolated benchmark worker: {engine_name} ...")
        raw = _invoke_subprocess_worker(py_exe, engine_name, args.dataset_dir)
        evaluated = _evaluate_engine_output(raw, manifest)
        summaries.append(evaluated)
        if evaluated.get("available"):
            print(
                f"    OK: CER={evaluated['cer_exact_mean']:.4f} (ASCII={evaluated['cer_ascii_mean']:.4f}) "
                f"WER={evaluated['wer_mean']:.4f} EntF1={evaluated['entity_f1']:.4f} "
                f"p50={evaluated['latency_p50_ms']}ms p95={evaluated['latency_p95_ms']}ms "
                f"PeakRAM={evaluated['peak_rss_mb']}MB"
            )
        else:
            print(f"    UNAVAILABLE: {evaluated.get('error')}")

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "cpu_count": os.cpu_count(),
        },
        "dataset_size": len(manifest),
        "categories": sorted({item["category"] for item in manifest}),
        "engines": summaries,
    }
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Saved empirical OCR benchmark results to {args.output}")


if __name__ == "__main__":
    main()
