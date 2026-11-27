"""7-Baseline RAG Ablation & Dev-Only Scope Gate Calibration Suite for Trợ lý VeriShield."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = REPO_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.services.assistant_rag import (  # noqa: E402
    DEFAULT_TAU_BM25,
    DEFAULT_TAU_CENT,
    DEFAULT_TAU_RAW,
    AssistantKnowledgeRetriever,
    RagRetrievalMode,
    _tokenize_vi_bm25,
)
from app.services.knowledge_base import normalize_vi_search  # noqa: E402
from app.services.scam_classifier import ScamClassifier  # noqa: E402

EVAL_DIR = Path(__file__).resolve().parent
CASES_PATH = EVAL_DIR / "assistant_eval_cases.json"
RESULTS_PATH = EVAL_DIR / "rag_ablation_results.json"
MODEL_DIR = BACKEND_DIR / "app" / "data" / "models"
IDX_PATH = MODEL_DIR / "assistant_kb_index.json"
EMB_PATH = MODEL_DIR / "assistant_kb_embeddings.npy"
_WORD_RE = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True)
class BaselineSpec:
    code: str
    name: str
    mode: RagRetrievalMode
    use_embedding: bool
    use_hint: bool
    gate_policy: str


BASELINES: tuple[BaselineSpec, ...] = (
    BaselineSpec("B0", "BM25 (Case-less)", "bm25", False, False, "bm25_only"),
    BaselineSpec("B1", "Raw E5 Cosine (Case-less)", "raw_dense", True, False, "naive_raw_081"),
    BaselineSpec("B2", "Centered E5 Cosine (Case-less)", "centered_dense", True, False, "centered_only"),
    BaselineSpec("B3", "BM25 + Raw E5 RRF (Case-less)", "rrf_raw", True, False, "naive_raw_081"),
    BaselineSpec("B4", "BM25 + Centered E5 RRF (Case-less)", "rrf_centered", True, False, "centered_only"),
    BaselineSpec("B5", "B4 + Dual-Signal Gate (Case-less)", "rrf_centered", True, False, "dual_gate"),
    BaselineSpec("B6", "B5 + Case Hint Boost (Case-bound)", "hybrid", True, True, "dual_gate"),
)


def assert_no_dev_test_leakage(cases: list[dict[str, Any]], max_jaccard: float = 0.55) -> float:
    """Enforce zero normalized query duplicates and cross-split unigram Jaccard < max_jaccard."""
    seen: dict[str, str] = {}
    for c in cases:
        norm = normalize_vi_search(str(c["query"]))
        cid = str(c["id"])
        if norm in seen:
            raise ValueError(f"Duplicate normalized query between {seen[norm]} and {cid}")
        seen[norm] = cid

    dev = [c for c in cases if c["split"] == "dev"]
    test = [c for c in cases if c["split"] == "test"]
    worst = 0.0
    for dc in dev:
        d_toks = set(_WORD_RE.findall(normalize_vi_search(str(dc["query"]))))
        for tc in test:
            t_toks = set(_WORD_RE.findall(normalize_vi_search(str(tc["query"]))))
            jac = len(d_toks & t_toks) / max(len(d_toks | t_toks), 1)
            if jac > worst:
                worst = jac
            if jac >= max_jaccard:
                raise ValueError(
                    f"Dev-Test leakage detected (Jaccard={jac:.3f} >= {max_jaccard}): "
                    f"{dc['id']} <-> {tc['id']}"
                )
    return worst


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(math.ceil((pct / 100.0) * len(ordered))) - 1))
    return ordered[idx]


def _ndcg_at_k(ranked_ids: list[str], expected: set[str], k: int = 3) -> float:
    if not expected:
        return 0.0
    dcg = 0.0
    for rank, cid in enumerate(ranked_ids[:k], start=1):
        if cid in expected:
            dcg += 1.0 / math.log2(rank + 1)
    ideal_hits = min(len(expected), k)
    idcg = sum(1.0 / math.log2(r + 1) for r in range(1, ideal_hits + 1))
    return dcg / idcg if idcg > 0 else 0.0


def _check_gate(
    spec: BaselineSpec, res: Any, retriever: AssistantKnowledgeRetriever, q_tok_cnt: int
) -> bool:
    if spec.gate_policy == "bm25_only":
        return retriever.evaluate_scope_gate(
            has_dense=False, top_raw=0.0, top_cent=0.0, top_bm25=res.top_bm25, q_token_count=q_tok_cnt
        )[0]
    if spec.gate_policy == "naive_raw_081":
        return bool(res.top_raw_cosine >= 0.81)
    if spec.gate_policy == "centered_only":
        return bool(res.top_centered_cosine >= retriever.tau_cent)
    return bool(res.in_domain)


def evaluate_split(
    cases: list[dict[str, Any]],
    embeddings: dict[str, np.ndarray],
    retriever: AssistantKnowledgeRetriever,
) -> list[dict[str, Any]]:
    """Evaluate all 7 baselines with identical ranking + end-to-end gated columns."""
    rows: list[dict[str, Any]] = []
    for spec in BASELINES:
        in_total = ood_total = in_rejected = ood_rejected = 0
        hit1 = hit3 = hit5 = gated_hit3 = 0
        sop_total = sop_hit3 = unacc_total = unacc_hit3 = 0
        mrr5_sum = ndcg3_sum = 0.0
        latencies_ms: list[float] = []

        for case in cases:
            cid = str(case["id"])
            query = str(case["query"])
            is_in = bool(case["in_domain"])
            hint = str(case["scam_type_hint"]) if (spec.use_hint and case.get("scam_type_hint")) else None
            q_emb = embeddings[cid] if spec.use_embedding else None
            q_tok_cnt = len({t for t in _tokenize_vi_bm25(query) if "_" not in t})

            res = retriever.search(
                query, query_embedding=q_emb, scam_type_hint=hint, top_k=5, mode=spec.mode
            )
            latencies_ms.append(res.retrieval_ms)
            accepted = _check_gate(spec, res, retriever, q_tok_cnt)

            if not is_in:
                ood_total += 1
                if not accepted:
                    ood_rejected += 1
                continue

            in_total += 1
            if not accepted:
                in_rejected += 1

            expected = set(case.get("expected_chunk_ids", []))
            is_sop = case.get("group") == "sop"
            is_unacc = not bool(case.get("accented", True))
            if is_sop:
                sop_total += 1
            if is_unacc:
                unacc_total += 1

            ranked_ids = [ch.chunk_id for ch in res.chunks]
            top3_hit = any(x in expected for x in ranked_ids[:3])
            if ranked_ids[:1] and ranked_ids[0] in expected:
                hit1 += 1
            if top3_hit:
                hit3 += 1
                if accepted:
                    gated_hit3 += 1
                if is_sop:
                    sop_hit3 += 1
                if is_unacc:
                    unacc_hit3 += 1
            if any(x in expected for x in ranked_ids[:5]):
                hit5 += 1

            for rank, ch_id in enumerate(ranked_ids[:5], start=1):
                if ch_id in expected:
                    mrr5_sum += 1.0 / rank
                    break
            ndcg3_sum += _ndcg_at_k(ranked_ids, expected, k=3)

        rows.append(
            {
                "baseline": spec.code,
                "name": spec.name,
                "mode": spec.mode,
                "recall_at_1": round(hit1 / max(in_total, 1), 4),
                "recall_at_3": round(hit3 / max(in_total, 1), 4),
                "recall_at_5": round(hit5 / max(in_total, 1), 4),
                "mrr_at_5": round(mrr5_sum / max(in_total, 1), 4),
                "ndcg_at_3": round(ndcg3_sum / max(in_total, 1), 4),
                "sop_recall_at_3": round(sop_hit3 / max(sop_total, 1), 4),
                "unaccented_recall_at_3": round(unacc_hit3 / max(unacc_total, 1), 4),
                "gated_recall_at_3": round(gated_hit3 / max(in_total, 1), 4),
                "in_domain_frr": round(in_rejected / max(in_total, 1), 4),
                "ood_rejection_rate": round(ood_rejected / max(ood_total, 1), 4),
                "retrieval_mean_ms": round(sum(latencies_ms) / max(len(latencies_ms), 1), 3),
                "retrieval_p50_ms": round(_percentile(latencies_ms, 50.0), 3),
                "retrieval_p95_ms": round(_percentile(latencies_ms, 95.0), 3),
            }
        )
    return rows


def calibrate_thresholds_on_dev(
    dev_cases: list[dict[str, Any]],
    embeddings: dict[str, np.ndarray],
    retriever: AssistantKnowledgeRetriever,
) -> dict[str, Any]:
    """Sweep (tau_raw, tau_cent, tau_bm25) via retriever.evaluate_scope_gate on Dev ONLY."""
    dev_signals: list[tuple[bool, bool, str, float, float, float, int]] = []
    for case in dev_cases:
        q = str(case["query"])
        res = retriever.search(
            q, query_embedding=embeddings[str(case["id"])], top_k=5, mode="rrf_centered"
        )
        dev_signals.append(
            (
                bool(case["in_domain"]),
                bool(case.get("accented", True)),
                str(case["id"]),
                res.top_raw_cosine,
                res.top_centered_cosine,
                res.top_bm25,
                len({t for t in _tokenize_vi_bm25(q) if "_" not in t}),
            )
        )

    orig = (retriever.tau_raw, retriever.tau_cent, retriever.tau_bm25)
    in_total = sum(1 for x in dev_signals if x[0])
    ood_total = sum(1 for x in dev_signals if not x[0])
    ood_max_raw = max(x[3] for x in dev_signals if not x[0])
    ood_max_cent = max(x[4] for x in dev_signals if not x[0])
    ood_max_bm25 = max(x[5] for x in dev_signals if not x[0])

    # Deterministic tie-breaking: maximize OOD reject, minimize FRR, maximize balanced OOD safety margin
    best: tuple[float, float, float, float, float, float] | None = None
    try:
        for tau_raw in (0.82, 0.83, 0.84, 0.845, 0.85, 0.86):
            for tau_cent in (0.24, 0.25, 0.26, 0.27, 0.28, 0.30):
                for tau_bm25 in (22.0, 24.0, 25.0, 26.0, 26.5, 27.0, 28.0):
                    retriever.tau_raw, retriever.tau_cent, retriever.tau_bm25 = (
                        tau_raw, tau_cent, tau_bm25
                    )
                    in_rej = ood_rej = 0
                    for is_in, _acc, _cid, s_raw, s_cent, s_bm25, q_cnt in dev_signals:
                        passed = retriever.evaluate_scope_gate(
                            has_dense=True, top_raw=s_raw, top_cent=s_cent,
                            top_bm25=s_bm25, q_token_count=q_cnt,
                        )[0]
                        if is_in and not passed:
                            in_rej += 1
                        elif not is_in and not passed:
                            ood_rej += 1
                    frr = in_rej / max(in_total, 1)
                    ood_rate = ood_rej / max(ood_total, 1)
                    if frr <= 0.02:
                        margin = (
                            (tau_raw - ood_max_raw) * 10.0
                            + (tau_cent - ood_max_cent) * 5.0
                            + (tau_bm25 - ood_max_bm25) * 0.1
                        )
                        cand = (ood_rate, -frr, round(margin, 6), tau_raw, tau_cent, tau_bm25)
                        if best is None or cand > best:
                            best = cand
    finally:
        retriever.tau_raw, retriever.tau_cent, retriever.tau_bm25 = orig

    return {"best": best, "dev_signals": dev_signals}


def _format_markdown_table(split_label: str, rows: list[dict[str, Any]]) -> str:
    header = (
        "| Baseline | Config | R@1 | R@3 | R@5 | MRR@5 | nDCG@3 | "
        "SOP R@3 | Unacc R@3 | Gated R@3 | In-Dom FRR | OOD Reject | Mean ms | P95 ms |"
    )
    lines = [
        f"### {split_label}",
        header,
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for r in rows:
        lines.append(
            f"| {r['baseline']} | {r['name']} | {r['recall_at_1']:.1%} | {r['recall_at_3']:.1%} | "
            f"{r['recall_at_5']:.1%} | {r['mrr_at_5']:.4f} | {r['ndcg_at_3']:.4f} | "
            f"{r['sop_recall_at_3']:.1%} | {r['unaccented_recall_at_3']:.1%} | "
            f"{r['gated_recall_at_3']:.1%} | {r['in_domain_frr']:.1%} | "
            f"{r['ood_rejection_rate']:.1%} | {r['retrieval_mean_ms']:.2f} | "
            f"{r['retrieval_p95_ms']:.2f} |"
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run 7-baseline RAG ablation on Dev & Held-out Test splits."
    )
    parser.add_argument(
        "--calibrate-dev", action="store_true", help="Print Dev-only threshold sweep diagnostics."
    )
    parser.add_argument(
        "--show-errors", action="store_true", help="Print Dev-split misses for error analysis."
    )
    args = parser.parse_args()

    eval_data = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    all_cases: list[dict[str, Any]] = list(eval_data["cases"])
    max_cross_jaccard = assert_no_dev_test_leakage(all_cases)
    dev_cases = [c for c in all_cases if c["split"] == "dev"]
    test_cases = [c for c in all_cases if c["split"] == "test"]

    retriever = AssistantKnowledgeRetriever(index_path=IDX_PATH, embeddings_path=EMB_PATH)
    assert retriever.is_available, "AssistantKnowledgeRetriever index missing or invalid"
    valid_ids = {str(ch["chunk_id"]) for ch in retriever.chunks}
    for case in all_cases:
        for exp_id in case.get("expected_chunk_ids", []):
            if exp_id not in valid_ids:
                raise ValueError(f"Eval case {case['id']} references unknown chunk_id {exp_id!r}")

    clf = ScamClassifier(str(MODEL_DIR), intra_threads=2)
    assert clf.is_available, "ScamClassifier ONNX model unavailable"
    clf.encode_text("Khởi động mô hình kiểm tra lừa đảo", prefix="query")

    embeddings: dict[str, np.ndarray] = {}
    encode_latencies_ms: list[float] = []
    for case in all_cases:
        t0 = time.perf_counter()
        vec = clf.encode_text(str(case["query"]), prefix="query")
        encode_latencies_ms.append((time.perf_counter() - t0) * 1000.0)
        assert vec is not None
        embeddings[str(case["id"])] = vec

    if args.calibrate_dev:
        cal = calibrate_thresholds_on_dev(dev_cases, embeddings, retriever)
        print("=== DEV-ONLY SIGNAL DISTRIBUTION ===")
        in_acc = [x for x in cal["dev_signals"] if x[0] and x[1]]
        in_unacc = [x for x in cal["dev_signals"] if x[0] and not x[1]]
        ood = [x for x in cal["dev_signals"] if not x[0]]
        for label, grp in [
            ("Dev In-Domain Accented", in_acc),
            ("Dev In-Domain Unaccented", in_unacc),
            ("Dev OOD", ood),
        ]:
            raws = [x[3] for x in grp]
            cents = [x[4] for x in grp]
            bm25s = [x[5] for x in grp]
            print(
                f"{label:26s} (n={len(grp):2d}): raw=[{min(raws):.4f}, {max(raws):.4f}] | "
                f"cent=[{min(cents):.4f}, {max(cents):.4f}] | bm25=[{min(bm25s):.2f}, {max(bm25s):.2f}]"
            )
        print("Dev-optimal (ood_rej, -frr, margin, tau_raw, tau_cent, tau_bm25):", cal["best"])

    if args.show_errors:
        print("\n=== DEV-ONLY GATE/RETRIEVAL ERRORS (B5/B6) ===")
        for case in dev_cases:
            res = retriever.search(
                str(case["query"]), query_embedding=embeddings[str(case["id"])],
                scam_type_hint=case.get("scam_type_hint"), top_k=5, mode="hybrid",
            )
            if case["in_domain"]:
                exp = set(case["expected_chunk_ids"])
                top3 = [c.chunk_id for c in res.chunks[:3]]
                if not res.in_domain or not (set(top3) & exp):
                    print(
                        f"  DEV MISS {case['id']} (in_dom={res.in_domain} raw={res.top_raw_cosine:.3f} "
                        f"cent={res.top_centered_cosine:.3f} bm25={res.top_bm25:.1f}): "
                        f"got={top3} expected={sorted(exp)}"
                    )
            elif res.in_domain:
                print(
                    f"  DEV OOD FP {case['id']} ({res.scope_reason} raw={res.top_raw_cosine:.3f} "
                    f"cent={res.top_centered_cosine:.3f} bm25={res.top_bm25:.1f}): {case['query']}"
                )

    dev_rows = evaluate_split(dev_cases, embeddings, retriever)
    test_rows = evaluate_split(test_cases, embeddings, retriever)
    onnx_stats = {
        "encode_mean_ms": round(sum(encode_latencies_ms) / max(len(encode_latencies_ms), 1), 3),
        "encode_p50_ms": round(_percentile(encode_latencies_ms, 50.0), 3),
        "encode_p95_ms": round(_percentile(encode_latencies_ms, 95.0), 3),
    }

    print(
        f"\nCorpus: {retriever.chunk_count} chunks | Dev: {len(dev_cases)} cases | "
        f"Held-out Test: {len(test_cases)} cases | Max Dev-Test Jaccard: {max_cross_jaccard:.3f}"
    )
    print(
        f"ONNX E5 INT8 encode latency: mean={onnx_stats['encode_mean_ms']:.2f}ms, "
        f"p50={onnx_stats['encode_p50_ms']:.2f}ms, p95={onnx_stats['encode_p95_ms']:.2f}ms"
    )
    print(
        f"Active Scope Gate thresholds: tau_raw={DEFAULT_TAU_RAW}, "
        f"tau_cent={DEFAULT_TAU_CENT}, tau_bm25={DEFAULT_TAU_BM25}\n"
    )
    print(_format_markdown_table(f"Dev Split ({len(dev_cases)} cases)", dev_rows))
    print()
    print(_format_markdown_table(f"Held-Out Test Split ({len(test_cases)} cases)", test_rows))

    output_payload = {
        "schema_version": "1.1.0",
        "chunk_count": retriever.chunk_count,
        "max_dev_test_jaccard": round(max_cross_jaccard, 4),
        "dataset_counts": {
            "total": len(all_cases),
            "dev_total": len(dev_cases),
            "dev_in_domain": sum(1 for c in dev_cases if c["in_domain"]),
            "dev_ood": sum(1 for c in dev_cases if not c["in_domain"]),
            "test_total": len(test_cases),
            "test_in_domain": sum(1 for c in test_cases if c["in_domain"]),
            "test_ood": sum(1 for c in test_cases if not c["in_domain"]),
        },
        "calibrated_thresholds": {
            "tau_raw": DEFAULT_TAU_RAW,
            "tau_cent": DEFAULT_TAU_CENT,
            "tau_bm25": DEFAULT_TAU_BM25,
        },
        "onnx_encode_latency": onnx_stats,
        "dev": dev_rows,
        "test": test_rows,
    }
    RESULTS_PATH.write_text(json.dumps(output_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nSaved ablation results to {RESULTS_PATH}")


if __name__ == "__main__":
    main()
