"""Unit tests for curated KB artifacts and Hybrid Assistant RAG Retriever."""

from __future__ import annotations

import json
import re
import warnings
from pathlib import Path

import numpy as np
import pytest

from app.services.assistant_rag import (
    AssistantKnowledgeRetriever,
    RagRetrievalMode,
    _tokenize_vi_bm25,
)
from app.services.ioc_extractor import LABELED_ACCOUNT_SPAN_RE, is_labeled_account_match
from app.services.knowledge_base import normalize_vi_search
from app.services.scam_classifier import ScamClassifier

REPO_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = Path(__file__).resolve().parents[2] / "app" / "data"
MODEL_DIR = DATA_DIR / "models"
EMB_PATH = MODEL_DIR / "assistant_kb_embeddings.npy"
IDX_PATH = MODEL_DIR / "assistant_kb_index.json"
EVAL_CASES_PATH = REPO_ROOT / "evaluation" / "assistant_eval" / "assistant_eval_cases.json"

_HOTLINE_OR_PHONE_RE = re.compile(
    r"(?<!\d)(?:1800|1900)[\s.\-]?\d{4,6}(?!\d)|"
    r"(?<!\d)(?:\+?84|0)[35789][\s.\-]?\d{3}[\s.\-]?\d{2,3}[\s.\-]?\d{2,3}(?!\d)"
)
_WORD_RE = re.compile(r"[a-z0-9]+")


@pytest.fixture(scope="module")
def classifier() -> ScamClassifier:
    clf = ScamClassifier(str(MODEL_DIR), intra_threads=2)
    assert clf.is_available is True
    return clf


@pytest.fixture(scope="module")
def retriever() -> AssistantKnowledgeRetriever:
    ret = AssistantKnowledgeRetriever(index_path=IDX_PATH, embeddings_path=EMB_PATH)
    assert ret.is_available is True
    return ret


def test_normalize_vi_search_public_alias() -> None:
    assert normalize_vi_search("Đã lỡ chuyển tiền ĐẾN kẻ lừa đảo!") == "da lo chuyen tien den ke lua dao!"


def test_domain_syllables_not_dropped_as_stopwords() -> None:
    tokens = set(_tokenize_vi_bm25("Bộ Công an phường trình báo giải ngân hai mặt CCCD Kho bạc"))
    for domain_tok in ("bo", "hai", "giai", "trinh", "phuong", "bac"):
        assert domain_tok in tokens, f"Domain syllable {domain_tok!r} was dropped by _VI_STOPWORDS"


def test_kb_index_artifacts_hygiene_and_raw_unit_norm() -> None:
    assert EMB_PATH.exists(), "assistant_kb_embeddings.npy is missing"
    assert IDX_PATH.exists(), "assistant_kb_index.json is missing"

    payload = json.loads(IDX_PATH.read_text(encoding="utf-8"))
    chunks = payload["chunks"]
    n_chunks = len(chunks)
    assert 120 <= n_chunks <= 160
    assert payload["chunk_count"] == n_chunks
    assert payload["max_token_len"] <= 180
    assert payload["overall_unk_ratio"] < 0.02

    e_raw = np.load(str(EMB_PATH))
    assert e_raw.dtype == np.float32
    assert e_raw.shape == (n_chunks, 384)
    assert np.all(np.isfinite(e_raw))
    assert np.allclose(np.linalg.norm(e_raw, axis=1), 1.0, atol=1e-5)

    # Disk embeddings MUST be RAW unit vectors (anisotropic ||mu|| > 0.5), NOT pre-centered
    mean_norm = float(np.linalg.norm(e_raw.mean(axis=0)))
    assert mean_norm > 0.5, f"Expected raw anisotropic E5 matrix on disk, got ||mu||={mean_norm:.4f}"

    bin_vcb_found = False
    for ch in chunks:
        assert ch["token_len"] <= 180
        fields = [
            f"{ch['title']}. {ch['content']}",
            " | ".join(str(x) for x in ch.get("tags", [])),
            " | ".join(str(x) for x in ch.get("official_domains", [])),
            " | ".join(str(x) for x in ch.get("verified_channels", [])),
        ]
        for field_text in fields:
            assert "momo" not in field_text.lower()
            assert not _HOTLINE_OR_PHONE_RE.search(field_text), f"Forbidden phone in {ch['chunk_id']}"
            for m in LABELED_ACCOUNT_SPAN_RE.finditer(field_text):
                assert not is_labeled_account_match(field_text, m), (
                    f"Chunk {ch['chunk_id']} mangled by LABELED_ACCOUNT_SPAN_RE on {m.group(0)!r}"
                )
        if ch["chunk_id"] == "napas_bin_970436":
            bin_vcb_found = True
            assert "BIN 970436 (Vietcombank)" in fields[0]
            assert "TK 970436" not in fields[0] and "STK 970436" not in fields[0]
    assert bin_vcb_found is True

    total_models_mb = sum(p.stat().st_size for p in MODEL_DIR.rglob("*") if p.is_file()) / (1024 * 1024)
    assert total_models_mb < 50.0, f"models/ dir size {total_models_mb:.2f} MB exceeds 50 MB"


def test_eval_suite_zero_dev_test_leakage() -> None:
    cases = json.loads(EVAL_CASES_PATH.read_text(encoding="utf-8"))["cases"]
    dev = [c for c in cases if c["split"] == "dev"]
    test = [c for c in cases if c["split"] == "test"]
    assert len(cases) >= 105 and len(dev) >= 45 and len(test) >= 60

    norm_all = [normalize_vi_search(str(c["query"])) for c in cases]
    assert len(norm_all) == len(set(norm_all)), "Duplicate normalized query found in eval cases!"

    for d_case in dev:
        d_toks = set(_WORD_RE.findall(normalize_vi_search(str(d_case["query"]))))
        for t_case in test:
            t_toks = set(_WORD_RE.findall(normalize_vi_search(str(t_case["query"]))))
            jaccard = len(d_toks & t_toks) / max(len(d_toks | t_toks), 1)
            assert jaccard < 0.55, (
                f"Dev-Test leakage ({jaccard:.3f}): {d_case['id']} <-> {t_case['id']}"
            )


def test_retriever_startup_centering_reduces_anisotropy(retriever: AssistantKnowledgeRetriever) -> None:
    assert retriever.embeddings_raw is not None
    assert retriever.embeddings_centered is not None
    assert retriever.mean_vector is not None
    assert retriever.embeddings_centered.shape == retriever.embeddings_raw.shape
    assert np.allclose(np.linalg.norm(retriever.embeddings_centered, axis=1), 1.0, atol=1e-5)

    raw_sim = retriever.embeddings_raw @ retriever.embeddings_raw.T
    cent_sim = retriever.embeddings_centered @ retriever.embeddings_centered.T
    mask = ~np.eye(retriever.chunk_count, dtype=bool)
    assert float(cent_sim[mask].mean()) < float(raw_sim[mask].mean()) - 0.5


@pytest.mark.parametrize(
    ("query", "expected_ids"),
    [
        (
            "Tôi lỡ chuyển tiền cho kẻ lừa đảo rồi phải làm sao?",
            {"sop_transferred_money_60min", "sop_bank_dispute_freeze"},
        ),
        (
            "lo chuyen tien cho ke lua dao phai lam sao",
            {"sop_transferred_money_60min", "sop_bank_dispute_freeze"},
        ),
        (
            "cài file .apk giả VNeID có bị mất tiền không và cần làm gì",
            {
                "sop_installed_fake_apk_disconnect",
                "sop_installed_fake_apk_cleanup",
                "pb_scam_police_vneid_apk_signals",
                "pb_scam_police_vneid_apk_action",
            },
        ),
        (
            "biên lai chuyển khoản giả có nên giao hàng không",
            {
                "sop_merchant_fake_receipt_action",
                "ver_merchant_balance_and_soundbox",
                "pb_scam_merchant_fake_bill_signals",
                "pb_scam_merchant_fake_bill_action",
            },
        ),
        (
            "mã BIN 970436 là ngân hàng nào",
            {"napas_bin_970436", "tax_napas_bin_directory"},
        ),
    ],
)
def test_accented_and_unaccented_vietnamese_retrieval(
    classifier: ScamClassifier,
    retriever: AssistantKnowledgeRetriever,
    query: str,
    expected_ids: set[str],
) -> None:
    q_emb = classifier.encode_text(query, prefix="query")
    assert q_emb is not None
    res = retriever.search(query, query_embedding=q_emb, top_k=3, mode="hybrid")
    assert res.in_domain is True, f"False rejection for in-domain query: {query!r} ({res.scope_reason})"
    top_ids = {ch.chunk_id for ch in res.chunks}
    assert top_ids & expected_ids, f"Expected one of {expected_ids}, got {[c.chunk_id for c in res.chunks]}"


@pytest.mark.parametrize(
    "short_in_query",
    [
        "cài file apk",
        "lộ OTP",
        "lộ CVV",
        "biên lai giả",
        "lỡ chuyển tiền",
        "giả công an",
        "BIN 970436 là ngân hàng nào",
    ],
)
def test_short_legitimate_queries_pass_both_hybrid_and_lexical(
    classifier: ScamClassifier,
    retriever: AssistantKnowledgeRetriever,
    short_in_query: str,
) -> None:
    q_emb = classifier.encode_text(short_in_query, prefix="query")
    assert q_emb is not None
    res_hyb = retriever.search(short_in_query, query_embedding=q_emb, top_k=3, mode="hybrid")
    assert res_hyb.in_domain is True, (
        f"Hybrid false reject on {short_in_query!r}: raw={res_hyb.top_raw_cosine}, "
        f"cent={res_hyb.top_centered_cosine}, bm25={res_hyb.top_bm25}"
    )
    res_lex = retriever.search(short_in_query, query_embedding=None, top_k=3, mode="hybrid")
    assert res_lex.in_domain is True, (
        f"Lexical-only false reject on {short_in_query!r}: bm25={res_lex.top_bm25}"
    )


@pytest.mark.parametrize("short_ood_query", ["phở bò", "code python", "thời tiết"])
def test_short_ood_queries_rejected_both_hybrid_and_lexical(
    classifier: ScamClassifier,
    retriever: AssistantKnowledgeRetriever,
    short_ood_query: str,
) -> None:
    q_emb = classifier.encode_text(short_ood_query, prefix="query")
    assert q_emb is not None
    res_hyb = retriever.search(short_ood_query, query_embedding=q_emb, top_k=3, mode="hybrid")
    assert res_hyb.in_domain is False, (
        f"Hybrid OOD leak on {short_ood_query!r}: raw={res_hyb.top_raw_cosine}, "
        f"cent={res_hyb.top_centered_cosine}, bm25={res_hyb.top_bm25}"
    )
    res_lex = retriever.search(short_ood_query, query_embedding=None, top_k=3, mode="hybrid")
    assert res_lex.in_domain is False, (
        f"Lexical-only OOD leak on {short_ood_query!r}: bm25={res_lex.top_bm25}"
    )


def test_degenerate_embeddings_and_empty_queries_fall_back_safely(
    retriever: AssistantKnowledgeRetriever,
) -> None:
    query = "lo chuyen tien cho ke lua dao phai lam sao"
    bad_vectors = [
        np.zeros(384, dtype=np.float32),
        np.full(384, np.nan, dtype=np.float32),
        np.full(384, np.inf, dtype=np.float32),
        np.array([1.0, 2.0, 3.0], dtype=np.float32),
    ]
    for vec in bad_vectors:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            res = retriever.search(query, query_embedding=vec, top_k=3, mode="hybrid")
        assert not caught, f"Unexpected warning on degenerate vector: {[str(w.message) for w in caught]}"
        assert res.top_raw_cosine == 0.0
        assert res.top_centered_cosine == 0.0
        assert res.in_domain is True
        assert any(c.chunk_id == "sop_transferred_money_60min" for c in res.chunks)

    for empty_q in ("", "   \n\t  "):
        res_empty = retriever.search(empty_q, query_embedding=np.zeros(384, dtype=np.float32), top_k=3)
        assert res_empty.in_domain is False
        assert res_empty.top_bm25 == 0.0


def test_scam_type_hint_boost_helps_relevant_and_never_hijacks_unrelated(
    classifier: ScamClassifier,
    retriever: AssistantKnowledgeRetriever,
) -> None:
    # 1. Contextual hint helps ambiguous merchant case
    q_merchant = "khách đưa ảnh báo chuyển thành công nhưng chưa thấy cộng tiền"
    emb_m = classifier.encode_text(q_merchant, prefix="query")
    assert emb_m is not None
    res_boost = retriever.search(
        q_merchant, query_embedding=emb_m, scam_type_hint="merchant", top_k=3, mode="hybrid"
    )
    assert res_boost.in_domain is True
    assert any("merchant" in ch.scam_types for ch in res_boost.chunks[:2])

    # 2. Mismatched hint on minor word overlap MUST NOT hijack rank #1 or unrelated chunks
    q_apk = "đã lỡ cài tệp .apk giả mạo VNeID phải ngắt mạng và gỡ như thế nào"
    emb_apk = classifier.encode_text(q_apk, prefix="query")
    assert emb_apk is not None
    res_base = retriever.search(q_apk, query_embedding=emb_apk, top_k=3, mode="rrf_centered")
    res_mismatch = retriever.search(
        q_apk,
        query_embedding=emb_apk,
        scam_type_hint="scam_charity_mule_impersonation",
        top_k=3,
        mode="hybrid",
    )
    assert res_mismatch.chunks[0].chunk_id == res_base.chunks[0].chunk_id
    assert "scam_charity_mule_impersonation" not in res_mismatch.chunks[0].scam_types


@pytest.mark.parametrize(
    "ood_query",
    [
        "cách nấu phở bò ngon tại nhà",
        "viết code python sắp xếp mảng nhanh",
        "thời tiết Hà Nội hôm nay có mưa không",
        "giải phương trình bậc hai x^2 - 5x + 6 = 0",
    ],
)
def test_ood_scope_gate_rejects_non_fraud_queries(
    classifier: ScamClassifier,
    retriever: AssistantKnowledgeRetriever,
    ood_query: str,
) -> None:
    q_emb = classifier.encode_text(ood_query, prefix="query")
    assert q_emb is not None
    res = retriever.search(ood_query, query_embedding=q_emb, top_k=4, mode="hybrid")
    assert res.in_domain is False, (
        f"Expected OOD rejection for {ood_query!r}, got in_domain=True "
        f"(raw={res.top_raw_cosine:.4f}, cent={res.top_centered_cosine:.4f}, bm25={res.top_bm25:.4f})"
    )


def test_all_seven_modes_and_retrieval_latency_under_20ms(
    classifier: ScamClassifier,
    retriever: AssistantKnowledgeRetriever,
) -> None:
    query = "bị gọi điện giả công an yêu cầu chuyển tiền chứng minh trong sạch"
    q_emb = classifier.encode_text(query, prefix="query")
    assert q_emb is not None

    modes: list[RagRetrievalMode] = [
        "bm25", "raw_dense", "centered_dense", "rrf_raw", "rrf_centered", "rrf_centered_boost", "hybrid"
    ]
    for mode in modes:
        res = retriever.search(
            query, query_embedding=q_emb, scam_type_hint="SCAM_IMPERSONATION", top_k=4, mode=mode
        )
        assert len(res.chunks) == 4
        assert res.retrieval_ms < 20.0, f"Mode {mode} took {res.retrieval_ms:.2f}ms (expected < 20ms)"
        scores = [c.score for c in res.chunks]
        assert scores == sorted(scores, reverse=True)


def test_category_filter_restricts_chunks(
    classifier: ScamClassifier,
    retriever: AssistantKnowledgeRetriever,
) -> None:
    query = "làm sao kiểm tra tên miền vneid chính thức của cơ quan nhà nước"
    q_emb = classifier.encode_text(query, prefix="query")
    assert q_emb is not None
    res = retriever.search(query, query_embedding=q_emb, category="verification", top_k=3)
    assert res.in_domain is True
    assert len(res.chunks) > 0
    assert all(c.category == "verification" for c in res.chunks)
