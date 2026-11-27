"""Hybrid Vietnamese Fraud KB Retriever (Raw E5 + Startup Centered E5 + BM25 + RRF)."""

from __future__ import annotations

import json
import math
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any, Final, Literal

import numpy as np
from pydantic import BaseModel, Field

from app.services.knowledge_base import normalize_vi_search

RagRetrievalMode = Literal[
    "hybrid", "bm25", "raw_dense", "centered_dense", "rrf_raw", "rrf_centered", "rrf_centered_boost"
]

# Calibrated strictly on evaluation/assistant_eval/assistant_eval_cases.json (Dev split, FRR <= 2%).
DEFAULT_TAU_RAW: Final[float] = 0.845
DEFAULT_TAU_CENT: Final[float] = 0.26
DEFAULT_TAU_BM25: Final[float] = 26.5

_RRF_K: Final[int] = 60
_DENSE_CONF_CENT: Final[float] = 0.18
_HINT_BOOST: Final[float] = 1.12
_HINT_MIN_CENT: Final[float] = 0.22
_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9]+")
_VI_STOPWORDS: Final[frozenset[str]] = frozenset({
    "la", "cua", "va", "co", "khong", "cho", "voi", "khi", "bi", "de", "nhu", "mot", "cac",
    "nhung", "nay", "do", "thi", "da", "duoc", "se", "hay", "hoac", "tren", "duoi", "trong",
    "ngoai", "toi", "minh", "em", "anh", "chi", "gi", "sao", "nao", "phai", "can", "nen", "lam",
    "giup", "xin", "chao", "neu", "boi", "cung", "rat", "dang", "vua", "roi", "nhe", "nha", "vay",
    "chua", "tu", "den", "ra", "vao", "ve", "vi", "o", "a", "oi", "cach", "hom", "mai", "ngay",
    "thang", "nam", "gio", "moi", "nhieu", "tot", "nhanh", "qua", "tai", "nguoi", "viec", "dieu",
    "truoc", "sau", "theo", "ban",
})


class RetrievedChunk(BaseModel):
    chunk_id: str
    source: str
    category: str
    title: str
    content: str
    score: float
    raw_cosine: float = 0.0
    centered_cosine: float = 0.0
    bm25_score: float = 0.0
    tags: list[str] = Field(default_factory=list)
    scam_types: list[str] = Field(default_factory=list)


class RagSearchResult(BaseModel):
    chunks: list[RetrievedChunk]
    in_domain: bool
    top_raw_cosine: float
    top_centered_cosine: float
    top_bm25: float
    scope_reason: str
    retrieval_ms: float


def _l2_norm(arr: np.ndarray) -> np.ndarray:
    a = arr.astype(np.float32, copy=False)
    denom = np.maximum(np.linalg.norm(a, axis=-1, keepdims=True), np.float32(1e-8))
    return (a / denom).astype(np.float32)


def _tokenize_vi_bm25(text: str) -> list[str]:
    """Accent-folded Vietnamese unigrams + compound bigrams (accented & unaccented parity)."""
    raw = _TOKEN_RE.findall(normalize_vi_search(text))
    if not raw:
        return []
    out = [t for t in raw if len(t) >= 2 and t not in _VI_STOPWORDS]
    return out + [
        f"{a}_{b}" for a, b in zip(raw, raw[1:], strict=False)
        if not (a in _VI_STOPWORDS and b in _VI_STOPWORDS)
    ]


def _rank_desc(values: np.ndarray) -> np.ndarray:
    order = np.argsort(-values, kind="mergesort")
    ranks = np.empty_like(order, dtype=np.int32)
    ranks[order] = np.arange(1, len(values) + 1, dtype=np.int32)
    return ranks


class AssistantKnowledgeRetriever:
    """In-memory hybrid retriever: Raw E5 + Startup Mean-Centered E5 + Vietnamese BM25 + RRF."""

    def __init__(
        self, index_path: str | Path, embeddings_path: str | Path, *,
        tau_raw: float = DEFAULT_TAU_RAW, tau_cent: float = DEFAULT_TAU_CENT,
        tau_bm25: float = DEFAULT_TAU_BM25,
    ) -> None:
        self.tau_raw, self.tau_cent, self.tau_bm25 = tau_raw, tau_cent, tau_bm25
        self.chunks: list[dict[str, Any]] = []
        self.embeddings_raw: np.ndarray | None = None
        self.mean_vector: np.ndarray | None = None
        self.embeddings_centered: np.ndarray | None = None
        self._scam_sets: list[frozenset[str]] = []
        self._doc_tfs, self._doc_lens = list[Counter[str]](), list[int]()
        self._avg_dl, self._idf = 1.0, dict[str, float]()
        idx_file, emb_file = Path(index_path), Path(embeddings_path)
        if not idx_file.exists():
            return
        self.chunks = list(json.loads(idx_file.read_text(encoding="utf-8")).get("chunks", []))
        n_docs = len(self.chunks)
        if n_docs == 0:
            return
        self._scam_sets = [
            frozenset(str(s).strip().lower() for s in ch.get("scam_types", []) if str(s).strip())
            for ch in self.chunks
        ]
        df_counter: Counter[str] = Counter()
        for ch in self.chunks:
            t = _tokenize_vi_bm25(str(ch.get("title", "")))
            g = _tokenize_vi_bm25(" ".join(str(x) for x in ch.get("tags", [])))
            w = [*t, *t, *g, *g, *_tokenize_vi_bm25(str(ch.get("content", "")))]
            tf = Counter(w)
            self._doc_tfs.append(tf)
            self._doc_lens.append(len(w))
            df_counter.update(tf.keys())
        self._avg_dl = sum(self._doc_lens) / max(n_docs, 1)
        self._idf = {k: math.log((n_docs - d + 0.5) / (d + 0.5) + 1.0) for k, d in df_counter.items()}
        if emb_file.exists():
            loaded = np.load(str(emb_file)).astype(np.float32)
            if loaded.ndim == 2 and loaded.shape[0] == n_docs and np.all(np.isfinite(loaded)):
                self.embeddings_raw = _l2_norm(loaded)
                self.mean_vector = self.embeddings_raw.mean(axis=0).astype(np.float32)
                self.embeddings_centered = _l2_norm(self.embeddings_raw - self.mean_vector)

    @property
    def is_available(self) -> bool:
        return all((self.chunks, self.embeddings_raw is not None, self.embeddings_centered is not None))

    @property
    def chunk_count(self) -> int:
        return len(self.chunks)

    def _score_bm25(self, query: str) -> tuple[np.ndarray, int]:
        scores = np.zeros(len(self.chunks), dtype=np.float32)
        q_counts = Counter(_tokenize_vi_bm25(query))
        if not q_counts:
            return scores, 0
        k1, b = 1.5, 0.75
        for idx, tf in enumerate(self._doc_tfs):
            norm_len = k1 * (1.0 - b + b * self._doc_lens[idx] / max(self._avg_dl, 1.0))
            scores[idx] = sum(
                qf * self._idf.get(term, 0.0) * (tf[term] * (k1 + 1.0)) / (tf[term] + norm_len)
                for term, qf in q_counts.items() if tf.get(term, 0) > 0
            )
        return scores, sum(1 for t in q_counts if "_" not in t)

    def evaluate_scope_gate(
        self, *, has_dense: bool, top_raw: float, top_cent: float, top_bm25: float,
        q_token_count: int = 8,
    ) -> tuple[bool, str]:
        """Dual-signal Scope Gate with query-length-aware short-query BM25 cutoff."""
        eff_bm25 = (
            self.tau_bm25 * max(0.38, q_token_count / 6.5) if 0 < q_token_count <= 6 else self.tau_bm25
        )
        if not has_dense:
            ok = q_token_count > 0 and top_bm25 >= eff_bm25
            return ok, "lexical_only_in_domain" if ok else "lexical_only_below_threshold"
        if top_cent >= self.tau_cent and top_raw >= self.tau_raw:
            return True, "semantic_centered_and_raw_pass"
        if top_cent >= self.tau_cent + 0.04 and top_raw >= self.tau_raw - 0.02:
            return True, "semantic_strong_centered_pass"
        if top_raw >= self.tau_raw + 0.02 and top_cent >= self.tau_cent * 0.72:
            return True, "semantic_high_raw_paraphrase_pass"
        if q_token_count > 0 and (
            (top_bm25 >= eff_bm25 and top_raw >= self.tau_raw - 0.05) or top_bm25 >= eff_bm25 * 1.25
        ):
            return True, "dual_lexical_and_semantic_pass"
        return False, "out_of_domain_below_dual_gate"

    def search(
        self, query: str, *, query_embedding: np.ndarray | None = None,
        scam_type_hint: str | None = None, category: str | None = None,
        top_k: int = 4, mode: RagRetrievalMode = "hybrid",
    ) -> RagSearchResult:
        """Run hybrid retrieval + Dual-Signal Scope Gate over the in-memory KB index."""
        t0, n = time.perf_counter(), len(self.chunks)
        if n == 0 or not query.strip():
            return RagSearchResult(
                chunks=[], in_domain=False, top_raw_cosine=0.0, top_centered_cosine=0.0,
                top_bm25=0.0, scope_reason="empty_query_or_index", retrieval_ms=0.0,
            )
        bm25, q_tok_cnt = self._score_bm25(query)
        raw_s, cent_s, has_dense = np.zeros(n, dtype=np.float32), np.zeros(n, dtype=np.float32), False
        if (
            mode != "bm25" and query_embedding is not None and self.embeddings_raw is not None
            and self.embeddings_centered is not None and self.mean_vector is not None
            and query_embedding.shape == (self.embeddings_raw.shape[1],)
            and bool(np.all(np.isfinite(query_embedding)))
        ):
            q_norm = float(np.linalg.norm(query_embedding.astype(np.float64)))
            if math.isfinite(q_norm) and q_norm > 1e-8:
                has_dense = True
                q_unit = (query_embedding.astype(np.float64) / q_norm).astype(np.float32)
                raw_s = self.embeddings_raw @ q_unit
                cent_s = self.embeddings_centered @ _l2_norm(q_unit - self.mean_vector)
        top_raw, top_cent, top_bm25 = (
            float(np.max(raw_s)) if has_dense else 0.0,
            float(np.max(cent_s)) if has_dense else 0.0,
            float(np.max(bm25)),
        )
        in_domain, scope_reason = self.evaluate_scope_gate(
            has_dense=has_dense, top_raw=top_raw, top_cent=top_cent,
            top_bm25=top_bm25, q_token_count=q_tok_cnt,
        )
        if mode == "bm25" or not has_dense:
            scores = bm25.astype(np.float64)
        elif mode == "raw_dense":
            scores = raw_s.astype(np.float64)
        elif mode == "centered_dense":
            scores = cent_s.astype(np.float64)
        else:
            d_r, b_r = _rank_desc(raw_s if mode == "rrf_raw" else cent_s), _rank_desc(bm25)
            lex = np.where(bm25 > 0.0, 1.0 / (_RRF_K + b_r), 0.0)
            dense = (
                1.0 / (_RRF_K + d_r) if mode == "rrf_raw"
                else np.where(cent_s >= _DENSE_CONF_CENT, 1.0 / (_RRF_K + d_r), 0.0)
            )
            if float(np.max(dense)) == 0.0 and float(np.max(lex)) == 0.0:
                dense = 1.0 / (_RRF_K + d_r)
            scores = dense + lex
            hint = (scam_type_hint or "").strip().lower()
            if hint and mode in ("hybrid", "rrf_centered_boost"):
                bm25_floor = max(5.0, 0.35 * top_bm25)
                for i in range(n):
                    if hint in self._scam_sets[i] and (
                        cent_s[i] >= _HINT_MIN_CENT or (top_bm25 > 0.0 and bm25[i] >= bm25_floor)
                    ):
                        scores[i] *= _HINT_BOOST
        cat = (category or "").strip().lower()
        order = [i for i in range(n) if not cat or cat == "all" or self.chunks[i]["category"] == cat]
        order.sort(key=lambda i: (float(scores[i]), float(cent_s[i]), float(bm25[i])), reverse=True)
        out = [
            RetrievedChunk(
                chunk_id=str(ch["chunk_id"]), source=str(ch["source"]), category=str(ch["category"]),
                title=str(ch["title"]), content=str(ch["content"]), score=round(float(scores[i]), 6),
                raw_cosine=round(float(raw_s[i]), 6), centered_cosine=round(float(cent_s[i]), 6),
                bm25_score=round(float(bm25[i]), 6), tags=list(ch.get("tags", [])),
                scam_types=list(ch.get("scam_types", [])),
            )
            for i in order[: max(1, top_k)] for ch in (self.chunks[i],)
        ]
        return RagSearchResult(
            chunks=out, in_domain=in_domain, top_raw_cosine=round(top_raw, 6),
            top_centered_cosine=round(top_cent, 6), top_bm25=round(top_bm25, 6),
            scope_reason=scope_reason, retrieval_ms=round((time.perf_counter() - t0) * 1000.0, 3),
        )
