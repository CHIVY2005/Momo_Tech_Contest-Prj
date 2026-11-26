"""Hybrid Vietnamese Scam Knowledge Base retriever (384-d cosine + accent-insensitive lexical)."""

from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path
from typing import Any

import numpy as np

from app.schemas import AnalyzeMode


def _normalize_vi_search(text: str) -> str:
    """Lowercase and strip Vietnamese diacritics (including đ -> d) for robust lexical recall."""
    mapped = text.lower().replace("đ", "d")
    decomposed = unicodedata.normalize("NFD", mapped)
    stripped = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    return re.sub(r"\s+", " ", stripped).strip()


class KnowledgeBaseRetriever:
    """Retrieves top-K Vietnamese scam playbooks using neural embeddings + lexical matching."""

    def __init__(self, kb_path: str, embeddings_path: str | None = None) -> None:
        path = Path(kb_path)
        data = json.loads(path.read_text(encoding="utf-8"))
        self.playbooks: list[dict[str, Any]] = data.get("playbooks", [])
        self._normalized_keywords: list[list[str]] = [
            [_normalize_vi_search(kw) for kw in pb.get("keywords", []) if kw]
            for pb in self.playbooks
        ]
        self._normalized_titles: list[str] = [
            _normalize_vi_search(pb.get("name_vi", "")) for pb in self.playbooks
        ]

        self._embeddings: np.ndarray | None = None
        emb_file = Path(embeddings_path) if embeddings_path else None
        if emb_file and emb_file.exists():
            try:
                loaded = np.load(str(emb_file)).astype(np.float32)
                if loaded.ndim == 2 and loaded.shape[0] == len(self.playbooks):
                    norms = np.linalg.norm(loaded, axis=1, keepdims=True)
                    self._embeddings = loaded / np.maximum(norms, 1e-8)
            except Exception:
                self._embeddings = None

    def match_playbooks(
        self,
        text: str,
        mode: AnalyzeMode,
        query_embedding: np.ndarray | None = None,
        top_k: int = 3,
    ) -> list[dict[str, Any]]:
        """Rank playbooks by hybrid semantic cosine similarity + Vietnamese phrase overlap."""
        norm_query = _normalize_vi_search(text)
        has_vec = (
            self._embeddings is not None
            and query_embedding is not None
            and query_embedding.ndim == 1
            and query_embedding.shape[0] == self._embeddings.shape[1]
        )

        cos_scores: np.ndarray | None = None
        if has_vec and self._embeddings is not None and query_embedding is not None:
            q_norm = query_embedding / max(float(np.linalg.norm(query_embedding)), 1e-8)
            cos_scores = self._embeddings @ q_norm

        scored: list[tuple[float, dict[str, Any]]] = []
        for idx, pb in enumerate(self.playbooks):
            lex_score = 0.0
            if norm_query:
                for kw_norm in self._normalized_keywords[idx]:
                    if kw_norm and kw_norm in norm_query:
                        # Weight multi-word Vietnamese domain phrases higher than single words
                        word_count = len(kw_norm.split())
                        lex_score += 1.0 + 0.45 * min(word_count, 4)

                for token in self._normalized_titles[idx].split():
                    if len(token) >= 4 and token in norm_query:
                        lex_score += 0.25

            vec_score = 0.0
            if cos_scores is not None:
                raw_cos = float(cos_scores[idx])
                # Pruned E5 embeddings sit around ~0.72-0.80 for unrelated Vietnamese prose;
                # only reward genuine high-similarity semantic alignment (>= 0.85).
                if raw_cos >= 0.85:
                    vec_score = (raw_cos - 0.70) * 8.0

            total = lex_score + vec_score
            if total < 1.40:
                continue

            if mode in pb.get("modes", []):
                total *= 1.15
            scored.append((total, pb))

        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [pb for _, pb in scored[: max(1, top_k)]]
