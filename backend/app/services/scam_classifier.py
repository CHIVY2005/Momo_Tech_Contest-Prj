"""Runtime Dual-Head ONNX classifier & 384-d semantic embedder (<20ms CPU, zero PyTorch)."""

from __future__ import annotations

import json
import math
import re
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

from app.core.onnx_session import build_cpu_session_options
from app.schemas import SCAM_LABELS, ScamClassifierOutput

MAX_MODEL_SEQ_LEN: Final[int] = 192
MAX_INFERENCE_WINDOWS: Final[int] = 40
_EARLY_EXIT_THRESHOLD: Final[float] = 0.75
_PEAK_SELECT_THRESHOLD: Final[float] = 0.45
_FOCUS_WIN_CHARS: Final[int] = 280
_FOCUS_STRIDE_CHARS: Final[int] = 210
_CLAUSE_SPLIT_RE: Final[re.Pattern[str]] = re.compile(r"(?:\n+|(?<=[.!?;])\s+)")
_SENT_BOUNDARY_RE: Final[re.Pattern[str]] = re.compile(r"[.!?\n;]+[ \t]*")
_DIGITS_RE: Final[re.Pattern[str]] = re.compile(r"\d+")
_SCAM_POSITIVE_LABELS: Final[frozenset[str]] = frozenset(
    {
        "SCAM_IMPERSONATION", "SCAM_TASK_INVEST_LOAN",
        "SCAM_PHISHING_APK_OTP", "SCAM_URGENT_BORROW", "PROMPT_INJECTION",
    }
)


@dataclass(slots=True)
class _WindowPrediction:
    best_label: str
    prob_map: dict[str, float]
    scam_prob: float
    adv_prob: float
    inj_prob: float
    embedding: np.ndarray | None


def _softmax(logits: np.ndarray) -> np.ndarray:
    exps: np.ndarray = np.exp(logits - np.max(logits))
    res: np.ndarray = exps / max(float(np.sum(exps)), 1e-12)
    return res


def _collapse_clause_repeats(clause: str) -> str:
    if len(clause) <= 100:
        return clause
    if "," in clause:
        seen, kept = set(), []
        for seg in re.split(r",\s*", clause):
            s = seg.strip()
            norm = " ".join(s.lower().split())
            if s and not (len(norm) <= 48 and norm in seen):
                seen.add(norm)
                kept.append(s)
        clause = ", ".join(kept) if kept else clause
    words = clause.split()
    if len(words) >= 8:
        out_w: list[str] = []
        for w in words:
            if out_w and out_w[-1].lower() == w.lower():
                continue
            out_w.append(w)
            if (
                len(out_w) >= 4
                and (out_w[-1].lower(), out_w[-2].lower()) == (out_w[-3].lower(), out_w[-4].lower())
            ):
                del out_w[-2:]
        if len(out_w) < len(words):
            clause = " ".join(out_w)
    return clause


def _deduplicate_text(cleaned: str) -> tuple[str, str]:
    counts: dict[str, int] = {}
    items: list[tuple[str, str]] = []
    for raw in _CLAUSE_SPLIT_RE.split(cleaned):
        c = _collapse_clause_repeats(raw.strip())
        if c:
            norm = " ".join(c.lower().split())
            if norm not in counts:
                items.append((norm, c))
            counts[norm] = counts.get(norm, 0) + 1
    if not items:
        return cleaned, ""
    if sum(len(c) for _, c in items) > 600:
        s_counts: dict[str, int] = {}
        s_items: list[tuple[str, str]] = []
        for norm, c in items:
            key = _DIGITS_RE.sub("#", norm) if len(norm) >= 40 else norm
            if key not in s_counts:
                s_items.append((key, c))
            s_counts[key] = s_counts.get(key, 0) + counts[norm]
        items, counts = s_items, s_counts
    deduped = "\n".join(c for _, c in items)
    rare = [c for k, c in items if counts[k] == 1] if any(v >= 2 for v in counts.values()) else []
    return deduped, ("\n".join(rare) if 0 < len(rare) < len(items) else "")


class ScamClassifier:
    """Loads pruned multilingual-e5-small INT8 ONNX model for 7-class + embedding inference."""

    def __init__(
        self, model_dir: str, _injected_session: Any | None = None, intra_threads: int = 2
    ) -> None:
        self._dir = Path(model_dir)
        self._tokenizer: Tokenizer | None = None
        self._session: Any | None = _injected_session
        self._labels: tuple[str, ...] = SCAM_LABELS
        self._intra_threads = max(1, intra_threads)
        tok_f, lbl_f = self._dir / "tokenizer.json", self._dir / "label_map.json"
        onnx_f = self._dir / "scam_e5_int8.onnx"
        if lbl_f.exists():
            try:
                loaded = json.loads(lbl_f.read_text(encoding="utf-8")).get("labels")
                if isinstance(loaded, list) and len(loaded) == len(SCAM_LABELS):
                    self._labels = tuple(str(x) for x in loaded)
            except Exception:
                self._labels = SCAM_LABELS
        if tok_f.exists() and (_injected_session is not None or onnx_f.exists()):
            try:
                tok = Tokenizer.from_file(str(tok_f))
                tok.enable_truncation(max_length=MAX_MODEL_SEQ_LEN)
                self._tokenizer = tok
                if self._session is None:
                    opts = build_cpu_session_options(intra_threads=self._intra_threads)
                    self._session = ort.InferenceSession(
                        str(onnx_f), sess_options=opts, providers=["CPUExecutionProvider"]
                    )
            except Exception:
                self._tokenizer = self._session = None

    @property
    def is_available(self) -> bool:
        return self._tokenizer is not None and self._session is not None

    def _encode_and_run(
        self, cleaned_text: str, *, prefix: Literal["query", "passage"]
    ) -> tuple[Any, list[Any]] | None:
        if not cleaned_text or self._tokenizer is None or self._session is None:
            return None
        enc = self._tokenizer.encode(f"{prefix}: {cleaned_text}")
        feed = {
            "input_ids": np.ascontiguousarray([enc.ids], dtype=np.int64),
            "attention_mask": np.ascontiguousarray([enc.attention_mask], dtype=np.int64),
        }
        return enc, list(self._session.run(None, feed))

    @staticmethod
    def _extract_unit_embedding(outputs: list[Any]) -> np.ndarray | None:
        if len(outputs) >= 2 and outputs[1] is not None:
            vec = np.asarray(outputs[1][0], dtype=np.float32)
            norm = float(np.linalg.norm(vec))
            if norm > 1e-8:
                normalized: np.ndarray = (vec / np.float32(norm)).astype(np.float32, copy=False)
                return normalized
        return None

    def _decode_window_outputs(self, outputs: list[Any]) -> _WindowPrediction:
        probs = _softmax(np.asarray(outputs[0][0], dtype=np.float64))
        n_lbl = min(len(self._labels), len(probs))
        pmap = {self._labels[i]: round(float(probs[i]), 6) for i in range(n_lbl)}
        return _WindowPrediction(
            best_label=self._labels[int(np.argmax(probs))],
            prob_map=pmap,
            scam_prob=min(1.0, sum(v for k, v in pmap.items() if k in _SCAM_POSITIVE_LABELS)),
            adv_prob=pmap.get("SAFE_ADVISORY", 0.0),
            inj_prob=pmap.get("PROMPT_INJECTION", 0.0),
            embedding=self._extract_unit_embedding(outputs),
        )

    @staticmethod
    def _consumed_window_chars(encoded: Any, window_text: str, prefix_len: int) -> int:
        for _start, end in reversed(getattr(encoded, "offsets", None) or ()):
            if end > prefix_len:
                return min(len(window_text), int(end) - prefix_len)
        return max(1, (len(window_text) * 3) // 4)

    def encode_text(
        self, text: str, *, prefix: Literal["query", "passage"] = "query"
    ) -> np.ndarray | None:
        """Encode text into a unit-norm 384-d float32 E5 vector using the shared ONNX session."""
        res = self._encode_and_run(unicodedata.normalize("NFC", text).strip(), prefix=prefix)
        return None if res is None else self._extract_unit_embedding(res[1])

    def _scan_text_windows(
        self, target: str, budget: int, results: list[_WindowPrediction]
    ) -> bool:
        if not target or budget <= 0:
            return False
        n, pos, last_consumed, win_chars = len(target), 0, 0, _FOCUS_WIN_CHARS
        if n > win_chars and budget > 1:
            min_stride = math.ceil((n - win_chars) / (budget - 1))
            if min_stride > _FOCUS_STRIDE_CHARS:
                win_chars = min(460, max(win_chars, min_stride + 70))
        for idx in range(budget):
            rem_slots = budget - idx
            if idx == budget - 1 and pos + win_chars < n:
                pos = max(pos, n - (min(win_chars, last_consumed) if last_consumed else win_chars))
            end = min(n, pos + win_chars)
            if end < n:
                lo_e, hi_e = max(pos + win_chars // 2, end - 50), min(n, end + 40)
                m_end = _SENT_BOUNDARY_RE.search(target, lo_e, hi_e)
                if m_end and m_end.end() <= pos + win_chars + 40:
                    end = m_end.end()
            win_txt = target[pos:end].strip()
            run_res = self._encode_and_run(win_txt, prefix="query") if win_txt else None
            if run_res is None:
                break
            encoded, outputs = run_res
            pred = self._decode_window_outputs(outputs)
            results.append(pred)
            if max(pred.scam_prob, pred.inj_prob) >= _EARLY_EXIT_THRESHOLD:
                return True
            trunc = len(encoded.ids) >= MAX_MODEL_SEQ_LEN
            consumed = self._consumed_window_chars(encoded, win_txt, 7) if trunc else len(win_txt)
            last_consumed = max(last_consumed, consumed)
            if (not trunc and end >= n) or (trunc and pos + consumed >= n):
                break
            if trunc:
                ov = min(consumed // 6, 48) if consumed >= 12 else 0
                next_pos = pos + max(1, consumed - ov)
            else:
                rem = n - pos
                req = max(1, end - pos)
                if rem_slots > 1 and rem > win_chars:
                    req = math.ceil((rem - win_chars) / (rem_slots - 1))
                next_pos = pos + max(_FOCUS_STRIDE_CHARS, req)
                lo, hi = max(pos + 120, next_pos - 35), min(end - 25, n - 1)
                m_snap = _SENT_BOUNDARY_RE.search(target, lo, hi) if lo < hi else None
                if m_snap and m_snap.end() < n:
                    next_pos = m_snap.end()
            pos = next_pos if next_pos > pos else pos + max(1, consumed // 2)
        return False

    def predict(self, text: str) -> tuple[ScamClassifierOutput, np.ndarray | None]:
        """Run ONNX inference (dedup + zero-hole focused windows when truncated at 192 tokens)."""
        t0 = time.perf_counter()
        cleaned = unicodedata.normalize("NFC", text).strip()
        first = self._encode_and_run(cleaned, prefix="query")
        if first is None:
            return ScamClassifierOutput(available=False), None
        first_enc, first_out = first
        first_pred = self._decode_window_outputs(first_out)
        results: list[_WindowPrediction] = [first_pred]
        early = max(first_pred.scam_prob, first_pred.inj_prob) >= _EARLY_EXIT_THRESHOLD
        if not early and len(first_enc.ids) >= MAX_MODEL_SEQ_LEN:
            deduped, rare_text = _deduplicate_text(cleaned)
            if rare_text:
                early = self._scan_text_windows(rare_text, 6, results)
            if not early and len(results) < MAX_INFERENCE_WINDOWS:
                self._scan_text_windows(deduped, MAX_INFERENCE_WINDOWS - len(results), results)
        peak = max(results, key=lambda r: (r.scam_prob, r.inj_prob))
        chosen = peak if max(peak.scam_prob, peak.inj_prob) >= _PEAK_SELECT_THRESHOLD else results[0]
        return ScamClassifierOutput(
            available=True,
            predicted_label=chosen.best_label,
            scam_probability=round(max(r.scam_prob for r in results), 4),
            advisory_probability=round(min(r.adv_prob for r in results), 4),
            injection_probability=round(max(r.inj_prob for r in results), 4),
            class_probabilities=chosen.prob_map,
            latency_ms=int((time.perf_counter() - t0) * 1000),
        ), chosen.embedding

    def predict_and_encode(self, text: str) -> tuple[ScamClassifierOutput, np.ndarray | None]:
        """Alias for single-pass classification + 384-d query embedding extraction."""
        return self.predict(text)
