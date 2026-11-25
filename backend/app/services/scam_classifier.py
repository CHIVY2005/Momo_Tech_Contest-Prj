"""Runtime Dual-Head ONNX classifier & 384-d semantic embedder (<20ms CPU, zero PyTorch)."""

from __future__ import annotations

import json
import time
import unicodedata
from pathlib import Path
from typing import Any, Final

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

from app.core.onnx_session import build_cpu_session_options
from app.schemas import SCAM_LABELS, ScamClassifierOutput

MAX_MODEL_SEQ_LEN: Final[int] = 192
_SCAM_POSITIVE_LABELS: Final[frozenset[str]] = frozenset(
    {
        "SCAM_IMPERSONATION",
        "SCAM_TASK_INVEST_LOAN",
        "SCAM_PHISHING_APK_OTP",
        "SCAM_URGENT_BORROW",
        "PROMPT_INJECTION",
    }
)


def _softmax(logits: np.ndarray) -> np.ndarray:
    shifted = logits - np.max(logits)
    exps: np.ndarray = np.exp(shifted)
    denom = float(np.sum(exps))
    result: np.ndarray = exps / max(denom, 1e-12)
    return result


class ScamClassifier:
    """Loads pruned multilingual-e5-small INT8 ONNX model for 7-class + embedding inference."""

    def __init__(self, model_dir: str, _injected_session: Any | None = None) -> None:
        self._dir = Path(model_dir)
        self._tokenizer: Tokenizer | None = None
        self._session: Any | None = _injected_session
        self._labels: tuple[str, ...] = SCAM_LABELS

        tok_file = self._dir / "tokenizer.json"
        label_file = self._dir / "label_map.json"
        onnx_file = self._dir / "scam_e5_int8.onnx"

        if label_file.exists():
            try:
                loaded_labels = json.loads(label_file.read_text(encoding="utf-8")).get("labels")
                if isinstance(loaded_labels, list) and len(loaded_labels) == len(SCAM_LABELS):
                    self._labels = tuple(str(x) for x in loaded_labels)
            except Exception:
                self._labels = SCAM_LABELS

        if tok_file.exists() and (_injected_session is not None or onnx_file.exists()):
            try:
                tok = Tokenizer.from_file(str(tok_file))
                tok.enable_truncation(max_length=MAX_MODEL_SEQ_LEN)
                self._tokenizer = tok
                if self._session is None:
                    self._session = ort.InferenceSession(
                        str(onnx_file),
                        sess_options=build_cpu_session_options(intra_threads=4),
                        providers=["CPUExecutionProvider"],
                    )
            except Exception:
                self._tokenizer = None
                self._session = None

    @property
    def is_available(self) -> bool:
        return self._tokenizer is not None and self._session is not None

    def predict(self, text: str) -> tuple[ScamClassifierOutput, np.ndarray | None]:
        """Run single-pass ONNX inference returning (ScamClassifierOutput, 384-d L2 vector)."""
        cleaned = unicodedata.normalize("NFC", text).strip()
        if not cleaned or self._tokenizer is None or self._session is None:
            return ScamClassifierOutput(available=False), None

        t0 = time.perf_counter()
        encoded = self._tokenizer.encode(f"query: {cleaned}")
        ids = np.ascontiguousarray([encoded.ids], dtype=np.int64)
        mask = np.ascontiguousarray([encoded.attention_mask], dtype=np.int64)

        outputs = self._session.run(
            None,
            {"input_ids": ids, "attention_mask": mask},
        )
        latency_ms = int((time.perf_counter() - t0) * 1000)

        raw_logits = np.asarray(outputs[0][0], dtype=np.float64)
        probs = _softmax(raw_logits)
        prob_map = {
            self._labels[idx]: round(float(probs[idx]), 6)
            for idx in range(min(len(self._labels), len(probs)))
        }

        best_idx = int(np.argmax(probs))
        best_label = self._labels[best_idx]
        scam_prob = min(
            1.0,
            sum(val for lbl, val in prob_map.items() if lbl in _SCAM_POSITIVE_LABELS),
        )
        adv_prob = prob_map.get("SAFE_ADVISORY", 0.0)
        inj_prob = prob_map.get("PROMPT_INJECTION", 0.0)

        embedding: np.ndarray | None = None
        if len(outputs) >= 2 and outputs[1] is not None:
            vec = np.asarray(outputs[1][0], dtype=np.float32)
            norm = float(np.linalg.norm(vec))
            if norm > 1e-8:
                embedding = vec / norm

        return (
            ScamClassifierOutput(
                available=True,
                predicted_label=best_label,
                scam_probability=round(scam_prob, 4),
                advisory_probability=round(adv_prob, 4),
                injection_probability=round(inj_prob, 4),
                class_probabilities=prob_map,
                latency_ms=latency_ms,
            ),
            embedding,
        )
