"""Exact CER, WER, entity extraction F1, and latency percentile metrics for OCR benchmarking."""

from __future__ import annotations

import re
import unicodedata
from typing import Any


def normalize_ocr_text(text: str) -> str:
    """Normalize Unicode NFC and collapse whitespace for fair CER/WER comparison."""
    nfc = unicodedata.normalize("NFC", text or "")
    return re.sub(r"\s+", " ", nfc).strip()


def fold_vietnamese_ascii(text: str) -> str:
    """Fold Vietnamese diacritics to ASCII to isolate diacritic vs base-character error."""
    nfc = unicodedata.normalize("NFC", text or "")
    out: list[str] = []
    for ch in nfc:
        if ch == "đ":
            out.append("d")
        elif ch == "Đ":
            out.append("D")
        elif ord(ch) < 128:
            out.append(ch)
        else:
            decomp = unicodedata.normalize("NFD", ch)
            base = decomp[0] if decomp else ch
            out.append(base if ord(base) < 128 else ch)
    return "".join(out)


def levenshtein_distance(seq_a: list[str], seq_b: list[str]) -> int:
    """Compute exact Wagner-Fischer edit distance between two token sequences."""
    n, m = len(seq_a), len(seq_b)
    if n == 0:
        return m
    if m == 0:
        return n
    prev = list(range(m + 1))
    for i, a in enumerate(seq_a, start=1):
        curr = [i]
        for j, b in enumerate(seq_b, start=1):
            cost = 0 if a == b else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def compute_cer(reference: str, hypothesis: str, *, fold_ascii: bool = False) -> float:
    """Compute Character Error Rate (edit distance / reference length)."""
    ref = normalize_ocr_text(reference)
    hyp = normalize_ocr_text(hypothesis)
    if fold_ascii:
        ref = fold_vietnamese_ascii(ref).lower()
        hyp = fold_vietnamese_ascii(hyp).lower()
    if not ref:
        return 0.0 if not hyp else 1.0
    dist = levenshtein_distance(list(ref), list(hyp))
    return round(dist / len(ref), 4)


def compute_wer(reference: str, hypothesis: str) -> float:
    """Compute Word Error Rate (word-level edit distance / reference word count)."""
    ref_words = normalize_ocr_text(reference).split()
    hyp_words = normalize_ocr_text(hypothesis).split()
    if not ref_words:
        return 0.0 if not hyp_words else 1.0
    dist = levenshtein_distance(ref_words, hyp_words)
    return round(dist / len(ref_words), 4)


def percentile(values: list[float], pct: float) -> float:
    """Compute linear-interpolated percentile (e.g. pct=50 or pct=95)."""
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(float(ordered[0]), 2)
    k = (len(ordered) - 1) * (pct / 100.0)
    lo = int(k)
    hi = min(len(ordered) - 1, lo + 1)
    frac = k - lo
    return round(float(ordered[lo] + frac * (ordered[hi] - ordered[lo])), 2)


_AMOUNT_EXTRACT_RE = re.compile(
    r"\b\d{1,3}(?:[.,]\d{3})+\b"
)
_REF_EXTRACT_RE = re.compile(r"\b(?:FT\d{8,16}|FAKE\d{2,8}|VCB\d{6,12})\b", re.IGNORECASE)


def extract_benchmark_entities(
    text: str,
    *,
    extract_iocs_fn: Any,
) -> dict[str, set[str]]:
    """Extract normalized URLs, phones, bank accounts, amounts, and ref codes from OCR text."""
    iocs = extract_iocs_fn(text)
    urls = {u.lower().rstrip("/") for u in iocs.urls}
    phones = {re.sub(r"\D", "", p) for p in iocs.phones if p}
    accounts = {re.sub(r"\D", "", a) for a in iocs.bank_accounts if a}
    amounts = {re.sub(r"[.,]", "", m.group(0)) for m in _AMOUNT_EXTRACT_RE.finditer(text)}
    refs = {m.group(0).upper() for m in _REF_EXTRACT_RE.finditer(text)}
    return {
        "urls": urls,
        "phones": phones,
        "bank_accounts": accounts,
        "amounts": amounts,
        "ref_codes": refs,
    }


def score_entity_extraction(
    expected: dict[str, list[str]],
    predicted: dict[str, set[str]],
) -> dict[str, float]:
    """Compute exact-match micro precision, recall, and F1 over expected vs predicted entities."""
    tp = 0
    fp = 0
    fn = 0
    for key in ("urls", "phones", "bank_accounts", "amounts", "ref_codes"):
        exp_set = {
            (
                v.lower().rstrip("/")
                if key == "urls"
                else v.upper()
                if key == "ref_codes"
                else re.sub(r"\D", "", v)
            )
            for v in expected.get(key, [])
            if v
        }
        pred_set = predicted.get(key, set())
        tp += len(exp_set & pred_set)
        fp += len(pred_set - exp_set)
        fn += len(exp_set - pred_set)

    precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if fn == 0 else 0.0)
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return {
        "tp": float(tp),
        "fp": float(fp),
        "fn": float(fn),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }
