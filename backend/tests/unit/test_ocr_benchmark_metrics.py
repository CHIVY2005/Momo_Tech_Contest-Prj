"""Unit tests for OCR benchmark CER, WER, entity extraction F1, and synthetic dataset generation."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from evaluation.ocr_benchmark.generate_dataset import build_synthetic_dataset  # noqa: E402
from evaluation.ocr_benchmark.metrics import (  # noqa: E402
    compute_cer,
    compute_wer,
    extract_benchmark_entities,
    percentile,
    score_entity_extraction,
)

from app.services.ioc_extractor import extract_iocs  # noqa: E402


def test_cer_wer_and_percentile_exact_values() -> None:
    assert compute_cer("Chuyển khoản thành công", "Chuyển khoản thành công") == 0.0
    assert compute_wer("Chuyển khoản thành công", "Chuyển khoản thành công") == 0.0

    # Diacritic stripping raises exact CER while ASCII-folded CER remains 0.0
    assert compute_cer("Chuyển khoản", "Chuyen khoan", fold_ascii=False) > 0.1
    assert compute_cer("Chuyển khoản", "Chuyen khoan", fold_ascii=True) == 0.0

    assert percentile([10.0, 20.0, 30.0, 40.0, 50.0], 50) == 30.0
    assert percentile([10.0, 20.0, 30.0, 40.0, 50.0], 95) == 48.0


def test_entity_extraction_scoring_and_dataset_generator(tmp_path: Path) -> None:
    txt = (
        "Truy cập https://napas-demo.top/v chuyển 5.000.000 VND "
        "tới STK nhận: 190300011122 Mã GD: FT263301122334 SĐT 0981000101"
    )
    pred = extract_benchmark_entities(txt, extract_iocs_fn=extract_iocs)
    score = score_entity_extraction(
        {
            "urls": ["https://napas-demo.top/v"],
            "phones": ["0981000101"],
            "bank_accounts": ["190300011122"],
            "amounts": ["5000000"],
            "ref_codes": ["FT263301122334"],
        },
        pred,
    )
    assert score["f1"] == 1.0
    assert score["precision"] == 1.0
    assert score["recall"] == 1.0

    samples = build_synthetic_dataset(out_dir=tmp_path / "bench_ds")
    assert len(samples) == 25
    categories = {s.category for s in samples}
    assert categories == {"chat_sms", "bank_receipt", "vietqr", "dark_mode", "low_quality"}
    assert (tmp_path / "bench_ds" / "manifest.json").is_file()
