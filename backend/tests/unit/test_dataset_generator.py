import importlib.util
from collections import Counter
from pathlib import Path

from app.schemas import SCAM_LABELS


def test_synthetic_vn_dataset_generator_produces_balanced_unique_samples() -> None:
    script_path = Path(__file__).resolve().parents[3] / "training" / "generate_vn_dataset.py"
    spec = importlib.util.spec_from_file_location("generate_vn_dataset", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    samples = module.generate_synthetic_samples(per_class=60, seed=2026)
    assert len(samples) == 60 * len(SCAM_LABELS)

    counts = Counter(item["label"] for item in samples)
    for label in SCAM_LABELS:
        assert counts[label] == 60

    unique_texts = {item["text"] for item in samples}
    assert len(unique_texts) == len(samples)

    # Ensure zero label leakage in full 520-per-class generation
    full_samples = module.generate_synthetic_samples(per_class=520, seed=2026)
    assert len({item["text"] for item in full_samples}) == len(full_samples)
    for row in full_samples:
        lbl = row["label"]
        assert f"[{lbl[:4]}-" not in row["text"], f"Label marker leaked into sample: {row['text']}"
        assert lbl not in row["text"], f"Raw class label leaked into sample: {row['text']}"
