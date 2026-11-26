import json
from pathlib import Path
from typing import Any

import numpy as np
from tokenizers import Tokenizer
from tokenizers.models import WordLevel
from tokenizers.pre_tokenizers import Whitespace

from app.schemas import SCAM_LABELS
from app.services.scam_classifier import ScamClassifier


class _DummyOnnxSession:
    def run(self, _output_names: Any, input_feed: dict[str, np.ndarray]) -> list[np.ndarray]:
        assert input_feed["input_ids"].dtype == np.int64
        assert input_feed["attention_mask"].dtype == np.int64
        # Strongly favor index 2 ("SCAM_IMPERSONATION")
        logits = np.array([[-2.0, -2.0, 4.5, -1.0, 0.2, -1.5, -2.0]], dtype=np.float32)
        emb = np.ones((1, 384), dtype=np.float32)
        emb = emb / np.linalg.norm(emb, axis=1, keepdims=True)
        return [logits, emb]


def test_classifier_graceful_skip_when_onnx_missing(tmp_path: Path) -> None:
    clf = ScamClassifier(str(tmp_path / "empty"))
    pred, emb = clf.predict("Công an yêu cầu chuyển khoản xác minh VNeID")
    assert pred.available is False
    assert pred.scam_probability == 0.0
    assert emb is None


def test_classifier_dual_head_softmax_and_embedding_extraction(tmp_path: Path) -> None:
    vocab = {"<pad>": 0, "<s>": 1, "</s>": 2, "<unk>": 3, "query:": 4, "cong": 5, "an": 6}
    tok = Tokenizer(WordLevel(vocab=vocab, unk_token="<unk>"))
    tok.pre_tokenizer = Whitespace()  # type: ignore[assignment]
    tok.save(str(tmp_path / "tokenizer.json"))
    (tmp_path / "label_map.json").write_text(
        json.dumps({"labels": list(SCAM_LABELS)}),
        encoding="utf-8",
    )

    clf = ScamClassifier(str(tmp_path), _injected_session=_DummyOnnxSession())
    pred, emb = clf.predict("cong an")
    assert pred.available is True
    assert pred.predicted_label == "SCAM_IMPERSONATION"
    assert pred.scam_probability > 0.95
    assert abs(sum(pred.class_probabilities.values()) - 1.0) < 1e-4
    assert emb is not None and emb.shape == (384,)
    assert abs(float(np.linalg.norm(emb)) - 1.0) < 1e-4


def test_real_exported_e5_int8_onnx_artifact_size_accuracy_and_cpu_latency() -> None:
    model_dir = Path(__file__).resolve().parents[2] / "app" / "data" / "models"
    onnx_path = model_dir / "scam_e5_int8.onnx"
    if not onnx_path.exists():
        return

    # Hard Invariant #4: Model artifact committed to Git must remain < 50 MB
    size_mb = onnx_path.stat().st_size / (1024 * 1024)
    assert size_mb < 50.0, f"scam_e5_int8.onnx is {size_mb:.2f} MB (must be < 50 MB)"

    clf = ScamClassifier(str(model_dir))
    assert clf.is_available is True

    # Warmup pass
    clf.predict("Xin chào buổi sáng")

    latencies: list[int] = []
    scam_pred, scam_emb = clf.predict(
        "Cơ quan Cảnh sát điều tra yêu cầu chuyển tạm giữ 20 triệu vào STK 8800123456 ngay lập tức"
    )
    latencies.append(scam_pred.latency_ms)
    assert scam_pred.scam_probability >= 0.75
    assert scam_emb is not None and scam_emb.shape == (384,)

    adv_pred, _ = clf.predict(
        "[CẢNH BÁO AN TOÀN] Vietcombank khuyến cáo khách hàng "
        "TUYỆT ĐỐI KHÔNG cung cấp mã OTP hay cài file .apk"
    )
    latencies.append(adv_pred.latency_ms)
    assert adv_pred.predicted_label == "SAFE_ADVISORY"
    assert adv_pred.advisory_probability >= 0.60

    norm_pred, _ = clf.predict("Chào Lan, tối nay 7h ghé chợ mua rau muống về nấu cơm nhé.")
    latencies.append(norm_pred.latency_ms)
    assert norm_pred.predicted_label == "SAFE_NORMAL"
    assert norm_pred.scam_probability < 0.35

    latencies.sort()
    p50_ms = latencies[len(latencies) // 2]
    assert p50_ms < 35, f"Expected ONNX CPU P50 < 35ms, got {p50_ms}ms"
