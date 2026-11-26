"""Fine-tune intfloat/multilingual-e5-small (MIT), prune VI+EN vocab, and export INT8 ONNX (<40MB)."""

# ruff: noqa: S106

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
import onnxruntime as ort
import torch
import torch.nn as nn
import torch.nn.functional as F
from generate_vn_dataset import SCAM_LABELS, save_splits
from onnxruntime.quantization import QuantType, quantize_dynamic
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from torch.utils.data import DataLoader, Dataset
from transformers import AutoModel, AutoTokenizer

MODEL_NAME = "intfloat/multilingual-e5-small"
MAX_SEQ_LEN = 192
TRAIN_SEQ_LEN = 96
TARGET_MAX_VOCAB = 36_000
MAX_ONNX_SIZE_MB = 50.0

_VIETNAMESE_CHARS = frozenset(
    "ÀÁÂÃÈÉÊÌÍÒÓÔÕÙÚÝàáâãèéêìíòóôõùúýĂăĐđĨĩŨũƠơƯư"
    "ẠạẢảẤấẦầẨẩẪẫẬậẮắẰằẲẳẴẵẶặẸẹẺẻẼẽẾếỀềỂểỄễỆệ"
    "ỈỉỊịỌọỎỏỐốỒồỔổỖỗỘộỚớỜờỞởỠỡỢợỤụỦủỨứỪừỬửỮữỰự"
    "ỲỳỴỵỶỷỸỹ₫"
)


def _classify_token(token_str: str) -> str:
    """Classify SentencePiece token as 'vi' (has VN diacritic), 'ascii' (EN/digits/punct), or 'other'."""
    clean = token_str.replace("▁", "")
    if not clean:
        return "ascii"
    has_vi = False
    for ch in clean:
        if ch in _VIETNAMESE_CHARS:
            has_vi = True
        elif ord(ch) > 0x007E:
            return "other"
    return "vi" if has_vi else "ascii"


class DualHeadE5Classifier(nn.Module):
    """Outputs both 7-class scam logits and 384-d L2-normalized semantic embeddings."""

    def __init__(self, encoder: nn.Module, hidden_size: int = 384, num_labels: int = 7) -> None:
        super().__init__()
        self.encoder = encoder
        self.dropout = nn.Dropout(0.1)
        self.classifier = nn.Linear(hidden_size, num_labels)

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        last_hidden = outputs.last_hidden_state
        mask_expanded = attention_mask.unsqueeze(-1).to(last_hidden.dtype)
        summed = torch.sum(last_hidden * mask_expanded, dim=1)
        counts = torch.clamp(mask_expanded.sum(dim=1), min=1e-9)
        pooled = summed / counts
        normalized_emb = F.normalize(pooled, p=2, dim=1)
        logits = self.classifier(self.dropout(pooled))
        return logits, normalized_emb


class JsonlScamDataset(Dataset[dict[str, torch.Tensor]]):
    def __init__(self, path: Path, tokenizer: Any, label_to_id: dict[str, int]) -> None:
        self.rows = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.tokenizer = tokenizer
        self.label_to_id = label_to_id

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, idx: int) -> dict[str, torch.Tensor]:
        row = self.rows[idx]
        enc = self.tokenizer(
            f"query: {row['text']}",
            truncation=True,
            max_length=TRAIN_SEQ_LEN,
            padding="max_length",
            return_tensors="pt",
        )
        return {
            "input_ids": enc["input_ids"].squeeze(0),
            "attention_mask": enc["attention_mask"].squeeze(0),
            "labels": torch.tensor(self.label_to_id[row["label"]], dtype=torch.long),
        }


def prune_e5_vocabulary(
    base_model: Any,
    fast_tokenizer: Any,
    train_only_texts: list[str],
    out_tokenizer_dir: Path,
) -> tuple[Any, dict[int, int]]:
    """Prune 250k SentencePiece vocab strictly from training + KB texts (zero val/test leakage)."""
    tmp_tok_dir = out_tokenizer_dir / "_raw_tok"
    tmp_tok_dir.mkdir(parents=True, exist_ok=True)
    fast_tokenizer.save_pretrained(str(tmp_tok_dir))
    tok_json_path = tmp_tok_dir / "tokenizer.json"
    tok_data = json.loads(tok_json_path.read_text(encoding="utf-8"))

    vocab_list: list[list[Any]] = tok_data["model"]["vocab"]
    must_keep_ids: set[int] = set(range(min(16, len(vocab_list))))
    for added in tok_data.get("added_tokens", []):
        aid = int(added["id"])
        if 0 <= aid < len(vocab_list):
            must_keep_ids.add(aid)
    for text in train_only_texts:
        for tid in fast_tokenizer.encode(text, add_special_tokens=True):
            if 0 <= tid < len(vocab_list):
                must_keep_ids.add(tid)

    ascii_candidates: list[tuple[float, int]] = []
    for old_id, entry in enumerate(vocab_list):
        if old_id in must_keep_ids:
            continue
        kind = _classify_token(str(entry[0]))
        if kind == "vi":
            must_keep_ids.add(old_id)
        elif kind == "ascii":
            score = float(entry[1]) if len(entry) > 1 else -99.0
            ascii_candidates.append((score, old_id))

    ascii_candidates.sort(key=lambda item: item[0], reverse=True)
    remaining_budget = max(0, TARGET_MAX_VOCAB - len(must_keep_ids))
    for _, old_id in ascii_candidates[:remaining_budget]:
        must_keep_ids.add(old_id)

    old_to_new: dict[int, int] = {}
    new_vocab_list: list[list[Any]] = []
    kept_old_ids: list[int] = sorted(must_keep_ids)

    for old_id in kept_old_ids:
        old_to_new[old_id] = len(new_vocab_list)
        new_vocab_list.append(vocab_list[old_id])

    tok_data["model"]["vocab"] = new_vocab_list
    if "unk_id" in tok_data["model"]:
        tok_data["model"]["unk_id"] = old_to_new.get(tok_data["model"]["unk_id"], 3)

    for added in tok_data.get("added_tokens", []):
        if added["id"] in old_to_new:
            added["id"] = old_to_new[added["id"]]
    if "post_processor" in tok_data and tok_data["post_processor"]:
        proc_str = json.dumps(tok_data["post_processor"])
        tok_data["post_processor"] = json.loads(proc_str)

    out_tokenizer_dir.mkdir(parents=True, exist_ok=True)
    (out_tokenizer_dir / "tokenizer.json").write_text(
        json.dumps(tok_data, ensure_ascii=False),
        encoding="utf-8",
    )

    old_emb: nn.Embedding = base_model.embeddings.word_embeddings
    new_emb = nn.Embedding(len(kept_old_ids), old_emb.embedding_dim, padding_idx=old_emb.padding_idx)
    with torch.no_grad():
        idx_tensor = torch.tensor(kept_old_ids, dtype=torch.long)
        new_emb.weight.copy_(old_emb.weight[idx_tensor])
    base_model.embeddings.word_embeddings = new_emb
    base_model.config.vocab_size = len(kept_old_ids)
    return base_model, old_to_new


def _evaluate_int8_onnx_on_test(
    onnx_path: Path,
    rust_tok: Any,
    test_jsonl_path: Path,
    label_to_id: dict[str, int],
) -> tuple[float, list[list[int]], dict[str, Any]]:
    """Run the actual quantized INT8 ONNX artifact + shipped tokenizer on held-out test.jsonl."""
    opts = ort.SessionOptions()
    opts.enable_cpu_mem_arena = False
    opts.enable_mem_pattern = False
    sess = ort.InferenceSession(str(onnx_path), sess_options=opts, providers=["CPUExecutionProvider"])

    rows = [
        json.loads(line)
        for line in test_jsonl_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    y_true: list[int] = []
    y_pred: list[int] = []
    for row in rows:
        encoded = rust_tok.encode(f"query: {row['text']}")
        ids = encoded.ids[:MAX_SEQ_LEN]
        attn = [1] * len(ids)
        feed = {
            "input_ids": np.asarray([ids], dtype=np.int64),
            "attention_mask": np.asarray([attn], dtype=np.int64),
        }
        logits, _ = sess.run(["logits", "embedding"], feed)
        pred_idx = int(np.argmax(logits[0]))
        y_pred.append(pred_idx)
        y_true.append(label_to_id[row["label"]])

    macro_f1 = float(f1_score(y_true, y_pred, average="macro"))
    cm = confusion_matrix(y_true, y_pred).tolist()
    rep = classification_report(y_true, y_pred, target_names=list(SCAM_LABELS), output_dict=True)
    return macro_f1, cm, rep


def main() -> None:
    parser = argparse.ArgumentParser(description="Fine-tune & export pruned E5 INT8 ONNX.")
    parser.add_argument("--data-dir", type=Path, default=Path("training/data"))
    parser.add_argument("--out-dir", type=Path, default=Path("backend/app/data/models"))
    parser.add_argument("--kb-path", type=Path, default=Path("backend/app/data/vn_scam_kb.json"))
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--lr", type=float, default=1.5e-4)
    args = parser.parse_args()

    torch.set_num_threads(min(8, max(2, torch.get_num_threads())))
    if not (args.data_dir / "train.jsonl").exists():
        save_splits(args.data_dir, per_class=520)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[train_export_e5_onnx] Using device: {device}")

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    encoder = AutoModel.from_pretrained(MODEL_NAME)

    # Fit vocabulary strictly on training split + production playbook KB (never val/test!)
    train_only_texts = [
        json.loads(line)["text"]
        for line in (args.data_dir / "train.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    kb_data = json.loads(args.kb_path.read_text(encoding="utf-8"))
    for pb in kb_data["playbooks"]:
        train_only_texts.append(f"passage: {pb['name_vi']} {' '.join(pb['keywords'])}")

    encoder, _ = prune_e5_vocabulary(encoder, tokenizer, train_only_texts, args.out_dir)
    from tokenizers import Tokenizer as FastRustTokenizer
    from transformers import PreTrainedTokenizerFast

    pruned_rust_tok = FastRustTokenizer.from_file(str(args.out_dir / "tokenizer.json"))
    print(f"[train_export_e5_onnx] Pruned vocabulary size: {pruned_rust_tok.get_vocab_size()}")

    train_tok = PreTrainedTokenizerFast(  # noqa: S106
        tokenizer_object=pruned_rust_tok,
        bos_token="<s>",
        eos_token="</s>",
        unk_token="<unk>",
        sep_token="</s>",
        pad_token="<pad>",
        cls_token="<s>",
    )

    label_to_id = {lbl: i for i, lbl in enumerate(SCAM_LABELS)}
    train_ds = JsonlScamDataset(args.data_dir / "train.jsonl", train_tok, label_to_id)
    test_ds = JsonlScamDataset(args.data_dir / "test.jsonl", train_tok, label_to_id)
    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)
    test_loader = DataLoader(test_ds, batch_size=args.batch_size, shuffle=False)

    model = DualHeadE5Classifier(encoder, hidden_size=384, num_labels=len(SCAM_LABELS)).to(device)
    for param in model.encoder.embeddings.parameters():
        param.requires_grad = False
    encoder_layers = getattr(getattr(model.encoder, "encoder", None), "layer", None)
    if encoder_layers is not None:
        for layer in list(encoder_layers)[:8]:
            for param in layer.parameters():
                param.requires_grad = False

    trainable_params = [p for p in model.parameters() if p.requires_grad]
    optimizer = torch.optim.AdamW(trainable_params, lr=args.lr, weight_decay=0.01)
    criterion = nn.CrossEntropyLoss()

    for epoch in range(1, args.epochs + 1):
        model.train()
        total_loss = 0.0
        for batch in train_loader:
            optimizer.zero_grad()
            logits, _ = model(
                batch["input_ids"].to(device),
                batch["attention_mask"].to(device),
            )
            loss = criterion(logits, batch["labels"].to(device))
            loss.backward()
            optimizer.step()
            total_loss += float(loss.item())
        print(f"Epoch {epoch}/{args.epochs} - avg_loss={total_loss / len(train_loader):.4f}")

    model.eval()
    fp32_true: list[int] = []
    fp32_pred: list[int] = []
    with torch.no_grad():
        for batch in test_loader:
            logits, _ = model(
                batch["input_ids"].to(device),
                batch["attention_mask"].to(device),
            )
            fp32_pred.extend(torch.argmax(logits, dim=1).cpu().tolist())
            fp32_true.extend(batch["labels"].tolist())
    fp32_f1 = float(f1_score(fp32_true, fp32_pred, average="macro"))

    pb_vecs: list[np.ndarray] = []
    with torch.no_grad():
        for pb in kb_data["playbooks"]:
            passage = (
                f"passage: {pb['name_vi']}. Dấu hiệu: {' '.join(pb.get('keywords', []))}. "
                f"{' '.join(pb.get('red_flags', []))}"
            )
            enc_pb = train_tok(
                passage,
                truncation=True,
                max_length=MAX_SEQ_LEN,
                padding="max_length",
                return_tensors="pt",
            )
            _, emb = model(enc_pb["input_ids"].to(device), enc_pb["attention_mask"].to(device))
            pb_vecs.append(emb.squeeze(0).cpu().numpy().astype(np.float32))
    np.save(str(args.out_dir / "playbook_embeddings.npy"), np.stack(pb_vecs, axis=0))

    model_cpu = model.cpu().eval()
    dummy_ids = torch.ones((1, 32), dtype=torch.long)
    dummy_mask = torch.ones((1, 32), dtype=torch.long)
    fp32_onnx = args.out_dir / "_temp_scam_e5_fp32.onnx"
    int8_onnx = args.out_dir / "scam_e5_int8.onnx"

    torch.onnx.export(
        model_cpu,
        (dummy_ids, dummy_mask),
        str(fp32_onnx),
        input_names=["input_ids", "attention_mask"],
        output_names=["logits", "embedding"],
        dynamic_axes={
            "input_ids": {0: "batch", 1: "seq"},
            "attention_mask": {0: "batch", 1: "seq"},
            "logits": {0: "batch"},
            "embedding": {0: "batch"},
        },
        opset_version=17,
        dynamo=False,
    )
    quantize_dynamic(
        model_input=str(fp32_onnx),
        model_output=str(int8_onnx),
        weight_type=QuantType.QUInt8,
    )
    fp32_onnx.unlink(missing_ok=True)

    raw_tok_tmp = args.out_dir / "_raw_tok"
    if raw_tok_tmp.exists():
        for child in raw_tok_tmp.iterdir():
            child.unlink()
        raw_tok_tmp.rmdir()

    size_mb = round(int8_onnx.stat().st_size / (1024 * 1024), 2)
    if size_mb >= MAX_ONNX_SIZE_MB:
        int8_onnx.unlink(missing_ok=True)
        raise RuntimeError(
            f"Exported scam_e5_int8.onnx is {size_mb} MB (>= {MAX_ONNX_SIZE_MB} MB Git limit)!"
        )

    int8_f1, int8_cm, int8_report = _evaluate_int8_onnx_on_test(
        int8_onnx,
        pruned_rust_tok,
        args.data_dir / "test.jsonl",
        label_to_id,
    )
    print(f"[train_export_e5_onnx] FP32 Macro-F1={fp32_f1:.4f} | INT8 ONNX Macro-F1={int8_f1:.4f}")

    (args.out_dir / "label_map.json").write_text(
        json.dumps({"labels": list(SCAM_LABELS)}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (args.out_dir / "training_metrics.json").write_text(
        json.dumps(
            {
                "backbone": MODEL_NAME,
                "license": "MIT",
                "vocab_fit_scope": "train_plus_kb_only",
                "pruned_vocab_size": pruned_rust_tok.get_vocab_size(),
                "onnx_size_mb": size_mb,
                "pytorch_fp32_test_macro_f1": round(fp32_f1, 4),
                "onnx_int8_test_macro_f1": round(int8_f1, 4),
                "test_macro_f1": round(int8_f1, 4),
                "confusion_matrix": int8_cm,
                "classification_report": int8_report,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"[train_export_e5_onnx] Saved {int8_onnx} ({size_mb} MB) successfully!")


if __name__ == "__main__":
    main()
