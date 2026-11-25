"""Fine-tune intfloat/multilingual-e5-small (MIT), prune VI+EN vocab, and export INT8 ONNX (<40MB)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
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


def _is_vi_en_token(token_str: str) -> bool:
    """Keep ASCII, Latin-1, Latin Extended-A/B, and Latin Extended Additional (Vietnamese) tokens."""
    clean = token_str.replace("▁", "")
    if not clean:
        return True
    for ch in clean:
        cp = ord(ch)
        is_vi_latin = (
            cp <= 0x024F  # Basic Latin + Latin-1 + Latin Extended-A/B (includes ơ, ư, đ)
            or (0x1E00 <= cp <= 0x1EFF)  # Vietnamese tone combinations
            or (0x2000 <= cp <= 0x206F)  # General punctuation / currency (₫ = 0x20AB)
            or (0x20A0 <= cp <= 0x20CF)
        )
        if not is_vi_latin:
            return False
    return True


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
            max_length=MAX_SEQ_LEN,
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
    corpus_texts: list[str],
    out_tokenizer_dir: Path,
) -> tuple[Any, dict[int, int]]:
    """Prune 250k multilingual SentencePiece/Unigram vocab in tokenizer.json down to VI+EN (~40k)."""
    tmp_tok_dir = out_tokenizer_dir / "_raw_tok"
    tmp_tok_dir.mkdir(parents=True, exist_ok=True)
    fast_tokenizer.save_pretrained(str(tmp_tok_dir))
    tok_json_path = tmp_tok_dir / "tokenizer.json"
    tok_data = json.loads(tok_json_path.read_text(encoding="utf-8"))

    # Always keep special IDs (0..10) + any token triggered by our Vietnamese corpus + VI/EN subwords
    must_keep_ids: set[int] = set(range(min(16, fast_tokenizer.vocab_size)))
    for text in corpus_texts:
        must_keep_ids.update(fast_tokenizer.encode(text, add_special_tokens=True))

    vocab_list: list[list[Any]] = tok_data["model"]["vocab"]
    old_to_new: dict[int, int] = {}
    new_vocab_list: list[list[Any]] = []
    kept_old_ids: list[int] = []

    for old_id, entry in enumerate(vocab_list):
        piece = str(entry[0])
        if old_id in must_keep_ids or _is_vi_en_token(piece):
            old_to_new[old_id] = len(new_vocab_list)
            new_vocab_list.append(entry)
            kept_old_ids.append(old_id)

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


def main() -> None:
    parser = argparse.ArgumentParser(description="Fine-tune & export pruned E5 INT8 ONNX.")
    parser.add_argument("--data-dir", type=Path, default=Path("training/data"))
    parser.add_argument("--out-dir", type=Path, default=Path("backend/app/data/models"))
    parser.add_argument("--kb-path", type=Path, default=Path("backend/app/data/vn_scam_kb.json"))
    parser.add_argument("--epochs", type=int, default=4)
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--lr", type=float, default=3e-5)
    args = parser.parse_args()

    if not (args.data_dir / "train.jsonl").exists():
        save_splits(args.data_dir, per_class=520)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[train_export_e5_onnx] Using device: {device}")

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    encoder = AutoModel.from_pretrained(MODEL_NAME)

    corpus_texts = [
        json.loads(line)["text"]
        for split in ("train.jsonl", "val.jsonl", "test.jsonl")
        for line in (args.data_dir / split).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    kb_data = json.loads(args.kb_path.read_text(encoding="utf-8"))
    for pb in kb_data["playbooks"]:
        corpus_texts.append(f"passage: {pb['name_vi']} {' '.join(pb['keywords'])}")

    encoder, _ = prune_e5_vocabulary(encoder, tokenizer, corpus_texts, args.out_dir)
    from tokenizers import Tokenizer as FastRustTokenizer

    pruned_rust_tok = FastRustTokenizer.from_file(str(args.out_dir / "tokenizer.json"))
    print(f"[train_export_e5_onnx] Pruned vocabulary size: {pruned_rust_tok.get_vocab_size()}")

    # Wrap pruned tokenizer for training
    from transformers import PreTrainedTokenizerFast

    train_tok = PreTrainedTokenizerFast(
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
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
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
    y_true: list[int] = []
    y_pred: list[int] = []
    with torch.no_grad():
        for batch in test_loader:
            logits, _ = model(
                batch["input_ids"].to(device),
                batch["attention_mask"].to(device),
            )
            preds = torch.argmax(logits, dim=1).cpu().tolist()
            y_pred.extend(preds)
            y_true.extend(batch["labels"].tolist())

    macro_f1 = float(f1_score(y_true, y_pred, average="macro"))
    cm = confusion_matrix(y_true, y_pred).tolist()
    report = classification_report(y_true, y_pred, target_names=list(SCAM_LABELS), output_dict=True)
    print(f"[train_export_e5_onnx] Test Macro-F1: {macro_f1:.4f}")

    # Export Playbook Passage Embeddings (float32 [N, 384])
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

    # Export FP32 ONNX -> Quantize INT8 -> Remove temporary FP32 file
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

    (args.out_dir / "label_map.json").write_text(
        json.dumps({"labels": list(SCAM_LABELS)}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    size_mb = round(int8_onnx.stat().st_size / (1024 * 1024), 2)
    (args.out_dir / "training_metrics.json").write_text(
        json.dumps(
            {
                "backbone": MODEL_NAME,
                "license": "MIT",
                "pruned_vocab_size": pruned_rust_tok.get_vocab_size(),
                "onnx_size_mb": size_mb,
                "test_macro_f1": round(macro_f1, 4),
                "confusion_matrix": cm,
                "classification_report": report,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"[train_export_e5_onnx] Saved {int8_onnx} ({size_mb} MB) successfully!")


if __name__ == "__main__":
    main()
