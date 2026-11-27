"""Offline ONNX KB indexer for Trợ lý VeriShield (builds raw L2-norm E_raw + metadata JSON)."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
from tokenizers import Tokenizer

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_DIR = REPO_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.services.ioc_extractor import LABELED_ACCOUNT_SPAN_RE, is_labeled_account_match  # noqa: E402
from app.services.scam_classifier import ScamClassifier  # noqa: E402

SCHEMA_VERSION = "1.0.0"
MAX_CHUNK_TOKENS = 180
MAX_OVERALL_UNK_RATIO = 0.02
MAX_MODELS_DIR_MB = 50.0

_FORBIDDEN_HOTLINE_RE = re.compile(
    r"(?<!\d)(?:1800|1900)[\s.\-]?\d{4,6}(?!\d)|(?<!\d)(?:\+?84|0)[35789][\s.\-]?\d{3}[\s.\-]?\d{2,3}[\s.\-]?\d{2,3}(?!\d)"
)
_BRAND_SLUG_RE = re.compile(r"[^a-z0-9]+")

_PLAYBOOK_SCAM_LABELS: dict[str, list[str]] = {
    "scam_napas_sms_points": ["SCAM_PHISHING_APK_OTP", "SCAM_IMPERSONATION"],
    "scam_police_vneid_apk": ["SCAM_IMPERSONATION", "SCAM_PHISHING_APK_OTP"],
    "scam_vietqr_receive_refund": ["SCAM_PHISHING_APK_OTP", "merchant"],
    "scam_merchant_fake_bill": ["merchant"],
    "scam_qr_sticker_swap": ["merchant"],
    "scam_biometric_qd2345_support": ["SCAM_IMPERSONATION", "SCAM_PHISHING_APK_OTP"],
    "scam_deepvoice_urgent_borrow": ["SCAM_URGENT_BORROW"],
    "scam_task_ctv_commission": ["SCAM_TASK_INVEST_LOAN"],
    "scam_fake_shipper_membership": ["SCAM_IMPERSONATION", "SCAM_PHISHING_APK_OTP"],
    "scam_upfront_loan_fee": ["SCAM_TASK_INVEST_LOAN"],
    "scam_crypto_vip_investment": ["SCAM_TASK_INVEST_LOAN"],
    "scam_sim_lock_telecom": ["SCAM_IMPERSONATION"],
    "scam_evn_tax_apk": ["SCAM_IMPERSONATION", "SCAM_PHISHING_APK_OTP"],
    "scam_credit_card_upgrade_cashout": ["SCAM_PHISHING_APK_OTP"],
    "scam_sms_brandname_bts_spoof": ["SCAM_PHISHING_APK_OTP"],
    "scam_hotel_resort_fanpage_clone": ["SCAM_IMPERSONATION"],
    "scam_fake_recovery_lawyer": ["SCAM_IMPERSONATION"],
    "scam_romance_customs_parcel": ["SCAM_IMPERSONATION"],
    "scam_charity_mule_impersonation": ["SCAM_IMPERSONATION"],
    "scam_child_competition_vote_link": ["SCAM_PHISHING_APK_OTP", "SCAM_URGENT_BORROW"],
}


def _slugify(text: str) -> str:
    folded = text.lower().replace("đ", "d")
    decomposed = unicodedata.normalize("NFD", folded)
    ascii_only = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    return _BRAND_SLUG_RE.sub("_", ascii_only).strip("_")


def _compute_model_fingerprint(model_dir: Path) -> str:
    hasher = hashlib.sha256()
    for fname in ("scam_e5_int8.onnx", "tokenizer.json"):
        fpath = model_dir / fname
        if fpath.exists():
            hasher.update(fname.encode("utf-8"))
            hasher.update(fpath.read_bytes())
    return hasher.hexdigest()[:16]


def _load_curated_json_chunks(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    source = str(payload.get("source", path.stem))
    out: list[dict[str, Any]] = []
    for item in payload.get("chunks", []):
        out.append(
            {
                "chunk_id": str(item["chunk_id"]),
                "source": source,
                "category": str(item["category"]),
                "title": str(item["title"]).strip(),
                "content": str(item["content"]).strip(),
                "tags": [str(t).strip() for t in item.get("tags", []) if str(t).strip()],
                "scam_types": [str(s).strip() for s in item.get("scam_types", []) if str(s).strip()],
                "official_domains": [
                    str(d).strip() for d in item.get("official_domains", []) if str(d).strip()
                ],
                "verified_channels": [
                    str(v).strip() for v in item.get("verified_channels", []) if str(v).strip()
                ],
            }
        )
    return out


def _build_vn_scam_kb_chunks(vn_kb_path: Path) -> list[dict[str, Any]]:
    data = json.loads(vn_kb_path.read_text(encoding="utf-8"))
    chunks: list[dict[str, Any]] = []

    # 1. Playbooks -> 2 atomic chunks each (signals/red-flags & counter-replies/urgent-steps)
    for pb in data.get("playbooks", []):
        pb_id = str(pb["id"])
        name_vi = str(pb["name_vi"]).strip()
        modes = [str(m) for m in pb.get("modes", [])]
        keywords = [str(k).strip() for k in pb.get("keywords", []) if str(k).strip()]
        tactics = [str(x).strip() for x in pb.get("psychological_tactics", []) if str(x).strip()]
        red_flags = [str(x).strip() for x in pb.get("red_flags", []) if str(x).strip()]
        counters = [str(x).strip() for x in pb.get("counter_replies", []) if str(x).strip()]
        steps = [str(x).strip() for x in pb.get("urgent_steps", []) if str(x).strip()]

        scam_types = list(dict.fromkeys([*_PLAYBOOK_SCAM_LABELS.get(pb_id, []), pb_id, *modes]))

        sig_parts = []
        if tactics:
            sig_parts.append("Tâm lý thao túng: " + "; ".join(tactics) + ".")
        if red_flags:
            sig_parts.append("Dấu hiệu nhận diện: " + "; ".join(red_flags) + ".")
        chunks.append(
            {
                "chunk_id": f"pb_{pb_id}_signals",
                "source": "vn_scam_kb",
                "category": "scam_pattern",
                "title": f"Dấu hiệu thủ đoạn: {name_vi}",
                "content": " ".join(sig_parts),
                "tags": [*keywords, "dấu hiệu lừa đảo", "thủ đoạn"],
                "scam_types": scam_types,
                "official_domains": [],
                "verified_channels": [],
            }
        )

        act_parts = []
        if counters:
            act_parts.append("Câu phản biện gợi ý: " + " ".join(counters))
        if steps:
            act_parts.append("Bước xử lý ngay: " + " ".join(steps))
        chunks.append(
            {
                "chunk_id": f"pb_{pb_id}_action",
                "source": "vn_scam_kb",
                "category": "scam_pattern",
                "title": f"Cách xử lý & phản biện: {name_vi}",
                "content": " ".join(act_parts),
                "tags": [*keywords, "cách xử lý", "phản biện"],
                "scam_types": scam_types,
                "official_domains": [],
                "verified_channels": [],
            }
        )

    # 2. Official brands -> 17 official domain reference chunks
    for brand_entry in data.get("official_brands", []):
        brand = str(brand_entry["brand"]).strip()
        domains = [str(d).strip() for d in brand_entry.get("official_domains", []) if str(d).strip()]
        keywords = [str(k).strip() for k in brand_entry.get("keywords", []) if str(k).strip()]
        slug = _slugify(brand)
        domain_str = ", ".join(domains)
        is_gov = any(d.endswith(".gov.vn") for d in domains)
        channel_note = (
            "Không tải ứng dụng tệp .apk ngoài Google Play / App Store và không làm việc qua Zalo cá nhân."
            if is_gov
            else (
                "Không bấm link đăng nhập trong SMS lạ; luôn tự mở ứng dụng chính thức "
                "hoặc xem tổng đài in mặt sau thẻ."
            )
        )
        chunks.append(
            {
                "chunk_id": f"brand_{slug}",
                "source": "vn_scam_kb",
                "category": "official_channel",
                "title": f"Tên miền và kênh chính thức của {brand}",
                "content": (
                    f"Tên miền chính thức của {brand} là {domain_str}. "
                    f"Cảnh giác trang giả mạo {brand} dùng đuôi tên miền lạ (.top, .vip, .xyz, .site). "
                    f"{channel_note}"
                ),
                "tags": [brand, *keywords, *domains, "tên miền chính thức", "kênh chính thức"],
                "scam_types": ["SCAM_IMPERSONATION", "SCAM_PHISHING_APK_OTP"],
                "official_domains": domains,
                "verified_channels": domains,
            }
        )

    # 3. NAPAS BINs -> 18 chunks formatted STRICTLY as "BIN 970436 (Vietcombank)"
    napas_bins: dict[str, str] = {str(k): str(v) for k, v in data.get("napas_bins", {}).items()}
    for bin_code, bank_name in napas_bins.items():
        chunks.append(
            {
                "chunk_id": f"napas_bin_{bin_code}",
                "source": "vn_scam_kb",
                "category": "official_channel",
                "title": f"Mã BIN NAPAS: BIN {bin_code} ({bank_name})",
                "content": (
                    f"Mã định danh ngân hàng chuyển nhanh NAPAS 247: BIN {bin_code} ({bank_name}). "
                    f"Khi quét mã VietQR có mã BIN {bin_code}, ngân hàng thụ hưởng là {bank_name}. "
                    "Luôn đối chiếu đúng tên người nhận và số tiền trên ứng dụng "
                    "trước khi xác nhận chuyển."
                ),
                "tags": [f"BIN {bin_code}", bin_code, bank_name, "napas", "vietqr", "mã bin"],
                "scam_types": ["merchant", "scam_vietqr_receive_refund", "scam_qr_sticker_swap"],
                "official_domains": ["napas.com.vn"],
                "verified_channels": ["napas.com.vn"],
            }
        )

    # 4. Six concise taxonomy & BIN directory overview chunks for broad Vietnamese queries
    sample_bins = ", ".join(f"BIN {code} ({name})" for code, name in list(napas_bins.items())[:6])
    overview_chunks: list[dict[str, Any]] = [
        {
            "chunk_id": "tax_impersonation_overview",
            "source": "vn_scam_kb",
            "category": "scam_pattern",
            "title": "Tổng quan nhóm lừa đảo mạo danh cơ quan nhà nước, ngân hàng và tổ chức",
            "content": (
                "Kẻ gian mạo danh Công an, Viện Kiểm sát, Cục Thuế, EVN, Cục Viễn thông, "
                "nhân viên ngân hàng, shipper hoặc fanpage resort tích xanh để hù dọa pháp lý, "
                "khóa SIM, cắt điện hoặc dụ cập nhật VNeID/sinh trắc học. Nguyên tắc chung: "
                "không chuyển tiền chứng minh trong sạch, không cài tệp .apk, "
                "luôn tự xác minh qua kênh chính thức."
            ),
            "tags": [
                "lừa đảo mạo danh", "giả công an", "giả ngân hàng",
                "giả cơ quan nhà nước", "các hình thức lừa đảo",
            ],
            "scam_types": ["SCAM_IMPERSONATION"],
            "official_domains": ["bocongan.gov.vn", "vneid.gov.vn", "gdt.gov.vn"],
            "verified_channels": ["Công an xã/phường gần nhất", "canhbao.khonggianmang.vn"],
        },
        {
            "chunk_id": "tax_phishing_apk_otp_overview",
            "source": "vn_scam_kb",
            "category": "scam_pattern",
            "title": "Tổng quan nhóm lừa đảo đường link giả, tệp .apk độc hại và đánh cắp OTP",
            "content": (
                "Thủ đoạn gồm SMS Brandname trạm BTS giả báo đăng nhập lạ, đổi điểm NAPAS, "
                "quét VietQR nhận tiền hoàn, link bình chọn cho bé chiếm Zalo, và dụ cài tệp "
                ".apk giả VNeID/Thuế/EVN xin quyền Trợ năng. Tuyệt đối không bấm link trong SMS, "
                "không cài tệp .apk ngoài kho ứng dụng và không chia sẻ OTP/CVV."
            ),
            "tags": [
                "phishing", "đường link lừa đảo", "file apk",
                "đánh cắp otp", "sms brandname", "vietqr giả",
            ],
            "scam_types": ["SCAM_PHISHING_APK_OTP"],
            "official_domains": ["canhbao.khonggianmang.vn"],
            "verified_channels": ["Ứng dụng ngân hàng chính thức", "canhbao.khonggianmang.vn"],
        },
        {
            "chunk_id": "tax_task_invest_loan_overview",
            "source": "vn_scam_kb",
            "category": "scam_pattern",
            "title": "Tổng quan nhóm lừa đảo việc làm CTV, sàn đầu tư lãi cao và vay tiền online",
            "content": (
                "Gồm tuyển cộng tác viên chốt đơn Shopee/TikTok hưởng hoa hồng, sàn chứng khoán/"
                "tiền số cam kết lợi nhuận, và vay tín chấp giải ngân nhanh nhưng đòi đóng phí "
                "bảo hiểm hay tiền sửa sai số tài khoản. Dấu hiệu cốt lõi: mồi lãi nhỏ ban đầu "
                "rồi ép nạp thêm tiền ngày càng lớn để rút gốc - hãy dừng nạp ngay."
            ),
            "tags": [
                "việc nhẹ lương cao", "cộng tác viên", "đầu tư tài chính",
                "vay tiền online", "lừa đảo đầu tư",
            ],
            "scam_types": ["SCAM_TASK_INVEST_LOAN"],
            "official_domains": ["canhbao.khonggianmang.vn"],
            "verified_channels": ["Công an xã/phường gần nhất"],
        },
        {
            "chunk_id": "tax_urgent_borrow_overview",
            "source": "vn_scam_kb",
            "category": "scam_pattern",
            "title": "Tổng quan nhóm lừa đảo chiếm tài khoản và Deepfake người thân mượn tiền gấp",
            "content": (
                "Kẻ gian chiếm Zalo/Facebook hoặc dùng video Deepfake ngắn mờ giật giả người thân "
                "bị cấp cứu, tai nạn, nhờ chuyển tiền gấp vào số tài khoản mang tên người lạ. "
                "Cách phòng tránh duy nhất là gọi lại trực tiếp bằng cuộc gọi di động truyền thống "
                "và kiểm chứng câu hỏi riêng trước khi chuyển tiền."
            ),
            "tags": ["mượn tiền gấp", "giả người thân", "deepfake", "hack zalo", "vay tiền cấp cứu"],
            "scam_types": ["SCAM_URGENT_BORROW"],
            "official_domains": [],
            "verified_channels": ["Gọi điện thoại di động trực tiếp cho người thân"],
        },
        {
            "chunk_id": "tax_merchant_fraud_overview",
            "source": "vn_scam_kb",
            "category": "scam_pattern",
            "title": "Tổng quan nhóm gian lận nhắm vào chủ cửa hàng: Biên lai giả và tráo mã QR",
            "content": (
                "Chủ shop thường gặp hai thủ đoạn chính: khách đưa ảnh biên lai chuyển khoản "
                "chỉnh sửa hoặc ảnh cũ rồi hối giao hàng vì 'nghẽn mạng liên ngân hàng', và kẻ "
                "gian lén dán đè mã QR giả lên bảng thanh toán tại quầy. Luôn kiểm tra số dư "
                "thực tế trên ứng dụng ngân hàng hoặc loa Soundbox và quét kiểm tra bảng QR mỗi ngày."
            ),
            "tags": [
                "lừa đảo chủ cửa hàng", "biên lai giả", "bill chuyển khoản giả",
                "dán đè qr", "merchant", "soundbox",
            ],
            "scam_types": ["merchant", "scam_merchant_fake_bill", "scam_qr_sticker_swap"],
            "official_domains": [],
            "verified_channels": ["Ứng dụng ngân hàng của cửa hàng", "Loa thông báo Soundbox"],
        },
        {
            "chunk_id": "tax_napas_bin_directory",
            "source": "vn_scam_kb",
            "category": "official_channel",
            "title": "Danh mục tham chiếu nhanh một số mã BIN NAPAS ngân hàng Việt Nam",
            "content": (
                f"Mã BIN NAPAS gồm 6 chữ số đầu nhận diện ngân hàng trong chuẩn VietQR, "
                f"ví dụ: {sample_bins}. Khi kiểm tra mã QR thanh toán, hãy đối chiếu mã BIN "
                "với tên ngân hàng hiển thị trên ứng dụng chuyển tiền và xác nhận đúng tên "
                "chủ tài khoản thụ hưởng."
            ),
            "tags": ["danh sách mã bin", "bin napas", "mã ngân hàng vietqr", "tra cứu bin", "napas"],
            "scam_types": ["merchant", "scam_vietqr_receive_refund", "scam_qr_sticker_swap"],
            "official_domains": ["napas.com.vn"],
            "verified_channels": ["napas.com.vn"],
        },
    ]
    chunks.extend(overview_chunks)
    return chunks


def _validate_chunk_hygiene(chunk: dict[str, Any]) -> None:
    fields: list[tuple[str, str]] = [
        ("title+content", f"{chunk['title']}. {chunk['content']}"),
        ("tags", " | ".join(str(x) for x in chunk.get("tags", []))),
        ("official_domains", " | ".join(str(x) for x in chunk.get("official_domains", []))),
        ("verified_channels", " | ".join(str(x) for x in chunk.get("verified_channels", []))),
    ]
    for field_name, text in fields:
        if not text:
            continue
        if "momo" in text.lower():
            raise ValueError(
                f"Chunk {chunk['chunk_id']} ({field_name}) violates brand invariant (contains 'MoMo')."
            )
        if _FORBIDDEN_HOTLINE_RE.search(text):
            raise ValueError(
                f"Chunk {chunk['chunk_id']} ({field_name}) contains unverified hotline/phone: {text!r}"
            )
        for match in LABELED_ACCOUNT_SPAN_RE.finditer(text):
            if is_labeled_account_match(text, match):
                raise ValueError(
                    f"Chunk {chunk['chunk_id']} ({field_name}) triggers LABELED_ACCOUNT_SPAN_RE "
                    f"on {match.group(0)!r} (BINs must use 'BIN 970436 (BankName)' format)."
                )


def build_index() -> None:
    data_dir = BACKEND_DIR / "app" / "data"
    model_dir = data_dir / "models"
    kb_dir = data_dir / "kb"

    all_chunks: list[dict[str, Any]] = []
    all_chunks.extend(_load_curated_json_chunks(kb_dir / "incident_response_sops.json"))
    all_chunks.extend(_load_curated_json_chunks(kb_dir / "verification_guides.json"))
    all_chunks.extend(_build_vn_scam_kb_chunks(data_dir / "vn_scam_kb.json"))

    seen_ids: set[str] = set()
    for ch in all_chunks:
        cid = ch["chunk_id"]
        if cid in seen_ids:
            raise ValueError(f"Duplicate chunk_id detected: {cid}")
        seen_ids.add(cid)
        _validate_chunk_hygiene(ch)

    clf = ScamClassifier(str(model_dir), intra_threads=2)
    if not clf.is_available:
        raise RuntimeError(f"ScamClassifier ONNX model unavailable in {model_dir}")

    # Load untruncated tokenizer solely to measure exact passage token length & <unk> rate
    raw_tok = Tokenizer.from_file(str(model_dir / "tokenizer.json"))
    raw_tok.no_truncation()
    unk_id = raw_tok.token_to_id("<unk>")

    vectors: list[np.ndarray] = []
    total_tokens = 0
    total_unks = 0
    max_token_len = 0

    for ch in all_chunks:
        passage_body = f"{ch['title']}. {ch['content']}"
        cleaned_passage = unicodedata.normalize("NFC", passage_body).strip()
        enc = raw_tok.encode(f"passage: {cleaned_passage}")
        tok_len = len(enc.ids)
        unk_count = sum(1 for tid in enc.ids if unk_id is not None and tid == unk_id)
        unk_ratio = unk_count / max(tok_len, 1)

        if tok_len > MAX_CHUNK_TOKENS:
            raise ValueError(
                f"Chunk {ch['chunk_id']} exceeds {MAX_CHUNK_TOKENS} tokens (got {tok_len}). "
                "Shorten chunk text so E5 MAX_MODEL_SEQ_LEN=192 never truncates."
            )

        ch["token_len"] = tok_len
        ch["unk_ratio"] = round(unk_ratio, 6)
        total_tokens += tok_len
        total_unks += unk_count
        max_token_len = max(max_token_len, tok_len)

        vec = clf.encode_text(cleaned_passage, prefix="passage")
        if vec is None or vec.shape != (384,):
            raise RuntimeError(f"Failed to encode chunk {ch['chunk_id']}")
        vectors.append(vec)

    overall_unk_ratio = total_unks / max(total_tokens, 1)
    if overall_unk_ratio >= MAX_OVERALL_UNK_RATIO:
        raise ValueError(
            f"Overall <unk> ratio {overall_unk_ratio:.4%} exceeds {MAX_OVERALL_UNK_RATIO:.2%}"
        )

    e_raw = np.vstack(vectors).astype(np.float32)
    if e_raw.shape != (len(all_chunks), 384):
        raise AssertionError(f"Unexpected E_raw shape: {e_raw.shape}")
    if not np.all(np.isfinite(e_raw)):
        raise AssertionError("E_raw contains NaN or Inf values!")

    # Defensive unit L2 normalization on raw matrix (NEVER store centered vectors on disk)
    norms = np.linalg.norm(e_raw, axis=1, keepdims=True)
    e_raw = (e_raw / np.maximum(norms, np.float32(1e-8))).astype(np.float32)
    final_norms = np.linalg.norm(e_raw, axis=1)
    if not np.allclose(final_norms, 1.0, atol=1e-5):
        raise AssertionError(
            f"E_raw norms deviate from 1.0: min={final_norms.min()}, max={final_norms.max()}"
        )

    emb_out = model_dir / "assistant_kb_embeddings.npy"
    idx_out = model_dir / "assistant_kb_index.json"

    np.save(str(emb_out), e_raw)
    index_payload = {
        "schema_version": SCHEMA_VERSION,
        "model_fingerprint": _compute_model_fingerprint(model_dir),
        "embedding_dim": int(e_raw.shape[1]),
        "chunk_count": len(all_chunks),
        "max_token_len": max_token_len,
        "overall_unk_ratio": round(overall_unk_ratio, 6),
        "chunks": all_chunks,
    }
    idx_out.write_text(json.dumps(index_payload, ensure_ascii=False, indent=2), encoding="utf-8")

    # Enforce hard Git artifact size budget (< 50 MB)
    total_models_bytes = sum(p.stat().st_size for p in model_dir.rglob("*") if p.is_file())
    total_models_mb = total_models_bytes / (1024 * 1024)
    if total_models_mb >= MAX_MODELS_DIR_MB:
        raise AssertionError(f"models/ dir size {total_models_mb:.2f} MB exceeds {MAX_MODELS_DIR_MB} MB!")

    by_source = Counter(ch["source"] for ch in all_chunks)
    by_category = Counter(ch["category"] for ch in all_chunks)
    mean_tok = total_tokens / max(len(all_chunks), 1)

    print("=== VeriShield Assistant KB Index Built Successfully ===")
    print(f"Total chunks        : {len(all_chunks)}")
    print(f"By source           : {dict(by_source)}")
    print(f"By category         : {dict(by_category)}")
    print(f"Token lengths       : mean={mean_tok:.1f}, max={max_token_len} (limit <= {MAX_CHUNK_TOKENS})")
    print(f"Overall <unk> ratio : {overall_unk_ratio:.4%} (limit < {MAX_OVERALL_UNK_RATIO:.2%})")
    print(
        f"E_raw shape & dtype : {e_raw.shape}, {e_raw.dtype}, "
        f"norm=[{final_norms.min():.6f}, {final_norms.max():.6f}]"
    )
    print(f"Embeddings artifact : {emb_out.name} ({emb_out.stat().st_size / 1024:.1f} KiB)")
    print(f"Index JSON artifact : {idx_out.name} ({idx_out.stat().st_size / 1024:.1f} KiB)")
    print(f"Total models/ size  : {total_models_mb:.2f} MB (limit < {MAX_MODELS_DIR_MB:.0f} MB)")


if __name__ == "__main__":
    build_index()
