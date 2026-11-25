from pathlib import Path

import numpy as np

from app.services.knowledge_base import KnowledgeBaseRetriever


def test_kb_retriever_matches_napas_police_and_diacritic_free_queries() -> None:
    kb_path = Path(__file__).resolve().parents[2] / "app" / "data" / "vn_scam_kb.json"
    kb = KnowledgeBaseRetriever(str(kb_path))

    napas_hits = kb.match_playbooks(
        "Tin nhan tu NAPAS thong bao doi diem thuong the tin dung sap het han",
        mode="personal",
    )
    assert len(napas_hits) >= 1
    assert napas_hits[0]["id"] == "scam_napas_sms_points"

    merchant_hits = kb.match_playbooks(
        "Khách gửi ảnh chuyển khoản thành công giục shipper đang đợi giao hàng gấp",
        mode="merchant",
    )
    assert len(merchant_hits) >= 1
    assert merchant_hits[0]["id"] == "scam_merchant_fake_bill"


def test_kb_retriever_uses_semantic_embeddings_when_available(tmp_path: Path) -> None:
    kb_path = Path(__file__).resolve().parents[2] / "app" / "data" / "vn_scam_kb.json"
    kb_base = KnowledgeBaseRetriever(str(kb_path))
    n_playbooks = len(kb_base.playbooks)

    emb_matrix = np.zeros((n_playbooks, 384), dtype=np.float32)
    target_idx = next(
        i for i, p in enumerate(kb_base.playbooks) if p["id"] == "scam_vietqr_receive_refund"
    )
    emb_matrix[target_idx, 0] = 1.0
    emb_file = tmp_path / "playbook_embeddings.npy"
    np.save(str(emb_file), emb_matrix)

    kb_vec = KnowledgeBaseRetriever(str(kb_path), embeddings_path=str(emb_file))
    query_vec = np.zeros(384, dtype=np.float32)
    query_vec[0] = 1.0
    hits = kb_vec.match_playbooks("mã lạ", mode="personal", query_embedding=query_vec, top_k=2)
    assert hits[0]["id"] == "scam_vietqr_receive_refund"
