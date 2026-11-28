"""Unit tests for context-aware follow-up suggestions & semantic deduplication."""

from __future__ import annotations

from app.schemas import (
    ActionBundle,
    AnalysisReport,
    ImageForensicsResult,
    PreTransferIntervention,
    ReceiptLogicResult,
    UrlFinding,
    VietQRInfo,
)
from app.schemas.assistant import AssistantHistoryTurn
from app.services.assistant_followups import (
    extract_followup_intents,
    generate_followup_suggestions,
    is_duplicate_question,
    normalize_followup_text,
)


def _make_report(
    *,
    case_id: str = "vs_11111111111111111111111111111111",
    mode: str = "personal",
    risk_score: int = 85,
    verdict: str = "CRITICAL_SCAM",
    in_active_call: bool = False,
    with_url: bool = False,
    with_vietqr: bool = False,
    playbooks: list[str] | None = None,
) -> AnalysisReport:
    is_merchant = mode == "merchant"
    return AnalysisReport(
        case_id=case_id,
        created_at="2026-11-28T08:00:00Z",
        mode="merchant" if is_merchant else "personal",
        in_active_call=in_active_call,
        risk_score=risk_score,
        verdict=verdict,  # type: ignore[arg-type]
        confidence=0.9,
        receipt_verification_status="UNVERIFIED_SCREENSHOT" if is_merchant else "NOT_APPLICABLE",
        summary_vi="Cảnh báo rủi ro cần kiểm chứng.",
        matched_playbooks=playbooks or [],
        url_findings=(
            [
                UrlFinding(
                    url="https://fake-vcb.top/login",
                    domain="fake-vcb.top",
                    normalized_ascii_domain="fake-vcb.top",
                    spoofed_brand="Vietcombank",
                    risk_points=75,
                )
            ]
            if with_url
            else []
        ),
        vietqr_findings=(
            [
                VietQRInfo(
                    raw="000201",
                    kind="VALID_VIETQR",
                    crc_valid=True,
                    bank_bin="970436",
                    bank_name="Vietcombank",
                    receive_scam_detected=True,
                )
            ]
            if with_vietqr
            else []
        ),
        image_forensics=(
            ImageForensicsResult(
                filename="bill.png",
                format="PNG",
                width=600,
                height=900,
                dhash_hex="0123456789abcdef",
                tamper_score=45,
            )
            if is_merchant
            else None
        ),
        receipt_logic=(
            ReceiptLogicResult(
                is_receipt_candidate=True,
                bank_detected="Vietcombank",
                verification_status="UNVERIFIED_SCREENSHOT",
            )
            if is_merchant
            else None
        ),
        actions=ActionBundle(
            urgent_steps=["Dừng chuyển tiền và tự kiểm chứng qua ứng dụng ngân hàng."],
            merchant_balance_warning=(
                "Ảnh chụp biên lai không phải bằng chứng tiền đã vào tài khoản. "
                "Kiểm tra số dư thực tế trên ứng dụng ngân hàng hoặc loa Soundbox trước khi giao hàng."
                if is_merchant
                else None
            ),
            pre_transfer=PreTransferIntervention(should_hold_transfer=risk_score >= 55),
        ),
    )


def test_normalize_followup_text_strips_diacritics_punctuation_and_filler_prefixes() -> None:
    a = normalize_followup_text("Xin hỏi: Tôi lỡ chuyển tiền rồi, cần làm gì ngay?!")
    b = normalize_followup_text("  toi lo chuyen tien roi can lam gi ngay  ")
    assert a == b
    assert "xin hoi" not in a


def test_exact_and_semantic_duplicate_detection_catches_vietnamese_paraphrases() -> None:
    # Exact (modulo case/diacritics/punctuation)
    assert is_duplicate_question(
        "Tôi lỡ chuyển tiền rồi thì cần làm gì ngay trong 60 phút đầu?",
        ["toi lo chuyen tien roi thi can lam gi ngay trong 60 phut dau"],
    )

    # Semantic paraphrases (different wording, same intent)
    paraphrase_pairs = [
        (
            "Tôi lỡ chuyển tiền rồi thì cần làm gì ngay trong 60 phút đầu?",
            "Mình vừa chuyển khoản nhầm cho kẻ gian mất rồi, bây giờ xử lý sao?",
        ),
        (
            "Tôi lỡ cung cấp mã OTP hoặc mật khẩu ngân hàng thì xử lý sao?",
            "Em lỡ đọc mã xác thực SmartOTP cho người lạ rồi phải khóa tài khoản thế nào?",
        ),
        (
            "Tôi có nên giao hàng ngay dựa trên ảnh biên lai này không?",
            "Khách gửi ảnh bill chuyển khoản, mình đưa hàng luôn được chưa?",
        ),
        (
            "Cách đối chiếu tiền đã thực sự vào tài khoản và loa Soundbox?",
            "Làm sao kiểm tra chắc chắn tiền đã về số dư ngân hàng chưa?",
        ),
        (
            "Cần thu thập và lưu những bằng chứng nào để trình báo Công an?",
            "Tôi nên giữ lại giấy tờ hay chụp màn hình chứng cứ gì trước khi đi báo?",
        ),
        (
            "Làm sao phân biệt tên miền ngân hàng thật và trang giả mạo?",
            "Cách nhận biết đường link trang web ngân hàng lừa đảo là gì?",
        ),
    ]
    for candidate, asked in paraphrase_pairs:
        assert is_duplicate_question(candidate, [asked]), (
            f"Expected semantic duplicate for candidate={candidate!r} vs asked={asked!r}"
        )

    # Distinct questions MUST NOT be falsely marked as duplicate
    assert not is_duplicate_question(
        "Cần thu thập và lưu những bằng chứng nào để trình báo Công an?",
        ["Tôi vừa lỡ chuyển tiền cho kẻ gian rồi, cần làm gì ngay?"],
    )
    assert not is_duplicate_question(
        "Cách kiểm tra mã VietQR và số tài khoản nhận trước khi chuyển tiền?",
        ["Làm sao tránh bẫy dịch vụ lấy lại tiền bị lừa trên mạng?"],
    )


def test_generate_followups_excludes_current_and_prior_questions_over_8_turn_conversation() -> None:
    report = _make_report(
        mode="personal",
        risk_score=88,
        verdict="CRITICAL_SCAM",
        with_url=True,
        playbooks=["scam_police_vneid_apk"],
    )
    history: list[AssistantHistoryTurn] = []
    seen_normalized: set[str] = set()
    seen_intents: set[str] = set()

    current_msg = "Hãy giải thích các dấu hiệu rủi ro quan trọng nhất trong hồ sơ này."
    for turn in range(1, 9):
        followups = generate_followup_suggestions(
            report=report,
            current_message=current_msg,
            history=history,
            reply_text="Đã hướng dẫn cụ thể cho câu hỏi hiện tại.",
        )
        assert len(followups) <= 3
        # No suggestion may duplicate any prior or current question (exact or semantic)
        all_asked = [t.content for t in history if t.role == "user"] + [current_msg]
        for suggestion in followups:
            norm_s = normalize_followup_text(suggestion)
            assert norm_s not in seen_normalized, f"Turn {turn} repeated suggestion: {suggestion!r}"
            assert not is_duplicate_question(suggestion, all_asked), (
                f"Turn {turn} suggested duplicate of asked history: {suggestion!r}"
            )
            # Also no overlap with already-picked intents
            cand_intents = extract_followup_intents(suggestion)
            assert not (cand_intents & seen_intents), (
                f"Turn {turn} repeated intent {cand_intents & seen_intents}: {suggestion!r}"
            )

        if not followups:
            # Exhausted cleanly -> empty list is expected when no relevant follow-ups remain
            break

        # Advance conversation by selecting the first follow-up
        seen_normalized.add(normalize_followup_text(current_msg))
        seen_intents.update(extract_followup_intents(current_msg))
        history.append(AssistantHistoryTurn(role="user", content=current_msg))
        history.append(
            AssistantHistoryTurn(role="assistant", content=f"Trả lời ngắn gọn lượt {turn}.")
        )
        current_msg = followups[0]

    assert len(history) >= 10, "Should sustain at least 5+ distinct follow-up turns before exhaustion"


def test_generate_followups_returns_empty_list_when_all_relevant_topics_exhausted() -> None:
    report = _make_report(mode="merchant", risk_score=15, verdict="SAFE")
    history: list[AssistantHistoryTurn] = []
    current_msg = "Tôi có nên giao hàng ngay dựa trên ảnh biên lai này không?"

    final_followups: list[str] = ["placeholder"]
    for turn in range(1, 12):
        final_followups = generate_followup_suggestions(
            report=report,
            current_message=current_msg,
            history=history,
            reply_text="Đã hướng dẫn.",
        )
        if not final_followups:
            break
        history.append(AssistantHistoryTurn(role="user", content=current_msg))
        history.append(AssistantHistoryTurn(role="assistant", content=f"Phản hồi lượt {turn}."))
        current_msg = final_followups[0]

    assert final_followups == [], "Exhausted merchant conversation must return [] instead of repeating"


def test_generate_followups_adapts_to_different_reports_and_isolates_history() -> None:
    merchant_report = _make_report(
        case_id="vs_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        mode="merchant",
        risk_score=18,
        verdict="SAFE",
    )
    high_risk_vietqr = _make_report(
        case_id="vs_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        mode="personal",
        risk_score=90,
        verdict="CRITICAL_SCAM",
        with_vietqr=True,
        in_active_call=True,
    )

    f_merchant = generate_followup_suggestions(
        report=merchant_report,
        current_message="Giải thích hồ sơ này.",
        history=[],
    )
    f_vietqr = generate_followup_suggestions(
        report=high_risk_vietqr,
        current_message="Giải thích hồ sơ này.",
        history=[],
    )
    assert 2 <= len(f_merchant) <= 3
    assert 2 <= len(f_vietqr) <= 3
    assert any(
        "biên lai" in q.lower() or "số dư" in q.lower() or "giao hàng" in q.lower()
        for q in f_merchant
    )
    assert not any("biên lai" in q.lower() for q in f_vietqr)
    assert any(
        "vietqr" in q.lower() or "chuyển tiền" in q.lower() or "điện thoại" in q.lower()
        for q in f_vietqr
    )
