"""Unit tests for the 3-tier pre-emission output safety gate (assistant_guardrails.py)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.schemas.analysis import ActionBundle, AnalysisReport, PreTransferIntervention
from app.schemas.common import AnalyzeMode, ReceiptVerificationStatus, score_to_verdict
from app.schemas.forensics import ImageForensicsResult, ReceiptLogicResult
from app.services.assistant_guardrails import (
    MAX_TIER2_SENTENCE_CHARS,
    MERCHANT_BALANCE_WARNING_VI,
    ThinkStreamFilter,
    Tier2SentenceGate,
    build_degraded_rag_reply,
    build_tier0_deterministic_reply,
    classify_output_tier,
    validate_full_reply,
)
from app.services.assistant_rag import RetrievedChunk


def _make_report(
    *,
    mode: AnalyzeMode = "personal",
    risk_score: int = 75,
    receipt_status: ReceiptVerificationStatus = "NOT_APPLICABLE",
    is_receipt_candidate: bool = False,
    receipt_reasons: list[str] | None = None,
    tamper_reasons: list[str] | None = None,
    prompt_injection_detected: bool = False,
    summary_vi: str = "Phát hiện nhiều dấu hiệu nghi vấn lừa đảo.",
) -> AnalysisReport:
    verdict = score_to_verdict(risk_score)
    receipt_logic: ReceiptLogicResult | None = None
    image_forensics: ImageForensicsResult | None = None
    merchant_warning: str | None = None
    if mode == "merchant" or is_receipt_candidate or receipt_status != "NOT_APPLICABLE":
        if receipt_status == "NOT_APPLICABLE":
            receipt_status = "UNVERIFIED_SCREENSHOT"
        receipt_logic = ReceiptLogicResult(
            is_receipt_candidate=True,
            bank_detected="Vietcombank",
            verification_status=receipt_status,
            is_replayed=(receipt_status == "REPLAYED_RECEIPT"),
            beneficiary_mismatch=(receipt_status == "BENEFICIARY_MISMATCH"),
            logic_risk_points=0 if receipt_status == "UNVERIFIED_SCREENSHOT" else 60,
            reasons=receipt_reasons or [],
        )
        image_forensics = ImageForensicsResult(
            filename="receipt.png",
            format="PNG",
            width=800,
            height=1200,
            dhash_hex="0" * 16,
            tamper_score=0 if receipt_status == "UNVERIFIED_SCREENSHOT" else 55,
            reasons=tamper_reasons or [],
        )
        merchant_warning = MERCHANT_BALANCE_WARNING_VI

    return AnalysisReport(
        case_id="vs_0123456789abcdef0123456789abcdef",
        created_at="2026-11-27T05:00:00Z",
        mode=mode,
        risk_score=risk_score,
        verdict=verdict,
        confidence=0.88,
        prompt_injection_detected=prompt_injection_detected,
        receipt_verification_status=receipt_status,
        summary_vi=summary_vi,
        receipt_logic=receipt_logic,
        image_forensics=image_forensics,
        actions=ActionBundle(
            urgent_steps=[
                "Kiểm tra trực tiếp số dư trên ứng dụng ngân hàng chính thức.",
                "Lưu giữ toàn bộ bằng chứng liên quan để trình báo khi cần.",
            ],
            merchant_balance_warning=merchant_warning,
            pre_transfer=PreTransferIntervention(should_hold_transfer=risk_score >= 55),
        ),
    )


def _make_chunk(
    *,
    chunk_id: str = "ver_merchant_balance_and_soundbox",
    title: str = "Cách chủ cửa hàng xác minh tiền đã về",
    content: str = (
        "Ảnh chụp màn hình biên lai không phải bằng chứng tiền đã vào tài khoản. "
        "Chỉ giao hàng sau khi kiểm tra biến động số dư trên ứng dụng ngân hàng hoặc loa Soundbox."
    ),
) -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id=chunk_id,
        source="verification_guides",
        category="verification",
        title=title,
        content=content,
        score=0.95,
    )


class TestThinkStreamFilter:
    def test_strips_split_multi_char_think_tags(self) -> None:
        filt = ThinkStreamFilter()
        out = [
            filt.feed("<th"),
            filt.feed("ink>secret reasoning</th"),
            filt.feed("ink>visible"),
            filt.flush(),
        ]
        assert "".join(out) == "visible"

    def test_strips_one_char_at_a_time_and_case_insensitive(self) -> None:
        raw = "Xin chào <ThInK>nội dung nháp 1</THINK>bạn<think>nháp 2</think> nhé!"
        filt = ThinkStreamFilter()
        emitted = "".join(filt.feed(ch) for ch in raw) + filt.flush()
        assert emitted == "Xin chào bạn nhé!"

    def test_suppresses_unclosed_think_at_eof(self) -> None:
        filt = ThinkStreamFilter()
        emitted = filt.feed("Phần đầu. <think>suy nghĩ chưa đóng") + filt.flush()
        assert emitted == "Phần đầu. "
        assert "suy nghĩ" not in emitted

    def test_preserves_normal_angle_brackets_across_chunks(self) -> None:
        filt = ThinkStreamFilter()
        out = "".join([filt.feed("Giá trị <"), filt.feed(" 5 và <th"), filt.flush()])
        assert out == "Giá trị < 5 và <th"

    def test_handles_attributes_whitespace_nested_think_and_non_think_tags(self) -> None:
        cases = [
            ("<think >hidden</think >visible", "visible"),
            ('<think type="r">hidden</think>visible', "visible"),
            ("A<think>outer <think>inner</think> still hidden</think>B", "AB"),
            ("a < b <test> ok", "a < b <test> ok"),
        ]
        for raw, expected in cases:
            filt = ThinkStreamFilter()
            assert "".join(filt.feed(ch) for ch in raw) + filt.flush() == expected
        # Multi-chunk split inside attribute and closing whitespace
        f2 = ThinkStreamFilter()
        assert "".join([
            f2.feed("A<th"), f2.feed('ink type="r">inner <think>x</th'),
            f2.feed("ink> hidden</th"), f2.feed("ink >B"), f2.flush(),
        ]) == "AB"
        # Unclosed nested think suppresses remaining content at EOF
        f3 = ThinkStreamFilter()
        assert f3.feed("Safe <think>outer <think>inner</think> leak") + f3.flush() == "Safe "


class TestClassifyOutputTier:
    def test_tier0_for_merchant_receipt_settlement_accented_and_unaccented(self) -> None:
        merchant_safe = _make_report(
            mode="merchant",
            risk_score=10,
            receipt_status="UNVERIFIED_SCREENSHOT",
        )
        receipt_personal = _make_report(
            mode="personal",
            risk_score=78,
            receipt_status="TAMPER_OR_LOGIC_ANOMALY",
            is_receipt_candidate=True,
        )
        tier0_queries = [
            "Tiền về chưa?",
            "Tiền đã về tài khoản chưa?",
            "tien ve tai khoan chua",
            "Khách đã chuyển tiền chưa?",
            "Giao hàng được chưa?",
            "Biên lai này thật không?",
            "tien vao tai khoan chua",
            "chac chan an toan chua",
            "Tôi có nên giao hàng ngay dựa trên ảnh biên lai này không?",
        ]
        for query in tier0_queries:
            assert classify_output_tier(
                message=query, report=merchant_safe, turn_injection_detected=False
            ) == 0, f"Expected Tier 0 for merchant query: {query!r}"
            assert classify_output_tier(
                message=query, report=receipt_personal, turn_injection_detected=False
            ) == 0, f"Expected Tier 0 for receipt query: {query!r}"

    def test_tier1_for_merchant_general_injection_safe_and_sensitive_queries(self) -> None:
        merchant_report = _make_report(
            mode="merchant", risk_score=15, receipt_status="UNVERIFIED_SCREENSHOT"
        )
        safe_personal = _make_report(mode="personal", risk_score=12)
        risky_personal = _make_report(mode="personal", risk_score=84)
        injected_report = _make_report(
            mode="personal", risk_score=80, prompt_injection_detected=True
        )

        # Merchant report with non-binary explanation question -> Tier 1
        assert (
            classify_output_tier(
                message="Giải thích chi tiết các chỉ số ELA và EXIF trong báo cáo này.",
                report=merchant_report,
                turn_injection_detected=False,
            )
            == 1
        )
        # Prompt injection in current turn -> Tier 1
        assert (
            classify_output_tier(
                message="Thủ đoạn giả danh công an có dấu hiệu gì?",
                report=risky_personal,
                turn_injection_detected=True,
            )
            == 1
        )
        # SAFE report or report with OCR prompt injection -> Tier 1
        assert (
            classify_output_tier(
                message="Giải thích kết quả phân tích này giúp tôi.",
                report=safe_personal,
                turn_injection_detected=False,
            )
            == 1
        )
        assert (
            classify_output_tier(
                message="Giải thích kết quả phân tích này giúp tôi.",
                report=injected_report,
                turn_injection_detected=False,
            )
            == 1
        )
        # Sensitive safety / transfer / OTP / APK / incident response queries -> Tier 1
        sensitive_queries = [
            "Tôi chuyển tiền được không?",
            "Tiền đã vào tài khoản chưa?",
            "Cho khách lấy hàng được chưa?",
            "Tôi có thể chuyển tiền cho người này không?",
            "Có nên chuyển 5 triệu cho họ không?",
            "Link này có an toàn để đăng nhập không?",
            "Trang web này có an toàn không?",
            "Tôi lỡ chuyển tiền cho kẻ lừa đảo rồi phải làm sao?",
            "Tôi lỡ lộ OTP cho người lạ rồi!",
            "Có nên cài apk VNeID từ link Zalo không?",
            "Khách giục giao hàng thì tôi cần làm gì?",
        ]
        for query in sensitive_queries:
            assert classify_output_tier(
                message=query, report=None, turn_injection_detected=False
            ) == 1, f"Expected Tier 1 for sensitive query: {query!r}"

    def test_tier2_for_general_education_and_non_receipt_risk_explanation(self) -> None:
        risky_personal = _make_report(mode="personal", risk_score=86)
        tier2_cases: list[tuple[str, AnalysisReport | None]] = [
            ("Thủ đoạn giả danh công an thường có những dấu hiệu nào?", None),
            ("Cách kiểm tra tên miền ngân hàng chính thức như thế nào?", None),
            ("Giải thích các dấu hiệu rủi ro của đường dẫn trong hồ sơ này.", risky_personal),
            ("Hướng dẫn cách nhận biết mã VietQR theo chuẩn NAPAS.", risky_personal),
        ]
        for query, rep in tier2_cases:
            assert classify_output_tier(
                message=query, report=rep, turn_injection_detected=False
            ) == 2, f"Expected Tier 2 for query: {query!r}"


class TestDeterministicBuilders:
    def test_tier0_deterministic_reply_covers_status_reasons_and_passes_gate(self) -> None:
        report = _make_report(
            mode="merchant",
            risk_score=88,
            receipt_status="REPLAYED_RECEIPT",
            receipt_reasons=["Mã tham chiếu giao dịch trùng với biên lai đã gửi trước đó."],
            tamper_reasons=["Phát hiện vùng nén ELA bất thường quanh khu vực số tiền."],
        )
        chunks = [_make_chunk()]
        reply, notice = build_tier0_deterministic_reply(report, chunks)
        assert notice == {
            "code": "MERCHANT_BALANCE_REQUIRED",
            "message": MERCHANT_BALANCE_WARNING_VI,
        }
        assert "REPLAYED_RECEIPT" in reply
        assert "88/100" in reply
        assert "CRITICAL_SCAM" in reply
        assert "ELA" in reply or "trùng" in reply
        assert "momo" not in reply.lower()
        ok, codes, _ = validate_full_reply(
            draft_text=reply,
            report=report,
            rag_chunks=chunks,
            require_balance_check=True,
            require_epistemic_limit=True,
        )
        assert ok is True, f"Tier 0 reply failed validation: {codes}"
        assert codes == []

    def test_degraded_rag_reply_appends_merchant_warning_and_passes_gate(self) -> None:
        merchant_safe = _make_report(
            mode="merchant", risk_score=10, receipt_status="UNVERIFIED_SCREENSHOT"
        )
        chunks = [_make_chunk()]
        reply = build_degraded_rag_reply(
            merchant_safe, chunks, message="Kiểm tra biên lai giúp tôi"
        )
        assert MERCHANT_BALANCE_WARNING_VI in reply
        assert "momo" not in reply.lower()
        ok, codes, _ = validate_full_reply(
            draft_text=reply,
            report=merchant_safe,
            rag_chunks=chunks,
            require_balance_check=True,
            require_epistemic_limit=True,
        )
        assert ok is True, f"Degraded merchant reply failed validation: {codes}"

    def test_degraded_rag_reply_non_merchant_risky_without_chunks_passes_epistemic_limit(self) -> None:
        risky = _make_report(
            mode="personal",
            risk_score=82,
            summary_vi="Phát hiện dấu hiệu giả mạo cơ quan chức năng.",
        )
        risky.actions.urgent_steps = ["Dừng ngay thao tác chuyển tiền."]
        reply = build_degraded_rag_reply(risky, [], message="Giải thích hồ sơ")
        ok, codes, _ = validate_full_reply(
            draft_text=reply,
            report=risky,
            rag_chunks=[],
            require_balance_check=False,
            require_epistemic_limit=True,
        )
        assert ok is True, f"Degraded risky reply without chunks failed: {codes}"


class TestValidateFullReply:
    def test_blocks_accented_unaccented_and_obfuscated_settlement_claims(self) -> None:
        merchant_report = _make_report(
            mode="merchant", risk_score=12, receipt_status="UNVERIFIED_SCREENSHOT"
        )
        unsafe_drafts = [
            "Tiền đã vào tài khoản, bạn yên tâm giao hàng.",
            "tien da vao tai khoan roi, ban cu giao hang di.",
            "ban cu yen tam giao hang di, so du on dinh roi.",
            "Biên lai này hoàn toàn thật, giao hàng ngay đi.",
            "Tiền\u200b đã vào tài khoản rồi, kiểm tra số dư trên ứng dụng ngân hàng cũng thấy.",
            "Ảnh chụp không phải bằng chứng tiền đã vào tài khoản, bạn yên tâm giao hàng đi.",
            "Tôi đã kiểm tra và thấy tiền đã vào tài khoản.",
            "Tôi đã xác minh tiền đã vào tài khoản.",
            "Bạn có thể giao hàng sau khi kiểm tra biên lai.",
        ]
        for draft in unsafe_drafts:
            ok, codes, safe_text = validate_full_reply(
                draft_text=draft,
                report=merchant_report,
                rag_chunks=[_make_chunk()],
                require_balance_check=True,
                require_epistemic_limit=True,
            )
            assert ok is False, f"Expected failure for: {draft!r}"
            assert "RECEIPT_SETTLEMENT_CLAIM" in codes
            assert MERCHANT_BALANCE_WARNING_VI in safe_text

    def test_blocks_absolute_safety_and_unsafe_action_advice(self) -> None:
        ok1, codes1, _ = validate_full_reply(
            draft_text="Giao dịch này chắc chắn an toàn 100%.",
            report=None,
            rag_chunks=[],
            require_balance_check=False,
            require_epistemic_limit=True,
        )
        assert ok1 is False
        assert "ABSOLUTE_SAFETY_CLAIM" in codes1

        ok2, codes2, _ = validate_full_reply(
            draft_text="chac chan an toan 100%, ban cu chuyen tien ngay di.",
            report=None,
            rag_chunks=[],
            require_balance_check=False,
            require_epistemic_limit=False,
        )
        assert ok2 is False
        assert "ABSOLUTE_SAFETY_CLAIM" in codes2
        assert "UNSAFE_ACTION_ADVICE" in codes2

        ok3, codes3, _ = validate_full_reply(
            draft_text="Bạn có thể cung cấp mã OTP cho nhân viên để mở khóa tài khoản.",
            report=None,
            rag_chunks=[],
            require_balance_check=False,
            require_epistemic_limit=False,
        )
        assert ok3 is False
        assert "UNSAFE_ACTION_ADVICE" in codes3

    def test_no_false_positive_on_conditional_handover_and_negated_warnings(self) -> None:
        merchant_report = _make_report(
            mode="merchant", risk_score=10, receipt_status="UNVERIFIED_SCREENSHOT"
        )
        safe_drafts = [
            "Bạn chỉ có thể giao hàng sau khi kiểm tra số dư thực tế trên ứng dụng ngân hàng.",
            "Chỉ sau khi kiểm tra số dư thực tế trên ứng dụng ngân hàng, bạn mới có thể giao hàng.",
            "Bạn hãy kiểm tra xem tiền đã vào tài khoản chưa trên ứng dụng ngân hàng của mình.",
            (
                "Không thể khẳng định chắc chắn an toàn chỉ từ ảnh chụp. "
                "Bạn bắt buộc phải kiểm tra biến động số dư trên ứng dụng ngân hàng hoặc loa Soundbox."
            ),
            (
                "Ảnh chụp biên lai không phải bằng chứng tiền đã vào tài khoản. "
                "Tuyệt đối không cung cấp mã OTP cho bất kỳ ai và chỉ giao hàng sau khi "
                "đối chiếu số dư trên ứng dụng ngân hàng."
            ),
        ]
        for draft in safe_drafts:
            ok, codes, out = validate_full_reply(
                draft_text=draft,
                report=merchant_report,
                rag_chunks=[_make_chunk()],
                require_balance_check=True,
                require_epistemic_limit=True,
            )
            assert ok is True, f"False positive {codes} on safe draft: {draft!r}"
            assert codes == []
            assert out == draft

    def test_enforces_positive_balance_check_and_epistemic_limit(self) -> None:
        merchant_report = _make_report(
            mode="merchant", risk_score=15, receipt_status="UNVERIFIED_SCREENSHOT"
        )
        ok_bal, codes_bal, fallback_bal = validate_full_reply(
            draft_text="Biên lai này chưa có dấu hiệu chỉnh sửa rõ ràng, bạn nên cẩn thận.",
            report=merchant_report,
            rag_chunks=[_make_chunk()],
            require_balance_check=True,
            require_epistemic_limit=False,
        )
        assert ok_bal is False
        assert "MISSING_BALANCE_CHECK" in codes_bal
        assert MERCHANT_BALANCE_WARNING_VI in fallback_bal

        ok_epi, codes_epi, _ = validate_full_reply(
            draft_text="Bạn có thể tiếp tục trao đổi với người bán bình thường.",
            report=None,
            rag_chunks=[_make_chunk()],
            require_balance_check=False,
            require_epistemic_limit=True,
        )
        assert ok_epi is False
        assert "MISSING_EPISTEMIC_LIMIT" in codes_epi

    def test_t8_blocks_ungrounded_hotlines_and_allows_grounded_and_non_hotlines(self) -> None:
        kb_chunk = _make_chunk(
            chunk_id="sop_kb_grounded",
            title="Kênh hỗ trợ có căn cứ",
            content="Liên hệ tổng đài 1800 1090 hoặc gọi 113 trong tình huống khẩn cấp.",
        )
        ungrounded_samples = [
            "Hãy gọi tổng đài 1900 999 999 để kiểm tra ngay.",
            "Liên hệ hotline 1900.888.777 để được hỗ trợ hoàn tiền.",
            "Gọi số 1800-5555 để khóa thẻ khẩn cấp.",
            "Gọi 0912.345.678 hoặc +84 912 345 678 để xác minh.",
            "Liên hệ đường dây nóng 024 3824 3524.",
        ]
        for draft in ungrounded_samples:
            ok, codes, _ = validate_full_reply(
                draft_text=draft,
                report=None,
                rag_chunks=[kb_chunk],
                require_balance_check=False,
                require_epistemic_limit=False,
            )
            assert ok is False, f"Expected UNGROUNDED_HOTLINE for: {draft!r}"
            assert "UNGROUNDED_HOTLINE" in codes

        allowed_draft = (
            "Số tiền nghi vấn 15.000.000 đ gửi tới BIN 970436 (tài khoản 09****78) ngày 02.11.2026 "
            "lúc 15:30 cần được báo Công an hoặc gọi 113. Bạn cũng có thể nhắn TTTB gửi 1414 "
            "hoặc liên hệ kênh đã xác thực 1800-1090."
        )
        ok_good, codes_good, _ = validate_full_reply(
            draft_text=allowed_draft,
            report=None,
            rag_chunks=[kb_chunk],
            require_balance_check=False,
            require_epistemic_limit=False,
        )
        assert ok_good is True, f"False positive {codes_good} on allowed numbers"

    def test_empty_draft_fails_closed(self) -> None:
        ok, codes, fallback = validate_full_reply(
            draft_text="   \n  ",
            report=None,
            rag_chunks=[_make_chunk()],
            require_balance_check=False,
            require_epistemic_limit=False,
        )
        assert ok is False
        assert "EMPTY_REPLY" in codes
        assert len(fallback) > 20


class TestTier2SentenceGate:
    def test_does_not_split_numbers_lists_apk_or_domains(self) -> None:
        gate = Tier2SentenceGate(report=None, rag_chunks=[_make_chunk()])
        text = (
            "1. Bước một: kiểm tra khoản 15.000.000 đ và không tải tệp .apk, "
            "chỉ tra cứu tại vneid.gov.vn hoặc vietcombank.com.vn. "
            "2. Bước hai: liên hệ chi nhánh chính thức."
        )
        emitted = gate.feed(text)
        assert len(emitted) == 1
        assert "15.000.000 đ" in emitted[0]
        assert "1. Bước một" in emitted[0]
        assert ".apk" in emitted[0]
        assert "vneid.gov.vn" in emitted[0]
        assert "vietcombank.com.vn" in emitted[0]
        assert gate.promoted_to_tier1 is False

        passed, codes, remainder, notice = gate.finalize()
        assert passed is True
        assert codes == []
        assert notice is None
        assert remainder == "2. Bước hai: liên hệ chi nhánh chính thức."
        assert "".join(emitted) + remainder == text

    def test_does_not_split_domain_across_chunk_boundary(self) -> None:
        gate = Tier2SentenceGate(report=None, rag_chunks=[_make_chunk()])
        assert gate.feed("Chỉ tra cứu tại vneid.") == []
        assert gate.feed("gov.vn để bảo đảm chính xác. ") == [
            "Chỉ tra cứu tại vneid.gov.vn để bảo đảm chính xác. "
        ]
        passed, codes, remainder, notice = gate.finalize()
        assert passed is True
        assert codes == []
        assert remainder == ""
        assert notice is None

    def test_long_incomplete_sentence_promotes_to_tier1_without_flushing(self) -> None:
        gate = Tier2SentenceGate(report=None, rag_chunks=[_make_chunk()])
        long_sentence = (
            "Kẻ gian thường tạo tâm lý hoang mang kéo dài bằng nhiều cuộc gọi liên tiếp "
            "giả danh cơ quan chức năng yêu cầu nạn nhân tự cô lập khỏi gia đình và "
            "tuyệt đối không tiết lộ thông tin cho bất kỳ ai xung quanh trong suốt nhiều giờ liền"
        )
        assert len(long_sentence) > MAX_TIER2_SENTENCE_CHARS
        assert len(long_sentence) >= 210

        emitted = gate.feed(long_sentence)
        assert emitted == []
        assert gate.promoted_to_tier1 is True
        assert gate.buffered_remainder == long_sentence

        passed, codes, remainder, notice = gate.finalize()
        assert passed is True
        assert codes == []
        assert remainder == long_sentence
        assert notice is None

    def test_promoted_buffer_catches_cross_sentence_unsafe_claim_at_finalize(self) -> None:
        gate = Tier2SentenceGate(report=None, rag_chunks=[_make_chunk()])
        first_emitted = gate.feed("Thủ đoạn lừa đảo trực tuyến ngày càng tinh vi hơn. ")
        assert len(first_emitted) == 1
        assert gate.promoted_to_tier1 is False

        long_unsafe_tail = (
            "Tuy nhiên với trường hợp bạn vừa mô tả thì chúng tôi đã xem qua toàn bộ thông tin "
            "cơ bản trên tin nhắn và nhận thấy mọi chi tiết đều khớp với quy trình chuẩn nên "
            "giao dịch này chắc chắn an toàn 100%"
        )
        assert len(long_unsafe_tail) > MAX_TIER2_SENTENCE_CHARS
        assert gate.feed(long_unsafe_tail) == []
        assert gate.promoted_to_tier1 is True

        passed, codes, fallback, notice = gate.finalize()
        assert passed is False
        assert "ABSOLUTE_SAFETY_CLAIM" in codes
        assert notice is not None
        assert notice["code"] == "FAIL_CLOSED_FALLBACK"
        assert "chắc chắn an toàn 100%" not in fallback

    def test_midstream_unsafe_sentence_blocked_before_emission(self) -> None:
        gate = Tier2SentenceGate(report=None, rag_chunks=[_make_chunk()])
        emitted = gate.feed("Hãy gọi ngay số 1900 999 999 để lấy lại tiền. ")
        assert emitted == []
        assert gate.blocked is True
        assert gate.promoted_to_tier1 is True
        assert "UNGROUNDED_HOTLINE" in gate.violation_codes

        # Subsequent chunks must also not emit raw LLM text
        assert gate.feed("Nội dung phía sau. ") == []
        passed, codes, fallback, notice = gate.finalize()
        assert passed is False
        assert "UNGROUNDED_HOTLINE" in codes
        assert notice is not None
        assert "1900 999 999" not in fallback


def test_constants_and_type_exports() -> None:
    assert MAX_TIER2_SENTENCE_CHARS == 160
    assert "Soundbox" in MERCHANT_BALANCE_WARNING_VI
    assert "momo" not in MERCHANT_BALANCE_WARNING_VI.lower()
    # Smoke check mypy-safe typing of dict notice returned by Tier 0
    reply, notice = build_tier0_deterministic_reply(None, [])
    assert isinstance(reply, str) and len(reply) > 20
    notice_check: dict[str, Any] = notice
    assert notice_check["code"] == "MERCHANT_BALANCE_REQUIRED"


class TestRedTeamHardeningRegressions:
    def test_c1_blocks_negation_bleeding_and_digit_period_clause_merge(self) -> None:
        merchant_report = _make_report(
            mode="merchant", risk_score=10, receipt_status="UNVERIFIED_SCREENSHOT"
        )
        bypasses = [
            (
                "Chưa phát hiện dấu hiệu giả mạo trên ảnh biên lai nên bạn có thể giao hàng ngay "
                "và nhớ kiểm tra số dư trên ứng dụng ngân hàng sau.",
                "RECEIPT_SETTLEMENT_CLAIM",
            ),
            (
                "Không có dấu hiệu chỉnh sửa nên tiền đã vào tài khoản rồi.",
                "RECEIPT_SETTLEMENT_CLAIM",
            ),
            (
                "Giao dịch này không có dấu hiệu lừa đảo nên chắc chắn an toàn 100%.",
                "ABSOLUTE_SAFETY_CLAIM",
            ),
            (
                "Bạn không cần lo lắng đâu cứ chuyển tiền ngay đi.",
                "UNSAFE_ACTION_ADVICE",
            ),
            (
                "Đừng lo lắng hãy gửi mã OTP cho nhân viên nhé.",
                "UNSAFE_ACTION_ADVICE",
            ),
            (
                "Ảnh chụp không phải bằng chứng cho khoản 15.000.000. Tiền đã vào tài khoản rồi.",
                "RECEIPT_SETTLEMENT_CLAIM",
            ),
            (
                "Hệ thống xác minh tiền đã vào tài khoản rồi.",
                "RECEIPT_SETTLEMENT_CLAIM",
            ),
            (
                "Tôi vừa kiểm tra tiền đã vào tài khoản rồi.",
                "RECEIPT_SETTLEMENT_CLAIM",
            ),
        ]
        for draft, expected_code in bypasses:
            ok, codes, _ = validate_full_reply(
                draft_text=draft,
                report=merchant_report,
                rag_chunks=[_make_chunk()],
                require_balance_check=False,
                require_epistemic_limit=False,
            )
            assert ok is False, f"C1 bypass leaked: {draft!r}"
            assert expected_code in codes, f"Expected {expected_code}, got {codes} for {draft!r}"

    def test_c2_blocks_obfuscated_markdown_paren_colon_slash_hotlines(self) -> None:
        obfuscated = [
            "Gọi **1900 999 999** ngay để xác minh.",
            "Liên hệ *1800 1234* hoặc _1900 888 777_.",
            "Hotline:1900999999 hỗ trợ 24/7.",
            "SĐT:0912345678 của nhân viên hỗ trợ.",
            "Gọi 1900999999/18008888 khi cần.",
            "Số cố định (024) 3824 3524.",
            "Chi nhánh Đà Nẵng (0236) 382 1234 và Cần Thơ (0292) 382 1234.",
            "Liên hệ (+84) 912 345 678 hoặc +84 (0) 912 345 678.",
            "Đường dây nóng 1900 - 999 - 999.",
        ]
        for draft in obfuscated:
            ok, codes, _ = validate_full_reply(
                draft_text=draft,
                report=None,
                rag_chunks=[],
                require_balance_check=False,
                require_epistemic_limit=False,
            )
            assert ok is False, f"C2 hotline bypass leaked: {draft!r}"
            assert "UNGROUNDED_HOTLINE" in codes, f"Got {codes} for {draft!r}"

    def test_c3_blocks_markdown_paren_smuggling_bare_imperatives_and_paraphrases(self) -> None:
        cases = [
            ("Tiền **đã vào** tài khoản rồi.", "RECEIPT_SETTLEMENT_CLAIM"),
            ("Tiền đã (vào) tài khoản rồi.", "RECEIPT_SETTLEMENT_CLAIM"),
            ("Bạn hãy **gửi mã OTP** cho nhân viên.", "UNSAFE_ACTION_ADVICE"),
            ("Gui ma OTP cho ho di.", "UNSAFE_ACTION_ADVICE"),
            ("Nhập mã OTP vào đường link đó đi.", "UNSAFE_ACTION_ADVICE"),
            ("Tải file .apk về cài đặt ngay.", "UNSAFE_ACTION_ADVICE"),
            ("Bạn cứ yên tâm chuyển tiền cho người đó nhé.", "UNSAFE_ACTION_ADVICE"),
            ("Bạn có thể chuyển khoản cho bên đó.", "UNSAFE_ACTION_ADVICE"),
            ("Tiền về tài khoản rồi.", "RECEIPT_SETTLEMENT_CLAIM"),
            ("Tiền vào tài khoản rồi.", "RECEIPT_SETTLEMENT_CLAIM"),
            ("Biên lai chuyển khoản này là thật 100%.", "RECEIPT_SETTLEMENT_CLAIM"),
            ("Ảnh chụp này là thật 100%.", "RECEIPT_SETTLEMENT_CLAIM"),
            ("Khách đã chuyển tiền thành công cho bạn rồi.", "RECEIPT_SETTLEMENT_CLAIM"),
            ("Giao hàng cho khách ngay.", "RECEIPT_SETTLEMENT_CLAIM"),
            ("Giao hàng cho khách đi.", "RECEIPT_SETTLEMENT_CLAIM"),
        ]
        for draft, expected_code in cases:
            ok, codes, _ = validate_full_reply(
                draft_text=draft,
                report=None,
                rag_chunks=[],
                require_balance_check=False,
                require_epistemic_limit=False,
            )
            assert ok is False, f"C3 bypass leaked: {draft!r}"
            assert expected_code in codes, f"Expected {expected_code}, got {codes} for {draft!r}"

    def test_r2_allows_incident_response_and_scam_education_while_blocking_unsafe_imperatives(
        self,
    ) -> None:
        legit_incident_and_edu = [
            (
                "Nếu bạn đã lỡ gửi mã OTP cho người lạ, hãy gọi tổng đài in mặt sau thẻ để khóa "
                "tài khoản ngay."
            ),
            (
                "Nếu bạn đã lỡ tải file .apk từ đường link lạ, hãy bật chế độ máy bay và gỡ ứng "
                "dụng ngay."
            ),
            "Kẻ gian thường dụ nạn nhân gửi mã OTP cho chúng để chiếm đoạt tài khoản.",
            (
                "Khi nạn nhân cài đặt file .apk từ tin nhắn giả mạo, mã độc có thể đọc trộm tin "
                "nhắn OTP."
            ),
        ]
        for draft in legit_incident_and_edu:
            ok, codes, _ = validate_full_reply(
                draft_text=draft,
                report=None,
                rag_chunks=[],
                require_balance_check=False,
                require_epistemic_limit=False,
            )
            assert ok is True, f"Round-2 false positive {codes} on legitimate reply: {draft!r}"

        still_unsafe = [
            "Nếu bạn muốn xác minh thì bạn cần gửi mã OTP cho họ.",
            "Khi nhân viên yêu cầu, bạn hãy gửi mã OTP cho họ.",
            "Bạn hãy **gửi mã OTP** cho họ.",
        ]
        for draft in still_unsafe:
            ok, codes, _ = validate_full_reply(
                draft_text=draft,
                report=None,
                rag_chunks=[],
                require_balance_check=False,
                require_epistemic_limit=False,
            )
            assert ok is False and "UNSAFE_ACTION_ADVICE" in codes, f"Leaked: {draft!r}"

    def test_i1_legitimate_merchant_replies_and_all_121_kb_chunks_pass_zero_fp(self) -> None:
        merchant_report = _make_report(
            mode="merchant", risk_score=10, receipt_status="UNVERIFIED_SCREENSHOT"
        )
        legit_merchant_replies = [
            (
                "Ảnh chụp biên lai không xác nhận được tiền đã vào tài khoản. "
                "Bạn cần kiểm tra số dư thực tế trên ứng dụng ngân hàng."
            ),
            (
                "Bạn không nên kiểm tra giao dịch qua đường link lạ khách gửi; hãy mở trực tiếp "
                "ứng dụng ngân hàng để kiểm tra số dư thực tế."
            ),
            "Sau khi kiểm tra số dư thực tế trên ứng dụng ngân hàng, bạn có thể giao hàng.",
            (
                "Ảnh chụp màn hình biên lai KHÔNG BAO GIỜ là bằng chứng tiền đã vào tài khoản. "
                "Chủ cửa hàng chỉ xác nhận đã nhận tiền và giao hàng sau khi tự mở ứng dụng ngân "
                "hàng kiểm tra lịch sử biến động số dư thực tế (đúng số tiền, đúng mã giao dịch) "
                "hoặc nghe loa Soundbox liên kết báo tiền về."
            ),
        ]
        for draft in legit_merchant_replies:
            ok, codes, _ = validate_full_reply(
                draft_text=draft,
                report=merchant_report,
                rag_chunks=[_make_chunk()],
                require_balance_check=True,
                require_epistemic_limit=True,
            )
            assert ok is True, f"I1 false positive {codes} on legitimate reply: {draft!r}"

        kb_path = (
            Path(__file__).resolve().parents[2]
            / "app"
            / "data"
            / "models"
            / "assistant_kb_index.json"
        )
        raw_chunks = json.loads(kb_path.read_text(encoding="utf-8"))["chunks"]
        assert len(raw_chunks) == 121
        for item in raw_chunks:
            chunk = RetrievedChunk(
                chunk_id=item["chunk_id"],
                source=item["source"],
                category=item["category"],
                title=item["title"],
                content=item["content"],
                score=1.0,
            )
            ok, codes, _ = validate_full_reply(
                draft_text=f"{chunk.title}. {chunk.content}",
                report=None,
                rag_chunks=[chunk],
                require_balance_check=False,
                require_epistemic_limit=False,
            )
            assert ok is True, f"KB chunk {chunk.chunk_id} false-positived with {codes}"

    def test_i3_tier2_gate_escalates_to_tier1_on_receipt_balance_handover_keywords(self) -> None:
        for kw_sentence in [
            "Khách vừa gửi ảnh biên lai cho cửa hàng. ",
            "Bạn nên mở app xem số dư thực tế. ",
            "Không nên vội giao hàng khi chưa đối chiếu. ",
            "Khách nói đã chuyển khoản xong. ",
            "Hãy theo dõi thông báo tiền về trên loa. ",
            "Kiểm tra xem tiền vào hay chưa. ",
        ]:
            gate = Tier2SentenceGate(report=None, rag_chunks=[_make_chunk()])
            emitted = gate.feed(kw_sentence)
            assert emitted == [], f"Expected 0 mid-stream chunks for {kw_sentence!r}"
            assert gate.promoted_to_tier1 is True
            assert gate.buffered_remainder == kw_sentence

