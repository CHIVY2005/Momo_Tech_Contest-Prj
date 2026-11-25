"""Shared pytest fixtures across unit and integration test suites."""

import pytest

from app.schemas import (
    ActionBundle,
    AnalysisReport,
    EvidenceItem,
    ExtractedIOCs,
    PreTransferIntervention,
    TraceStep,
)


@pytest.fixture
def sample_report() -> AnalysisReport:
    """Reusable synthetic scam report fixture for repository and PDF tests."""
    return AnalysisReport(
        case_id="case_fixture_001",
        created_at="2026-11-26T08:00:00Z",
        mode="personal",
        in_active_call=True,
        risk_score=88,
        verdict="CRITICAL_SCAM",
        confidence=0.95,
        degraded_mode=False,
        safety_advisory_detected=False,
        prompt_injection_detected=False,
        active_block_rule_hit=False,
        receipt_verification_status="NOT_APPLICABLE",
        summary_vi="Phát hiện kịch bản giả danh cán bộ Công an thúc ép chuyển tiền xác minh VNeID.",
        transcript="Yêu cầu anh giữ bí mật cuộc gọi và chuyển ngay 15 triệu đồng để xác minh.",
        classifier=None,
        matched_playbooks=["Giả danh Công an / Viện Kiểm sát / VNeID"],
        manipulation_tactics=["Gây hoảng loạn pháp lý", "Cô lập nạn nhân trong cuộc gọi"],
        highlighted_phrases=["giữ bí mật cuộc gọi", "chuyển ngay 15 triệu"],
        iocs=ExtractedIOCs(
            phones=["0912345678"],
            bank_accounts=["190384756201"],
            urls=["https://vneid-capnhat.vip/login"],
            domains=["vneid-capnhat.vip"],
            brands=["VNeID", "Techcombank"],
        ),
        vietqr_findings=[],
        url_findings=[],
        sandbox=None,
        image_forensics=None,
        receipt_logic=None,
        evidence=[
            EvidenceItem(
                source="url_inspector",
                severity="CRITICAL",
                title="Tên miền mạo danh VNeID",
                detail="Tên miền vneid-capnhat.vip không thuộc cổng dịch vụ công chính thức (.gov.vn).",
                snippet="https://vneid-capnhat.vip/login",
            )
        ],
        actions=ActionBundle(
            counter_replies=[
                "Cơ quan Công an không làm việc và yêu cầu chuyển tiền qua điện thoại/Zalo."
            ],
            family_shield_message=(
                "Cảnh báo gia đình: Tuyệt đối không chuyển tiền xác minh VNeID qua cuộc gọi lạ."
            ),
            urgent_steps=["Cúp máy ngay lập tức.", "Không cài đặt tệp .apk ngoài kho ứng dụng."],
            merchant_balance_warning=None,
            pre_transfer=PreTransferIntervention(
                should_hold_transfer=True,
                cooling_off_seconds=30,
                triggered_by_active_call=True,
                blocked_by_ops_rule=False,
                warning_headline="TẠM KHÓA 30 GIÂY — PHÁT HIỆN DẤU HIỆU THAO TÚNG TRONG CUỘC GỌI",
                verification_questions=[
                    "Người ở đầu dây có yêu cầu bạn giữ bí mật không?",
                    "Họ có tự xưng Công an, Ngân hàng hoặc NAPAS yêu cầu chuyển tiền không?",
                ],
            ),
        ),
        trace=[
            TraceStep(
                step_id="guardrails",
                title="Kiểm tra Guardrails & Prompt Injection",
                status="done",
                detail="Hoàn tất sàng lọc văn bản.",
                duration_ms=3,
            )
        ],
        community_hits=3,
    )
