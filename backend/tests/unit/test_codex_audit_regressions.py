from __future__ import annotations

import io
from pathlib import Path

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from PIL import Image
from pydantic import ValidationError

from app.config import Settings
from app.core.security import InvalidMediaError, is_public_ip, validate_upload_bytes
from app.db.repository import CaseRepository
from app.main import create_app
from app.schemas import (
    ActionBundle,
    AnalysisReport,
    EvidenceItem,
    ExtractedIOCs,
    ImageForensicsResult,
    PreTransferIntervention,
    ReceiptLogicResult,
    SandboxInspection,
    VietQRInfo,
)
from app.services.guardrails import evaluate_guardrails
from app.services.ioc_extractor import extract_iocs, mask_ioc
from app.services.llm_client import _call_openai_key, normalize_openai_chat_url
from app.services.receipt_validator import validate_receipt_logic
from app.services.risk_calibrator import calibrate_risk
from app.services.url_inspector import inspect_url
from app.services.vietqr_parser import build_vietqr_test_payload, crc16_ccitt_false, parse_qr_payload


def test_public_case_redacts_raw_vietqr_payloads_ocr_text_and_formatted_pii(
    tmp_path: Path,
) -> None:
    repo = CaseRepository(str(tmp_path / "redact.db"))
    repo.init_db()

    raw_qr = build_vietqr_test_payload("970436", "190384756201", amount="500000", note="CHUYEN KHOAN")
    report = AnalysisReport(
        case_id="vs_redact_full01",
        created_at="2026-11-26T02:00:00+00:00",
        mode="merchant",
        risk_score=88,
        verdict="CRITICAL_SCAM",
        confidence=0.95,
        receipt_verification_status="TAMPER_OR_LOGIC_ANOMALY",
        summary_vi="Phát hiện biên lai chuyển tới 1903 8475 6201 và SĐT 0912.345.678.",
        transcript="Chuyển gấp vào STK 1903-8475-6201 hoặc gọi 0912 345 678",
        iocs=ExtractedIOCs(
            phones=["0912345678"],
            bank_accounts=["190384756201"],
            urls=["https://evil.top/pay?stk=190384756201"],
            domains=["evil.top"],
            brands=["Vietcombank"],
        ),
        vietqr_findings=[
            VietQRInfo(
                raw=raw_qr,
                kind="VALID_VIETQR",
                crc_valid=True,
                bank_bin="970436",
                bank_name="Vietcombank",
                account_number="190384756201",
            )
        ],
        image_forensics=ImageForensicsResult(
            filename="bill.jpg",
            format="JPEG",
            width=400,
            height=600,
            dhash_hex="0011223344556677",
            tamper_score=60,
            qr_payloads=[raw_qr],
            ocr_text="Tài khoản nhận: 190384756201 - Liên hệ 0912.345.678",
        ),
        receipt_logic=ReceiptLogicResult(
            is_receipt_candidate=True,
            verification_status="TAMPER_OR_LOGIC_ANOMALY",
            logic_risk_points=50,
            reasons=["Lệch STK 190384756201"],
        ),
        evidence=[
            EvidenceItem(
                source="receipt_validator",
                severity="HIGH",
                title="Sai STK",
                detail="Biên lai ghi 1903 8475 6201",
                snippet="0912-345-678",
            )
        ],
        actions=ActionBundle(
            counter_replies=["Tôi không chuyển vào 190384756201."],
            family_shield_message="Cảnh giác SĐT 0912.345.678 và STK 190384756201!",
            urgent_steps=["Báo cáo số 0912345678"],
            merchant_balance_warning=(
                "LƯU Ý BẮT BUỘC: Kiểm tra biến động số dư thực tế hoặc Loa thông báo trước khi giao hàng."
            ),
            pre_transfer=PreTransferIntervention(should_hold_transfer=True, cooling_off_seconds=30),
        ),
    )

    repo.save_report(report, receipt_dhash="0011223344556677")
    loaded = repo.get_report("vs_redact_full01")
    assert loaded is not None
    serialized = loaded.model_dump_json()

    for forbidden in (
        "190384756201",
        "1903 8475 6201",
        "1903-8475-6201",
        "0912345678",
        "0912.345.678",
        "0912 345 678",
        "0912-345-678",
    ):
        assert forbidden not in serialized, f"Raw PII {forbidden!r} leaked in persisted case JSON!"


def test_block_rule_hash_ignores_caller_label_scrubs_reason_updates_campaigns_and_keeps_replay_hashes(
    tmp_path: Path,
    sample_report: AnalysisReport,
) -> None:
    repo = CaseRepository(str(tmp_path / "radar_sec.db"))
    repo.init_db()
    seed_file = Path(__file__).resolve().parents[2] / "app" / "data" / "seed_iocs.json"
    repo.seed_if_empty(str(seed_file))

    graph_before = repo.get_radar_graph()
    camp = next(c for c in graph_before.campaigns if c.campaign_id == "camp_vneid_apk_1126")
    initial_count = camp.case_count

    # Caller tries to sneak raw PII in masked_value and reason on hash-based block rule
    rule = repo.add_block_rule(
        ioc_type="phone",  # intentionally wrong type vs seeded campaign
        ioc_hash=camp.primary_ioc_hash,
        masked_value="999888777666",
        reason="Khóa nóng STK 999888777666 liên quan SĐT 0987654321",
    )
    assert rule.masked_value == camp.primary_ioc_masked
    assert rule.ioc_type == camp.primary_ioc_type
    assert "999888777666" not in rule.reason
    assert "0987654321" not in rule.reason

    # Save a qualifying report matching seeded campaign primary IOC (999888777666 in camp_police_vneid_01)
    matching_report = sample_report.model_copy(
        update={
            "case_id": "vs_camp_inc_01",
            "iocs": ExtractedIOCs(
                phones=[],
                bank_accounts=["999888777666"],
                urls=[],
                domains=[],
                brands=[],
            ),
        }
    )
    repo.save_report(matching_report, receipt_dhash="deadbeefcafe1234")
    # Re-saving same case_id must NOT double-increment campaign case_count
    repo.save_report(matching_report, receipt_dhash="deadbeefcafe1234")

    graph_after = repo.get_radar_graph()
    updated_camp = next(c for c in graph_after.campaigns if c.campaign_id == camp.campaign_id)
    assert updated_camp.case_count == initial_count + 1

    # Resetting transient block rules must NOT erase receipt replay history
    assert repo.is_receipt_replayed("deadbeefcafe1234", None, None) is True
    repo.reset_transient_rules()
    assert repo.is_receipt_replayed("deadbeefcafe1234", None, None) is True


def test_mask_ioc_conceals_short_accounts_and_extracts_stk_tam_giu_and_schemeless_links() -> None:
    masked_8 = mask_ioc("bank_account", "12345678")
    assert masked_8 != "1234****5678"
    assert "3456" not in masked_8

    masked_4 = mask_ioc("bank_account", "1234")
    assert masked_4 == "****"

    iocs = extract_iocs(
        "Yêu cầu chuyển tiền vào STK tạm giữ: 999888777666 hoặc truy cập www.napas-vip.top/login"
    )
    assert "999888777666" in iocs.bank_accounts
    assert any("napas-vip.top" in d for d in iocs.domains)

    # Scheme-less non-official domain vetoes safety advisory
    tricked_adv = evaluate_guardrails(
        "[CẢNH BÁO AN TOÀN] Ngân hàng khuyến cáo không cung cấp OTP. Chi tiết: www.napas-vip.top/verify"
    )
    assert tricked_adv.safety_advisory_detected is False
    assert tricked_adv.advisory_vetoed is True

    # Official domain from vn_scam_kb.json (https://techcombank.com) is recognized as official
    official_tcb = evaluate_guardrails(
        "[THÔNG BÁO BẢO MẬT] Techcombank cảnh báo không chia sẻ mã OTP và không cài file .apk lạ. "
        "Xem tại https://techcombank.com"
    )
    assert official_tcb.safety_advisory_detected is True
    assert official_tcb.advisory_vetoed is False


def test_security_blocks_site_local_ipv6_decompression_bomb_and_truncated_jpeg(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert is_public_ip("fec0::1") is False

    buf = io.BytesIO()
    Image.new("RGB", (40, 40), color=(10, 20, 30)).save(buf, format="JPEG")
    jpeg_bytes = buf.getvalue()

    monkeypatch.setattr(Image, "MAX_IMAGE_PIXELS", 100)
    with pytest.raises(InvalidMediaError):
        validate_upload_bytes(jpeg_bytes, max_bytes=1024 * 1024, kind="image")
    monkeypatch.undo()

    # Truncated JPEG (valid SOI/APP0 header, missing scan body/EOI) must fail pixel decode
    truncated_jpeg = jpeg_bytes[: max(24, len(jpeg_bytes) // 3)]
    with pytest.raises(InvalidMediaError):
        validate_upload_bytes(truncated_jpeg, max_bytes=1024 * 1024, kind="image")


@pytest.mark.asyncio
async def test_url_inspector_handles_malformed_redirect_and_redirect_dns_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_validate(
        target: str,
        resolve_dns: bool = True,
        timeout_sec: float = 2.5,
    ) -> tuple[bool, str | None, list[str]]:
        _ = (resolve_dns, timeout_sec)
        if "unresolvable.example" in target:
            return False, "DNS resolution failed: [Errno 11001] getaddrinfo failed", []
        return True, None, ["93.184.216.34"]

    monkeypatch.setattr("app.services.url_inspector.async_validate_url_target", _fake_validate)

    def _redirect_handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "https://short.example/malformed":
            return httpx.Response(302, headers={"Location": "http://[::1/broken"})
        if str(request.url) == "https://short.example/dead-dns":
            return httpx.Response(302, headers={"Location": "https://unresolvable.example/login"})
        return httpx.Response(200, text="ok")

    async with httpx.AsyncClient(transport=httpx.MockTransport(_redirect_handler)) as mock_client:
        malformed_res = await inspect_url(
            "https://short.example/malformed",
            enable_network=True,
            client=mock_client,
        )
        assert malformed_res.is_blocked_ssrf is True

        dns_fail_res = await inspect_url(
            "https://short.example/dead-dns",
            enable_network=True,
            client=mock_client,
        )
        assert dns_fail_res.is_blocked_ssrf is False


def test_vietqr_rejects_duplicate_tags_and_nondigit_account() -> None:
    # Duplicate Tag 54 inside valid CRC frame must be rejected
    dup_body = (
        "000201010212"
        "38540010A00000072701240006970422011077766655540208QRIBFTTA"
        "53037045405100005405999995802VN6304"
    )
    dup_qr = dup_body + crc16_ccitt_false(dup_body.encode("ascii"))
    info_dup, _ = parse_qr_payload(dup_qr)
    assert info_dup.kind != "VALID_VIETQR"

    # Non-digit account for QRIBFTTA must not be labeled VALID_VIETQR
    bad_acct_qr = build_vietqr_test_payload("970422", "ABCDEFGH")
    info_bad_acct, _ = parse_qr_payload(bad_acct_qr)
    assert info_bad_acct.kind != "VALID_VIETQR"


def test_receipt_validator_catches_replay_without_ocr_and_distinguishes_sender_vs_recipient() -> None:
    replay_no_ocr = validate_receipt_logic("", is_replayed_hash=True)
    assert replay_no_ocr.is_receipt_candidate is True
    assert replay_no_ocr.is_replayed is True
    assert replay_no_ocr.verification_status == "REPLAYED_RECEIPT"
    assert replay_no_ocr.logic_risk_points >= 85

    sender_first_text = (
        "CHUYỂN KHOẢN THÀNH CÔNG\n"
        "Ngân hàng Vietcombank\n"
        "STK nguồn: 111122223333\n"
        "Tài khoản thụ hưởng: 190311112222\n"
        "Số tiền: 500.000 VND\n"
        "Mã giao dịch: FT26330123456"
    )
    checked = validate_receipt_logic(sender_first_text, expected_merchant_account="190311112222")
    assert checked.beneficiary_mismatch is False
    assert checked.beneficiary_checked is True


@pytest.mark.asyncio
async def test_llm_client_https_requirement_audio_format_retry_and_prod_pin_guard() -> None:
    with pytest.raises(ValueError):
        normalize_openai_chat_url("http://cpa.joiboi.app/v1")
    assert normalize_openai_chat_url("http://127.0.0.1:8317/v1") == (
        "http://127.0.0.1:8317/v1/chat/completions"
    )

    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="production", analyst_pin="2026")

    seen_bodies: list[str] = []

    def _cpa_handler(request: httpx.Request) -> httpx.Response:
        body_str = request.content.decode("utf-8")
        seen_bodies.append(body_str)
        if '"response_format"' in body_str:
            return httpx.Response(400, json={"error": {"message": "response_format unsupported"}})
        return httpx.Response(
            200,
            json={
                "model": "gemini-4-hydrogen",
                "choices": [
                    {
                        "message": {
                            "content": (
                                '{"ai_risk_score": 82, "summary_vi": "Cuộc gọi giả danh Công an.", '
                                '"transcript": "Chuyển vào STK 999888777666"}'
                            )
                        }
                    }
                ],
            },
        )

    with respx.mock(assert_all_called=True) as router:
        router.post("https://cpa.joiboi.app/v1/chat/completions").mock(side_effect=_cpa_handler)
        parsed, actual_model, attempts, err = await _call_openai_key(
            endpoint="https://cpa.joiboi.app/v1/chat/completions",
            api_key="test_secret",
            model_name="gemini-4-hydrogen",
            prompt="Kiểm tra âm thanh",
            timeout_sec=5.0,
            max_retries=1,
            image_bytes=None,
            image_mime="image/jpeg",
            audio_bytes=b"RIFF\x24\x00\x00\x00WAVEfmt ",
            audio_mime="audio/wav",
        )

    assert err is None
    assert parsed is not None and parsed.ai_risk_score == 82
    assert actual_model == "gemini-4-hydrogen"
    assert attempts == 2
    # Second request dropped response_format BUT preserved input_audio!
    assert '"input_audio"' in seen_bodies[1]


def test_clean_receipt_with_unrelated_block_keeps_unverified_status_and_telegram_malformed_400(
    tmp_path: Path,
) -> None:
    cal = calibrate_risk(
        mode="merchant",
        tier1_score=0,
        classifier=None,
        ai_score=10,
        guardrails=evaluate_guardrails("Khách gửi ảnh biên lai"),
        url_findings=[],
        vietqr_findings=[],
        sandbox=SandboxInspection(available=True, visited_url="https://x.top", risk_points=55),
        image_forensics=ImageForensicsResult(
            filename="clean.png",
            format="PNG",
            width=300,
            height=400,
            dhash_hex="1234567890abcdef",
            tamper_score=0,
        ),
        receipt_logic=ReceiptLogicResult(
            is_receipt_candidate=True,
            verification_status="UNVERIFIED_SCREENSHOT",
            logic_risk_points=0,
        ),
        active_block_rule_hit=True,
        in_active_call=False,
    )
    assert cal.final_score >= 96
    assert cal.receipt_verification_status == "UNVERIFIED_SCREENSHOT"

    # Moderate sandbox score (55) with 0 neural scores must NOT calibrate to SAFE
    cal_mod_sbx = calibrate_risk(
        mode="personal",
        tier1_score=55,
        classifier=None,
        ai_score=0,
        guardrails=evaluate_guardrails("Xem trang này"),
        url_findings=[],
        vietqr_findings=[],
        sandbox=SandboxInspection(available=True, visited_url="https://x.top", risk_points=55),
        image_forensics=None,
        receipt_logic=None,
        active_block_rule_hit=False,
        in_active_call=False,
    )
    assert cal_mod_sbx.verdict != "SAFE"

    cfg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "tg_malformed.db"),
        gemini_api_key="",
        gemini_backup_api_key="",
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
        telegram_webhook_secret="sec_400",
    )
    client = TestClient(create_app(cfg))
    bad_tg = client.post(
        "/api/v1/bot/telegram",
        json={"update_id": 501, "message": "not-an-object"},
        headers={"X-Telegram-Bot-Api-Secret-Token": "sec_400"},
    )
    assert bad_tg.status_code == 400


def test_delta_public_case_projection_legacy_db_migration_and_subdomain_grouped_pii(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "delta_redact.db"
    repo = CaseRepository(str(db_path))
    repo.init_db()

    report = AnalysisReport(
        case_id="vs_delta_proj01",
        created_at="2026-11-26T03:00:00+00:00",
        mode="personal",
        risk_score=85,
        verdict="CRITICAL_SCAM",
        confidence=0.92,
        summary_vi="Cảnh báo lừa đảo.",
        highlighted_phrases=["Chuyển vào 190384756201", "Gọi 0912.345.678"],
        manipulation_tactics=["Thao túng chuyển khoản tới 1903 8475 6201"],
        iocs=ExtractedIOCs(
            phones=["0912345678"],
            bank_accounts=["190384756201"],
            urls=["https://0912345678.evil.top/pay?stk=190384756201"],
            domains=["0912345678.evil.top"],
            brands=[],
        ),
        sandbox=SandboxInspection(
            available=True,
            visited_url="https://0912345678.evil.top/pay?stk=190384756201",
            final_url="https://0912345678.evil.top/otp?phone=0912345678",
            page_title="Xác thực STK 190384756201",
            screenshot_base64="RAW_SCREENSHOT_BASE64_SECRET",
            risk_points=80,
            reasons=["Thu thập OTP cho 0912345678"],
        ),
        image_forensics=ImageForensicsResult(
            filename="shot.jpg",
            format="JPEG",
            width=300,
            height=300,
            dhash_hex="abcdef0123456789",
            ela_heatmap_base64="RAW_ELA_BASE64_SECRET",
        ),
        actions=ActionBundle(
            pre_transfer=PreTransferIntervention(should_hold_transfer=True, cooling_off_seconds=30),
        ),
    )
    repo.save_report(report)
    loaded = repo.get_report("vs_delta_proj01")
    assert loaded is not None
    dumped = loaded.model_dump_json()
    assert "190384756201" not in dumped
    assert "1903 8475 6201" not in dumped
    assert "0912345678" not in dumped
    assert "0912.345.678" not in dumped
    assert "RAW_SCREENSHOT_BASE64_SECRET" not in dumped
    assert "RAW_ELA_BASE64_SECRET" not in dumped

    # Subdomain PII must never leak into radar graph masked_value
    graph_json = repo.get_radar_graph().model_dump_json()
    assert "0912345678" not in graph_json

    # Legacy unredacted row written before remediation must still be redacted on get_report()
    import sqlite3

    with sqlite3.connect(str(db_path)) as raw_conn:
        raw_conn.execute(
            "INSERT INTO cases (case_id, created_at, verdict, risk_score, report_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                "vs_legacy_raw01",
                report.created_at,
                report.verdict,
                report.risk_score,
                report.model_copy(update={"case_id": "vs_legacy_raw01"}).model_dump_json(),
            ),
        )
    legacy_loaded = repo.get_report("vs_legacy_raw01")
    assert legacy_loaded is not None
    assert "190384756201" not in legacy_loaded.model_dump_json()
    assert "RAW_SCREENSHOT_BASE64_SECRET" not in legacy_loaded.model_dump_json()

    # Grouped unknown account numbers in hash-based block rule reasons must be scrubbed
    seed_file = Path(__file__).resolve().parents[2] / "app" / "data" / "seed_iocs.json"
    repo.seed_if_empty(str(seed_file))
    camp = repo.get_radar_graph().campaigns[0]
    hash_rule = repo.add_block_rule(
        ioc_type=camp.primary_ioc_type,
        ioc_hash=camp.primary_ioc_hash,
        reason="Phát hiện chuyển tiếp qua 1903 8475 6201 và 8888-7777-6666",
    )
    assert "1903 8475 6201" not in hash_rule.reason
    assert "8888-7777-6666" not in hash_rule.reason


def test_delta_schemeless_common_domains_veto_advisory_and_merchant_settlement_invariants() -> None:
    # Ordinary .com / .org scheme-less links and official-prefix spoofed subdomains must veto advisory
    spoof_sub = evaluate_guardrails(
        "[CẢNH BÁO AN TOÀN] Vietcombank khuyến cáo bảo mật tài khoản. "
        "Xem tại vietcombank.com.evil.org/verify"
    )
    assert spoof_sub.safety_advisory_detected is False
    assert spoof_sub.advisory_vetoed is True

    bare_com = evaluate_guardrails(
        "[THÔNG BÁO BẢO MẬT] Không cung cấp OTP cho bất kỳ ai. Truy cập evil-check-otp.com/login"
    )
    assert bare_com.safety_advisory_detected is False
    assert bare_com.advisory_vetoed is True

    # Negated merchant balance warning must be rejected by AnalysisReport schema validator
    with pytest.raises(ValidationError):
        AnalysisReport(
            case_id="vs_bad_warn",
            created_at="2026-11-26T03:00:00+00:00",
            mode="merchant",
            risk_score=10,
            verdict="SAFE",
            confidence=0.8,
            receipt_verification_status="UNVERIFIED_SCREENSHOT",
            summary_vi="Ảnh chụp màn hình chưa đối soát.",
            receipt_logic=ReceiptLogicResult(
                is_receipt_candidate=True,
                verification_status="UNVERIFIED_SCREENSHOT",
            ),
            actions=ActionBundle(
                merchant_balance_warning="Không cần kiểm tra số dư trước khi giao hàng.",
                pre_transfer=PreTransferIntervention(should_hold_transfer=False),
            ),
        )

    # Affirmative LLM settlement paraphrase must be rewritten by _guard_merchant_summary
    from app.services.pipeline import _guard_merchant_summary

    guarded = _guard_merchant_summary(
        "Số dư đã được ghi có, có thể giao hàng ngay.",
        mode="merchant",
        receipt_status="UNVERIFIED_SCREENSHOT",
    )
    assert "có thể giao hàng" not in guarded.lower()
    assert "chưa" in guarded.lower()

    # Receipt candidate with no timestamp, amount, or OCR boxes marks applicability flags False
    minimal_rcpt = validate_receipt_logic("GIAO DỊCH THÀNH CÔNG")
    assert minimal_rcpt.is_receipt_candidate is True
    assert minimal_rcpt.timestamp_checked is False
    assert minimal_rcpt.amount_checked is False
    assert minimal_rcpt.geometry_checked is False


@pytest.mark.asyncio
async def test_delta_non_receipt_double_upload_sandbox_pinned_hops_and_prod_pin_telegram_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Published placeholder PINs must fail closed in production, and "2026" must fail outside demo
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="production", analyst_pin="CHANGE_ME_STRONG_ANALYST_PIN")
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_env="development", analyst_pin="2026")

    # Atomic Telegram update claim prevents duplicate concurrent execution
    repo = CaseRepository(str(tmp_path / "tg_claim.db"))
    repo.init_db()
    state1, _, _ = repo.claim_telegram_update(9001)
    state2, _, _ = repo.claim_telegram_update(9001)
    assert state1 == "claimed"
    assert state2 == "in_progress"
    repo.save_telegram_update_cache(9001, "vs_done1", "Đã xử lý")
    state3, cid3, reply3 = repo.claim_telegram_update(9001)
    assert state3 == "cached"
    assert cid3 == "vs_done1"
    assert reply3 == "Đã xử lý"

    # Uploading an ordinary non-receipt image twice must NOT turn into REPLAYED_RECEIPT
    from app.services.pipeline import AnalysisPipeline

    cfg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "non_rcpt.db"),
        gemini_api_key="",
        gemini_backup_api_key="",
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
        enable_local_ocr=False,
        enable_local_stt=False,
    )
    repo_img = CaseRepository(cfg.sqlite_path)
    repo_img.init_db()
    pipe = AnalysisPipeline(settings=cfg, repo=repo_img)

    buf = io.BytesIO()
    Image.new("RGB", (120, 120), color=(40, 120, 200)).save(buf, format="PNG")
    plain_png = buf.getvalue()

    benign_txt = "Hẹn trưa nay 12h cả phòng mình ghé quán cơm tấm đầu ngõ ăn trưa nhé!"
    rep1 = await pipe.run(mode="personal", text=benign_txt, image_bytes=plain_png)
    rep2 = await pipe.run(mode="personal", text=benign_txt, image_bytes=plain_png)
    assert rep1.receipt_verification_status != "REPLAYED_RECEIPT"
    assert rep2.receipt_verification_status != "REPLAYED_RECEIPT"
    assert rep2.risk_score == rep1.risk_score
    assert rep2.verdict == "SAFE"

    # Unavailable Playwright sandbox must NOT emit HIGH-severity phishing threat evidence
    cfg_sbx = cfg.model_copy(update={"enable_playwright_sandbox": True})
    pipe_sbx = AnalysisPipeline(settings=cfg_sbx, repo=repo_img)

    async def _unavailable_sandbox(
        url: str,
        enabled: bool = True,
        timeout_ms: int = 3000,
    ) -> SandboxInspection:
        _ = (enabled, timeout_ms)
        return SandboxInspection(
            available=False,
            visited_url=url,
            blocked_ssrf=False,
            risk_points=0,
            reasons=["Buồng cô lập không thể hoàn tất hiển thị (RuntimeError)."],
        )

    monkeypatch.setattr("app.services.pipeline.detonate_url_in_sandbox", _unavailable_sandbox)
    rep_sbx = await pipe_sbx.run(mode="personal", text="Kiểm tra https://vneid-capnhat.top/login")
    assert all(ev.source != "phishing_sandbox" for ev in rep_sbx.evidence)

    # Sandbox HTTP fetcher must follow multi-hop redirects inside safe_client (never returning 3xx)
    # and block a 2nd-hop redirect to loopback
    from app.core.security import SsrfBlockedError
    from app.services.phishing_detonator import _fetch_via_pinned_client

    async def _mock_validate(
        target: str,
        resolve_dns: bool = True,
        timeout_sec: float = 2.5,
    ) -> tuple[bool, str | None, list[str]]:
        _ = (resolve_dns, timeout_sec)
        if "127.0.0.1" in target:
            return False, "Target resolves to non-public IP 127.0.0.1", []
        return True, None, ["93.184.216.34"]

    monkeypatch.setattr("app.services.phishing_detonator.async_validate_url_target", _mock_validate)

    def _hop_transport(req: httpx.Request) -> httpx.Response:
        u = str(req.url)
        if u == "https://hop1.example/start":
            return httpx.Response(302, headers={"Location": "https://hop2.example/mid"})
        if u == "https://hop2.example/mid":
            return httpx.Response(200, text="<html>ok</html>", headers={"Content-Type": "text/html"})
        if u == "https://hop1.example/evil":
            return httpx.Response(302, headers={"Location": "https://hop2.example/ssrf"})
        if u == "https://hop2.example/ssrf":
            return httpx.Response(302, headers={"Location": "http://127.0.0.1/admin"})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(_hop_transport)) as hop_client:
        st, hdrs, body, final_u = await _fetch_via_pinned_client(
            hop_client,
            "GET",
            "https://hop1.example/start",
            [],
        )
        assert st == 200
        assert "location" not in {k.lower() for k in hdrs}
        assert final_u == "https://hop2.example/mid"
        assert b"ok" in body

        with pytest.raises(SsrfBlockedError):
            await _fetch_via_pinned_client(hop_client, "GET", "https://hop1.example/evil", [])


@pytest.mark.asyncio
async def test_delta_r2_metadata_redaction_legacy_radar_migration_and_default_env_posture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for k in ("APP_ENV", "ANALYST_PIN"):
        monkeypatch.delenv(k, raising=False)

    # Omitting APP_ENV must NOT opt into demo or accept published '2026' PIN
    default_cfg = Settings(_env_file=None)
    assert default_cfg.app_env == "development"
    assert default_cfg.analyst_pin == ""
    demo_cfg = Settings(_env_file=None, app_env="demo")
    assert demo_cfg.analyst_pin == "2026"

    db_path = tmp_path / "r2_sec.db"
    repo = CaseRepository(str(db_path))
    repo.init_db()

    rep = AnalysisReport(
        case_id="vs_r2_meta01",
        created_at="2026-11-26T04:00:00+00:00",
        mode="merchant",
        risk_score=12,
        verdict="SAFE",
        confidence=0.9,
        receipt_verification_status="UNVERIFIED_SCREENSHOT",
        summary_vi="Ảnh biên lai chưa đối soát.",
        image_forensics=ImageForensicsResult(
            filename="zalo_0912345678_190384756201.jpg",
            format="JPEG",
            width=400,
            height=500,
            dhash_hex="1122334455667788",
            exif_software="Photoshop Account 190384756201",
        ),
        receipt_logic=ReceiptLogicResult(
            is_receipt_candidate=True,
            reference_code="FT190384756201",
            verification_status="UNVERIFIED_SCREENSHOT",
        ),
        actions=ActionBundle(
            merchant_balance_warning=(
                "Chỉ giao hàng sau khi trực tiếp kiểm tra ứng dụng ngân hàng "
                "hoặc Loa thông báo ghi nhận số dư."
            ),
            pre_transfer=PreTransferIntervention(should_hold_transfer=False),
        ),
    )
    live_out = repo.save_report(rep)
    stored_out = repo.get_report("vs_r2_meta01")
    assert stored_out is not None
    for candidate_json in (live_out.model_dump_json(), stored_out.model_dump_json()):
        assert "0912345678" not in candidate_json
        assert "190384756201" not in candidate_json

    # Private replay fingerprint on raw reference_code must still have been recorded
    assert repo.is_receipt_replayed(None, None, "FT190384756201") is True

    # Legacy radar rows (8-digit full-reveal account, 4-label subdomain, unredacted block_rule)
    import sqlite3

    with sqlite3.connect(str(db_path)) as raw_conn:
        raw_conn.execute(
            "INSERT INTO ioc_sightings (ioc_hash, ioc_type, masked_value, hit_count) VALUES (?, ?, ?, 3)",
            ("h_old_acct8", "bank_account", "1234****5678"),
        )
        raw_conn.execute(
            "INSERT INTO ioc_sightings (ioc_hash, ioc_type, masked_value, hit_count) VALUES (?, ?, ?, 2)",
            ("h_old_dom4", "domain", "a.0912345678.na****.top"),
        )
        raw_conn.execute(
            "INSERT INTO block_rules "
            "(rule_id, ioc_hash, ioc_type, masked_value, reason, created_at, expires_at) "
            "VALUES ('r_leg', 'h_leg', 'bank_account', '190384756201', 'Khóa 1903 8475 6201', "
            "'2026-11-26T00:00:00+00:00', '2099-01-01T00:00:00+00:00')",
        )

    repo.init_db()
    migrated_graph_json = repo.get_radar_graph().model_dump_json()
    assert "1234****5678" not in migrated_graph_json
    assert "0912345678" not in migrated_graph_json
    assert "190384756201" not in migrated_graph_json
    assert "1903 8475 6201" not in migrated_graph_json


@pytest.mark.asyncio
async def test_delta_r2_sentence_end_links_sender_only_stk_owner_lease_and_benchmark_clock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Sentence-ending bare domain & unlisted TLD with port/query/fragment must veto safety advisory
    sent_end = evaluate_guardrails(
        "[CẢNH BÁO AN TOÀN] Không chia sẻ mã OTP với bất kỳ ai. Xem chi tiết tại example.com."
    )
    assert sent_end.safety_advisory_detected is False
    assert sent_end.advisory_vetoed is True

    unlisted_tld = evaluate_guardrails(
        "[THÔNG BÁO BẢO MẬT] Tuyệt đối không cung cấp mật khẩu. "
        "Kiểm tra tại vcb-security.finance:8443/check?u=1#top."
    )
    assert unlisted_tld.safety_advisory_detected is False
    assert unlisted_tld.advisory_vetoed is True

    # Genuine advisory mentioning .apk filename at sentence end must STILL be recognized as safe advisory
    genuine_apk_adv = evaluate_guardrails(
        "[CẢNH BÁO AN TOÀN] Ngân hàng khuyến cáo tuyệt đối không cung cấp mã OTP "
        "và không cài đặt tệp VNeID.apk."
    )
    assert genuine_apk_adv.safety_advisory_detected is True
    assert genuine_apk_adv.advisory_vetoed is False

    # Sender-only STK without recipient label must leave beneficiary_checked=False
    sender_only_rcpt = validate_receipt_logic(
        "GIAO DỊCH THÀNH CÔNG\nNgười gửi: NGUYEN VAN A\nSTK: 111122223333\nSố tiền: 200.000 VND",
        expected_merchant_account="999988887777",
    )
    assert sender_only_rcpt.beneficiary_checked is False
    assert sender_only_rcpt.beneficiary_mismatch is False

    # Trusted merchant receipt summary must never echo free-form LLM settlement confirmations
    from app.services.pipeline import _guard_merchant_summary

    for st in (
        "UNVERIFIED_SCREENSHOT",
        "TAMPER_OR_LOGIC_ANOMALY",
        "REPLAYED_RECEIPT",
        "BENEFICIARY_MISMATCH",
    ):
        out_s = _guard_merchant_summary(
            "Ngân hàng xác nhận người bán đã nhận đủ tiền.",
            mode="merchant",
            receipt_status=st,  # type: ignore[arg-type]
        )
        assert "nhận đủ tiền" not in out_s.lower()

    # Owner-tagged Telegram lease prevents expired worker from deleting or overwriting new owner
    repo = CaseRepository(str(tmp_path / "lease.db"))
    repo.init_db()
    st1, _, _ = repo.claim_telegram_update(4242, owner_id="worker_1", lease_seconds=0)
    assert st1 == "claimed"
    st2, _, _ = repo.claim_telegram_update(4242, owner_id="worker_2", lease_seconds=60)
    assert st2 == "claimed"
    # Stale worker_1 tries to release or overwrite worker_2's active claim -> ignored!
    repo.release_telegram_update_claim(4242, owner_id="worker_1")
    repo.save_telegram_update_cache(4242, "vs_stale", "stale", owner_id="worker_1")
    st3, _, _ = repo.claim_telegram_update(4242, owner_id="worker_3", lease_seconds=60)
    assert st3 == "in_progress"
    repo.save_telegram_update_cache(4242, "vs_winner", "winner_reply", owner_id="worker_2")
    st4, cid4, rep4 = repo.claim_telegram_update(4242, owner_id="worker_3", lease_seconds=60)
    assert (st4, cid4, rep4) == ("cached", "vs_winner", "winner_reply")

    # Sandbox timeout_ms=400 must bound total wall-clock wait near 0.4s (not 0.4s + 2.5s = 2.9s)
    import asyncio
    import time

    from app.services.phishing_detonator import detonate_url_in_sandbox

    async def _slow_validate(
        target: str,
        resolve_dns: bool = True,
        timeout_sec: float = 2.5,
    ) -> tuple[bool, str | None, list[str]]:
        _ = (target, timeout_sec)
        if resolve_dns:
            await asyncio.sleep(2.0)
        return True, None, ["93.184.216.34"]

    monkeypatch.setattr("app.services.phishing_detonator.async_validate_url_target", _slow_validate)
    t0 = time.perf_counter()
    slow_res = await detonate_url_in_sandbox("https://slow.example/login", enabled=True, timeout_ms=400)
    elapsed = time.perf_counter() - t0
    assert slow_res.available is False
    assert elapsed < 1.5


@pytest.mark.asyncio
async def test_delta_r3_legacy_case_8digit_vietqr_snippet_random_tg_case_and_17digit_stk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sqlite3

    db_path = tmp_path / "r3_sec.db"
    repo = CaseRepository(str(db_path))
    repo.init_db()

    # 1. Legacy case JSON with 4+4 eight-digit account mask ("1234****5678") in iocs, vietqr, and summary
    legacy_case = AnalysisReport(
        case_id="vs_leg8_01",
        created_at="2026-11-26T04:10:00+00:00",
        mode="personal",
        risk_score=80,
        verdict="CRITICAL_SCAM",
        confidence=0.9,
        summary_vi="Phát hiện STK 1234****5678 đáng ngờ.",
        iocs=ExtractedIOCs(phones=[], bank_accounts=["1234****5678"], urls=[], domains=[], brands=[]),
        vietqr_findings=[
            VietQRInfo(
                raw="[VIETQR_REDACTED:970422:1234****5678]",
                kind="VALID_VIETQR",
                crc_valid=True,
                bank_bin="970422",
                account_number="1234****5678",
            )
        ],
        actions=ActionBundle(pre_transfer=PreTransferIntervention(should_hold_transfer=True)),
    )
    with sqlite3.connect(str(db_path)) as raw_conn:
        raw_conn.execute(
            "INSERT INTO cases (case_id, created_at, verdict, risk_score, report_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                legacy_case.case_id,
                legacy_case.created_at,
                legacy_case.verdict,
                legacy_case.risk_score,
                legacy_case.model_dump_json(),
            ),
        )
    repo.init_db()
    with sqlite3.connect(str(db_path)) as raw_conn:
        migrated_raw_str = str(
            raw_conn.execute(
                "SELECT report_json FROM cases WHERE case_id = 'vs_leg8_01'"
            ).fetchone()[0]
        )
    loaded_leg8 = repo.get_report("vs_leg8_01")
    assert loaded_leg8 is not None
    assert "1234****5678" not in migrated_raw_str
    assert "1234****5678" not in loaded_leg8.model_dump_json()

    # 2. Invalid-CRC VietQR whose beneficiary 190384756201 appears nowhere outside the QR frame
    valid_qr = build_vietqr_test_payload("970436", "190384756201", amount="250000")
    corrupted_qr = valid_qr[:-4] + ("0000" if valid_qr[-4:] != "0000" else "FFFF")
    v_info, v_ev = parse_qr_payload(corrupted_qr)
    assert v_info.kind == "INVALID_CRC_VIETQR"
    for item in v_ev:
        assert "190384756201" not in (item.snippet or "")
        assert "190384756201" not in item.detail

    # 3. Telegram webhook must allocate an opaque random case_id (never predictable from update_id)
    from app.services.pipeline import AnalysisPipeline
    from app.services.telegram_bot import handle_telegram_update

    async def _fail_on_outbound_telegram(*_a: object, **_kw: object) -> None:
        pytest.fail("Unexpected outbound Telegram network call in unit test")

    monkeypatch.setattr("app.services.telegram_bot._deliver_telegram_message", _fail_on_outbound_telegram)

    cfg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "tg_opaque.db"),
        gemini_api_key="",
        gemini_backup_api_key="",
        telegram_bot_token="",
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
        enable_local_ocr=False,
        enable_local_stt=False,
    )
    tg_repo = CaseRepository(cfg.sqlite_path)
    tg_repo.init_db()
    pipe = AnalysisPipeline(settings=cfg, repo=tg_repo)
    upd = {"update_id": 778899, "message": {"chat": {"id": 1001}, "text": "Kiểm tra tin nhắn bình thường"}}
    r_first = await handle_telegram_update(upd, pipe, cfg)
    r_retry = await handle_telegram_update(upd, pipe, cfg)
    assert "778899" not in str(r_first["case_id"])
    assert not str(r_first["case_id"]).startswith("vs_tg_")
    assert r_first["case_id"] == r_retry["case_id"]

    # 4. 17-digit recipient account must NOT prefix-match its first 16 digits
    rcpt_17 = validate_receipt_logic(
        "CHUYỂN KHOẢN THÀNH CÔNG\nTài khoản thụ hưởng: 19031111222233339\nSố tiền: 100.000 VND",
        expected_merchant_account="1903111122223333",
    )
    assert rcpt_17.beneficiary_checked is True
    assert rcpt_17.beneficiary_mismatch is True


@pytest.mark.asyncio
async def test_delta_r4_rejected_emv_frame_6_to_19_acct_tg_rotation_retry_after_and_zero_attempt_init(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sqlite3

    db_path = tmp_path / "r4_sec.db"
    repo = CaseRepository(str(db_path))
    repo.init_db()

    # 1. CRC-correct NAPAS frame missing service code (sub38['02']) must NOT leak beneficiary in raw
    acct_sub = "00069704360112190384756201"
    tag38_val = f"0010A00000072701{len(acct_sub):02d}{acct_sub}"
    body_no_svc = f"00020101021138{len(tag38_val):02d}{tag38_val}53037045802VN6304"
    qr_no_svc = body_no_svc + crc16_ccitt_false(body_no_svc.encode("ascii"))
    v_nosvc, _ = parse_qr_payload(qr_no_svc)

    rep_emv = AnalysisReport(
        case_id="vs_r4_emv01",
        created_at="2026-11-26T06:35:00+00:00",
        mode="merchant",
        risk_score=10,
        verdict="SAFE",
        confidence=0.9,
        receipt_verification_status="UNVERIFIED_SCREENSHOT",
        summary_vi="Ảnh biên lai chưa đối soát.",
        vietqr_findings=[v_nosvc],
        image_forensics=ImageForensicsResult(
            filename="rcpt.jpg",
            format="JPEG",
            width=300,
            height=400,
            dhash_hex="9988776655443322",
            ocr_text="CHUYỂN KHOẢN THÀNH CÔNG\nTài khoản nhận: 19031111222233339",
        ),
        receipt_logic=validate_receipt_logic(
            "CHUYỂN KHOẢN THÀNH CÔNG\nTài khoản nhận: 19031111222233339",
            expected_merchant_account="19031111222233339",
        ),
        actions=ActionBundle(
            merchant_balance_warning=(
                "Chỉ giao hàng sau khi trực tiếp kiểm tra ứng dụng ngân hàng "
                "hoặc Loa thông báo ghi nhận số dư."
            ),
            pre_transfer=PreTransferIntervention(should_hold_transfer=False),
        ),
    )
    live_emv = repo.save_report(rep_emv)
    stored_emv = repo.get_report("vs_r4_emv01")
    assert stored_emv is not None
    for payload_json in (live_emv.model_dump_json(), stored_emv.model_dump_json()):
        assert "190384756201" not in payload_json
        assert "19031111222233339" not in payload_json

    # 2. 6-digit & 19-digit labeled accounts scrubbed in radar reasons, and grouped recipient checked
    r6 = repo.add_block_rule(
        ioc_type="domain",
        raw_value="evil-r4.top",
        reason="Liên quan STK: 654321 và TK 1234567890123456789",
    )
    assert "654321" not in r6.reason
    assert "1234567890123456789" not in r6.reason

    grouped_mismatch = validate_receipt_logic(
        "CHUYỂN KHOẢN THÀNH CÔNG\nTài khoản nhận: 190311 999\nSố tiền: 100.000 VND",
        expected_merchant_account="190311",
    )
    assert grouped_mismatch.beneficiary_checked is True
    assert grouped_mismatch.beneficiary_mismatch is True

    hyphen_mismatch = validate_receipt_logic(
        "CHUYỂN KHOẢN THÀNH CÔNG\nTài khoản nhận: 190311-888\nSố tiền: 100.000 VND",
        expected_merchant_account="190311",
    )
    assert hyphen_mismatch.beneficiary_checked is True
    assert hyphen_mismatch.beneficiary_mismatch is True

    # 3. Legacy predictable vs_tg_<id> case rotated on init_db, and fake '****' block_rule label replaced
    with sqlite3.connect(str(db_path)) as raw_conn:
        leg_tg_rep = rep_emv.model_copy(update={"case_id": "vs_tg_555666"})
        raw_conn.execute(
            "INSERT INTO cases (case_id, created_at, verdict, risk_score, report_json) "
            "VALUES (?, ?, ?, ?, ?)",
            ("vs_tg_555666", leg_tg_rep.created_at, leg_tg_rep.verdict, 10, leg_tg_rep.model_dump_json()),
        )
        raw_conn.execute(
            "INSERT INTO telegram_updates (update_id, status, case_id, reply_text, created_at) "
            "VALUES (555666, 'completed', 'vs_tg_555666', 'Đã xong', '2026-11-26T05:00:00+00:00')"
        )
        raw_conn.execute(
            "INSERT INTO block_rules "
            "(rule_id, ioc_hash, ioc_type, masked_value, reason, created_at, expires_at) "
            "VALUES ('r_spoof_star', 'deadbeef0011', 'bank_account', '190384756201****', 'test', "
            "'2026-11-26T00:00:00+00:00', '2099-01-01T00:00:00+00:00')"
        )

    repo.init_db()
    assert repo.get_report("vs_tg_555666") is None
    tg_cached = repo.get_telegram_update_cache(555666)
    assert tg_cached is not None and tg_cached[0] is not None
    assert tg_cached[0] != "vs_tg_555666"
    assert repo.get_report(tg_cached[0]) is not None
    assert "190384756201" not in repo.get_radar_graph().model_dump_json()

    # 4. Retry-After exceeding budget must NOT immediately hit same endpoint with backup key
    from app.services.llm_client import execute_llm_call

    cfg_2k = Settings(
        _env_file=None,
        llm_provider="openai_compatible",
        gemini_base_url="https://cpa.joiboi.app/v1",
        gemini_api_key="key_primary",
        gemini_backup_api_key="key_backup",
        llm_max_retries=1,
    )
    calls_429 = 0

    def _429_long(_req: httpx.Request) -> httpx.Response:
        nonlocal calls_429
        calls_429 += 1
        return httpx.Response(429, headers={"Retry-After": "60"}, json={"error": "rate_limit"})

    with respx.mock(assert_all_called=True) as router_429:
        router_429.post("https://cpa.joiboi.app/v1/chat/completions").mock(side_effect=_429_long)
        out_429 = await execute_llm_call(settings=cfg_2k, prompt="test")
    assert calls_429 == 1
    assert out_429.error_code == "HTTP_429_RETRY_AFTER_EXCEEDED"

    # 5. Local client init failure (0 provider attempts) records 0 failed attempts & 1 terminal error
    import sys

    repo_root = str(Path(__file__).resolve().parents[3])
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    from evaluation.run_benchmark import BenchmarkCase, run_benchmark_suite

    cfg_google_init = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "g_init.db"),
        llm_provider="google_genai",
        gemini_api_key="dummy_key",
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
        enable_local_ocr=False,
        enable_local_stt=False,
    )

    def _boom_client(*_a: object, **_kw: object) -> object:
        raise RuntimeError("local ssl cert store broken")

    monkeypatch.setattr("app.services.llm_client.genai.Client", _boom_client)
    init_sum = await run_benchmark_suite(
        cases=[
            BenchmarkCase(
                case_id="c_init_fail",
                category="benign_normal",
                mode="personal",
                text="Hẹn ăn trưa lúc 12h nhé.",
                expected_is_scam=False,
            )
        ],
        settings=cfg_google_init,
        require_live_llm=False,
    )
    assert init_sum["api_health"]["terminal_error_count"] == 1
    assert init_sum["api_health"]["provider_attempt_error_count"] == 0
    assert init_sum["api_health"]["api_error_count"] == 0


@pytest.mark.asyncio
async def test_delta_r5_short_recipient_reason_domain_migration_vietqr_mismatch_and_retry_after_last_hop(
    tmp_path: Path,
) -> None:
    import sqlite3

    import cv2

    db_path = tmp_path / "r5_sec.db"
    repo = CaseRepository(str(db_path))
    repo.init_db()

    # 1. Six- and seven-digit 'Tài khoản nhận' / 'Số tài khoản thụ hưởng' scrubbed in new & migrated reasons
    repo.add_block_rule(
        ioc_type="domain",
        raw_value="evil-r5.top",
        reason="Tài khoản nhận: 654321 và Số tài khoản thụ hưởng: 7654321",
    )
    with sqlite3.connect(str(db_path)) as raw_conn:
        raw_conn.execute(
            "INSERT INTO ioc_sightings (ioc_hash, ioc_type, masked_value, hit_count) "
            "VALUES ('h_dom_acct', 'domain', '123456789012****.top', 3)"
        )
        raw_conn.execute(
            "INSERT INTO campaigns "
            "(campaign_id, title_vi, playbook_id, case_count, primary_ioc_type, "
            "primary_ioc_hash, primary_ioc_masked, recommended_action) "
            "VALUES ('c_dom_acct', 'Camp', 'pb', 2, 'domain', ?, "
            "'999988887777****.vip', 'Block')",
            ("a" * 64,),
        )
        raw_conn.execute(
            "INSERT INTO block_rules "
            "(rule_id, ioc_hash, ioc_type, masked_value, reason, created_at, expires_at) "
            "VALUES ('r_unmatched_dom', 'h_unmatched_dom', 'domain', '555566667777****.xyz', "
            "'Tài khoản nhận: 612345', '2026-11-26T00:00:00+00:00', '2099-01-01T00:00:00+00:00')"
        )
    repo.init_db()
    radar_json = repo.get_radar_graph().model_dump_json()
    for secret_digits in (
        "654321",
        "7654321",
        "612345",
        "123456789012",
        "999988887777",
        "555566667777",
    ):
        assert secret_digits not in radar_json

    # 2. Trailing punctuation/spaces on recipient lines must NOT suppress beneficiary comparison
    for line in (
        "CHUYỂN KHOẢN THÀNH CÔNG\nTài khoản nhận: 190399998888.\nSố tiền: 200.000 VND",
        "CHUYỂN KHOẢN THÀNH CÔNG\nTài khoản nhận: 190399998888   \nSố tiền: 200.000 VND",
    ):
        mis = validate_receipt_logic(line, expected_merchant_account="190311112222")
        assert mis.beneficiary_checked is True
        assert mis.beneficiary_mismatch is True
        ok = validate_receipt_logic(line, expected_merchant_account="190399998888")
        assert ok.beneficiary_checked is True
        assert ok.beneficiary_mismatch is False

    # 3. Merchant image with VietQR beneficiary mismatch sets BENEFICIARY_MISMATCH & QR summary
    from app.services.pipeline import AnalysisPipeline

    qr_payload = build_vietqr_test_payload("970436", "190399998888", amount="150000")
    qr_mat = cv2.QRCodeEncoder_create().encode(qr_payload)
    qr_img = Image.fromarray(qr_mat).resize((260, 260), Image.Resampling.NEAREST).convert("RGB")
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")

    cfg_m = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "m_vqr.db"),
        gemini_api_key="",
        gemini_backup_api_key="",
        telegram_bot_token="",
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
        enable_local_ocr=False,
        enable_local_stt=False,
    )
    m_repo = CaseRepository(cfg_m.sqlite_path)
    m_repo.init_db()
    m_pipe = AnalysisPipeline(settings=cfg_m, repo=m_repo)
    m_rep = await m_pipe.run(
        mode="merchant",
        text="Khách gửi mã thanh toán tại quầy",
        image_bytes=buf.getvalue(),
        image_filename="qr.png",
        image_mime="image/png",
        expected_merchant_account="190311112222",
    )
    assert m_rep.receipt_verification_status == "BENEFICIARY_MISMATCH"
    assert "vietqr" in m_rep.summary_vi.lower() or "mã qr" in m_rep.summary_vi.lower()
    assert m_rep.actions.merchant_balance_warning is not None

    # 4. Retry-After respected on max_retries=0, exhausted retries, and 503 before backup-key failover
    from app.services.llm_client import execute_llm_call

    for status_code, max_ret in ((429, 0), (429, 1), (503, 0)):
        cfg_ra = Settings(
            _env_file=None,
            llm_provider="openai_compatible",
            gemini_base_url="https://cpa.joiboi.app/v1",
            gemini_api_key="k1",
            gemini_backup_api_key="k2",
            llm_max_retries=max_ret,
        )
        seen_calls = 0

        def _ra_handler(_req: httpx.Request, sc: int = status_code, mr: int = max_ret) -> httpx.Response:
            nonlocal seen_calls
            seen_calls += 1
            hdr_val = "0" if (mr == 1 and seen_calls == 1) else "60"
            return httpx.Response(sc, headers={"Retry-After": hdr_val}, json={"error": "busy"})

        with respx.mock(assert_all_called=True) as r_ra:
            r_ra.post("https://cpa.joiboi.app/v1/chat/completions").mock(side_effect=_ra_handler)
            out_ra = await execute_llm_call(settings=cfg_ra, prompt="check")

        expected_calls = 2 if max_ret == 1 else 1
        assert seen_calls == expected_calls
        assert out_ra.error_code == f"HTTP_{status_code}_RETRY_AFTER_EXCEEDED"


def test_delta_r6_unified_account_spans_live_domain_suffix_legacy_merchant_upgrade_and_tg_64bit(
    tmp_path: Path,
) -> None:
    import json
    import sqlite3

    db_path = tmp_path / "r6_sec.db"
    repo = CaseRepository(str(db_path))
    repo.init_db()

    # 1. 'Tài khoản nhận: 190311 999' scrubbed in new & migrated reasons; live domain suffix validated
    r_dom = repo.add_block_rule(
        ioc_type="domain",
        raw_value="phish.190384756201",
        reason="Tài khoản nhận: 190311 999",
    )
    assert "190384756201" not in r_dom.masked_value
    assert "190311" not in r_dom.reason
    assert "999" not in r_dom.reason
    immediate_graph = repo.get_radar_graph().model_dump_json()
    assert "190384756201" not in immediate_graph
    assert "190311 999" not in immediate_graph

    with sqlite3.connect(str(db_path)) as raw_conn:
        raw_conn.execute(
            "INSERT INTO block_rules "
            "(rule_id, ioc_hash, ioc_type, masked_value, reason, created_at, expires_at) "
            "VALUES ('r_leg_grp9', 'h_leg_grp9', 'domain', 'phish.190384756201', "
            "'Tài khoản nhận: 190311 999', '2026-11-26T00:00:00+00:00', '2099-01-01T00:00:00+00:00')"
        )
        raw_conn.execute(
            "INSERT INTO cases (case_id, created_at, verdict, risk_score, report_json) "
            "VALUES ('vs_corrupt_01', '2026-11-25T10:00:00+00:00', 'SAFE', 0, '{corrupt_json')"
        )
    assert repo.get_report("vs_corrupt_01") is None

    # 2. Double spaces & tabs between account digit groups must NOT prefix-match first group
    for sep in ("  ", "\t\t", "   "):
        rcpt_ws = validate_receipt_logic(
            f"CHUYỂN KHOẢN THÀNH CÔNG\nTài khoản nhận: 190311{sep}999\nSố tiền: 100.000 VND",
            expected_merchant_account="190311",
        )
        assert rcpt_ws.beneficiary_checked is True
        assert rcpt_ws.beneficiary_mismatch is True

    # 3. Legacy raw JSON with old merchant warning & affirmative summary upgraded on init_db & get_report
    legacy_raw_dict = {
        "case_id": "vs_leg_merch_01",
        "created_at": "2026-11-25T10:00:00+00:00",
        "mode": "merchant",
        "in_active_call": False,
        "risk_score": 10,
        "verdict": "SAFE",
        "confidence": 0.9,
        "degraded_mode": False,
        "safety_advisory_detected": False,
        "prompt_injection_detected": False,
        "active_block_rule_hit": False,
        "receipt_verification_status": "UNVERIFIED_SCREENSHOT",
        "summary_vi": "Người bán đã nhận được tiền đầy đủ, giao hàng ngay.",
        "transcript": None,
        "matched_playbooks": [],
        "manipulation_tactics": [],
        "highlighted_phrases": [],
        "iocs": {"phones": [], "bank_accounts": [], "urls": [], "domains": [], "brands": []},
        "vietqr_findings": [],
        "url_findings": [],
        "sandbox": None,
        "image_forensics": None,
        "receipt_logic": {
            "is_receipt_candidate": True,
            "verification_status": "UNVERIFIED_SCREENSHOT",
            "logic_risk_points": 0,
            "reasons": [],
        },
        "evidence": [],
        "actions": {
            "counter_replies": [],
            "family_shield_message": "",
            "urgent_steps": [],
            "merchant_balance_warning": "Ảnh biên lai không chứng minh tiền đã vào tài khoản.",
            "pre_transfer": {"should_hold_transfer": False, "cooling_off_seconds": 0},
        },
        "trace": [],
        "community_hits": 0,
    }
    with sqlite3.connect(str(db_path)) as raw_conn:
        raw_conn.execute(
            "INSERT INTO cases (case_id, created_at, verdict, risk_score, report_json) "
            "VALUES (?, ?, ?, ?, ?)",
            ("vs_leg_merch_01", "2026-11-25T10:00:00+00:00", "SAFE", 10, json.dumps(legacy_raw_dict)),
        )
    # Must succeed on direct get_report BEFORE init_db AND after init_db migration
    direct_leg = repo.get_report("vs_leg_merch_01")
    assert direct_leg is not None
    assert "nhận được tiền" not in direct_leg.summary_vi.lower()
    assert "chưa" in direct_leg.summary_vi.lower()
    repo.init_db()
    migrated_leg = repo.get_report("vs_leg_merch_01")
    assert migrated_leg is not None
    assert "nhận được tiền" not in migrated_leg.summary_vi.lower()
    migrated_graph_obj = repo.get_radar_graph()
    migrated_graph_r6 = migrated_graph_obj.model_dump_json()
    assert "190384756201" not in migrated_graph_r6
    assert "190311" not in migrated_graph_r6
    for rule in migrated_graph_obj.active_block_rules:
        assert "190311" not in rule.reason
        assert "999" not in rule.reason
    with sqlite3.connect(str(db_path)) as raw_conn:
        assert (
            raw_conn.execute(
                "SELECT COUNT(*) FROM cases WHERE case_id = 'vs_corrupt_01'"
            ).fetchone()[0]
            == 0
        )

    # 4. Out-of-range Telegram update_id (> SQLite INT64 max or negative) must return HTTP 400 (never 500)
    cfg_tg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "tg_64.db"),
        gemini_api_key="",
        gemini_backup_api_key="",
        telegram_bot_token="",
        telegram_webhook_secret="sec_64",
        enable_live_network_checks=False,
        enable_playwright_sandbox=False,
    )
    client = TestClient(create_app(cfg_tg))
    for bad_uid in (-5, 1 << 80):
        res_bad = client.post(
            "/api/v1/bot/telegram",
            json={"update_id": bad_uid, "message": {"chat": {"id": 1}, "text": "test"}},
            headers={"X-Telegram-Bot-Api-Secret-Token": "sec_64"},
        )
        assert res_bad.status_code == 400
    assert client.get("/api/v1/radar/graph").json()["stats"]["total_cases"] == 0


def test_delta_r7_dotted_acct_suffix_allowlist_merchant_warning_no_prefix_ioc_and_zip_link(
    tmp_path: Path,
) -> None:
    import json
    import sqlite3

    db_path = tmp_path / "r7_sec.db"
    repo = CaseRepository(str(db_path))
    repo.init_db()

    # 1. Dotted beneficiary account extracted & scrubbed while genuine VND amount preserved
    dotted_iocs = extract_iocs("Tài khoản nhận: 123.456.789 — Số tiền: 2.500.000 VND")
    assert dotted_iocs.bank_accounts == ["123456789"]

    r_dot = repo.add_block_rule(
        ioc_type="domain",
        raw_value="phish.xn--190384756201",
        reason="Tài khoản nhận: 123.456.789 — Số tiền: 2.500.000 VND",
    )
    assert "190384756201" not in r_dot.masked_value
    assert "xn--" not in r_dot.masked_value
    assert "123.456.789" not in r_dot.reason
    assert "456" not in r_dot.reason
    assert "2.500.000 VND" in r_dot.reason

    # 2. Unrecognized suffix & dotted account in legacy radar rows migrated safely
    with sqlite3.connect(str(db_path)) as raw_conn:
        raw_conn.execute(
            "INSERT INTO block_rules "
            "(rule_id, ioc_hash, ioc_type, masked_value, reason, created_at, expires_at) "
            "VALUES ('r_leg_xn', 'h_leg_xn', 'domain', 'ph****.xn--190384756201', "
            "'Tài khoản nhận: 123.456.789 (2.500.000 VND)', "
            "'2026-11-26T00:00:00+00:00', '2099-01-01T00:00:00+00:00')"
        )
        raw_conn.execute(
            "INSERT INTO ioc_sightings (ioc_hash, ioc_type, masked_value, hit_count) "
            "VALUES ('h_leg_name_tld', 'domain', 'ph****.nguyenvana', 2)"
        )

    # 3. Single grouped account emits ONLY full account (no spurious prefix matching prefix rule)
    grp_iocs = extract_iocs("Tài khoản nhận: 190311 999")
    assert grp_iocs.bank_accounts == ["190311999"]
    repo.add_block_rule(ioc_type="bank_account", raw_value="190311", reason="Prefix test rule")
    assert repo.match_active_block_rules(grp_iocs) == []

    # 4. Account-only receipt with dotted beneficiary must NOT mark absent amount as checked
    acct_only = validate_receipt_logic(
        "GIAO DỊCH THÀNH CÔNG\nTài khoản nhận: 123.456.789",
        expected_merchant_account="190311112222",
    )
    assert acct_only.beneficiary_checked is True
    assert acct_only.beneficiary_mismatch is True
    assert acct_only.amount_checked is False
    assert acct_only.amount_format_anomaly is False

    # 5. Negated merchant warning rejected by schema AND upgraded unconditionally in repo
    with pytest.raises(ValidationError):
        AnalysisReport(
            case_id="vs_neg_warn",
            created_at="2026-11-26T07:00:00+00:00",
            mode="merchant",
            risk_score=10,
            verdict="SAFE",
            confidence=0.9,
            receipt_verification_status="UNVERIFIED_SCREENSHOT",
            summary_vi="Chưa đối soát.",
            receipt_logic=ReceiptLogicResult(
                is_receipt_candidate=True,
                verification_status="UNVERIFIED_SCREENSHOT",
            ),
            actions=ActionBundle(
                merchant_balance_warning="Không cần đối chiếu số dư trước khi giao hàng.",
                pre_transfer=PreTransferIntervention(should_hold_transfer=False),
            ),
        )

    legacy_neg_warn_case = {
        "case_id": "vs_leg_neg_warn",
        "created_at": "2026-11-25T10:00:00+00:00",
        "mode": "merchant",
        "in_active_call": False,
        "risk_score": 10,
        "verdict": "SAFE",
        "confidence": 0.9,
        "degraded_mode": False,
        "safety_advisory_detected": False,
        "prompt_injection_detected": False,
        "active_block_rule_hit": False,
        "receipt_verification_status": "UNVERIFIED_SCREENSHOT",
        "summary_vi": "Người bán đã nhận tiền.",
        "transcript": None,
        "matched_playbooks": [],
        "manipulation_tactics": [],
        "highlighted_phrases": [],
        "iocs": {"phones": [], "bank_accounts": [], "urls": [], "domains": [], "brands": []},
        "vietqr_findings": [],
        "url_findings": [],
        "sandbox": None,
        "image_forensics": None,
        "receipt_logic": {
            "is_receipt_candidate": True,
            "verification_status": "UNVERIFIED_SCREENSHOT",
            "logic_risk_points": 0,
            "reasons": [],
        },
        "evidence": [],
        "actions": {
            "counter_replies": [],
            "family_shield_message": "",
            "urgent_steps": [],
            "merchant_balance_warning": "Không cần đối chiếu số dư trước khi giao hàng.",
            "pre_transfer": {"should_hold_transfer": False, "cooling_off_seconds": 0},
        },
        "trace": [],
        "community_hits": 0,
    }
    # 6. High-risk legacy merchant image report (clean image, missing status) -> UNVERIFIED_SCREENSHOT
    legacy_high_clean_img_case = {
        "case_id": "vs_leg_hi_clean",
        "created_at": "2026-11-25T10:00:00+00:00",
        "mode": "merchant",
        "in_active_call": False,
        "risk_score": 90,
        "verdict": "CRITICAL_SCAM",
        "confidence": 0.95,
        "degraded_mode": False,
        "safety_advisory_detected": False,
        "prompt_injection_detected": False,
        "active_block_rule_hit": True,
        "receipt_verification_status": "NOT_APPLICABLE",
        "summary_vi": "Khớp luật chặn IOC của đội Fraud Ops.",
        "transcript": None,
        "matched_playbooks": [],
        "manipulation_tactics": [],
        "highlighted_phrases": [],
        "iocs": {"phones": [], "bank_accounts": [], "urls": [], "domains": [], "brands": []},
        "vietqr_findings": [],
        "url_findings": [],
        "sandbox": None,
        "image_forensics": {
            "filename": "clean.png",
            "format": "PNG",
            "width": 300,
            "height": 400,
            "dhash_hex": "1122334455667788",
            "tamper_score": 0,
            "editing_software_detected": False,
            "reasons": [],
        },
        "receipt_logic": None,
        "evidence": [],
        "actions": {
            "counter_replies": [],
            "family_shield_message": "",
            "urgent_steps": [],
            "merchant_balance_warning": None,
            "pre_transfer": {"should_hold_transfer": True, "cooling_off_seconds": 30},
        },
        "trace": [],
        "community_hits": 0,
    }
    with sqlite3.connect(str(db_path)) as raw_conn:
        for row_dict in (legacy_neg_warn_case, legacy_high_clean_img_case):
            raw_conn.execute(
                "INSERT INTO cases (case_id, created_at, verdict, risk_score, report_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    row_dict["case_id"],
                    row_dict["created_at"],
                    row_dict["verdict"],
                    row_dict["risk_score"],
                    json.dumps(row_dict),
                ),
            )

    direct_neg = repo.get_report("vs_leg_neg_warn")
    assert direct_neg is not None
    assert direct_neg.actions.merchant_balance_warning is not None
    assert "không cần" not in direct_neg.actions.merchant_balance_warning.lower()
    assert "kiểm tra" in direct_neg.actions.merchant_balance_warning.lower()

    direct_hi = repo.get_report("vs_leg_hi_clean")
    assert direct_hi is not None
    assert direct_hi.receipt_verification_status == "UNVERIFIED_SCREENSHOT"
    assert "TAMPER_OR_LOGIC_ANOMALY" not in direct_hi.summary_vi

    repo.init_db()
    mig_neg = repo.get_report("vs_leg_neg_warn")
    assert mig_neg is not None and mig_neg.actions.merchant_balance_warning is not None
    assert "không cần" not in mig_neg.actions.merchant_balance_warning.lower()
    mig_hi = repo.get_report("vs_leg_hi_clean")
    assert mig_hi is not None
    assert mig_hi.receipt_verification_status == "UNVERIFIED_SCREENSHOT"
    assert "TAMPER_OR_LOGIC_ANOMALY" not in mig_hi.summary_vi

    mig_graph_obj = repo.get_radar_graph()
    mig_graph_json = mig_graph_obj.model_dump_json()
    assert "190384756201" not in mig_graph_json
    assert "xn--" not in mig_graph_json
    assert "nguyenvana" not in mig_graph_json
    for rule in mig_graph_obj.active_block_rules:
        assert "123.456.789" not in rule.reason
        assert "456" not in rule.reason
        if rule.rule_id == "r_leg_xn":
            assert "2.500.000 VND" in rule.reason

    # 7. Bare .zip web address vetoes safety advisory while explicit filename control stays safe
    zip_link_adv = evaluate_guardrails(
        "[CẢNH BÁO AN TOÀN] Không chia sẻ mã OTP với bất kỳ ai. Xem chi tiết tại example.zip."
    )
    assert zip_link_adv.safety_advisory_detected is False
    assert zip_link_adv.advisory_vetoed is True

    file_ctrl_adv = evaluate_guardrails(
        "[CẢNH BÁO AN TOÀN] Ngân hàng khuyến cáo không chia sẻ mã OTP và "
        "không mở tệp hoadon.zip hoặc tệp VNeID.apk."
    )
    assert file_ctrl_adv.safety_advisory_detected is True
    assert file_ctrl_adv.advisory_vetoed is False


def test_delta_r8_newline_date_acct_malformed_row_overlength_ref_and_tlv_vs_crc(
    tmp_path: Path,
) -> None:
    import json
    import sqlite3

    db_path = tmp_path / "r8_sec.db"
    repo = CaseRepository(str(db_path))
    repo.init_db()

    # 1 & 2. Newline after STK and date-shaped explicit beneficiary redacted; real date preserved
    r_nl = repo.add_block_rule(
        ioc_type="domain",
        raw_value="evil-r8.top",
        reason="STK:\n654321 | Tài khoản nhận: 12.03.2001 | Ngày sinh: 12.03.2001",
    )
    assert "654321" not in r_nl.reason
    assert "Tài khoản nhận: 12.03.2001" not in r_nl.reason
    assert "Ngày sinh: 12.03.2001" in r_nl.reason

    with sqlite3.connect(str(db_path)) as raw_conn:
        raw_conn.execute(
            "INSERT INTO block_rules "
            "(rule_id, ioc_hash, ioc_type, masked_value, reason, created_at, expires_at) "
            "VALUES ('r_leg_nl', 'h_leg_nl', 'domain', 'ev****.top', "
            "'STK:\n654321 — Tài khoản nhận: 12.03.2001 — Ngày: 12.03.2001', "
            "'2026-11-26T00:00:00+00:00', '2099-01-01T00:00:00+00:00')"
        )

    # 3. Malformed historical numeric score in one merchant row must NOT break init_db for valid rows
    valid_rep = AnalysisReport(
        case_id="vs_valid_keep",
        created_at="2026-11-26T07:00:00+00:00",
        mode="personal",
        risk_score=12,
        verdict="SAFE",
        confidence=0.9,
        summary_vi="An toàn.",
        actions=ActionBundle(pre_transfer=PreTransferIntervention(should_hold_transfer=False)),
    )
    repo.save_report(valid_rep)
    bad_score_row = {
        "case_id": "vs_bad_score_01",
        "created_at": "2026-11-25T10:00:00+00:00",
        "mode": "merchant",
        "risk_score": 85,
        "verdict": "CRITICAL_SCAM",
        "confidence": 0.9,
        "receipt_verification_status": "NOT_APPLICABLE",
        "summary_vi": "Cảnh báo.",
        "image_forensics": {
            "filename": "x.png",
            "format": "PNG",
            "width": 100,
            "height": 100,
            "dhash_hex": "1122334455667788",
            "tamper_score": "not_a_number",
        },
        "actions": {"pre_transfer": {"should_hold_transfer": True, "cooling_off_seconds": 30}},
    }
    with sqlite3.connect(str(db_path)) as raw_conn:
        raw_conn.execute(
            "INSERT INTO cases (case_id, created_at, verdict, risk_score, report_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                "vs_bad_score_01",
                "2026-11-25T10:00:00+00:00",
                "CRITICAL_SCAM",
                85,
                json.dumps(bad_score_row),
            ),
        )

    repo.init_db()
    assert repo.get_report("vs_valid_keep") is not None
    assert repo.get_report("vs_bad_score_01") is None

    graph_r8 = repo.get_radar_graph()
    assert "654321" not in graph_r8.model_dump_json()
    for rule in graph_r8.active_block_rules:
        assert "Tài khoản nhận: 12.03.2001" not in rule.reason
        if rule.rule_id == "r_leg_nl":
            assert "Ngày: 12.03.2001" in rule.reason

    # 4. Overlength references (>24 chars) sharing a 24-char prefix must NOT collide as replay keys
    rcpt_a = validate_receipt_logic(
        "CHUYỂN KHOẢN THÀNH CÔNG\nSố tiền: 100.000 VND\nMã GD: TX263301234567890123456789AAA"
    )
    rcpt_b = validate_receipt_logic(
        "CHUYỂN KHOẢN THÀNH CÔNG\nSố tiền: 100.000 VND\nMã GD: TX263301234567890123456789BBB"
    )
    assert rcpt_a.reference_valid is False and rcpt_a.reference_code is None
    assert rcpt_b.reference_valid is False and rcpt_b.reference_code is None
    assert repo.claim_receipt_replay("aaaa000011112222", "Vietcombank", rcpt_a.reference_code) is False
    assert repo.claim_receipt_replay("bbbb000011112222", "Vietcombank", rcpt_b.reference_code) is False

    # 5. CRC-correct duplicate-tag VietQR reports structural TLV error (crc_valid=True, tlv_valid=False)
    valid_qr = build_vietqr_test_payload("970436", "190384756201", amount="100000")
    dup_body = valid_qr[:-8] + "5802VN6304"
    dup_qr = dup_body + crc16_ccitt_false(dup_body.encode("ascii"))
    v_dup, dup_ev = parse_qr_payload(dup_qr)
    assert v_dup.kind == "INVALID_CRC_VIETQR"
    assert v_dup.crc_valid is True
    assert v_dup.tlv_valid is False
    assert any("cấu trúc" in ev.title.lower() and "crc" not in ev.title.lower() for ev in dup_ev)
    assert all("không khớp" not in ev.detail.lower() for ev in dup_ev)


def test_delta_r9_clause_delimiters_tag54_tag3801_multiline_dong_compound_and_sep_refs(
    tmp_path: Path,
) -> None:
    from app.services.ioc_extractor import scrub_free_text_pii

    db_path = tmp_path / "r9_sec.db"
    repo = CaseRepository(str(db_path))
    repo.init_db()

    # 1. Clause delimiters (' - ', ' — ', '. ') must NOT bridge account tokens into amounts/timestamps
    for phrase, secret_sub in (
        ("Tài khoản nhận: 123.456.789 — 2.500.000 VND", "123.456.789"),
        ("Tài khoản nhận: 654321 - 2.500.000 VND", "654321"),
        ("STK: 190311 999 - 500.000 đ", "190311"),
        ("Tài khoản nhận: 12.03.2001 - 2.500.000 VND", "12.03.2001"),
    ):
        scrubbed = scrub_free_text_pii(phrase)
        assert secret_sub not in scrubbed, f"Leaked {secret_sub} in: {scrubbed}"
        assert "2.500.000" in scrubbed or "500.000" in scrubbed

    blk_iocs = extract_iocs("Chuyển ngay vào STK 999888777666 - 2.000.000 VND")
    assert blk_iocs.bank_accounts == ["999888777666"]
    ts_iocs = extract_iocs("Tài khoản nhận: 190311112222. 14:30 26/11/2026")
    assert ts_iocs.bank_accounts == ["190311112222"]

    same_line_rcpt = validate_receipt_logic(
        "CHUYỂN KHOẢN THÀNH CÔNG\nTài khoản nhận: 190311112222 - 5,000.000 VND",
        expected_merchant_account="190311112222",
    )
    assert same_line_rcpt.beneficiary_checked is True
    assert same_line_rcpt.beneficiary_mismatch is False
    assert same_line_rcpt.amount_checked is True
    assert same_line_rcpt.amount_format_anomaly is True

    # 2. Unified multi-line explicit labels & Vietnamese 'đồng phạm/bọn/thời' compounds
    for ml_phrase, secret in (
        ("Tài khoản người nhận:\n654321", "654321"),
        ("Số tài khoản người nhận:\n12.03.2001", "12.03.2001"),
        ("Tài khoản cá nhân:\n654321", "654321"),
        ("TK thụ hưởng:\n654321", "654321"),
        ("STK đến:\n654321", "654321"),
        ("STK: 654321 đồng phạm chiến dịch VNeID", "654321"),
        ("Tài khoản nhận: 123.456.789 đồng bọn lừa đảo", "123.456.789"),
    ):
        assert secret not in scrub_free_text_pii(ml_phrase), ml_phrase

    dong_iocs = extract_iocs("Tài khoản nhận: 999888777666 đồng thời gửi link")
    assert dong_iocs.bank_accounts == ["999888777666"]

    ml_rcpt = validate_receipt_logic(
        "CHUYỂN KHOẢN THÀNH CÔNG\nTài khoản nhận:\n190399998888\nSố tiền: 500.000 VND",
        expected_merchant_account="190311112222",
    )
    assert ml_rcpt.beneficiary_checked is True
    assert ml_rcpt.beneficiary_mismatch is True

    # 3. Unvalidated VietQR Tag 54 PII rejected as TLV invalid & redact_report_pii scrubs amount + dedupes
    bad_t54_qr = build_vietqr_test_payload("970436", "190384756201", amount="STK 190384756201")
    v_t54, ev_t54 = parse_qr_payload(bad_t54_qr)
    assert v_t54.kind == "INVALID_CRC_VIETQR"
    assert v_t54.crc_valid is True
    assert v_t54.tlv_valid is False
    assert v_t54.amount is None
    assert len(ev_t54) >= 1

    # Duplicate Tag 01 inside NAPAS Tag 38.01 must NOT silently downgrade to benign TEXT_QR
    dup_acct_sub = "000697043601121903111122220112999888777666"
    tag38_dup = f"0010A00000072701{len(dup_acct_sub):02d}{dup_acct_sub}0208QRIBFTTA"
    body_3801 = f"00020101021138{len(tag38_dup):02d}{tag38_dup}53037045802VN6304"
    qr_3801 = body_3801 + crc16_ccitt_false(body_3801.encode("ascii"))
    v_3801, ev_3801 = parse_qr_payload(qr_3801, expected_merchant_account="190311112222")
    assert v_3801.kind == "INVALID_CRC_VIETQR"
    assert v_3801.crc_valid is True
    assert v_3801.tlv_valid is False
    assert len(ev_3801) >= 1

    # Legacy/crafted VietQR amount PII scrubbed & bank_accounts deduplicated in redact_report_pii
    crafted_rep = AnalysisReport(
        case_id="vs_r9_dedup",
        created_at="2026-11-26T07:45:00+00:00",
        mode="personal",
        risk_score=75,
        verdict="HIGH_RISK",
        confidence=0.9,
        summary_vi="Cảnh báo.",
        iocs=ExtractedIOCs(bank_accounts=["190384756201"]),
        vietqr_findings=[
            VietQRInfo(
                raw="000201dummy",
                kind="VALID_VIETQR",
                crc_valid=True,
                bank_bin="970436",
                account_number="190384756201",
                amount="Call 0912345678",
            )
        ],
        actions=ActionBundle(pre_transfer=PreTransferIntervention(should_hold_transfer=True)),
    )
    red_crafted = repo.save_report(crafted_rep)
    assert "0912345678" not in red_crafted.model_dump_json()
    assert len(red_crafted.iocs.bank_accounts) == 1

    # 4. Separator-delimited refs stay distinct & invalid refs are NOT registered as replay keys
    sep_a = validate_receipt_logic("CHUYỂN KHOẢN THÀNH CÔNG\nMã GD: FT2633012345-001\nSố tiền: 100.000 VND")
    sep_b = validate_receipt_logic("CHUYỂN KHOẢN THÀNH CÔNG\nMã GD: FT2633012345-002\nSố tiền: 100.000 VND")
    assert sep_a.reference_code == "FT2633012345-001"
    assert sep_b.reference_code == "FT2633012345-002"
    assert sep_a.reference_code != sep_b.reference_code

    slash_a = validate_receipt_logic(
        "CHUYỂN KHOẢN THÀNH CÔNG\nMã GD: VCB20261126/001\nSố tiền: 100.000 VND"
    )
    slash_b = validate_receipt_logic(
        "CHUYỂN KHOẢN THÀNH CÔNG\nMã GD: VCB20261126/002\nSố tiền: 100.000 VND"
    )
    assert slash_a.reference_code == "VCB20261126/001"
    assert slash_b.reference_code == "VCB20261126/002"

    bad_alpha_rcpt = validate_receipt_logic("CHUYỂN KHOẢN THÀNH CÔNG\nMã GD: CHUYEN\nSố tiền: 100.000 VND")
    assert bad_alpha_rcpt.reference_valid is False
    bad_rep = AnalysisReport(
        case_id="vs_r9_badref",
        created_at="2026-11-26T07:45:00+00:00",
        mode="merchant",
        risk_score=45,
        verdict="SUSPICIOUS",
        confidence=0.85,
        receipt_verification_status="TAMPER_OR_LOGIC_ANOMALY",
        summary_vi="Bất thường biên lai.",
        receipt_logic=bad_alpha_rcpt,
        actions=ActionBundle(
            merchant_balance_warning="Kiểm tra biến động số dư hoặc Loa thông báo trước khi giao hàng.",
            pre_transfer=PreTransferIntervention(should_hold_transfer=False),
        ),
    )
    repo.save_report(bad_rep, track_replay=True)
    assert repo.is_receipt_replayed(None, bad_alpha_rcpt.bank_detected, "CHUYEN") is False


def test_delta_r10_bank_above_amount_and_large_vietqr_amount_vs_leading_zero_tag54(
    tmp_path: Path,
) -> None:
    # 1. Bank name immediately above transfer amount must NOT erase amount or mask mixed separators
    clean_below = validate_receipt_logic(
        "CHUYỂN KHOẢN THÀNH CÔNG\nVietcombank\n500.000 VND"
    )
    assert clean_below.amount_checked is True
    assert clean_below.amount_format_anomaly is False

    tampered_comma_dot = validate_receipt_logic(
        "CHUYỂN KHOẢN THÀNH CÔNG\nVietcombank\n5,000.000 VND"
    )
    assert tampered_comma_dot.amount_checked is True
    assert tampered_comma_dot.amount_format_anomaly is True
    assert tampered_comma_dot.logic_risk_points >= 30

    tampered_dot_comma = validate_receipt_logic(
        "CHUYỂN KHOẢN THÀNH CÔNG\nTechcombank\n5.000,000 VND"
    )
    assert tampered_dot_comma.amount_checked is True
    assert tampered_dot_comma.amount_format_anomaly is True
    assert tampered_dot_comma.logic_risk_points >= 30

    # 2. Leading-zero phone-shaped Tag 54 rejected; legitimate >=10,000,000 VND preserved after redaction
    phone_t54 = build_vietqr_test_payload("970436", "190384756201", amount="0912345678")
    v_phone_t54, ev_phone_t54 = parse_qr_payload(phone_t54)
    assert v_phone_t54.kind == "INVALID_CRC_VIETQR"
    assert v_phone_t54.crc_valid is True
    assert v_phone_t54.tlv_valid is False
    assert v_phone_t54.amount is None
    assert len(ev_phone_t54) >= 1

    repo = CaseRepository(str(tmp_path / "r10_vqr.db"))
    repo.init_db()
    big_qr = build_vietqr_test_payload("970436", "190384756201", amount="15000000")
    v_big, _ = parse_qr_payload(big_qr)
    assert v_big.kind == "VALID_VIETQR"
    assert v_big.amount == "15000000"

    big_rep = AnalysisReport(
        case_id="vs_r10_bigamt",
        created_at="2026-11-26T08:02:00+00:00",
        mode="personal",
        risk_score=10,
        verdict="SAFE",
        confidence=0.9,
        summary_vi="Mã VietQR hợp lệ.",
        iocs=ExtractedIOCs(bank_accounts=["190384756201"]),
        vietqr_findings=[v_big],
        actions=ActionBundle(pre_transfer=PreTransferIntervention(should_hold_transfer=False)),
    )
    saved_big = repo.save_report(big_rep)
    loaded_big = repo.get_report("vs_r10_bigamt")
    assert saved_big.vietqr_findings[0].amount == "15000000"
    assert loaded_big is not None
    assert loaded_big.vietqr_findings[0].amount == "15000000"
