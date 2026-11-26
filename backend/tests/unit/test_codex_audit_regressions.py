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

    cfg = Settings(
        _env_file=None,
        sqlite_path=str(tmp_path / "tg_opaque.db"),
        gemini_api_key="",
        gemini_backup_api_key="",
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
