"""Pure 3-signal risk calibration with deterministic security floors, caps, and merchant status."""

from __future__ import annotations

from pydantic import BaseModel

from app.schemas import (
    AnalyzeMode,
    ImageForensicsResult,
    ReceiptLogicResult,
    ReceiptVerificationStatus,
    SandboxInspection,
    ScamClassifierOutput,
    UrlFinding,
    VerdictLevel,
    VietQRInfo,
    score_to_verdict,
)
from app.services.guardrails import GuardrailResult


class CalibrationResult(BaseModel):
    """Calibrated final score, verdict, confidence, and receipt verification status."""

    final_score: int
    verdict: VerdictLevel
    confidence: float
    receipt_verification_status: ReceiptVerificationStatus


def _has_hard_threat(
    guardrails: GuardrailResult,
    url_findings: list[UrlFinding],
    vietqr_findings: list[VietQRInfo],
    sandbox: SandboxInspection | None,
    image_forensics: ImageForensicsResult | None,
    receipt_logic: ReceiptLogicResult | None,
    has_visual_bill_anomaly: bool = False,
) -> bool:
    if guardrails.prompt_injection_detected or has_visual_bill_anomaly:
        return True
    if any(
        u.is_blocked_ssrf or u.spoofed_brand or u.is_idn_homoglyph or u.risk_points >= 40
        for u in url_findings
    ):
        return True
    if any(
        v.kind == "INVALID_CRC_VIETQR" or v.receive_scam_detected or v.beneficiary_mismatch
        for v in vietqr_findings
    ):
        return True
    if sandbox and (sandbox.blocked_ssrf or sandbox.risk_points >= 40):
        return True
    if image_forensics and image_forensics.tamper_score >= 35:
        return True
    return bool(receipt_logic and receipt_logic.logic_risk_points > 0)


def calibrate_risk(
    mode: AnalyzeMode,
    tier1_score: int,
    classifier: ScamClassifierOutput | None,
    ai_score: int | None,
    guardrails: GuardrailResult,
    url_findings: list[UrlFinding],
    vietqr_findings: list[VietQRInfo],
    sandbox: SandboxInspection | None,
    image_forensics: ImageForensicsResult | None,
    receipt_logic: ReceiptLogicResult | None,
    active_block_rule_hit: bool,
    in_active_call: bool,
    has_visual_bill_anomaly: bool = False,
) -> CalibrationResult:
    """Fuse Tier-1, Dual-Head ONNX, and Gemini signals while enforcing hard safety invariants."""
    t1 = max(0, min(100, tier1_score))
    onnx_avail = classifier is not None and classifier.available
    onnx_score = round(classifier.scam_probability * 100) if (classifier and onnx_avail) else 0
    llm_avail = ai_score is not None
    llm_val = max(0, min(100, ai_score)) if ai_score is not None else 0

    if onnx_avail and llm_avail:
        fused = round(0.30 * t1 + 0.35 * onnx_score + 0.35 * llm_val)
        confidence = 0.93
    elif onnx_avail:
        fused = round(0.45 * t1 + 0.55 * onnx_score)
        confidence = 0.84
    elif llm_avail:
        fused = round(0.45 * t1 + 0.55 * llm_val)
        confidence = 0.86
    else:
        fused = t1
        confidence = 0.74

    if in_active_call and max(fused, t1, onnx_score) >= 25:
        fused += 10

    hard_threat = _has_hard_threat(
        guardrails=guardrails,
        url_findings=url_findings,
        vietqr_findings=vietqr_findings,
        sandbox=sandbox,
        image_forensics=image_forensics,
        receipt_logic=receipt_logic,
        has_visual_bill_anomaly=has_visual_bill_anomaly,
    )

    is_neural_advisory = bool(
        onnx_avail
        and classifier is not None
        and not guardrails.advisory_vetoed
        and classifier.predicted_label == "SAFE_ADVISORY"
        and classifier.advisory_probability >= 0.70
        and (ai_score is None or llm_val < 45)
    )

    advisory_overridden_by_signals = bool(
        in_active_call
        or (onnx_avail and classifier is not None and classifier.scam_probability >= 0.75)
        or (
            onnx_avail
            and classifier is not None
            and classifier.scam_probability >= 0.50
            and llm_avail
            and llm_val >= 75
        )
    )

    # 1. Active Fraud Ops Block Rule always overrides (>= 95)
    if active_block_rule_hit:
        fused = max(fused, 96)
        confidence = 0.99
    # 2. Official Safety Advisory Cap (<= 20) when free of threat/scam indicators and not vetoed
    elif (
        (guardrails.safety_advisory_detected or is_neural_advisory)
        and not guardrails.advisory_vetoed
        and not hard_threat
        and not advisory_overridden_by_signals
    ):
        fused = min(fused, 16)
        confidence = max(confidence, 0.92)
    else:
        # 3. Deterministic Cybersecurity & Forensics Floors
        if guardrails.prompt_injection_detected:
            fused = max(fused, 78)
        if any(
            u.is_blocked_ssrf or u.spoofed_brand or u.is_idn_homoglyph or u.risk_points >= 75
            for u in url_findings
        ):
            fused = max(fused, 82)
        if any(v.receive_scam_detected or v.beneficiary_mismatch for v in vietqr_findings):
            fused = max(fused, 85)
        elif any(v.kind == "INVALID_CRC_VIETQR" for v in vietqr_findings):
            fused = max(fused, 72)

        if sandbox:
            if sandbox.blocked_ssrf or sandbox.has_apk_download or sandbox.risk_points >= 75:
                fused = max(fused, 85)
            elif sandbox.risk_points >= 40:
                fused = max(fused, 52)

        if receipt_logic:
            if receipt_logic.is_replayed or receipt_logic.beneficiary_mismatch:
                fused = max(fused, 85)
            elif receipt_logic.logic_risk_points >= 40:
                fused = max(fused, 72)
            elif receipt_logic.logic_risk_points > 0 or (
                receipt_logic.is_receipt_candidate
                and receipt_logic.verification_status
                not in ("NOT_APPLICABLE", "UNVERIFIED_SCREENSHOT")
            ):
                fused = max(fused, 45)

        if image_forensics:
            if image_forensics.tamper_score >= 50:
                fused = max(fused, 70)
            elif image_forensics.tamper_score >= 35:
                fused = max(fused, 45)

        if has_visual_bill_anomaly:
            fused = max(fused, 45)

    final_score = max(0, min(100, fused))
    verdict = score_to_verdict(final_score)

    # Derive ReceiptVerificationStatus strictly from receipt & payment-QR forensic evidence
    has_qr_beneficiary_mismatch = any(v.beneficiary_mismatch for v in vietqr_findings)
    has_qr_payment_anomaly = any(
        v.receive_scam_detected or v.kind == "INVALID_CRC_VIETQR" for v in vietqr_findings
    )
    has_receipt_specific_anomaly = bool(
        (image_forensics is not None and image_forensics.tamper_score >= 35)
        or (receipt_logic is not None and receipt_logic.logic_risk_points > 0)
        or has_visual_bill_anomaly
        or (mode == "merchant" and has_qr_payment_anomaly)
    )
    receipt_status: ReceiptVerificationStatus = "NOT_APPLICABLE"
    if receipt_logic and receipt_logic.is_replayed:
        receipt_status = "REPLAYED_RECEIPT"
    elif (receipt_logic and receipt_logic.beneficiary_mismatch) or (
        mode == "merchant" and has_qr_beneficiary_mismatch
    ):
        receipt_status = "BENEFICIARY_MISMATCH"
    elif receipt_logic and receipt_logic.is_receipt_candidate:
        receipt_status = receipt_logic.verification_status
        if receipt_status == "UNVERIFIED_SCREENSHOT" and has_receipt_specific_anomaly:
            receipt_status = "TAMPER_OR_LOGIC_ANOMALY"
    elif mode == "merchant" and (image_forensics is not None or bool(vietqr_findings)):
        receipt_status = (
            "TAMPER_OR_LOGIC_ANOMALY" if has_receipt_specific_anomaly else "UNVERIFIED_SCREENSHOT"
        )

    return CalibrationResult(
        final_score=final_score,
        verdict=verdict,
        confidence=round(confidence, 2),
        receipt_verification_status=receipt_status,
    )
