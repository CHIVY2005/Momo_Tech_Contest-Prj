"""Analysis report, classifier output, action copilot, and demo scenario contracts."""

from pydantic import BaseModel, Field, model_validator

from app.schemas.common import (
    AnalyzeMode,
    EvidenceItem,
    ExtractedIOCs,
    ReceiptVerificationStatus,
    TraceStep,
    VerdictLevel,
    score_to_verdict,
)
from app.schemas.forensics import (
    ImageForensicsResult,
    ReceiptLogicResult,
    SandboxInspection,
    UrlFinding,
    VietQRInfo,
)


class ScamClassifierOutput(BaseModel):
    """Prediction from the pruned multilingual-e5-small INT8 ONNX classifier."""

    available: bool
    predicted_label: str = "SAFE_NORMAL"
    scam_probability: float = Field(default=0.0, ge=0.0, le=1.0)
    advisory_probability: float = Field(default=0.0, ge=0.0, le=1.0)
    injection_probability: float = Field(default=0.0, ge=0.0, le=1.0)
    class_probabilities: dict[str, float] = Field(default_factory=dict)
    latency_ms: int = Field(default=0, ge=0)


class PreTransferIntervention(BaseModel):
    """Psychological cooling-off intervention before wallet transfer confirmation."""

    should_hold_transfer: bool
    cooling_off_seconds: int = Field(default=0, ge=0)
    triggered_by_active_call: bool = False
    blocked_by_ops_rule: bool = False
    warning_headline: str = ""
    verification_questions: list[str] = Field(default_factory=list)


class ActionBundle(BaseModel):
    """Actionable protective steps, counter-replies, and merchant balance reminder."""

    counter_replies: list[str] = Field(default_factory=list)
    family_shield_message: str = ""
    urgent_steps: list[str] = Field(default_factory=list)
    merchant_balance_warning: str | None = None
    pre_transfer: PreTransferIntervention


class DemoScenario(BaseModel):
    """One-click realistic Vietnamese scam or safety-control scenario for judges."""

    demo_id: str
    title_vi: str
    subtitle_vi: str
    category_badge: str
    mode: AnalyzeMode
    in_active_call: bool = False
    transfer_amount: int | None = None
    expected_merchant_account: str | None = None
    text: str = ""
    url: str | None = None
    image_filename: str | None = None
    audio_filename: str | None = None
    expected_verdict: VerdictLevel


class AnalysisReport(BaseModel):
    """Complete calibrated investigation report persisted and returned to clients."""

    case_id: str
    created_at: str
    mode: AnalyzeMode
    in_active_call: bool = False
    risk_score: int = Field(ge=0, le=100)
    verdict: VerdictLevel
    confidence: float = Field(ge=0.0, le=1.0)
    degraded_mode: bool = False
    safety_advisory_detected: bool = False
    prompt_injection_detected: bool = False
    active_block_rule_hit: bool = False
    receipt_verification_status: ReceiptVerificationStatus = "NOT_APPLICABLE"
    summary_vi: str
    transcript: str | None = None
    classifier: ScamClassifierOutput | None = None
    matched_playbooks: list[str] = Field(default_factory=list)
    manipulation_tactics: list[str] = Field(default_factory=list)
    highlighted_phrases: list[str] = Field(default_factory=list)
    iocs: ExtractedIOCs = Field(default_factory=ExtractedIOCs)
    vietqr_findings: list[VietQRInfo] = Field(default_factory=list)
    url_findings: list[UrlFinding] = Field(default_factory=list)
    sandbox: SandboxInspection | None = None
    image_forensics: ImageForensicsResult | None = None
    receipt_logic: ReceiptLogicResult | None = None
    evidence: list[EvidenceItem] = Field(default_factory=list)
    actions: ActionBundle
    trace: list[TraceStep] = Field(default_factory=list)
    community_hits: int = Field(default=0, ge=0)
    llm_provider: str = "none"
    llm_model: str | None = None
    llm_latency_ms: int | None = Field(default=None, ge=0)
    llm_attempts: int = Field(default=0, ge=0)
    llm_failed_attempts: int = Field(default=0, ge=0)
    llm_error: str | None = None

    @model_validator(mode="after")
    def _enforce_report_invariants(self) -> "AnalysisReport":
        expected_verdict = score_to_verdict(self.risk_score)
        if self.verdict != expected_verdict:
            raise ValueError(
                f"verdict {self.verdict!r} contradicts risk_score {self.risk_score} "
                f"(expected {expected_verdict!r})"
            )

        is_merchant_receipt = self.mode == "merchant" and (
            self.image_forensics is not None
            or (self.receipt_logic is not None and self.receipt_logic.is_receipt_candidate)
        )
        if is_merchant_receipt:
            if self.verdict == "SAFE" and self.receipt_verification_status != "UNVERIFIED_SCREENSHOT":
                raise ValueError(
                    "SAFE merchant receipt must set receipt_verification_status='UNVERIFIED_SCREENSHOT'"
                )
            if self.receipt_verification_status == "NOT_APPLICABLE":
                raise ValueError(
                    "Merchant receipt report cannot use receipt_verification_status='NOT_APPLICABLE'"
                )
            warning = self.actions.merchant_balance_warning
            if not (warning and warning.strip()):
                raise ValueError(
                    "Merchant receipt report must populate actions.merchant_balance_warning"
                )
            w_low = warning.lower()
            negated_phrases = (
                "không cần kiểm tra",
                "khỏi kiểm tra",
                "không phải kiểm tra",
                "có thể giao hàng ngay",
                "đã nhận đủ tiền",
            )
            if any(neg in w_low for neg in negated_phrases):
                raise ValueError(
                    "Merchant receipt warning must never negate balance verification"
                )
            has_check_verb = any(
                v in w_low
                for v in ("kiểm tra", "đối chiếu", "xác nhận", "chỉ giao hàng", "verify", "check")
            )
            has_balance_target = any(
                kw in w_low
                for kw in ("số dư", "loa thông báo", "soundbox", "ứng dụng ngân hàng", "balance")
            )
            if not (has_check_verb and has_balance_target):
                raise ValueError(
                    "Merchant receipt warning must instruct verifying actual balance or Soundbox"
                )
        return self
