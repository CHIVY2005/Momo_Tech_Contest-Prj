"""Shared core enums, primitives, and verdict mapping helpers."""

from typing import Literal

from pydantic import BaseModel, Field

VerdictLevel = Literal["SAFE", "SUSPICIOUS", "HIGH_RISK", "CRITICAL_SCAM"]
AnalyzeMode = Literal["personal", "merchant", "wallet_transfer"]
SeverityLevel = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
TraceStatus = Literal["running", "done", "warning", "skipped"]
IocType = Literal["phone", "bank_account", "domain"]
ReceiptVerificationStatus = Literal[
    "NOT_APPLICABLE",
    "UNVERIFIED_SCREENSHOT",
    "TAMPER_OR_LOGIC_ANOMALY",
    "REPLAYED_RECEIPT",
    "BENEFICIARY_MISMATCH",
]
QrKind = Literal["VALID_VIETQR", "INVALID_CRC_VIETQR", "URL_QR", "TEXT_QR"]

SCAM_LABELS: tuple[str, ...] = (
    "SAFE_NORMAL",
    "SAFE_ADVISORY",
    "SCAM_IMPERSONATION",
    "SCAM_TASK_INVEST_LOAN",
    "SCAM_PHISHING_APK_OTP",
    "SCAM_URGENT_BORROW",
    "PROMPT_INJECTION",
)


def score_to_verdict(score: int) -> VerdictLevel:
    """Map calibrated 0..100 risk score to one of the four fixed verdict levels."""
    if score < 0 or score > 100:
        raise ValueError(f"Risk score must be in 0..100, got {score}")
    if score <= 24:
        return "SAFE"
    if score <= 54:
        return "SUSPICIOUS"
    if score <= 79:
        return "HIGH_RISK"
    return "CRITICAL_SCAM"


class TraceStep(BaseModel):
    """Single live pipeline step streamed over SSE."""

    step_id: str
    title: str
    status: TraceStatus
    detail: str
    duration_ms: int = Field(default=0, ge=0)


class EvidenceItem(BaseModel):
    """Auditable piece of deterministic or multimodal evidence."""

    source: str
    severity: SeverityLevel
    title: str
    detail: str
    snippet: str | None = None


class ExtractedIOCs(BaseModel):
    """Normalized indicators of compromise extracted from user artifacts."""

    phones: list[str] = Field(default_factory=list)
    bank_accounts: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    brands: list[str] = Field(default_factory=list)
