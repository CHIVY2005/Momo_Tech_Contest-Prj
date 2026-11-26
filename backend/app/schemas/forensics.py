"""Forensic, VietQR, URL, and sandbox inspection data contracts."""

from pydantic import BaseModel, Field

from app.schemas.common import QrKind, ReceiptVerificationStatus


class VietQRInfo(BaseModel):
    """Decoded EMVCo / NAPAS VietQR payload and cryptographic CRC status."""

    raw: str
    kind: QrKind
    crc_valid: bool
    tlv_valid: bool = True
    bank_bin: str | None = None
    bank_name: str | None = None
    account_number: str | None = None
    service_code: str | None = None
    is_dynamic: bool = False
    amount: str | None = None
    note: str | None = None
    receive_scam_detected: bool = False
    beneficiary_mismatch: bool = False


class SandboxInspection(BaseModel):
    """Isolated Playwright headless browser detonation summary."""

    available: bool
    visited_url: str
    final_url: str | None = None
    page_title: str | None = None
    blocked_ssrf: bool = False
    has_password_field: bool = False
    has_otp_field: bool = False
    has_apk_download: bool = False
    impersonated_brand: str | None = None
    screenshot_base64: str | None = None
    risk_points: int = Field(default=0, ge=0, le=100)
    reasons: list[str] = Field(default_factory=list)


class UrlFinding(BaseModel):
    """Static and network-level URL security inspection result."""

    url: str
    domain: str
    normalized_ascii_domain: str
    final_url: str | None = None
    redirect_hops: int = Field(default=0, ge=0)
    is_blocked_ssrf: bool = False
    is_idn_homoglyph: bool = False
    spoofed_brand: str | None = None
    domain_age_days: int | None = None
    urlhaus_listed: bool = False
    risk_points: int = Field(default=0, ge=0, le=100)
    reasons: list[str] = Field(default_factory=list)


class ImageForensicsResult(BaseModel):
    """Physical image forensics (ELA, EXIF, perceptual hash, QR, local OCR)."""

    filename: str
    format: str
    width: int = Field(gt=0)
    height: int = Field(gt=0)
    dhash_hex: str
    exif_software: str | None = None
    editing_software_detected: bool = False
    tamper_score: int = Field(default=0, ge=0, le=100)
    ela_heatmap_base64: str | None = None
    qr_payloads: list[str] = Field(default_factory=list)
    ocr_text: str = ""
    ocr_height_cv: float = Field(default=0.0, ge=0.0)
    reasons: list[str] = Field(default_factory=list)


class ReceiptLogicResult(BaseModel):
    """Vietnamese bank transfer receipt business-logic and geometry checks."""

    is_receipt_candidate: bool
    bank_detected: str | None = None
    reference_code: str | None = None
    reference_valid: bool = True
    timestamp_checked: bool = False
    timestamp_anomaly: bool = False
    amount_checked: bool = False
    amount_format_anomaly: bool = False
    geometry_checked: bool = False
    geometry_anomaly: bool = False
    beneficiary_checked: bool = False
    beneficiary_mismatch: bool = False
    extracted_recipient_account: str | None = None
    replay_checked: bool = False
    is_replayed: bool = False
    verification_status: ReceiptVerificationStatus = "NOT_APPLICABLE"
    logic_risk_points: int = Field(default=0, ge=0, le=100)
    reasons: list[str] = Field(default_factory=list)
