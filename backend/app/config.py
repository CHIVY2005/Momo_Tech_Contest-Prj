"""Application configuration loaded from backend/.env or environment variables."""

import hashlib
from functools import lru_cache
from pathlib import Path
from typing import Final, Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MAX_UPLOAD_CEILING_BYTES: Final[int] = 10 * 1024 * 1024
AppEnvSetting = Literal["demo", "development", "production"]
LlmProviderSetting = Literal["auto", "openai_compatible", "google_genai"]
ResolvedLlmProvider = Literal["openai_compatible", "google_genai"]
OcrProviderSetting = Literal["rapidocr_v5_latin", "rapidocr_v4", "mineru_basic_onnx", "disabled"]

_BACKEND_DIR: Final[Path] = Path(__file__).resolve().parents[1]
_REPO_ROOT_DIR: Final[Path] = _BACKEND_DIR.parent


class Settings(BaseSettings):
    """Runtime settings for VeriShield AI backend (supports both CPA OpenAI API & Google GenAI)."""

    model_config = SettingsConfigDict(
        env_file=(
            str(_REPO_ROOT_DIR / ".env"),
            str(_BACKEND_DIR / ".env"),
        ),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "VeriShield AI"
    app_version: str = "2.0.0"
    app_env: AppEnvSetting = "development"

    llm_provider: LlmProviderSetting = "auto"
    gemini_base_url: str = ""
    gemini_api_key: str = ""
    gemini_backup_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"
    llm_timeout_sec: float = Field(default=35.0, ge=2.0, le=120.0)
    llm_max_retries: int = Field(default=2, ge=0, le=5)

    telegram_bot_token: str = ""
    telegram_webhook_secret: str = ""
    telegram_bot_url: str = ""
    public_base_url: str = "https://verishield.joiboi.app"

    analyst_pin: str = ""
    ioc_hmac_secret: str = ""
    block_rule_ttl_minutes: int = Field(default=30, ge=1, le=1440)

    model_dir: str = "app/data/models"
    sqlite_path: str = "verishield.db"
    max_upload_bytes: int = Field(
        default=MAX_UPLOAD_CEILING_BYTES,
        ge=1024,
        le=MAX_UPLOAD_CEILING_BYTES,
    )
    max_images_per_request: int = Field(default=4, ge=1, le=8)
    max_audios_per_request: int = Field(default=2, ge=1, le=4)

    enable_live_network_checks: bool = True
    enable_playwright_sandbox: bool = True
    enable_local_ocr: bool = True
    enable_local_stt: bool = True
    ocr_provider: OcrProviderSetting = "rapidocr_v5_latin"
    ocr_model_dir: str = ""
    ocr_timeout_sec: float = Field(default=8.0, ge=0.5, le=30.0)
    ocr_max_concurrency: int = Field(default=2, ge=1, le=4)
    enable_gemini_ocr_fallback: bool = True

    rate_limit_per_minute: int = Field(default=45, ge=1)
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])

    @field_validator("llm_provider", mode="before")
    @classmethod
    def _normalize_provider(cls, raw: object) -> str:
        if not isinstance(raw, str):
            return "auto"
        cleaned = raw.strip().lower().replace("-", "_")
        if cleaned in ("", "auto"):
            return "auto"
        if cleaned in ("openai", "openai_compatible", "cpa", "cliproxyapi"):
            return "openai_compatible"
        if cleaned in ("google", "gemini", "google_genai", "genai"):
            return "google_genai"
        raise ValueError(
            f"Unsupported LLM_PROVIDER={raw!r}. Expected 'auto', 'openai_compatible', or 'google_genai'."
        )

    @model_validator(mode="after")
    def _validate_production_secrets(self) -> "Settings":
        pin = self.analyst_pin.strip()
        if self.app_env == "demo" and not pin:
            self.analyst_pin = "2026"
            return self

        placeholder_pins = {
            "change_me",
            "changeme",
            "change_me_strong_analyst_pin",
            "your_pin_here",
            "example",
            "password",
            "1234",
            "0000",
        }
        if pin.lower() in placeholder_pins:
            raise ValueError("ANALYST_PIN cannot be a placeholder/example value.")
        if self.app_env != "demo" and pin == "2026":
            raise ValueError(
                f"APP_ENV={self.app_env} forbids the published contest demo ANALYST_PIN ('2026')."
            )
        if self.app_env == "production" and len(pin) < 8:
            raise ValueError("APP_ENV=production requires ANALYST_PIN of at least 8 characters.")

        hmac_secret = self.ioc_hmac_secret.strip()
        if hmac_secret:
            if hmac_secret.lower() in placeholder_pins or hmac_secret.lower().startswith("change_me"):
                raise ValueError("IOC_HMAC_SECRET cannot be a placeholder/example value.")
            if self.app_env == "production" and len(hmac_secret) < 16:
                raise ValueError("APP_ENV=production requires IOC_HMAC_SECRET of at least 16 characters.")
        return self

    @property
    def resolved_ioc_hmac_secret(self) -> str:
        """Return explicit IOC_HMAC_SECRET, or derive a domain-separated key in production."""
        explicit = self.ioc_hmac_secret.strip()
        if explicit:
            return explicit
        if self.app_env == "production" and self.analyst_pin.strip():
            # Domain-separated fallback ensures production never uses unsalted SHA-256 even
            # before IOC_HMAC_SECRET is explicitly provisioned in deploy/.env.prod.
            return hashlib.sha256(
                f"verishield-ioc-hmac-v1:{self.analyst_pin.strip()}".encode()
            ).hexdigest()
        return ""

    @property
    def resolved_llm_provider(self) -> ResolvedLlmProvider:
        """Resolve effective provider based on explicit setting or GEMINI_BASE_URL presence."""
        if self.llm_provider == "openai_compatible":
            return "openai_compatible"
        if self.llm_provider == "google_genai":
            return "google_genai"
        return "openai_compatible" if self.gemini_base_url.strip() else "google_genai"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached runtime settings instance."""
    return Settings()
