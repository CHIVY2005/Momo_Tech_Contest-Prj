"""Application configuration loaded from backend/.env or environment variables."""

from functools import lru_cache
from pathlib import Path
from typing import Final, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MAX_UPLOAD_CEILING_BYTES: Final[int] = 10 * 1024 * 1024
LlmProviderSetting = Literal["auto", "openai_compatible", "google_genai"]
ResolvedLlmProvider = Literal["openai_compatible", "google_genai"]

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

    llm_provider: LlmProviderSetting = "auto"
    gemini_base_url: str = ""
    gemini_api_key: str = ""
    gemini_backup_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"
    llm_timeout_sec: float = Field(default=35.0, ge=2.0, le=120.0)
    llm_max_retries: int = Field(default=2, ge=0, le=5)

    telegram_bot_token: str = ""
    telegram_webhook_secret: str = ""

    analyst_pin: str = "2026"
    block_rule_ttl_minutes: int = Field(default=30, ge=1, le=1440)

    model_dir: str = "app/data/models"
    sqlite_path: str = "verishield.db"
    max_upload_bytes: int = Field(
        default=MAX_UPLOAD_CEILING_BYTES,
        ge=1024,
        le=MAX_UPLOAD_CEILING_BYTES,
    )

    enable_live_network_checks: bool = True
    enable_playwright_sandbox: bool = True
    enable_local_ocr: bool = True
    enable_local_stt: bool = True

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
