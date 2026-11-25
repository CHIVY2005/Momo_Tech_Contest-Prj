"""Application configuration loaded from environment variables."""

from functools import lru_cache
from typing import Final

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

MAX_UPLOAD_CEILING_BYTES: Final[int] = 10 * 1024 * 1024


class Settings(BaseSettings):
    """Runtime settings for VeriShield AI backend."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "VeriShield AI"
    app_version: str = "2.0.0"

    gemini_api_key: str = ""
    gemini_backup_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"

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


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached runtime settings instance."""
    return Settings()
