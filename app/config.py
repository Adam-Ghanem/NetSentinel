from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_ALLOWED_SQLITE_PREFIXES = ("sqlite:///", "sqlite+pysqlite:///")
_PLACEHOLDER_VALUES = {
    "your_abuseipdb_key_here",
    "your_virustotal_key_here",
    "changeme",
    "replace-me",
}


class Settings(BaseSettings):
    """Validated application configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    ENVIRONMENT: Literal["development", "test", "production"] = "development"
    DATABASE_URL: str = "sqlite:///netsentinel.db"
    ABUSEIPDB_API_KEY: str = Field(default="", repr=False)
    VIRUSTOTAL_API_KEY: str = Field(default="", repr=False)
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    DEMO_MODE: bool = False

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("DATABASE_URL must not be empty")
        if normalized.startswith(_ALLOWED_SQLITE_PREFIXES):
            return normalized
        if "://" not in normalized:
            raise ValueError("DATABASE_URL must be a valid SQLAlchemy URL")
        return normalized

    @field_validator("ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY")
    @classmethod
    def reject_placeholder_secrets(cls, value: str) -> str:
        normalized = value.strip()
        if normalized.lower() in _PLACEHOLDER_VALUES:
            raise ValueError("API key contains a documented placeholder value")
        return normalized

    @model_validator(mode="after")
    def enforce_production_safety(self) -> Settings:
        if self.ENVIRONMENT == "production" and self.DEMO_MODE:
            raise ValueError("DEMO_MODE cannot be enabled in production")
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide validated settings instance."""

    return Settings()


Config = get_settings()
