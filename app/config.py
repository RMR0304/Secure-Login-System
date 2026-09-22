"""
Configuration Management Module
===============================
Loads and validates application settings from environment variables and .env file
using Pydantic Settings. Ensures strict validation of security parameters.
"""

from functools import lru_cache
from typing import Literal
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with type enforcement and security validation."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )

    APP_ENV: Literal["development", "testing", "production"] = "development"
    DATABASE_URL: str = "sqlite:///./data/secure_password_storage.db"

    # Cryptographic secret for signing sessions and state verification
    SESSION_SECRET: str = Field(
        ...,
        min_length=16,
        description="Cryptographic secret key for session integrity",
    )

    # Session configuration
    SESSION_EXPIRE_MINUTES: int = Field(default=30, ge=1, le=1440)
    COOKIE_SECURE: bool = False

    # Account lockout configuration
    LOCKOUT_MAX_ATTEMPTS: int = Field(default=5, ge=1, le=20)
    LOCKOUT_DURATION_MINUTES: int = Field(default=15, ge=1, le=1440)

    # Recovery token configuration
    RECOVERY_TOKEN_EXPIRE_MINUTES: int = Field(default=10, ge=1, le=120)

    # Argon2id Parameters (RFC 9106 recommended defaults)
    ARGON2_TIME_COST: int = Field(default=2, ge=1, le=10)
    ARGON2_MEMORY_COST: int = Field(default=65536, ge=1024, le=1048576)
    ARGON2_PARALLELISM: int = Field(default=2, ge=1, le=16)

    @field_validator("SESSION_SECRET")
    @classmethod
    def validate_session_secret(cls, v: str) -> str:
        if not v or v.strip() == "" or v == "CHANGE_ME":
            raise ValueError(
                "SESSION_SECRET cannot be empty or default placeholder. Provide a valid secure secret."
            )
        return v


@lru_cache()
def get_settings() -> Settings:
    """Cached accessor for application settings."""
    return Settings()
