"""
Application configuration using Pydantic Settings.

This module loads settings from environment variables and .env file.
All secrets should be kept in .env (not committed to git).
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_host: str = "127.0.0.1"
    app_port: int = 8000
    app_env: str = "development"

    # Security policy (server-controlled, not from client)
    # Options: ALLOW, FLAG, BLOCK, SANITIZE
    default_policy: str = "ALLOW"

    # Risk thresholds for display levels
    risk_threshold_low: int = 30
    risk_threshold_medium: int = 60
    risk_threshold_high: int = 80

    # Input size limits (characters)
    max_user_message_length: int = 10000
    max_retrieved_content_length: int = 50000

    # Optional OpenAI provider settings
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o-mini"
    openai_timeout: float = 30.0

    # Audit settings
    audit_store_raw_prompts: bool = False
    database_url: str = "sqlite:///./gateway.db"


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Dependency injection for FastAPI to get settings."""
    return settings