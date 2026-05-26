"""
Centralized configuration via Pydantic Settings.
Loads from .env file or environment variables.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings — loaded from environment / .env file."""

    # ── Application ──────────────────────────────────────────────
    APP_NAME: str = "SentinelCommand"
    APP_VERSION: str = "1.0.0"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    LOG_LEVEL: str = "INFO"
    SIMULATION_MODE: bool = True

    # ── Database ─────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite+aiosqlite:///./sentinelcommand.db"

    # ── JWT Auth ─────────────────────────────────────────────────
    JWT_SECRET: str = "dev-secret-change-in-production-immediately"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 480

    # ── Audit ────────────────────────────────────────────────────
    AUDIT_HMAC_KEY: str = "dev-audit-key-change-in-production"

    # ── Azure AD (Optional) ──────────────────────────────────────
    AZURE_TENANT_ID: str = ""
    AZURE_CLIENT_ID: str = ""
    AZURE_CLIENT_SECRET: str = ""

    # ── Kafka (Optional) ─────────────────────────────────────────
    KAFKA_BOOTSTRAP_SERVERS: str = ""
    KAFKA_TOPIC: str = "security-events"
    KAFKA_GROUP_ID: str = "sentinelcommand"

    # ── Webhook (Optional) ───────────────────────────────────────
    WEBHOOK_URL: str = ""
    WEBHOOK_TYPE: str = "slack"  # slack | teams | custom

    # ── Prometheus ───────────────────────────────────────────────
    METRICS_ENABLED: bool = True

    # ── Paths ────────────────────────────────────────────────────
    BASE_DIR: str = str(Path(__file__).resolve().parent.parent.parent)
    DATA_DIR: str = ""
    LOG_DIR: str = ""

    def model_post_init(self, __context) -> None:
        if not self.DATA_DIR:
            self.DATA_DIR = os.path.join(self.BASE_DIR, "data")
        if not self.LOG_DIR:
            self.LOG_DIR = os.path.join(self.BASE_DIR, "logs")
        os.makedirs(self.DATA_DIR, exist_ok=True)
        os.makedirs(self.LOG_DIR, exist_ok=True)

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
    }


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings singleton."""
    return Settings()
