"""Application configuration via pydantic-settings.
All secrets are loaded from a .env file — never hardcoded.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(Path(__file__).parent.parent / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Google OAuth2 ────────────────────────────────────────────────────────
    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: str
    OAUTH_REDIRECT_URI: str = "http://127.0.0.1:8088/auth/callback"
    OAUTH_SCOPES: str = (
        "openid email profile "
        "https://www.googleapis.com/auth/gmail.readonly "
        "https://www.googleapis.com/auth/gmail.modify"
    )

    # ── Google APIs ──────────────────────────────────────────────────────────
    SAFE_BROWSING_API_KEY: str = ""
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-3.5-flash"

    # ── Pub/Sub ──────────────────────────────────────────────────────────────
    PUBSUB_TOPIC: str = ""              # projects/{proj}/topics/{topic}
    PUBSUB_PUSH_AUDIENCE: str = ""     # audience claim in Google's push JWT

    # ── Security ─────────────────────────────────────────────────────────────
    FERNET_KEY: str                     # base64-encoded 32-byte key
    SESSION_SECRET: str                 # random string for cookie signing
    SESSION_COOKIE_NAME: str = "threatlens_session"
    SESSION_MAX_AGE: int = 86400 * 7   # 7 days

    # ── Database ─────────────────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite+aiosqlite:///./threat_detection.db"

    # ── GeoIP ────────────────────────────────────────────────────────────────
    GEOIP_DB_PATH: Optional[str] = None   # path to GeoLite2-City.mmdb
    GEOIP_USE_IPAPI: bool = True           # fallback to ip-api.com if True

    # ── Pipeline Weights ─────────────────────────────────────────────────────
    WEIGHT_SPF_DKIM_DMARC: float = 0.30
    WEIGHT_GEOIP: float = 0.20
    WEIGHT_LLM: float = 0.35
    WEIGHT_SAFE_BROWSING: float = 0.15

    # ── Scoring Thresholds ───────────────────────────────────────────────────
    THRESHOLD_MEDIUM: float = 0.40
    THRESHOLD_HIGH: float = 0.70

    # ── Data Retention ───────────────────────────────────────────────────────────
    # Phase 1: Strip raw_headers_encrypted after N days (removes PII from headers)
    RETENTION_HEADERS_DAYS: int = 30
    # Phase 2: Hard-delete full ThreatScore records after N days
    RETENTION_DELETE_DAYS: int = 90

    # ── Server ───────────────────────────────────────────────────────────────
    HOST: str = "127.0.0.1"
    PORT: int = 8088
    DEBUG: bool = False
    ALLOWED_ORIGINS: str = ""  # Comma-separated list of extra allowed CORS origins
    FRONTEND_URL: str = ""     # Public URL of frontend (e.g. https://threatlens.vercel.app)

    @field_validator("FERNET_KEY", mode="before")
    @classmethod
    def validate_fernet_key(cls, v: str) -> str:
        if not v:
            raise ValueError("FERNET_KEY must be set in .env")
        return v

    @field_validator("SESSION_SECRET", mode="before")
    @classmethod
    def validate_session_secret(cls, v: str) -> str:
        if not v or len(v) < 32:
            raise ValueError("SESSION_SECRET must be at least 32 characters")
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
