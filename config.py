
"""
Centralized configuration for PromptShield AI.
Loads environment variables via python-dotenv (see .env.example).
Supports PostgreSQL on Vercel and SQLite for local development.
"""

import os
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))


def get_database_url():
    """Return a SQLAlchemy-compatible database URL."""
    database_url = os.environ.get("DATABASE_URL", "").strip()

    if not database_url:
        return f"sqlite:///{os.path.join(BASE_DIR, 'promptshield.db')}"

    # Normalize PostgreSQL URLs for the psycopg 3 driver.
    if database_url.startswith("postgres://"):
        database_url = database_url.replace(
            "postgres://", "postgresql+psycopg://", 1
        )
    elif database_url.startswith("postgresql://"):
        database_url = database_url.replace(
            "postgresql://", "postgresql+psycopg://", 1
        )

    return database_url


class BaseConfig:
    """Shared configuration."""

    SECRET_KEY = os.environ.get(
        "SECRET_KEY", "dev-secret-key-change-in-production"
    )

    SQLALCHEMY_DATABASE_URI = get_database_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JSON_SORT_KEYS = False

    # AI provider settings
    AI_PROVIDER = os.environ.get("AI_PROVIDER", "mock")
    OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
    OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "")
    OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

    # Risk thresholds
    RISK_THRESHOLD_LOW = int(os.environ.get("RISK_THRESHOLD_LOW", 20))
    RISK_THRESHOLD_MEDIUM = int(os.environ.get("RISK_THRESHOLD_MEDIUM", 40))
    RISK_THRESHOLD_HIGH = int(os.environ.get("RISK_THRESHOLD_HIGH", 60))
    RISK_THRESHOLD_CRITICAL = int(os.environ.get("RISK_THRESHOLD_CRITICAL", 80))

    DEFAULT_DEFENSE_MODE = os.environ.get("DEFAULT_DEFENSE_MODE", "standard")

    ENABLE_API_AUTH = os.environ.get(
        "ENABLE_API_AUTH", "true"
    ).lower() in {"1", "true", "yes", "on"}

    DEMO_MODE = os.environ.get(
        "DEMO_MODE", "true"
    ).lower() in {"1", "true", "yes", "on"}

    RATE_LIMIT = os.environ.get("RATE_LIMIT", "100/minute")

    ENABLE_TLS = os.environ.get(
        "ENABLE_TLS", "false"
    ).lower() in {"1", "true", "yes", "on"}

    SSL_CERT_FILE = os.environ.get("SSL_CERT_FILE", "")
    SSL_KEY_FILE = os.environ.get("SSL_KEY_FILE", "")

    ALLOWED_ORIGINS = [
        origin.strip()
        for origin in os.environ.get(
            "ALLOWED_ORIGINS",
            "http://127.0.0.1:5000,http://localhost:5000",
        ).split(",")
        if origin.strip()
    ]

    ML_BACKEND = os.environ.get("ML_BACKEND", "tfidf")

    # Gemini LLM judge
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
    GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "")
    GEMINI_TIMEOUT_SECONDS = int(
        os.environ.get("GEMINI_TIMEOUT_SECONDS", "10")
    )

    LLM_JUDGE_ENABLED = os.environ.get(
        "LLM_JUDGE_ENABLED", "false"
    ).lower() in {"1", "true", "yes", "on"}

    LLM_JUDGE_MODE = os.environ.get("LLM_JUDGE_MODE", "mock")

    RULE_WEIGHT = float(os.environ.get("RULE_WEIGHT", "0.35"))
    ML_WEIGHT = float(os.environ.get("ML_WEIGHT", "0.40"))
    LLM_JUDGE_WEIGHT = float(os.environ.get("LLM_JUDGE_WEIGHT", "0.25"))

    # Cryptographic and audit settings
    HMAC_SECRET = os.environ.get("HMAC_SECRET", "")
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "")
    AUDIT_SIGNING_KEY = os.environ.get("AUDIT_SIGNING_KEY", "")

    CANARY_ENABLED = os.environ.get(
        "CANARY_ENABLED", "true"
    ).lower() in {"1", "true", "yes", "on"}

    TARGET_SYSTEM_PROMPT = os.environ.get(
        "TARGET_SYSTEM_PROMPT",
        "PromptShield simulated protected system context.",
    )

    SYSTEM_PROMPT_HMAC = os.environ.get("SYSTEM_PROMPT_HMAC", "")


class DevelopmentConfig(BaseConfig):
    DEBUG = True


class ProductionConfig(BaseConfig):
    DEBUG = False


class TestingConfig(BaseConfig):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"


_CONFIGS = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config(name=None):
    name = name or os.environ.get("FLASK_ENV", "development")
    return _CONFIGS.get(name, DevelopmentConfig)
