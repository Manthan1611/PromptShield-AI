"""
Centralized configuration for PromptShield AI.
Loads environment variables via python-dotenv (see .env.example).
"""

import os
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))


class BaseConfig:
    """Shared configuration."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'promptshield.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JSON_SORT_KEYS = False

    # AI Provider settings (mock by default; no API key required)
    AI_PROVIDER = os.environ.get("AI_PROVIDER", "mock")
    OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
    OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "")
    OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

    # Risk engine thresholds (band ceilings -- score <= LOW is SAFE, etc.)
    # SAFE 0-20 / LOW 21-40 / MEDIUM 41-60 / HIGH 61-80 / CRITICAL 81-100
    RISK_THRESHOLD_LOW = int(os.environ.get("RISK_THRESHOLD_LOW", 20))
    RISK_THRESHOLD_MEDIUM = int(os.environ.get("RISK_THRESHOLD_MEDIUM", 40))
    RISK_THRESHOLD_HIGH = int(os.environ.get("RISK_THRESHOLD_HIGH", 60))
    RISK_THRESHOLD_CRITICAL = int(os.environ.get("RISK_THRESHOLD_CRITICAL", 80))

    # Default defense mode for the Security Lab / API when not specified.
    DEFAULT_DEFENSE_MODE = os.environ.get("DEFAULT_DEFENSE_MODE", "standard")

    ENABLE_API_AUTH = os.environ.get("ENABLE_API_AUTH", "true").lower() in {"1", "true", "yes", "on"}
    DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() in {"1", "true", "yes", "on"}
    RATE_LIMIT = os.environ.get("RATE_LIMIT", "100/minute")
    ENABLE_TLS = os.environ.get("ENABLE_TLS", "false").lower() in {"1", "true", "yes", "on"}
    SSL_CERT_FILE = os.environ.get("SSL_CERT_FILE", "")
    SSL_KEY_FILE = os.environ.get("SSL_KEY_FILE", "")
    ALLOWED_ORIGINS = [x.strip() for x in os.environ.get("ALLOWED_ORIGINS", "http://127.0.0.1:5000,http://localhost:5000").split(",") if x.strip()]
    ML_BACKEND = os.environ.get("ML_BACKEND", "tfidf")
    # Optional semantic LLM judge. Disabled by default so the app remains offline.
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
    GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "")
    GEMINI_TIMEOUT_SECONDS = int(os.environ.get("GEMINI_TIMEOUT_SECONDS", "10"))
    LLM_JUDGE_ENABLED = os.environ.get("LLM_JUDGE_ENABLED", "false").lower() in {"1", "true", "yes", "on"}
    LLM_JUDGE_MODE = os.environ.get("LLM_JUDGE_MODE", "mock")
    RULE_WEIGHT = float(os.environ.get("RULE_WEIGHT", "0.35"))
    ML_WEIGHT = float(os.environ.get("ML_WEIGHT", "0.40"))
    LLM_JUDGE_WEIGHT = float(os.environ.get("LLM_JUDGE_WEIGHT", "0.25"))
    # Part 3 cryptographic / audit security settings
    HMAC_SECRET = os.environ.get("HMAC_SECRET", "")
    ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "")
    AUDIT_SIGNING_KEY = os.environ.get("AUDIT_SIGNING_KEY", "")
    CANARY_ENABLED = os.environ.get("CANARY_ENABLED", "true").lower() in {"1", "true", "yes", "on"}
    TARGET_SYSTEM_PROMPT = os.environ.get("TARGET_SYSTEM_PROMPT", "PromptShield simulated protected system context.")
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
