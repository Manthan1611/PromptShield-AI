"""
PromptShield AI - Application Entrypoint
Interactive LLM Prompt Injection Security Testing & Defense Platform

Run with:
    python app.py

Serves at:
    http://127.0.0.1:5000
"""

import os
import time
from collections import defaultdict, deque

from flask import Flask, jsonify, request, session
from flask_cors import CORS

from config import get_config
import models  # register all SQLAlchemy models for create_all()
from extensions import db, migrate
from routes.main_routes import main_bp
from routes.api_routes import api_bp
from routes.page_routes import page_bp


def session_user_id():
    """Return the currently authenticated session user ID."""
    return session.get("user_id")


def _configure_rate_limiting(app):
    """
    Small dependency-free limiter suitable for local/demo deployments.

    Production deployments should put a shared reverse-proxy limiter
    in front of the application.
    """
    buckets = defaultdict(deque)
    app.extensions["rate_limit_buckets"] = buckets

    def parse_limit(value):
        try:
            count, period = value.split("/", 1)
            count = int(count)

            seconds = {
                "second": 1,
                "minute": 60,
                "hour": 3600
            }.get(period.rstrip("s"), 60)

            return max(1, count), seconds

        except Exception:
            return 100, 60

    @app.before_request
    def _rate_limit():
        # Only apply rate limiting to API routes.
        if not request.path.startswith("/api/"):
            return None

        # Health and login endpoints are excluded.
        if request.path in {
            "/api/health",
            "/api/auth/login"
        }:
            return None

        # Demo mode disables rate limiting.
        if app.config.get("DEMO_MODE"):
            return None

        limit, period = parse_limit(
            app.config.get("RATE_LIMIT", "100/minute")
        )

        # Prefer API key / authorization identity.
        key = (
            request.headers.get("X-API-Key")
            or request.headers.get("Authorization")
        )

        if not key:
            user_id = session_user_id()

            if user_id:
                key = f"user:{user_id}"
            else:
                key = f"ip:{request.remote_addr or 'unknown'}"

        now = time.monotonic()

        q = buckets[key]

        # Remove expired requests.
        while q and now - q[0] >= period:
            q.popleft()

        # Reject if limit exceeded.
        if len(q) >= limit:
            return jsonify({
                "success": False,
                "error": "Rate limit exceeded.",
                "status": 429
            }), 429

        q.append(now)

        return None


def register_error_handlers(app):
    """Register global Flask error handlers."""

    @app.errorhandler(404)
    def not_found(e):
        if _wants_json():
            return jsonify({
                "success": False,
                "error": "Not Found",
                "status": 404
            }), 404

        from flask import render_template
        return render_template("base.html", error_code=404), 404

    @app.errorhandler(500)
    def server_error(e):
        if _wants_json():
            return jsonify({
                "success": False,
                "error": "Internal Server Error",
                "status": 500
            }), 500

        from flask import render_template
        return render_template("base.html", error_code=500), 500

    @app.errorhandler(400)
    def bad_request(e):
        if _wants_json():
            return jsonify({
                "success": False,
                "error": "Bad Request",
                "status": 400
            }), 400

        from flask import render_template
        return render_template("base.html", error_code=400), 400


def _wants_json():
    """Determine whether the request expects an API JSON response."""
    return request.path.startswith("/api/")


def _maybe_seed(app):
    """
    Seed the database with baseline attack scenarios and demo
    SecurityTest records if the database is empty.
    """

    from models.attack_scenario import AttackScenario
    from models.security_test import SecurityTest

    # Seed attack scenarios.
    if AttackScenario.query.count() == 0:
        from database.seed import seed_all

        seed_all()

        app.logger.info(
            "Database seeded with baseline attack scenarios."
        )

    # Seed demo security tests.
    if SecurityTest.query.count() == 0:
        from database.seed import seed_demo_security_tests

        seed_demo_security_tests()

        app.logger.info(
            "Database seeded with demo security test records."
        )


def create_app(config_name=None):
    """
    Application factory.

    Keeps the app modular so Parts 2-4 can register
    additional blueprints / services without touching
    the main application structure.
    """

    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates"
    )

    # ---------------------------------------------------------------
    # Configuration
    # ---------------------------------------------------------------

    app.config.from_object(
        get_config(config_name)
    )

    # ---------------------------------------------------------------
    # Extensions
    # ---------------------------------------------------------------

    db.init_app(app)

    migrate.init_app(
        app,
        db
    )

    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": app.config.get(
                    "ALLOWED_ORIGINS",
                    []
                )
            }
        },
        supports_credentials=True
    )

    _configure_rate_limiting(app)

    # ---------------------------------------------------------------
    # Gemini configuration
    # ---------------------------------------------------------------
    #
    # IMPORTANT:
    # The actual GEMINI_API_KEY is NOT stored in this file.
    #
    # It should be supplied through the .env file:
    #
    # GEMINI_API_KEY=your_key_here
    #
    # The Gemini provider reads it from the environment/config.
    #
    # ---------------------------------------------------------------

    app.config.setdefault(
        "GEMINI_API_KEY",
        os.environ.get("GEMINI_API_KEY", "")
    )

    app.config.setdefault(
        "GEMINI_MODEL",
        os.environ.get("GEMINI_MODEL", "")
    )

    app.config.setdefault(
        "GEMINI_TIMEOUT_SECONDS",
        int(
            os.environ.get(
                "GEMINI_TIMEOUT_SECONDS",
                "10"
            )
        )
    )

    app.config.setdefault(
        "AI_PROVIDER",
        os.environ.get(
            "AI_PROVIDER",
            "mock"
        )
    )

    app.config.setdefault(
        "LLM_JUDGE_ENABLED",
        os.environ.get(
            "LLM_JUDGE_ENABLED",
            "false"
        ).lower() == "true"
    )

    app.config.setdefault(
        "LLM_JUDGE_MODE",
        os.environ.get(
            "LLM_JUDGE_MODE",
            "mock"
        )
    )

    # ---------------------------------------------------------------
    # Blueprints
    # ---------------------------------------------------------------

    app.register_blueprint(
        page_bp
    )

    # /api/health and other core API endpoints
    app.register_blueprint(
        main_bp,
        url_prefix="/api"
    )

    # /api/analyze, /api/detect/llm-judge, etc.
    app.register_blueprint(
        api_bp,
        url_prefix="/api"
    )

    # ---------------------------------------------------------------
    # Error handlers
    # ---------------------------------------------------------------

    register_error_handlers(app)

    # ---------------------------------------------------------------
    # Database bootstrap
    # ---------------------------------------------------------------

    with app.app_context():

        db.create_all()

        from database.schema import ensure_schema

        ensure_schema()

        _maybe_seed(app)

    return app


# -------------------------------------------------------------------
# Application instance
# -------------------------------------------------------------------

app = create_app()


# -------------------------------------------------------------------
# Run application
# -------------------------------------------------------------------

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    debug = (
        os.environ.get(
            "FLASK_DEBUG",
            "1"
        ) == "1"
    )

    print(
        f"\n  PromptShield AI running at "
        f"http://127.0.0.1:{port}\n"
    )

    ssl_context = None

    if (
        app.config.get("ENABLE_TLS")
        and app.config.get("SSL_CERT_FILE")
        and app.config.get("SSL_KEY_FILE")
    ):

        ssl_context = (
            app.config["SSL_CERT_FILE"],
            app.config["SSL_KEY_FILE"]
        )

        print("  TLS enabled")

    app.run(
        host="127.0.0.1",
        port=port,
        debug=debug,
        ssl_context=ssl_context
    )