"""Core/system and authentication API routes."""
from datetime import datetime
from flask import Blueprint, jsonify, request, current_app
from werkzeug.security import generate_password_hash
from extensions import db
from models.user import User
from models.api_key import APIKey
from services.auth import login_user, logout_user, require_auth

main_bp = Blueprint("main", __name__)

@main_bp.route("/health", methods=["GET"])
def health():
    statuses = {}
    checks = ["database", "authentication", "normalization", "context_isolation", "rule_detector", "ml_detector", "llm_judge", "crypto", "audit"]
    try:
        db.session.execute(db.text("SELECT 1"))
        statuses["database"] = "active"
    except Exception:
        statuses["database"] = "unavailable"
    statuses["application"] = "active"
    statuses["authentication"] = "active" if current_app.config.get("ENABLE_API_AUTH") else "disabled"
    statuses["normalization"] = "active"
    statuses["context_isolation"] = "active"
    statuses["rule_detector"] = "active"
    try:
        from services.ml_detector import MLDetector
        ml=MLDetector(current_app.config.get("ML_BACKEND","tfidf")).detect("health check")
        statuses["ml_detector"] = "active" if ml.get("available") else ml.get("status","unavailable")
    except Exception:
        statuses["ml_detector"] = "unavailable"
    try:
        from services.llm_judge import LLMJudge
        from services.ai_provider import GeminiLLMProvider
        cfg=current_app.config
        enabled=bool(cfg.get("LLM_JUDGE_ENABLED", False))
        mode=cfg.get("LLM_JUDGE_MODE","mock")
        if not enabled:
            judge_status="disabled"
        elif mode=="mock":
            judge_status="active"
        elif mode=="gemini":
            judge_status=GeminiLLMProvider(
                api_key=cfg.get("GEMINI_API_KEY",""),
                model=cfg.get("GEMINI_MODEL","") or GeminiLLMProvider.DEFAULT_MODEL,
                timeout_seconds=cfg.get("GEMINI_TIMEOUT_SECONDS",10),
            ).health_check()["status"]
        else:
            judge_status="unavailable"
        statuses["llm_judge"] = judge_status
    except Exception:
        statuses["llm_judge"] = "unavailable"

    # Detailed Gemini status is safe to expose: no API key is returned.
    try:
        from services.ai_provider import GeminiLLMProvider
        cfg=current_app.config
        gemini=GeminiLLMProvider(
            api_key=cfg.get("GEMINI_API_KEY",""),
            model=cfg.get("GEMINI_MODEL","") or GeminiLLMProvider.DEFAULT_MODEL,
            timeout_seconds=cfg.get("GEMINI_TIMEOUT_SECONDS",10),
        ).health_check()
        gemini["enabled"]=bool(cfg.get("LLM_JUDGE_ENABLED",False))
        if not gemini["enabled"]:
            gemini["status"]="disabled"
        statuses["gemini"]=gemini
    except Exception:
        statuses["gemini"]={"enabled":False,"configured":False,"provider":"gemini","model":None,"status":"unavailable"}
    try:
        from services.crypto_service import CryptoService
        statuses["crypto"]="active" if CryptoService().hmac_secret else "unavailable"
    except Exception: statuses["crypto"]="unavailable"
    try:
        from models.audit_log import AuditLog
        statuses["audit"]="active"
    except Exception: statuses["audit"]="unavailable"
    return jsonify({"success": True, "status": "ok", "service": "PromptShield AI", "part": 4,
                    "timestamp": datetime.utcnow().isoformat(), "subsystems": statuses})

@main_bp.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    identifier = data.get("username") or data.get("email")
    password = data.get("password")
    if not identifier or not password:
        return jsonify({"success": False, "error": "username/email and password are required."}), 400
    user = login_user(identifier, password)
    if not user:
        return jsonify({"success": False, "error": "Invalid credentials."}), 401
    return jsonify({"success": True, "data": {"user": user.to_dict()}})

@main_bp.route("/auth/logout", methods=["POST"])
def logout():
    logout_user()
    return jsonify({"success": True})

@main_bp.route("/auth/me", methods=["GET"])
@require_auth()
def me():
    user = getattr(__import__('flask').g, "current_user", None)
    return jsonify({"success": True, "data": user.to_dict() if user and user.id else {"username": "demo-admin", "role": "ADMIN"}})

@main_bp.route("/keys", methods=["GET"])
@require_auth({"ADMIN"})
def list_keys():
    return jsonify({"success": True, "data": [k.to_dict() for k in APIKey.query.order_by(APIKey.created_at.desc()).all()]})

@main_bp.route("/keys", methods=["POST"])
@require_auth({"ADMIN"})
def create_key():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    role = str(data.get("role", "VIEWER")).upper()
    if not name:
        return jsonify({"success": False, "error": "name is required."}), 400
    if role not in {"ADMIN", "ANALYST", "VIEWER"}:
        return jsonify({"success": False, "error": "Invalid role."}), 400
    key, raw = APIKey.generate(name, role)
    db.session.add(key); db.session.commit()
    return jsonify({"success": True, "data": {**key.to_dict(), "raw_key": raw, "warning": "Store this key now. It will not be shown again."}}), 201

@main_bp.route("/keys/<int:key_id>", methods=["PATCH"])
@require_auth({"ADMIN"})
def update_key(key_id):
    key = db.session.get(APIKey, key_id)
    if not key: return jsonify({"success": False, "error": "API key not found."}), 404
    data = request.get_json(silent=True) or {}
    if "active" in data: key.active = bool(data["active"])
    db.session.commit()
    return jsonify({"success": True, "data": key.to_dict()})

@main_bp.route("/keys/<int:key_id>", methods=["DELETE"])
@require_auth({"ADMIN"})
def delete_key(key_id):
    key = db.session.get(APIKey, key_id)
    if not key: return jsonify({"success": False, "error": "API key not found."}), 404
    db.session.delete(key); db.session.commit()
    return jsonify({"success": True})

@main_bp.route("/keys/<int:key_id>/rotate", methods=["POST"])
@require_auth({"ADMIN"})
def rotate_key(key_id):
    old = db.session.get(APIKey, key_id)
    if not old: return jsonify({"success": False, "error": "API key not found."}), 404
    old.active = False
    key, raw = APIKey.generate(old.name, old.role, old.expires_at)
    db.session.add(key); db.session.commit()
    return jsonify({"success": True, "data": {**key.to_dict(), "raw_key": raw, "warning": "Store this key now. It will not be shown again."}}), 201
