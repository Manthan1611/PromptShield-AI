"""Authentication, API-key authentication, and role-based authorization."""

from functools import wraps
from flask import current_app, jsonify, request, session, g
from werkzeug.security import check_password_hash

from extensions import db
from models.user import User
from models.api_key import APIKey

ROLES = {"ADMIN", "ANALYST", "VIEWER"}
ROLE_RANK = {"VIEWER": 1, "ANALYST": 2, "ADMIN": 3}


def _json_error(message, status):
    return jsonify({"success": False, "error": message}), status


def authenticate_request():
    """Authenticate via session or X-API-Key. Returns a User or None."""
    if session.get("user_id"):
        user = db.session.get(User, session["user_id"])
        if user:
            g.current_user = user
            return user
        session.pop("user_id", None)

    raw_key = request.headers.get("X-API-Key") or request.headers.get("Authorization", "")
    if raw_key.lower().startswith("bearer "):
        raw_key = raw_key[7:].strip()
    if raw_key:
        key = APIKey.verify(raw_key)
        if key and key.active and not key.is_expired:
            user = User.query.filter_by(role=key.role).first()
            if user is None:
                # API keys can authenticate independently when no matching user exists.
                user = User(username=f"api:{key.key_prefix}", email=f"{key.key_prefix}@api.local", password_hash="!", role=key.role)
                db.session.add(user)
                db.session.flush()
            key.mark_used()
            db.session.commit()
            g.current_user = user
            g.current_role = key.role.upper()
            g.current_api_key = key
            return user
    return None


def require_auth(roles=None):
    allowed = {r.upper() for r in roles} if roles else None

    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if current_app.config.get("DEMO_MODE", True):
                # Demo mode preserves the existing local application behavior.
                if not getattr(g, "current_user", None):
                    g.current_user = User(
                        id=0, username="demo-admin", email="demo@localhost",
                        password_hash="!", role="ADMIN"
                    )
                return fn(*args, **kwargs)

            user = authenticate_request()
            if user is None:
                return _json_error("Authentication required.", 401)
            role = getattr(g, "current_role", None) or user.role.upper()
            if allowed and role not in allowed:
                return _json_error("Insufficient permissions.", 403)
            return fn(*args, **kwargs)
        return wrapped
    return decorator


def login_user(username_or_email, password):
    user = User.query.filter(
        (User.username == username_or_email) | (User.email == username_or_email)
    ).first()
    if not user or not check_password_hash(user.password_hash, password):
        return None
    session.clear()
    session["user_id"] = user.id
    return user


def logout_user():
    session.clear()
