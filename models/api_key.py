"""Hashed API keys. Raw keys are never persisted."""

import hashlib
import hmac
import secrets
from datetime import datetime
from extensions import db


class APIKey(db.Model):
    __tablename__ = "api_keys"

    id = db.Column(db.Integer, primary_key=True)
    key_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    key_prefix = db.Column(db.String(32), nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="VIEWER", index=True)
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_used_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)

    @staticmethod
    def hash_key(raw_key):
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    @classmethod
    def generate(cls, name, role="VIEWER", expires_at=None):
        raw = "ps_live_" + secrets.token_urlsafe(32)
        obj = cls(
            key_hash=cls.hash_key(raw),
            key_prefix=raw[:8],
            name=name,
            role=role.upper(),
            expires_at=expires_at,
        )
        return obj, raw

    @classmethod
    def verify(cls, raw_key):
        digest = cls.hash_key(raw_key)
        candidates = cls.query.filter_by(active=True).all()
        for key in candidates:
            if hmac.compare_digest(key.key_hash, digest):
                return key
        return None

    @property
    def is_expired(self):
        return self.expires_at is not None and self.expires_at <= datetime.utcnow()

    def mark_used(self):
        self.last_used_at = datetime.utcnow()

    def masked(self):
        return f"{self.key_prefix}**************{self.key_hash[-4:].upper()}"

    def to_dict(self):
        return {
            "id": self.id, "name": self.name, "role": self.role,
            "active": self.active, "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "masked_key": self.masked(),
        }
