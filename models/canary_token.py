from datetime import datetime
from extensions import db
class CanaryToken(db.Model):
    __tablename__ = "canary_tokens"
    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(128), nullable=False, unique=True)
    label = db.Column(db.String(120), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
