"""SecurityTest model. Field names are part of the fixed database contract."""

from datetime import datetime
from extensions import db


class SecurityTest(db.Model):
    __tablename__ = "security_tests"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    prompt = db.Column(db.Text, nullable=False)
    attack_type = db.Column(db.String(80), nullable=True, index=True)
    difficulty = db.Column(db.String(20), nullable=True)  # easy / medium / hard

    risk_score = db.Column(db.Integer, nullable=True)      # 0-100
    risk_level = db.Column(db.String(20), nullable=True)   # low / medium / high / critical
    confidence = db.Column(db.Float, nullable=True)        # 0.0-1.0

    detection_result = db.Column(db.Text, nullable=True)   # JSON-serialized detection details
    defense_mode = db.Column(db.String(40), nullable=True)  # e.g. "monitor" / "block" / "sanitize"
    final_decision = db.Column(db.String(40), nullable=True)  # e.g. "allow" / "block" / "flag"

    events = db.relationship(
        "SecurityEvent", backref="test", lazy=True, cascade="all, delete-orphan"
    )

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "prompt": self.prompt,
            "attack_type": self.attack_type,
            "difficulty": self.difficulty,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "detection_result": self.detection_result,
            "defense_mode": self.defense_mode,
            "final_decision": self.final_decision,
        }

    def __repr__(self):
        return f"<SecurityTest {self.id} risk={self.risk_score}>"
