"""SecurityEvent model. Field names are part of the fixed database contract."""

from datetime import datetime
from extensions import db


class SecurityEvent(db.Model):
    __tablename__ = "security_events"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    event_type = db.Column(db.String(80), nullable=False, index=True)  # e.g. "detection", "block"
    severity = db.Column(db.String(20), nullable=False)  # info / low / medium / high / critical
    description = db.Column(db.Text, nullable=False)

    test_id = db.Column(db.Integer, db.ForeignKey("security_tests.id"), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type,
            "severity": self.severity,
            "description": self.description,
            "test_id": self.test_id,
        }

    def __repr__(self):
        return f"<SecurityEvent {self.event_type} sev={self.severity}>"
