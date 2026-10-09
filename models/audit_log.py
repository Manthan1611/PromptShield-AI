from datetime import datetime
from extensions import db

class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    user_id = db.Column(db.Integer, nullable=True)
    api_key_id = db.Column(db.Integer, nullable=True)
    request_id = db.Column(db.String(40), index=True)
    source = db.Column(db.String(255))
    attack_type = db.Column(db.String(120))
    normalization_result = db.Column(db.Text)
    rule_result = db.Column(db.Text)
    ml_result = db.Column(db.Text)
    llm_judge_result = db.Column(db.Text)
    hybrid_score = db.Column(db.Float)
    risk = db.Column(db.Float)
    decision = db.Column(db.String(40))
    output_status = db.Column(db.String(40))
    canary_status = db.Column(db.String(40))
    latency = db.Column(db.Text)
    previous_hash = db.Column(db.String(128))
    event_hash = db.Column(db.String(128), index=True)
    signature = db.Column(db.Text)
    action = db.Column(db.String(120))
    resource = db.Column(db.String(255))
    outcome = db.Column(db.String(40))
    details = db.Column(db.Text)
