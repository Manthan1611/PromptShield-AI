from datetime import datetime
from extensions import db
class FeedbackSample(db.Model):
    __tablename__ = "feedback_samples"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    prompt = db.Column(db.Text, nullable=False)
    prompt_hash = db.Column(db.String(64), nullable=True, index=True)
    label = db.Column(db.String(40), nullable=True)
    attack_type = db.Column(db.String(120), nullable=True)
    detector_results = db.Column(db.Text, nullable=True)
    analyst = db.Column(db.String(120), nullable=True)
    feedback = db.Column(db.Text, nullable=True)
