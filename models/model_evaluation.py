from datetime import datetime
from extensions import db
class ModelEvaluation(db.Model):
    __tablename__ = "model_evaluations"
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    model_name = db.Column(db.String(120), nullable=False)
    metric = db.Column(db.String(80), nullable=False)
    value = db.Column(db.Float, nullable=True)
    details = db.Column(db.Text, nullable=True)
