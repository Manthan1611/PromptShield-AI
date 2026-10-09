"""Safe, additive schema preparation for existing SQLite installations."""
from sqlalchemy import inspect, text
from extensions import db


def ensure_schema():
    inspector = inspect(db.engine)
    tables = set(inspector.get_table_names())
    if "users" in tables:
        cols = {c["name"] for c in inspector.get_columns("users")}
        if "role" not in cols:
            db.session.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'VIEWER'"))
            db.session.commit()
    if "security_events" in tables:
        cols = {c["name"] for c in inspector.get_columns("security_events")}
        additions = {
            "source": "VARCHAR(255)",
            "source_type": "VARCHAR(80)",
            "trust_level": "VARCHAR(40)",
            "injection_risk": "INTEGER",
            "suspicious_instructions": "TEXT",
            "provenance": "TEXT",
        }
        changed = False
        for name, sqltype in additions.items():
            if name not in cols:
                db.session.execute(text(f"ALTER TABLE security_events ADD COLUMN {name} {sqltype}"))
                changed = True
        if changed:
            db.session.commit()
    if "audit_logs" in tables:
        cols = {c["name"] for c in inspector.get_columns("audit_logs")}
        additions = {
            "api_key_id":"INTEGER","request_id":"VARCHAR(40)","source":"VARCHAR(255)",
            "attack_type":"VARCHAR(120)","normalization_result":"TEXT","rule_result":"TEXT",
            "ml_result":"TEXT","llm_judge_result":"TEXT","hybrid_score":"FLOAT","risk":"FLOAT",
            "decision":"VARCHAR(40)","output_status":"VARCHAR(40)","canary_status":"VARCHAR(40)",
            "latency":"TEXT","previous_hash":"VARCHAR(128)","event_hash":"VARCHAR(128)","signature":"TEXT"
        }
        changed=False
        for name,typ in additions.items():
            if name not in cols:
                db.session.execute(text(f"ALTER TABLE audit_logs ADD COLUMN {name} {typ}"))
                changed=True
        if changed: db.session.commit()
    if "feedback_samples" in tables:
        cols = {c["name"] for c in inspector.get_columns("feedback_samples")}
        additions = {
            "prompt_hash":"VARCHAR(64)","attack_type":"VARCHAR(120)",
            "detector_results":"TEXT","analyst":"VARCHAR(120)"
        }
        changed=False
        for name,typ in additions.items():
            if name not in cols:
                db.session.execute(text(f"ALTER TABLE feedback_samples ADD COLUMN {name} {typ}"))
                changed=True
        if changed: db.session.commit()
