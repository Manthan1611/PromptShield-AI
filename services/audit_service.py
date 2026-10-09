"""Tamper-evident audit logging with SHA-256 hash chaining."""
import hashlib, json
from datetime import datetime
from extensions import db
from models.audit_log import AuditLog
from services.crypto_service import CryptoService
class AuditService:
    def _canonical(self, payload): return json.dumps(payload,sort_keys=True,separators=(",",":"),default=str)
    def record(self, event, user_id=None, api_key_id=None, source=None):
        previous=AuditLog.query.order_by(AuditLog.id.desc()).first()
        previous_hash=previous.event_hash if previous else ""
        row_timestamp=datetime.utcnow()
        ts=row_timestamp.isoformat()
        safe={k:v for k,v in event.items() if k not in {"password","api_key","encryption_key","raw_secret","raw_key"}}
        data={"timestamp":ts,"event_data":safe,"previous_hash":previous_hash}
        event_hash=hashlib.sha256(self._canonical(data).encode()).hexdigest()
        sig=CryptoService().sign(event_hash)
        row=AuditLog(timestamp=row_timestamp,request_id=event.get("request_id"),user_id=user_id,
                     api_key_id=api_key_id,source=source,attack_type=event.get("attack_type"),
                     normalization_result=json.dumps(event.get("normalization"),default=str),
                     rule_result=json.dumps(event.get("rule_result"),default=str),
                     ml_result=json.dumps(event.get("ml_result"),default=str),
                     llm_judge_result=json.dumps(event.get("llm_judge_result"),default=str),
                     hybrid_score=event.get("hybrid_score"),risk=event.get("risk"),
                     decision=event.get("decision"),output_status=event.get("output_status"),
                     canary_status=event.get("canary_status"),latency=json.dumps(event.get("latency"),default=str),
                     previous_hash=previous_hash,event_hash=event_hash,signature=sig,
                     details=json.dumps(safe,default=str))
        db.session.add(row); db.session.commit(); return row
    def verify_chain(self):
        rows=AuditLog.query.order_by(AuditLog.id.asc()).all(); prev=""
        for row in rows:
            try: details=json.loads(row.details or "{}")
            except Exception: details={}
            data={"timestamp":row.timestamp.isoformat(),"event_data":details,"previous_hash":prev}
            expected=hashlib.sha256(self._canonical(data).encode()).hexdigest()
            if row.previous_hash!=prev or row.event_hash!=expected:
                return {"valid":False,"status":"TAMPER DETECTED","failed_id":row.id}
            prev=row.event_hash
        return {"valid":True,"status":"VALID","records":len(rows)}
