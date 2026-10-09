"""Dynamic canary generation and leak checks."""
import hashlib, secrets, os
class CanaryService:
    def __init__(self):
        self.enabled=os.getenv("CANARY_ENABLED","true").lower() in {"1","true","yes","on"}
    def generate(self):
        if not self.enabled: return {"enabled":False,"token":None,"token_hash":None}
        token="PS_CANARY_"+secrets.token_urlsafe(18)
        return {"enabled":True,"token":token,"token_hash":hashlib.sha256(token.encode()).hexdigest()}
    def check(self, output, token):
        leaked=bool(token and token in (output or ""))
        return {"status":"LEAKED" if leaked else "SAFE","leaked":leaked,"evidence":"Canary token observed in output." if leaked else None}
