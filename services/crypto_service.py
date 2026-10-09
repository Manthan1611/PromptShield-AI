"""Cryptographic primitives for PromptShield AI Part 3.

Secrets are never embedded in source. HMAC uses HMAC_SECRET, falling back to
Flask SECRET_KEY for local compatibility. AES-GCM requires ENCRYPTION_KEY.
"""
import base64, hashlib, hmac, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except Exception:
    Ed25519PrivateKey = None

class CryptoService:
    def __init__(self, hmac_secret=None, encryption_key=None, signing_key=None):
        self.hmac_secret = hmac_secret or os.getenv("HMAC_SECRET") or os.getenv("SECRET_KEY")
        self.encryption_key = encryption_key or os.getenv("ENCRYPTION_KEY")
        self.signing_key = signing_key or os.getenv("AUDIT_SIGNING_KEY")

    def hmac_sha256(self, value):
        if not self.hmac_secret:
            raise RuntimeError("HMAC secret is not configured.")
        return hmac.new(self.hmac_secret.encode(), value.encode(), hashlib.sha256).hexdigest()

    def verify_hmac(self, value, expected):
        try:
            actual = self.hmac_sha256(value)
        except RuntimeError:
            return {"valid": False, "hash": None, "status": "unavailable", "reason": "HMAC secret is not configured."}
        return {"valid": hmac.compare_digest(actual, expected or ""), "hash": actual,
                "status": "valid" if hmac.compare_digest(actual, expected or "") else "invalid",
                "reason": "HMAC matches." if hmac.compare_digest(actual, expected or "") else "HMAC mismatch."}

    def _aes_key(self):
        if not self.encryption_key:
            raise RuntimeError("ENCRYPTION_KEY is not configured.")
        raw = self.encryption_key.encode()
        try:
            decoded = base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))
            if len(decoded) == 32: return decoded
        except Exception:
            decoded = None
        if len(raw) == 32: return raw
        raise RuntimeError("ENCRYPTION_KEY must be a 32-byte value or URL-safe base64 encoding of one.")

    def encrypt(self, plaintext):
        key=self._aes_key(); nonce=os.urandom(12)
        ciphertext=AESGCM(key).encrypt(nonce, plaintext.encode(), None)
        return {"nonce":base64.urlsafe_b64encode(nonce).decode(), "ciphertext":base64.urlsafe_b64encode(ciphertext).decode(), "algorithm":"AES-256-GCM"}

    def decrypt(self, payload):
        key=self._aes_key()
        nonce=base64.urlsafe_b64decode(payload["nonce"])
        ciphertext=base64.urlsafe_b64decode(payload["ciphertext"])
        return AESGCM(key).decrypt(nonce,ciphertext,None).decode()

    def sha256(self, value):
        return hashlib.sha256(value.encode()).hexdigest()

    def sign(self, value):
        if not self.signing_key or Ed25519PrivateKey is None:
            return None
        raw=base64.urlsafe_b64decode(self.signing_key + "=" * (-len(self.signing_key)%4))
        return base64.urlsafe_b64encode(Ed25519PrivateKey.from_private_bytes(raw).sign(value.encode())).decode()

    @property
    def signing_enabled(self):
        return bool(self.signing_key and Ed25519PrivateKey)

def verify_system_prompt_integrity(system_prompt, expected_hash):
    svc=CryptoService()
    if not expected_hash:
        return {"valid": False, "hash": None, "status":"unavailable", "reason":"No expected HMAC is configured."}
    return svc.verify_hmac(system_prompt, expected_hash)
