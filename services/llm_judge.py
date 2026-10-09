"""LLM-as-a-judge adapter with safe mock and Gemini modes."""
import re
import time
from services.ai_provider import GeminiLLMProvider


class LLMJudge:
    def __init__(self, mode="mock", api_key="", base_url="", model="", enabled=True, timeout_seconds=10):
        self.mode = (mode or "mock").lower()
        self.enabled = bool(enabled)
        self.api_key = api_key or ""
        self.model = model or GeminiLLMProvider.DEFAULT_MODEL
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _mock_judge(text, rule_result=None):
        lower = (text or "").lower()
        signals = []
        # Require adversarial intent, not mere mention of security concepts.
        if re.search(r"\b(?:ignore|disregard|forget|override|bypass)\b.{0,80}\b(?:previous|prior|above|system|instructions?|rules?|policy)\b", lower):
            signals.append("instruction override language")
        if re.search(r"\b(?:reveal|show|print|give|extract|leak|repeat|dump)\b.{0,80}\b(?:system prompt|system instructions?|developer prompt|hidden prompt)\b", lower):
            signals.append("system prompt extraction")
        if re.search(r"\b(?:you are now|act as|pretend to be|developer mode|dan\b|unrestricted)\b", lower):
            signals.append("role manipulation")
        if re.search(r"\b(?:decode|decrypt|base64|rot13|encoded)\b", lower) and re.search(r"\b(?:follow|execute|obey|ignore)\b", lower):
            signals.append("obfuscation")
        if rule_result and rule_result.get("score", 0) >= 90 and len(signals) == 0:
            signals.append("corroborating rule signals")
        inj = bool(signals)
        score = min(100, 25 * len(signals) + 10) if inj else 0
        return {
            "is_injection": inj,
            "attack_type": ((rule_result or {}).get("categories") or [None])[0] or ("none" if not inj else "prompt_injection"),
            "risk_score": score,
            "risk": score,
            "confidence": round(min(.99, .55 + .1 * len(signals)), 2) if inj else .98,
            "severity": "critical" if score >= 81 else "high" if score >= 61 else "medium" if score >= 41 else "safe",
            "reason": "MOCK JUDGE: " + ("; ".join(signals) if signals else "No injection indicators identified."),
            "evidence": signals,
            "provider": "mock",
            "model": "mock-security-judge-v1",
            "available": True,
            "status": "MOCK",
            "judge_status": "mock",
            "latency_ms": 0,
        }

    def judge(self, text, rule_result=None):
        if not self.enabled:
            return {
                "is_injection": False, "attack_type": "none", "risk_score": None, "risk": None,
                "confidence": None, "severity": "safe", "reason": "LLM judge is disabled.",
                "evidence": [], "provider": "gemini" if self.mode == "gemini" else "mock",
                "model": self.model if self.mode == "gemini" else "mock-security-judge-v1",
                "available": False, "status": "DISABLED", "judge_status": "disabled", "latency_ms": 0,
            }
        if self.mode == "mock":
            return self._mock_judge(text, rule_result)
        if self.mode == "gemini":
            return GeminiLLMProvider(
                api_key=self.api_key, model=self.model, timeout_seconds=self.timeout_seconds
            ).analyze_prompt(text, rule_result=rule_result)
        return {
            "is_injection": False, "attack_type": "none", "risk_score": None, "risk": None,
            "confidence": None, "severity": "safe", "reason": "Unsupported LLM judge mode.",
            "evidence": [], "provider": self.mode, "model": self.model, "available": False,
            "status": "UNAVAILABLE", "judge_status": "unavailable", "latency_ms": 0,
        }
