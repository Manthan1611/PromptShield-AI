"""Part 3 output security pipeline."""
from services.leak_detector import LeakDetector
class OutputValidator:
    def __init__(self, detection_engine=None):
        self.detection_engine=detection_engine
        self.leak_detector=LeakDetector()
    def validate(self, response_text, prompt_had_attack=False, system_prompt="", canary_token=None, policy_context=None):
        leak=self.leak_detector.detect(response_text,system_prompt,canary_token)
        legacy=self.detection_engine.analyze_output(response_text) if self.detection_engine else {}
        refused=legacy.get("refused",False)
        persona_risk=35 if any(x in (response_text or "").lower() for x in ("developer mode","unrestricted","no restrictions")) else 0
        return {
            "safe": leak["safe"] and not legacy.get("leak_detected",False),
            "safety_status":"unsafe" if leak["leak_detected"] else ("blocked" if refused else "safe"),
            "policy_compliance":not leak["leak_detected"],
            "potential_information_leakage":leak["leak_detected"],
            "leak_detected":leak["leak_detected"],
            "leak_types":leak["leak_types"],
            "evidence":leak["evidence"],
            "severity":leak["severity"],
            "redacted_output":leak["redacted_output"],
            "instruction_following_risk":70 if prompt_had_attack and not refused and leak["leak_detected"] else (40 if prompt_had_attack and not refused else 0),
            "tool_abuse_risk":35 if "unauthorized_tool_instruction" in leak["leak_types"] else 0,
            "context_manipulation_detected":persona_risk>0,
            "context_manipulation_risk":persona_risk,
            "raw_output_safety":legacy
        }
