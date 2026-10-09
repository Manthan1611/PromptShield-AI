"""Hybrid Part 2 rule detector. Evidence is derived from the supplied text."""
import re

RULES = [
 ("INSTRUCTION_OVERRIDE","Instruction Override",r"\b(?:ignore|disregard|forget|override|bypass)\b.{0,80}\b(?:previous|prior|above|system|instructions?|rules?)",.85),
 ("SYSTEM_PROMPT_EXTRACTION","System Prompt Extraction",r"\b(?:reveal|show|print|give|extract|leak|repeat|disclose)\b.{0,80}\b(?:system prompt|system instructions?|developer prompt|hidden prompt|confidential instructions?)",.90),
 ("ROLE_HIJACKING","Role Hijacking",r"\b(?:you are now|act as|pretend to be|roleplay as|developer mode|dan\b|unrestricted)\b",.82),
 ("JAILBREAK","Jailbreak",r"\b(?:jailbreak|no restrictions|without restrictions|safety rules (?:do not|don't) apply|disable safety)\b",.88),
 ("INFORMATION_EXTRACTION","Information Extraction",r"\b(?:reveal|show|print|give|extract|disclose|dump|repeat)\b.{0,80}\b(?:internal|hidden|private|confidential|instructions?|configuration|information)\b",.86),
 ("SECRET_EXTRACTION","Secret Extraction",r"\b(?:api key|password|secret|credential|token|private key)\b.{0,50}\b(?:reveal|show|give|print|leak|dump)\b",.92),
 ("POLICY_BYPASS","Policy Bypass",r"\b(?:bypass|circumvent|evade|disable|ignore)\b.{0,60}\b(?:policy|safety|filter|guardrail|restriction)\b",.85),
 ("CONTEXT_MANIPULATION","Context Manipulation",r"\b(?:from now on|for the rest of|new context|change the rules|pretend that|assume that)\b",.72),
 ("DELIMITER_MANIPULATION","Delimiter Manipulation",r"(?:</?(?:system|developer|untrusted|trusted)[^>]*>|\[\[(?:system|developer|instruction)\]\])",.78),
 ("TOOL_ABUSE","Tool Abuse",r"\b(?:call|invoke|execute|run)\b.{0,60}\b(?:tool|function|shell|command|database|delete|drop|admin)\b",.86),
 ("OBFUSCATION","Obfuscation",r"\b(?:decode|decrypt|base64|rot13|hex|unicode|url[- ]?encode|encoded)\b",.74),
 ("ENCODED_PAYLOAD","Encoded Payload",r"(?:[A-Za-z0-9+/]{20,}={0,2}|(?:[0-9a-fA-F]{2}){12,})",.80),
 ("INDIRECT_INJECTION","Indirect Injection",r"\b(?:ignore|follow|execute|obey)\b.{0,80}\b(?:document|email|web page|pdf|external content|retrieved text)\b",.88),
 ("MULTI_STEP_MANIPULATION","Multi-Step Manipulation",r"\b(?:step\s*[1-9]|first\b.{0,40}\bthen\b.{0,40}\bfinally\b|after that|once you have)\b",.75),
]

class RuleDetector:
    def __init__(self, rules=None):
        self.rules = rules or RULES
    def detect(self, text, normalization=None, external_content=None):
        text = text or ""
        normalized = (normalization or {}).get("normalized_text", text)
        hay = f"{text}\n{normalized}"
        results=[]; categories=[]; total=0.0
        enc = set((normalization or {}).get("encoding_detections", []))
        for rid, cat, pattern, conf in self.rules:
            matches=list(re.finditer(pattern, hay, re.I|re.S))
            if matches:
                evidence=[m.group(0)[:240] for m in matches[:3]]
                if rid == "ENCODED_PAYLOAD" and not enc:
                    continue
                results.append({"rule_id":rid,"category":cat,"matched":True,"severity":min(100, round(conf*100)),"confidence":conf,"evidence":evidence})
                categories.append(cat); total=max(total, conf*100)
        if external_content:
            ext="\n".join(str(x.get("content","") if isinstance(x,dict) else x) for x in external_content)
            extres=self.detect(ext, normalization={"normalized_text":ext}, external_content=None)
            if extres["matched_rules"]:
                results.append({"rule_id":"INDIRECT_CONTENT","category":"Indirect Injection","matched":True,"severity":90,"confidence":.9,"evidence":extres["evidence"][:3]})
                categories.append("Indirect Injection"); total=max(total,90)
        score=min(100, round(total + max(0,len(categories)-1)*5))
        return {"score":score,"matched_rules":results,"categories":categories,"evidence":[e for r in results for e in r["evidence"]],"available":True}
