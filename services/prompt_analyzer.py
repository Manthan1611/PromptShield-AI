"""
Prompt Analyzer (Part 2).

Extracts structured, per-category signals from a submitted prompt.
Each category returns a 0-100 sub-score plus the specific matched
patterns, so both the RiskEngine (weighted aggregation) and the
Security Lab UI (individual detector display) can consume the same
structured output.

Public interface kept stable from Part 1: `PromptAnalyzer().analyze(prompt)`.
"""

import re
import unicodedata

CATEGORIES = (
    "instruction_override",
    "system_prompt_reference",
    "role_manipulation",
    "protected_info_request",
    "context_manipulation",
    "encoding_obfuscation",
    "tool_action_escalation",
    "multi_step_behavior",
)

# Each pattern contributes `weight` points (capped at 100) to its category
# when found in the (lowercased) prompt. Patterns are plain substrings or
# small regexes -- intentionally simple/transparent for an educational tool.
_PATTERNS = {
    "instruction_override": [
        (r"ignore (all )?(the )?previous instructions", 55),
        (r"disregard (the )?(above|previous)", 50),
        (r"forget (your|all|previous) (instructions|rules|guidelines)", 55),
        (r"new instructions?:", 40),
        (r"\boverride\b.*\b(instructions|rules|policy)\b", 45),
        (r"ignore your (rules|guidelines|programming|policy)", 55),
        (r"from now on,? (you|ignore)", 30),
    ],
    "system_prompt_reference": [
        (r"system prompt", 40),
        (r"your (initial|hidden|original) (instructions|prompt)", 45),
        (r"(show|reveal|print|output) (me )?your (instructions|prompt|guidelines)", 55),
        (r"what (are|were) you told", 25),
        (r"repeat (the text|everything) above", 35),
    ],
    "role_manipulation": [
        (r"\byou are now\b", 40),
        (r"\bact as\b", 25),
        (r"pretend (to be|you are)", 35),
        (r"roleplay as", 30),
        (r"developer mode", 50),
        (r"\bdan\b.*(mode|jailbreak)", 55),
        (r"jailbreak", 45),
        (r"no (restrictions|filters|limitations)", 35),
    ],
    "protected_info_request": [
        (r"(api|secret) key", 45),
        (r"\bpassword\b", 35),
        (r"\bcredentials?\b", 35),
        (r"confidential", 30),
        (r"reveal (your|the) (secrets?|internal)", 45),
        (r"training data", 20),
    ],
    "context_manipulation": [
        (r"let'?s play a game", 25),
        (r"for the rest of this conversation", 30),
        (r"in this hypothetical", 30),
        (r"pretend this (conversation|rule) (never happened|doesn'?t apply)", 45),
        (r"this is (just|only) a (test|simulation)", 20),
        (r"between (us|you and me)", 15),
    ],
    "encoding_obfuscation": [
        (r"[A-Za-z0-9+/]{40,}={0,2}", 40),  # long base64-looking blob
        (r"\\x[0-9a-f]{2}", 30),             # hex escapes
        (r"&#\d{2,4};", 25),                  # HTML entity encoding
        (r"(^|\s)[01]{16,}(\s|$)", 30),       # long binary strings
    ],
    "tool_action_escalation": [
        (r"\bexecute\b.*\b(command|code|script)\b", 45),
        (r"run this (command|script)", 45),
        (r"call the api", 30),
        (r"\bcurl\b|\bwget\b", 30),
        (r"drop table", 60),
        (r"delete (all|every)", 35),
        (r"os\.system|subprocess\.", 55),
        (r"access the database", 40),
    ],
    "multi_step_behavior": [
        (r"step 1[:.]", 25),
        (r"\bfirst,.*\bthen\b.*\bfinally\b", 35),
        (r"after that,", 15),
        (r"once you'?ve done that", 20),
    ],
}

_COMPILED = {
    cat: [(re.compile(p, re.IGNORECASE), w) for p, w in pats]
    for cat, pats in _PATTERNS.items()
}


class PromptAnalyzer:
    """Extracts per-category signals from a prompt for downstream scoring."""

    def analyze(self, prompt: str) -> dict:
        prompt = prompt or ""
        normalized = self._normalize(prompt)
        lower = normalized.lower()

        categories = {}
        flags = []
        for cat, compiled_patterns in _COMPILED.items():
            matched = []
            score = 0
            for regex, weight in compiled_patterns:
                m = regex.search(lower if cat != "encoding_obfuscation" else normalized)
                if m:
                    matched.append(m.group(0)[:60])
                    score += weight
            score = min(100, score)
            detected = score > 0
            categories[cat] = {
                "matched": matched,
                "score": score,
                "detected": detected,
            }
            if detected:
                flags.append(cat)

        # Average severity across only the categories that actually matched
        # (not all 8), plus a small breadth bonus for multiple simultaneous
        # categories -- otherwise one strong signal gets diluted by the
        # many legitimately-zero categories sitting alongside it.
        triggered_scores = [c["score"] for c in categories.values() if c["score"] > 0]
        if triggered_scores:
            avg = sum(triggered_scores) / len(triggered_scores)
            breadth_bonus = min(20, max(0, len(triggered_scores) - 1) * 8)
            total_indicator_score = min(100, round(avg + breadth_bonus))
        else:
            total_indicator_score = 0

        return {
            "length": len(prompt),
            "normalized_prompt": normalized,
            "categories": categories,
            "flags": flags,
            "total_indicator_score": total_indicator_score,
            # --- backward-compatible flat fields (Part 1 detection_engine) ---
            "marker_count": len(flags),
            "has_role_override_language": categories["role_manipulation"]["detected"],
            "has_instruction_override_language": categories["instruction_override"]["detected"],
        }

    @staticmethod
    def _normalize(prompt: str) -> str:
        """Strip zero-width/control characters and normalize unicode so
        simple obfuscation (odd spacing, homoglyphs) doesn't evade matching."""
        text = unicodedata.normalize("NFKC", prompt)
        text = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", text)  # zero-width chars
        text = re.sub(r"\s+", " ", text).strip()
        return text
