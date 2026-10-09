"""
Detection Engine (Part 2).

Implements four independent detectors whose results are shown
separately in the Security Lab UI, then combined into one
attack_type/difficulty/confidence verdict:

  1. RuleBasedDetector    - pattern-category matches from PromptAnalyzer
  2. HeuristicDetector     - structural/statistical signals on the raw prompt
  3. ContextConflictDetector - checks for direct conflict with the platform's
                                assumed baseline system policy
  4. OutputSafetyDetector  - analyzes a *model response* (used after the
                                Mock LLM produces output, not on the prompt)

Public interface kept stable from Part 1: `DetectionEngine().classify(analysis)`.
`analyze_output()` is new in Part 2 and used by the output-validation stage.
"""

import re

ATTACK_TYPES = (
    "direct_prompt_injection",
    "indirect_prompt_injection",
    "instruction_override",
    "role_manipulation",
    "context_manipulation",
    "information_extraction",
    "obfuscation",
    "multi_step_manipulation",
    "none",
)

DIFFICULTIES = ("easy", "medium", "hard", "n/a")

# Which analyzer category most strongly implies which attack_type label.
_CATEGORY_TO_ATTACK_TYPE = {
    "instruction_override": "instruction_override",
    "system_prompt_reference": "information_extraction",
    "role_manipulation": "role_manipulation",
    "protected_info_request": "information_extraction",
    "context_manipulation": "context_manipulation",
    "encoding_obfuscation": "obfuscation",
    "tool_action_escalation": "context_manipulation",
    "multi_step_behavior": "multi_step_manipulation",
}

_BASELINE_POLICY_MARKERS = (
    "ignore", "override", "you must now", "no longer", "instead of your rules",
    "disregard", "unrestricted", "without restriction", "bypass",
)

_REFUSAL_MARKERS = (
    "can't comply", "cannot comply", "can't help with that", "won't provide",
    "blocked by", "declined", "not able to assist with that",
)

_LEAK_MARKERS = (
    "[simulated leak]", "system directive", "internal instruction", "confidential:",
)


class RuleBasedDetector:
    """Reads PromptAnalyzer's category scores directly."""

    name = "rule_based"

    def run(self, analysis: dict) -> dict:
        categories = analysis.get("categories", {})
        if not categories or not analysis.get("flags"):
            return {"score": 0, "matched_categories": [], "top_category": None}

        top_category = max(categories.items(), key=lambda kv: kv[1]["score"])[0]
        return {
            "score": analysis.get("total_indicator_score", 0),
            "matched_categories": analysis.get("flags", []),
            "top_category": top_category,
        }


class HeuristicDetector:
    """Structural/statistical heuristics independent of keyword matching."""

    name = "heuristic"

    def run(self, prompt: str) -> dict:
        prompt = prompt or ""
        length = len(prompt)
        words = prompt.split()
        word_count = max(len(words), 1)

        upper_chars = sum(1 for c in prompt if c.isupper())
        upper_ratio = upper_chars / max(len(prompt), 1)

        imperative_markers = ("ignore", "must", "now", "immediately", "always", "never", "reveal", "override")
        imperative_hits = sum(1 for w in words if w.strip(".,!:;\"'").lower() in imperative_markers)
        imperative_ratio = imperative_hits / word_count

        punctuation_density = sum(1 for c in prompt if c in "!?") / max(length, 1)

        score = 0
        score += min(35, round(imperative_ratio * 250))
        score += min(25, round(upper_ratio * 120)) if length > 20 else 0
        score += min(20, round(punctuation_density * 400))
        score += 15 if length > 2000 else 0
        score = min(100, score)

        return {
            "score": score,
            "length": length,
            "word_count": word_count,
            "upper_ratio": round(upper_ratio, 3),
            "imperative_ratio": round(imperative_ratio, 3),
        }


class ContextConflictDetector:
    """Checks whether the prompt directly conflicts with the platform's
    assumed baseline system policy (a simple simulated 'system prompt')."""

    name = "context_conflict"

    def run(self, prompt: str) -> dict:
        lower = (prompt or "").lower()
        matched = [m for m in _BASELINE_POLICY_MARKERS if m in lower]
        score = min(100, len(matched) * 30)
        return {
            "score": score,
            "matched_markers": matched,
            "conflict_detected": len(matched) > 0,
        }


class OutputSafetyDetector:
    """Analyzes a *model response* (not a prompt) for unsafe compliance."""

    name = "output_safety"

    def run(self, response_text: str) -> dict:
        lower = (response_text or "").lower()
        refused = any(m in lower for m in _REFUSAL_MARKERS)
        leaked = any(m in lower for m in _LEAK_MARKERS)

        score = 0
        if leaked:
            score += 70
        if not refused and leaked:
            score += 15

        return {
            "score": min(100, score),
            "refused": refused,
            "leak_detected": leaked,
        }


class DetectionEngine:
    ATTACK_TYPES = ATTACK_TYPES

    def __init__(self):
        self.rule_based = RuleBasedDetector()
        self.heuristic = HeuristicDetector()
        self.context_conflict = ContextConflictDetector()
        self.output_safety = OutputSafetyDetector()

    def classify(self, analysis: dict, prompt: str = "") -> dict:
        """
        analysis: output of PromptAnalyzer.analyze()
        prompt: the raw prompt text (used by detectors that don't rely on
                pre-extracted categories)

        Combines all three prompt-side detectors into one verdict while
        keeping each detector's own result visible under `detectors`.
        """
        rb = self.rule_based.run(analysis)
        heur = self.heuristic.run(prompt or analysis.get("normalized_prompt", ""))
        cc = self.context_conflict.run(prompt or analysis.get("normalized_prompt", ""))

        # Weighted combination: rule-based signal is most reliable, then
        # context-conflict, then general heuristics.
        combined_score = round(rb["score"] * 0.55 + cc["score"] * 0.25 + heur["score"] * 0.20)
        detected = combined_score > 15 or bool(rb["matched_categories"])

        if not detected:
            attack_type = "none"
        elif rb["top_category"]:
            attack_type = _CATEGORY_TO_ATTACK_TYPE.get(rb["top_category"], "direct_prompt_injection")
        else:
            attack_type = "direct_prompt_injection"

        matched_count = len(rb["matched_categories"])
        if not detected:
            difficulty = "n/a"
        elif matched_count >= 3 or combined_score >= 70:
            difficulty = "hard"
        elif matched_count == 2 or combined_score >= 40:
            difficulty = "medium"
        else:
            difficulty = "easy"

        confidence = round(min(1.0, 0.35 + (combined_score / 100) * 0.6), 2)

        return {
            "attack_type": attack_type,
            "difficulty": difficulty,
            "detected": detected,
            "combined_score": combined_score,
            "confidence": confidence,
            "detectors": {
                "rule_based": rb,
                "heuristic": heur,
                "context_conflict": cc,
            },
        }

    def analyze_output(self, response_text: str) -> dict:
        """Run the output-safety detector against a model response."""
        return self.output_safety.run(response_text)
