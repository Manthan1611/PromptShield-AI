"""
Defense Engine (Part 2, new module — additive to the Part 1 services list).

Implements the four selectable defense modes and the concrete layers
each one activates:

    Disabled  -> (none)
    Basic     -> input filtering
    Standard  -> input filtering, prompt normalization, policy validation
    Maximum   -> input filtering, prompt normalization, context isolation,
                 output validation, policy enforcement

This module owns *which layers run*; the actual work of each layer is
delegated to PromptAnalyzer (filtering signal), the normalizer here,
and OutputValidator (output validation), so no logic is duplicated.
"""

import re

DEFENSE_LAYERS = {
    "disabled": [],
    "basic": ["input_filtering"],
    "standard": ["input_filtering", "prompt_normalization", "context_isolation", "policy_validation", "audit_logging"],
    "strict": ["input_filtering", "prompt_normalization", "context_isolation", "output_validation", "policy_enforcement", "canary_protection", "cryptographic_integrity", "audit_logging"],
    "maximum": [
        "input_filtering",
        "prompt_normalization",
        "context_isolation",
        "output_validation",
        "policy_enforcement", "canary_protection", "cryptographic_integrity", "audit_logging",
    ],
}

# Hard-block patterns used only by the input_filtering layer -- these are
# the small set of unambiguous cases we refuse before the model even runs,
# regardless of the rest of the pipeline's score.
_HARD_BLOCK_PATTERNS = (
    r"drop table",
    r"os\.system|subprocess\.",
    r"delete (all|every) (users?|records?|rows?)",
)


class DefenseEngine:
    def get_layers(self, mode: str) -> list:
        return DEFENSE_LAYERS.get(mode, [])

    def input_filtering(self, prompt: str, mode: str) -> dict:
        """Layer 1: screen the raw prompt for unambiguous hard-block patterns."""
        if "input_filtering" not in self.get_layers(mode):
            return {"applied": False, "blocked": False, "reason": None}

        lower = (prompt or "").lower()
        for pattern in _HARD_BLOCK_PATTERNS:
            if re.search(pattern, lower):
                return {
                    "applied": True,
                    "blocked": True,
                    "reason": f"Matched hard-block pattern: {pattern}",
                }
        return {"applied": True, "blocked": False, "reason": None}

    def normalize_prompt(self, prompt: str, mode: str) -> dict:
        """Layer 2: canonicalize whitespace/unicode (delegates the actual
        normalization to PromptAnalyzer._normalize so there's one
        implementation)."""
        if "prompt_normalization" not in self.get_layers(mode):
            return {"applied": False, "normalized_prompt": prompt}

        from services.prompt_analyzer import PromptAnalyzer
        normalized = PromptAnalyzer._normalize(prompt or "")
        return {"applied": True, "normalized_prompt": normalized}

    def isolate_context(self, prompt: str, mode: str) -> dict:
        """Layer 3: mark user content as untrusted/data-only, conceptually
        separate from the (simulated) system prompt. In this local
        simulation there is no real system prompt to protect, so this
        layer's effect is to flag the prompt as isolated for the pipeline
        report and slightly discount role/context-manipulation risk since
        it can no longer reach a real instruction channel."""
        if "context_isolation" not in self.get_layers(mode):
            return {"applied": False, "isolated": False}
        return {"applied": True, "isolated": True}

    def validate_output(self, response_text: str, mode: str, detection_engine) -> dict:
        """Layer 4: run OutputSafetyDetector-based validation on the model's
        response (delegates to DetectionEngine.analyze_output)."""
        if "output_validation" not in self.get_layers(mode):
            return {"applied": False, "result": None}
        return {"applied": True, "result": detection_engine.analyze_output(response_text)}

    def enforce_policy(self, decision: dict, mode: str) -> dict:
        """Layer 5: record that policy enforcement is active for this mode.
        The actual allow/flag/block decision comes from PolicyEngine; this
        layer just confirms enforcement ran and returns it unchanged."""
        if "policy_enforcement" not in self.get_layers(mode):
            return {"applied": False, "decision": decision}
        return {"applied": True, "decision": decision}
