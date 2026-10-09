"""
Functional API routes for PromptShield AI (Part 2).

Implements the full security pipeline:

  INPUT VALIDATION -> PROMPT NORMALIZATION -> PROMPT ANALYZER ->
  INJECTION DETECTOR -> RISK ENGINE -> MOCK LLM -> OUTPUT VALIDATOR ->
  POLICY ENGINE -> FINAL DECISION -> AUDIT LOG

/api/analyze  - runs the full pipeline and persists a SecurityTest
/api/detect   - prompt-side detectors only, no LLM call, no DB write
/api/defend   - policy/defense assessment for a given risk_level or prompt
/api/simulate - runs the pipeline via the Mock LLM, with optional
                Before/After (defense OFF vs ON) comparison

All four keep the exact request methods and URLs fixed in the Part 1
API contract; response shapes are additive (new fields), never removed.
"""

import json
import time
import uuid
import hashlib
import io
import re
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, current_app

from extensions import db
from models.security_test import SecurityTest
from models.security_event import SecurityEvent
from models.attack_scenario import AttackScenario
from services.prompt_analyzer import PromptAnalyzer
from services.detection_engine import DetectionEngine
from services.risk_engine import RiskEngine, RISK_LEVELS
from services.policy_engine import PolicyEngine
from services.defense_engine import DefenseEngine
from services.output_validator import OutputValidator
from services.ai_provider import get_provider
from services.auth import require_auth
from services.normalization_engine import NormalizationEngine
from services.context_isolation import ContextIsolation
from services.rule_detector import RuleDetector
from services.ml_detector import MLDetector
from services.llm_judge import LLMJudge
from services.hybrid_detector import HybridDetector

api_bp = Blueprint("api", __name__)

MAX_PROMPT_LENGTH = 8000

ALLOWED_ATTACK_TYPES = set(DetectionEngine.ATTACK_TYPES) | {"auto"}
ALLOWED_DIFFICULTIES = {"easy", "medium", "hard", "auto"}
ALLOWED_DEFENSE_MODES = set(PolicyEngine.DEFENSE_MODES)
ALLOWED_LLM_MODES = {"mock", "openai"}

PIPELINE_STAGES = (
    "authentication", "input_validation", "prompt_normalization", "trust_boundary",
    "gemini_judge", "safety_fallback", "risk",
    "llm_simulation", "output_analysis", "policy_decision", "final_result",
)


# --------------------------------------------------------------------------
# Request validation helpers
# --------------------------------------------------------------------------

class ValidationError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.message = message
        self.status = status


def _parse_json_body():
    # force=True: accept a JSON body even if the client forgot the
    # Content-Type header. silent=True: never raise here -- we want to
    # distinguish "no body sent" (-> treat as {}) from "body sent but
    # not valid JSON" (-> explicit error) ourselves, below.
    data = request.get_json(silent=True, force=True)
    if data is None:
        if request.data:
            raise ValidationError("Request body is not valid JSON.")
        data = {}
    if not isinstance(data, dict):
        raise ValidationError("JSON body must be an object.")
    return data


def _require_prompt(data: dict) -> str:
    if "prompt" not in data:
        raise ValidationError("Field 'prompt' is required.")
    raw = data.get("prompt")
    if not isinstance(raw, str):
        raise ValidationError("Field 'prompt' must be a string.")
    prompt = raw.strip()
    if not prompt:
        raise ValidationError("Field 'prompt' cannot be empty.")
    if len(prompt) > MAX_PROMPT_LENGTH:
        raise ValidationError(f"Field 'prompt' exceeds the maximum length of {MAX_PROMPT_LENGTH} characters.")
    return prompt


def _validate_choice(data: dict, field: str, allowed: set, default: str) -> str:
    value = data.get(field, default)
    if value is None:
        value = default
    if not isinstance(value, str) or value not in allowed:
        raise ValidationError(
            f"Invalid {field}: {value!r}. Must be one of: {', '.join(sorted(allowed))}."
        )
    return value


def _error_response(message: str, status: int = 400):
    return jsonify({"success": False, "error": message}), status


@api_bp.errorhandler(ValidationError)
def _handle_validation_error(err: ValidationError):
    return _error_response(err.message, err.status)


# --------------------------------------------------------------------------
# Core pipeline
# --------------------------------------------------------------------------

def _request_id():
    return "PS-2026-" + uuid.uuid4().hex[:8].upper()

def _detector_bundle():
    cfg=current_app.config
    return HybridDetector(
        RuleDetector(),
        MLDetector(cfg.get("ML_BACKEND","tfidf")),
        LLMJudge(
            cfg.get("LLM_JUDGE_MODE","mock"),
            cfg.get("GEMINI_API_KEY",""),
            "",
            cfg.get("GEMINI_MODEL","") or "gemini-3.8-flash",
            enabled=bool(cfg.get("LLM_JUDGE_ENABLED", False)),
            timeout_seconds=cfg.get("GEMINI_TIMEOUT_SECONDS", 10),
        ),
        {
            "rule": float(cfg.get("RULE_WEIGHT",.35)),
            "ml": float(cfg.get("ML_WEIGHT",.40)),
            "llm_judge": float(cfg.get("LLM_JUDGE_WEIGHT",.25)),
        })


def _local_safety_fallback(prompt: str):
    """Small fail-safe for unambiguous harmful requests and direct injection.
    Gemini remains the primary classifier; this is used only as a safety backstop.
    """
    text = (prompt or "").lower()
    harmful_patterns = (
        r"\bhow to (?:make|build|create|construct) (?:a |an )?(?:bomb|explosive|pipe bomb)\b",
        r"\b(?:instructions|steps|recipe|guide) to (?:make|build|create|construct) (?:a |an )?(?:bomb|explosive|pipe bomb)\b",
        r"\bhow to (?:poison|kill|seriously harm) (?:someone|a person|people)\b",
    )
    injection_patterns = (
        r"\bignore (?:all )?(?:previous|prior|above) instructions\b",
        r"\b(?:reveal|print|show|dump|extract) (?:the )?(?:system prompt|hidden instructions)\b",
        r"\b(?:bypass|disable|override) (?:the )?(?:safety|security|policy|guardrails?)\b",
    )
    if any(re.search(p, text, re.I) for p in harmful_patterns):
        return {
            "is_injection": False, "is_harmful_request": True,
            "attack_type": "harmful_content", "risk_score": 95,
            "confidence": 0.99, "severity": "critical",
            "reason": "Local safety fallback detected an actionable request for dangerous assistance.",
            "evidence": [prompt[:240]], "available": False,
            "provider": "local_safety_fallback", "status": "FALLBACK",
            "judge_status": "fallback", "model": None,
        }
    if any(re.search(p, text, re.I) for p in injection_patterns):
        return {
            "is_injection": True, "is_harmful_request": False,
            "attack_type": "prompt_injection", "risk_score": 95,
            "confidence": 0.99, "severity": "critical",
            "reason": "Local safety fallback detected an instruction override or prompt extraction attempt.",
            "evidence": [prompt[:240]], "available": False,
            "provider": "local_safety_fallback", "status": "FALLBACK",
            "judge_status": "fallback", "model": None,
        }
    return None


def _gemini_primary_detect(text, normalization, external_content=None):
    """Run Gemini when available and always retain local rule-based detection.

    The local rule detector is independent of Gemini quota and is the minimum
    detection layer. Gemini failures must never turn a matched injection rule
    into an automatic allow decision.
    """
    cfg = current_app.config
    rule = RuleDetector().detect(text, normalization, external_content or [])
    judge = LLMJudge(
        "gemini",
        cfg.get("GEMINI_API_KEY", ""),
        "",
        cfg.get("GEMINI_MODEL", "") or "gemini-3.5-flash",
        enabled=bool(cfg.get("LLM_JUDGE_ENABLED", True)),
        timeout_seconds=cfg.get("GEMINI_TIMEOUT_SECONDS", 30),
    )
    gemini_result = judge.judge(text, rule_result=rule)

    fallback = _local_safety_fallback(text)
    result = gemini_result
    if fallback and (
        not gemini_result.get("available")
        or fallback.get("risk_score", 0) > (gemini_result.get("risk_score") or 0)
    ):
        result = {**gemini_result, **fallback, "fallback_applied": True,
                  "gemini_result": gemini_result}

    # Map local rule labels into stable attack classifications.
    mapping = {
        "Instruction Override": "INSTRUCTION_OVERRIDE",
        "System Prompt Extraction": "SYSTEM_PROMPT_EXTRACTION",
        "Role Hijacking": "ROLE_HIJACKING",
        "Jailbreak": "JAILBREAK",
        "Information Extraction": "DATA_EXFILTRATION",
        "Secret Extraction": "DATA_EXFILTRATION",
        "Policy Bypass": "CONTEXT_MANIPULATION",
        "Context Manipulation": "CONTEXT_MANIPULATION",
        "Delimiter Manipulation": "CONTEXT_MANIPULATION",
        "Tool Abuse": "TOOL_ABUSE",
        "Obfuscation": "OBFUSCATION",
        "Encoded Payload": "OBFUSCATION",
        "Indirect Injection": "INDIRECT_INJECTION",
        "Multi-Step Manipulation": "MULTI_STEP_ATTACK",
    }
    classes = [mapping.get(category, category.upper().replace(" ", "_"))
               for category in rule.get("categories", [])]
    attack_type = result.get("attack_type", "none")
    if attack_type and str(attack_type).lower() != "none":
        classes.append(str(attack_type).upper())
    classes = list(dict.fromkeys(classes))

    rule_score = int(rule.get("score") or 0) if rule.get("available") else 0
    judge_score = int(result.get("risk_score") or 0)
    score = max(rule_score, judge_score if result.get("available") or result.get("fallback_applied") else 0)
    # A direct extraction / override rule is a strong signal even if the
    # external Gemini API is rate-limited.
    rule_detected = rule_score >= 40
    detected = bool(rule_detected or result.get("is_injection")
                    or result.get("is_harmful_request") or score >= 50)

    available = bool(result.get("available"))
    available_detectors = ["rule"] if rule.get("available") else []
    if available:
        available_detectors.append("gemini")
    if result.get("fallback_applied"):
        available_detectors.append("local_safety_fallback")

    return {
        "rule": rule,
        "ml": {"available": False, "status": "DISABLED",
               "prediction": "DISABLED", "probability": None},
        "llm_judge": result,
        "rule_score": rule_score if rule.get("available") else None,
        "ml_score": None,
        "llm_judge_score": judge_score if (available or result.get("fallback_applied")) else None,
        "hybrid_score": min(100, score),
        "available_detectors": available_detectors,
        "weights_used": {"rule": 1.0} if not available else {"rule": 0.5, "gemini": 0.5},
        "classifications": classes,
        "latencies": {"judge_latency_ms": result.get("latency_ms", 0)},
        "detected": detected,
    }


def _run_pipeline(prompt: str, defense_mode: str, llm_mode: str = "mock",
                   log_to_db: bool = True, external_content=None, source=None, source_type=None,
                   model_profile: str = "STANDARD") -> dict:
    """Complete Part 3 security pipeline. All stages return observable backend status."""
    from services.crypto_service import CryptoService
    from services.canary_service import CanaryService
    from services.audit_service import AuditService
    rid=_request_id(); started=time.perf_counter(); timings={}
    cfg=current_app.config
    defense=DefenseEngine(); policy_engine=PolicyEngine()
    normalization=NormalizationEngine().inspect(prompt)
    timings["normalization_latency_ms"]=round((time.perf_counter()-started)*1000,2)
    working_prompt=normalization["normalized_text"]
    stage_log=[{"stage":"authentication","detail":{"status":"authenticated_or_demo","auth_required":bool(cfg.get("ENABLE_API_AUTH",True))}}]

    filt=defense.input_filtering(prompt,defense_mode)
    stage_log.append({"stage":"input_validation","detail":filt})
    if filt["blocked"]:
        result=_build_blocked_result(prompt,defense_mode,filt,stage_log)
        result.update({"request_id":rid,"latency_ms":round((time.perf_counter()-started)*1000,2),"timings":timings})
        if log_to_db: result["test_id"]=_persist_result(prompt,result)
        return result

    stage_log.append({"stage":"prompt_normalization","detail":normalization})
    isolation=ContextIsolation().isolate(user_input=prompt,external_content=external_content or [],source=source,source_type=source_type)
    stage_log.append({"stage":"trust_boundary","detail":isolation})

    # Cryptographic system-prompt integrity check must happen before model execution.
    crypto=CryptoService()
    protected_prompt=cfg.get("TARGET_SYSTEM_PROMPT","")
    expected=cfg.get("SYSTEM_PROMPT_HMAC","")
    if not expected and crypto.hmac_secret:
        expected=crypto.hmac_sha256(protected_prompt)
    integrity=crypto.verify_hmac(protected_prompt,expected)
    stage_log.append({"stage":"cryptographic_integrity","detail":{"status":integrity["status"],"reason":integrity["reason"]}})
    if not integrity["valid"]:
        decision=policy_engine.decide("critical",defense_mode,output_risk="critical",integrity_status="FAILED")
        result={"success":True,"request_id":rid,"prompt":prompt,"working_prompt":working_prompt,
                "normalization":normalization,"context_isolation":isolation,"defense_mode":defense_mode,
                "layers_applied":defense.get_layers(defense_mode),"blocked_by":"cryptographic_integrity",
                "attack_type":"SYSTEM_PROMPT_EXTRACTION","attack_types":["SYSTEM_PROMPT_EXTRACTION"],
                "difficulty":"hard","detected":True,"confidence":1.0,"risk_score":100,"risk_level":"critical",
                "risk_explanation":{"contributors":[{"factor":"System Prompt Integrity Failure","points":100}],"total":100,"level":"critical"},
                "indicators":{},"recommendations":[integrity["reason"]],"detectors":{},"model_response":None,
                "model_behavior":"blocked_pre_llm","output_analysis":None,"canary":{"status":"SAFE"},
                "integrity":integrity,"final_decision":decision["final_decision"],
                "display_decision":decision["display_decision"],"decision_reason":decision["reason"],
                "pipeline_stages":PIPELINE_STAGES+("cryptographic_integrity","canary_check","audit"),
                "stage_log":stage_log,"timings":{"total_latency_ms":round((time.perf_counter()-started)*1000,2)}}
        if log_to_db: result["test_id"]=_persist_result(prompt,result)
        return result

    analysis=PromptAnalyzer().analyze(working_prompt)
    stage_log.append({"stage":"prompt_analysis","detail":{"flags":analysis["flags"],"total_indicator_score":analysis["total_indicator_score"]}})
    hybrid=_gemini_primary_detect(working_prompt,normalization,external_content)
    timings.update(hybrid.get("latencies",{}))
    stage_log.append({"stage":"injection_detection","detail":{"status":"completed","available_detectors":hybrid["available_detectors"],"hybrid_score":hybrid["hybrid_score"]}})

    factors={}
    cats=" ".join(hybrid["classifications"]).lower()
    if "obfuscat" in cats or normalization["encoding_detections"]: factors["obfuscation"]=min(15,normalization["risk_adjustment"])
    if "indirect" in cats or external_content: factors["indirect_injection"]=10
    if "tool" in cats: factors["tool_abuse"]=12
    if "secret" in cats or "extraction" in cats: factors["information_extraction"]=10
    if "role" in cats or "hijack" in cats: factors["privilege_escalation"]=8
    risk=_risk_engine().compute(hybrid=hybrid,context={"normalization_risk_adjustment":0,"risk_factors":factors})
    risk["explanation"]["contributors"] += [{"factor":k.replace("_"," ").title(),"points":v} for k,v in factors.items()]
    risk["explanation"]["total"]=risk["risk_score"]
    classification=DetectionEngine().classify(analysis,working_prompt)
    classification["attack_type"]=hybrid["classifications"][0] if hybrid["classifications"] else ("harmful_content" if hybrid["llm_judge"].get("is_harmful_request") else "prompt_injection" if hybrid["llm_judge"].get("is_injection") else "none")
    classification["detected"]=hybrid["detected"]; classification["confidence"]=hybrid["llm_judge"].get("confidence", risk["confidence"]) or risk["confidence"]
    classification["difficulty"]="hard" if risk["risk_score"]>=70 else "medium" if risk["risk_score"]>=40 else "easy"
    classification["detected_categories"]=hybrid["classifications"]
    stage_log.append({"stage":"risk","detail":{"score":risk["risk_score"],"level":risk["risk_level"]}})
    stage_log.append({"stage":"llm_judge","detail":hybrid["llm_judge"]})

    # Dynamic canary is injected only into the simulated protected context.
    canary=CanaryService().generate()
    canary_token=canary.get("token")
    provider_cfg={"AI_PROVIDER":"mock"} if llm_mode=="mock" else {"AI_PROVIDER":"openai","OPENAI_API_KEY":cfg.get("OPENAI_API_KEY",""),"OPENAI_BASE_URL":cfg.get("OPENAI_BASE_URL",""),"OPENAI_MODEL":cfg.get("OPENAI_MODEL","gpt-4o-mini")}
    provider=get_provider(provider_cfg)
    model_system_context=f"{protected_prompt}\nCANARY:{canary_token}" if canary_token else protected_prompt
    llm_started=time.perf_counter()
    llm_result=provider.generate(working_prompt,system_prompt=model_system_context,attack_detected=classification["detected"],defense_mode=defense_mode,model_profile=model_profile)
    timings["llm_latency_ms"]=round((time.perf_counter()-llm_started)*1000,2)
    stage_log.append({"stage":"llm_simulation","detail":{"behavior":llm_result.get("behavior"),"provider":llm_result.get("provider"),"status":"completed","simulated":True}})

    output_validator=OutputValidator(DetectionEngine())
    output_analysis=output_validator.validate(llm_result["output"],classification["detected"],protected_prompt,canary_token)
    canary_check=CanaryService().check(llm_result["output"],canary_token)
    stage_log.append({"stage":"output_analysis","detail":output_analysis})
    stage_log.append({"stage":"canary_check","detail":canary_check})
    output_risk="critical" if output_analysis["leak_detected"] or canary_check["leaked"] else ("high" if output_analysis["severity"]=="high" else "safe")
    if output_risk=="critical":
        risk["risk_score"]=100; risk["risk_level"]="critical"
        risk["explanation"]["contributors"].append({"factor":"Output Leak / Canary","points":100})
        risk["explanation"]["total"]=100
    decision=policy_engine.decide(risk["risk_level"],defense_mode,output_risk=output_risk,
                                   canary_status=canary_check["status"],integrity_status="VALID")
    defense.enforce_policy(decision,defense_mode)
    stage_log.append({"stage":"policy_decision","detail":decision})
    stage_log.append({"stage":"final_result","detail":{"final_decision":decision["final_decision"]}})

    timings["risk_latency_ms"]=0
    timings["total_latency_ms"]=round((time.perf_counter()-started)*1000,2)
    result={"success":True,"request_id":rid,"prompt":prompt,"working_prompt":working_prompt,
            "normalization":normalization,"context_isolation":isolation,"defense_mode":defense_mode,
            "layers_applied":defense.get_layers(defense_mode),"blocked_by":None,
            "attack_type":classification["attack_type"],"attack_types":hybrid["classifications"],
            "difficulty":classification["difficulty"],"detected":classification["detected"],
            "confidence":classification["confidence"],"risk_score":risk["risk_score"],"risk_level":risk["risk_level"],
            "risk_explanation":risk["explanation"],"indicators":risk["indicators"],"recommendations":risk["recommendations"],
            "detectors":{"rule":hybrid["rule"],"ml":hybrid["ml"],"llm_judge":hybrid["llm_judge"],
                         "rule_score":hybrid["rule_score"],"ml_score":hybrid["ml_score"],"llm_judge_score":hybrid["llm_judge_score"],
                         "hybrid_score":hybrid["hybrid_score"],"available_detectors":hybrid["available_detectors"],"weights_used":hybrid["weights_used"]},
            "threat_fingerprint":_fingerprint(hybrid),"model_response":llm_result["output"],
            "model_behavior":llm_result.get("behavior"),"model_profile":model_profile,"output_analysis":output_analysis,"canary":canary_check,
            "integrity":integrity,"final_decision":decision["final_decision"],"display_decision":decision["display_decision"],
            "decision_reason":decision["reason"],"decision_mapping":_risk_engine().decision(risk["risk_level"]),
            "pipeline_stages":PIPELINE_STAGES+("cryptographic_integrity","canary_check","audit"),
            "stage_log":stage_log,"timings":timings}
    if log_to_db:
        result["test_id"]=_persist_result(prompt,result)
    return result

def _fingerprint(hybrid):
    cats=set(hybrid.get("classifications",[]))
    mapping={"Instruction Override":"INSTRUCTION_OVERRIDE","Information Extraction":"DATA_EXFILTRATION","Role Manipulation":"ROLE_HIJACKING","Obfuscation":"OBFUSCATION","Context Manipulation":"CONTEXT_MANIPULATION","Tool Abuse":"TOOL_ABUSE","Indirect Injection":"INDIRECT_INJECTION","Multi-Step Manipulation":"MULTI_STEP_ATTACK"}
    return {label:(100 if key in cats else 0) for label,key in mapping.items()}

def _decision_reason(level, decision):
    return {"allow":"Risk is within the safe band.","flag":"Risk requires monitoring under the active defense policy.","block":"Risk exceeded the active blocking threshold.","allow_monitor":"Risk is low; allow while monitoring.","warn_sanitize":"Medium risk; warn and sanitize before model use.","block_sanitize":"High risk; block or sanitize according to defense policy.","block_alert":"Critical risk; block and alert."}.get(decision,f"Decision based on {level} risk.")


def _build_blocked_result(prompt, defense_mode, filter_result, stage_log) -> dict:
    """Early-exit result when input_filtering hard-blocks a prompt before
    the rest of the pipeline runs."""
    stage_log.append({"stage": "final_result", "detail": {"final_decision": "block"}})
    lower = prompt.lower()
    inferred_type = "tool_action_escalation" if ("table" in lower or "system" in lower) else "direct_prompt_injection"
    return {
        "success": True,
        "prompt": prompt,
        "normalization": NormalizationEngine().inspect(prompt),
        "context_isolation": ContextIsolation().isolate(user_input=prompt),
        "working_prompt": prompt,
        "defense_mode": defense_mode,
        "layers_applied": DefenseEngine().get_layers(defense_mode),
        "blocked_by": "input_filtering",
        "attack_type": inferred_type,
        "difficulty": "hard",
        "detected": True,
        "confidence": 0.95,
        "risk_score": 100,
        "risk_level": "critical",
        "indicators": {},
        "recommendations": ["Prompt matched a hard-block pattern and was rejected before reaching the model."],
        "detectors": {},
        "model_response": None,
        "model_behavior": "blocked_pre_llm",
        "output_analysis": None,
        "final_decision": "block",
        "pipeline_stages": PIPELINE_STAGES,
        "stage_log": stage_log,
        "filter_reason": filter_result["reason"],
    }


def _persist_result(prompt: str, result: dict) -> int:
    """Persist normal history plus a tamper-evident audit record."""
    test = SecurityTest(
        prompt=prompt, attack_type=result.get("attack_type"), difficulty=result.get("difficulty"),
        risk_score=result.get("risk_score"), risk_level=result.get("risk_level"),
        confidence=result.get("confidence"), detection_result=json.dumps({
            "detectors":result.get("detectors"),"indicators":result.get("indicators"),
            "recommendations":result.get("recommendations"),"output_analysis":result.get("output_analysis"),
            "blocked_by":result.get("blocked_by"),"normalization":result.get("normalization"),
            "context_isolation":result.get("context_isolation"),"request_id":result.get("request_id"),
            "timings":result.get("timings"),"risk_explanation":result.get("risk_explanation"),
            "threat_fingerprint":result.get("threat_fingerprint"),"canary":result.get("canary"),
            "integrity":result.get("integrity"),"display_decision":result.get("display_decision")
        },default=str), defense_mode=result.get("defense_mode"),
        final_decision=result.get("final_decision"))
    db.session.add(test); db.session.commit()
    if result.get("detected"):
        db.session.add(SecurityEvent(event_type="detection",severity=result.get("risk_level","info"),
            description=f"Detected {result.get('attack_type')} pattern (risk={result.get('risk_score')}).",test_id=test.id))
    if result.get("final_decision") in ("flag","block"):
        db.session.add(SecurityEvent(event_type="policy_decision",severity=result.get("risk_level","info"),
            description=f"Policy decision='{result.get('final_decision')}' under defense_mode='{result.get('defense_mode')}'.",test_id=test.id))
    if (result.get("output_analysis") or {}).get("leak_detected"):
        db.session.add(SecurityEvent(event_type="output_leak",severity="critical",
            description="Output leak detected; sensitive evidence was redacted.",test_id=test.id))
    db.session.commit()

    from services.audit_service import AuditService
    AuditService().record({
        "request_id":result.get("request_id"),"attack_type":result.get("attack_type"),
        "normalization":result.get("normalization"),"rule_result":(result.get("detectors") or {}).get("rule"),
        "ml_result":(result.get("detectors") or {}).get("ml"),"llm_judge_result":(result.get("detectors") or {}).get("llm_judge"),
        "hybrid_score":(result.get("detectors") or {}).get("hybrid_score"),"risk":result.get("risk_score"),
        "decision":result.get("final_decision"),"output_status":(result.get("output_analysis") or {}).get("safety_status"),
        "canary_status":(result.get("canary") or {}).get("status"),"latency":result.get("timings"),
        "source":"Security Lab"
    })
    return test.id

def _default_defense_mode() -> str:
    mode = current_app.config.get("DEFAULT_DEFENSE_MODE", "standard")
    return mode if mode in ALLOWED_DEFENSE_MODES else "standard"


def _risk_engine() -> RiskEngine:
    cfg = current_app.config
    return RiskEngine(
        low=cfg.get("RISK_THRESHOLD_LOW", 20),
        medium=cfg.get("RISK_THRESHOLD_MEDIUM", 40),
        high=cfg.get("RISK_THRESHOLD_HIGH", 60),
        critical=cfg.get("RISK_THRESHOLD_CRITICAL", 80),
    )


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------

@api_bp.route("/analyze", methods=["POST"])
@require_auth({"ADMIN", "ANALYST"})
def analyze():
    """Runs the full security pipeline and persists a SecurityTest."""
    data = _parse_json_body()
    prompt = _require_prompt(data)
    defense_mode = _validate_choice(data, "defense_mode", ALLOWED_DEFENSE_MODES, _default_defense_mode())
    llm_mode = _validate_choice(data, "llm_mode", ALLOWED_LLM_MODES, "mock")
    model_profile = _validate_choice(data, "model_profile", {"SECURE","STANDARD","VULNERABLE","CUSTOM"}, "STANDARD")
    _validate_choice(data, "attack_type", ALLOWED_ATTACK_TYPES, "auto")
    _validate_choice(data, "difficulty", ALLOWED_DIFFICULTIES, "auto")
    external_content = data.get("external_content", [])
    if isinstance(external_content, str):
        external_content = [{"content": external_content}]
    if not isinstance(external_content, list):
        raise ValidationError("Field 'external_content' must be a string or list.")

    result = _run_pipeline(prompt, defense_mode, llm_mode=llm_mode, log_to_db=True,
                           external_content=external_content, source=data.get("source"), source_type=data.get("source_type"), model_profile=model_profile)
    return jsonify({"success": True, "request_id": result.get("request_id"), "data": result, "error": None})


@api_bp.route("/normalize", methods=["POST"])
@require_auth({"ADMIN","ANALYST"})
def normalize():
    data=_parse_json_body(); prompt=_require_prompt(data)
    return jsonify({"success":True,"request_id":_request_id(),"data":NormalizationEngine().inspect(prompt),"error":None})

@api_bp.route("/detect/rules", methods=["POST"])
@require_auth({"ADMIN","ANALYST"})
def detect_rules():
    data=_parse_json_body(); prompt=_require_prompt(data); n=NormalizationEngine().inspect(prompt)
    return jsonify({"success":True,"request_id":_request_id(),"data":RuleDetector().detect(n["normalized_text"],n,data.get("external_content",[])),"error":None})

@api_bp.route("/detect/ml", methods=["POST"])
@require_auth({"ADMIN","ANALYST"})
def detect_ml():
    data=_parse_json_body(); prompt=_require_prompt(data); n=NormalizationEngine().inspect(prompt)
    return jsonify({"success":True,"request_id":_request_id(),"data":MLDetector(current_app.config.get("ML_BACKEND","tfidf")).detect(n["normalized_text"]),"error":None})

@api_bp.route("/detect/llm-judge", methods=["POST"])
@require_auth({"ADMIN","ANALYST"})
def detect_llm_judge():
    data=_parse_json_body(); prompt=_require_prompt(data); n=NormalizationEngine().inspect(prompt)
    cfg=current_app.config
    judge=LLMJudge(
        cfg.get("LLM_JUDGE_MODE","mock"),
        cfg.get("GEMINI_API_KEY",""),
        "",
        cfg.get("GEMINI_MODEL","") or "gemini-3.8-flash",
        enabled=bool(cfg.get("LLM_JUDGE_ENABLED", False)),
        timeout_seconds=cfg.get("GEMINI_TIMEOUT_SECONDS", 10),
    )
    return jsonify({"success":True,"request_id":_request_id(),"data":judge.judge(n["normalized_text"]),"error":None})

@api_bp.route("/detect/hybrid", methods=["POST"])
@require_auth({"ADMIN","ANALYST"})
def detect_hybrid():
    data=_parse_json_body(); prompt=_require_prompt(data); n=NormalizationEngine().inspect(prompt)
    h=_detector_bundle().detect(n["normalized_text"],n,data.get("external_content",[]))
    return jsonify({"success":True,"request_id":_request_id(),"data":h,"error":None})

@api_bp.route("/security-score-legacy", methods=["GET"])
@require_auth({"ADMIN","ANALYST","VIEWER"})
def security_score_legacy():
    latest=SecurityTest.query.order_by(SecurityTest.timestamp.desc()).first()
    if not latest: return jsonify({"success":True,"request_id":_request_id(),"data":{"risk_score":0,"risk_level":"safe","message":"No analysis has been recorded."},"error":None})
    try: details=json.loads(latest.detection_result or "{}")
    except Exception: details={}
    return jsonify({"success":True,"request_id":_request_id(),"data":{"risk_score":latest.risk_score,"risk_level":latest.risk_level,"confidence":latest.confidence,"request_id":details.get("request_id")},"error":None})

@api_bp.route("/threat-fingerprint", methods=["GET"])
@require_auth({"ADMIN","ANALYST","VIEWER"})
def threat_fingerprint():
    latest=SecurityTest.query.order_by(SecurityTest.timestamp.desc()).first()
    if not latest: fp={"Instruction Override":0,"Information Extraction":0,"Role Manipulation":0,"Obfuscation":0,"Context Manipulation":0,"Tool Abuse":0,"Indirect Injection":0,"Multi-Step Manipulation":0}
    else:
        try: fp=json.loads(latest.detection_result or "{}").get("threat_fingerprint") or {}
        except Exception: fp={}
    return jsonify({"success":True,"request_id":_request_id(),"data":fp,"error":None})

@api_bp.route("/detect", methods=["POST"])
@require_auth({"ADMIN", "ANALYST"})
def detect():
    """Prompt-side detectors only -- no LLM call, no DB write."""
    data = _parse_json_body()
    prompt = _require_prompt(data)

    normalized = PromptAnalyzer._normalize(prompt)
    analysis = PromptAnalyzer().analyze(normalized)
    classification = DetectionEngine().classify(analysis, normalized)

    signals = {cat: info["score"] for cat, info in analysis["categories"].items()}
    risk_result = _risk_engine().compute(signals)

    return jsonify({
        "success": True,
        "data": {
            "analysis": analysis,
            "classification": classification,
            "risk": risk_result,
        },
    })


@api_bp.route("/defend", methods=["POST"])
@require_auth({"ADMIN", "ANALYST"})
def defend():
    """
    Defense/policy assessment. Accepts either:
      - {"risk_level": "...", "defense_mode": "..."}  -> quick policy lookup
      - {"prompt": "...", "defense_mode": "..."}       -> full defense run
    """
    data = _parse_json_body()
    defense_mode = _validate_choice(data, "defense_mode", ALLOWED_DEFENSE_MODES, _default_defense_mode())

    if isinstance(data.get("prompt"), str) and data.get("prompt", "").strip():
        prompt = _require_prompt(data)
        result = _run_pipeline(prompt, defense_mode, log_to_db=False)
        return jsonify({"success": True, "data": result})

    risk_level = data.get("risk_level", "low")
    if risk_level not in RISK_LEVELS:
        raise ValidationError(f"Invalid risk_level: {risk_level!r}. Must be one of: {', '.join(RISK_LEVELS)}.")

    decision = PolicyEngine().decide(risk_level, defense_mode)
    layers = DefenseEngine().get_layers(defense_mode)

    return jsonify({
        "success": True,
        "data": {**decision, "layers_applied": layers},
    })


@api_bp.route("/simulate", methods=["POST"])
@require_auth({"ADMIN", "ANALYST"})
def simulate():
    """
    Runs the pipeline through the Mock LLM. Supports an optional
    Before/After comparison (defense OFF vs the requested defense_mode)
    for the Security Lab's comparison view.
    """
    data = _parse_json_body()
    prompt = _require_prompt(data)
    defense_mode = _validate_choice(data, "defense_mode", ALLOWED_DEFENSE_MODES, _default_defense_mode())
    llm_mode = _validate_choice(data, "llm_mode", ALLOWED_LLM_MODES, "mock")
    model_profile = _validate_choice(data, "model_profile", {"SECURE","STANDARD","VULNERABLE","CUSTOM"}, "STANDARD")
    scenario_id = data.get("scenario_id")
    compare = bool(data.get("compare", False))

    if scenario_id is not None and not isinstance(scenario_id, int):
        raise ValidationError("Field 'scenario_id' must be an integer.")

    if compare:
        before = _run_pipeline(prompt, "disabled", llm_mode=llm_mode, log_to_db=False, model_profile=model_profile)
        after = _run_pipeline(prompt, defense_mode, llm_mode=llm_mode, log_to_db=True, model_profile=model_profile)
        return jsonify({
            "success": True,
            "data": {
                "scenario_id": scenario_id,
                "compare": True,
                "before": before,
                "after": after,
            },
        })

    result = _run_pipeline(prompt, defense_mode, llm_mode=llm_mode, log_to_db=True, model_profile=model_profile)
    result["scenario_id"] = scenario_id
    return jsonify({"success": True, "data": result})


@api_bp.route("/crypto/verify", methods=["POST"])
@require_auth({"ADMIN","ANALYST"})
def crypto_verify():
    from services.crypto_service import CryptoService
    data=_parse_json_body()
    prompt=data.get("system_prompt", current_app.config.get("TARGET_SYSTEM_PROMPT",""))
    expected=data.get("expected_hmac", current_app.config.get("SYSTEM_PROMPT_HMAC",""))
    svc=CryptoService()
    result=svc.verify_hmac(prompt,expected)
    return jsonify({"success":True,"request_id":_request_id(),"data":result,"error":None})

@api_bp.route("/canary/check", methods=["POST"])
@require_auth({"ADMIN","ANALYST"})
def canary_check():
    from services.canary_service import CanaryService
    data=_parse_json_body()
    return jsonify({"success":True,"request_id":_request_id(),"data":CanaryService().check(data.get("output",""),data.get("canary_token")),"error":None})

@api_bp.route("/audit/verify", methods=["POST"])
@require_auth({"ADMIN","ANALYST"})
def audit_verify():
    from services.audit_service import AuditService
    return jsonify({"success":True,"request_id":_request_id(),"data":AuditService().verify_chain(),"error":None})

@api_bp.route("/dashboard", methods=["GET"])
@require_auth({"ADMIN", "ANALYST", "VIEWER"})
def dashboard():
    """SOC-style top-line metrics, computed live from SQLite -- never hard-coded."""
    total_tests = SecurityTest.query.count()
    total_events = SecurityEvent.query.count()
    threats_detected = SecurityTest.query.filter(SecurityTest.attack_type != "none").count()
    threats_blocked = SecurityTest.query.filter(SecurityTest.final_decision == "block").count()
    high_risk_events = SecurityTest.query.filter(
        SecurityTest.risk_level.in_(["high", "critical"])
    ).count()

    avg_risk_row = db.session.query(db.func.avg(SecurityTest.risk_score)).scalar()
    average_risk = round(avg_risk_row, 1) if avg_risk_row is not None else 0

    return jsonify({
        "success": True,
        "data": {
            "total_tests": total_tests,
            "total_events": total_events,
            "threats_detected": threats_detected,
            "threats_blocked": threats_blocked,
            "high_risk_events": high_risk_events,
            "average_risk": average_risk,
            # --- kept for backward compatibility with Part 1/2 callers ---
            "high_risk_tests": high_risk_events,
            "blocked_tests": threats_blocked,
            "scenario_count": AttackScenario.query.count(),
        },
    })


def _apply_test_filters(query):
    """Shared filtering for /api/analytics and /api/history: attack_type,
    risk_level, defense_mode, and an inclusive date range on `timestamp`."""
    attack_type = request.args.get("attack_type")
    if attack_type and attack_type not in ("all", "auto"):
        query = query.filter(SecurityTest.attack_type == attack_type)

    risk_level = request.args.get("risk_level")
    if risk_level and risk_level != "all":
        query = query.filter(SecurityTest.risk_level == risk_level)

    defense_mode = request.args.get("defense_mode")
    if defense_mode and defense_mode != "all":
        query = query.filter(SecurityTest.defense_mode == defense_mode)

    start_date = request.args.get("start_date")
    if start_date:
        try:
            start_dt = datetime.strptime(start_date, "%Y-%m-%d")
            query = query.filter(SecurityTest.timestamp >= start_dt)
        except ValueError:
            raise ValidationError("Field 'start_date' must be in YYYY-MM-DD format.")

    end_date = request.args.get("end_date")
    if end_date:
        try:
            end_dt = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
            query = query.filter(SecurityTest.timestamp < end_dt)
        except ValueError:
            raise ValidationError("Field 'end_date' must be in YYYY-MM-DD format.")

    return query


@api_bp.route("/analytics", methods=["GET"])
@require_auth({"ADMIN", "ANALYST", "VIEWER"})
def analytics():
    """
    Filterable analytics for charts and metrics. Query params:
      attack_type, risk_level, defense_mode, start_date, end_date (YYYY-MM-DD)
    """
    tests = _apply_test_filters(SecurityTest.query).order_by(SecurityTest.timestamp.asc()).all()
    total = len(tests)

    by_risk_level = {}
    by_attack_type = {}
    by_defense_mode = {}
    by_date = {}
    detector_totals = {}

    detected_count = 0
    blocked_count = 0
    high_risk_count = 0
    risk_sum = 0

    for t in tests:
        by_risk_level[t.risk_level] = by_risk_level.get(t.risk_level, 0) + 1
        by_attack_type[t.attack_type] = by_attack_type.get(t.attack_type, 0) + 1

        mode_bucket = by_defense_mode.setdefault(t.defense_mode, {"count": 0, "blocked": 0, "detected": 0})
        mode_bucket["count"] += 1

        is_detected = t.attack_type != "none"
        is_blocked = t.final_decision == "block"
        if is_detected:
            detected_count += 1
            mode_bucket["detected"] += 1
        if is_blocked:
            blocked_count += 1
            mode_bucket["blocked"] += 1
        if t.risk_level in ("high", "critical"):
            high_risk_count += 1
        risk_sum += t.risk_score or 0

        date_key = t.timestamp.strftime("%Y-%m-%d") if t.timestamp else "unknown"
        by_date[date_key] = by_date.get(date_key, 0) + 1

        if t.detection_result:
            try:
                parsed = json.loads(t.detection_result)
                detectors = (parsed or {}).get("detectors") or {}
                for name, info in detectors.items():
                    score = (info or {}).get("score")
                    if isinstance(score, (int, float)):
                        bucket = detector_totals.setdefault(name, {"sum": 0, "count": 0})
                        bucket["sum"] += score
                        bucket["count"] += 1
            except (ValueError, TypeError):
                parsed = {}

    by_defense_mode_out = {}
    for mode, b in by_defense_mode.items():
        by_defense_mode_out[mode] = {
            "count": b["count"],
            "block_rate": round(100 * b["blocked"] / b["count"], 1) if b["count"] else 0,
            "detection_rate": round(100 * b["detected"] / b["count"], 1) if b["count"] else 0,
        }

    detection_methods = {
        name: round(b["sum"] / b["count"], 1) if b["count"] else 0
        for name, b in detector_totals.items()
    }

    timeseries = [{"date": d, "count": c} for d, c in sorted(by_date.items())]

    average_risk = round(risk_sum / total, 1) if total else 0
    detection_rate = round(100 * detected_count / total, 1) if total else 0
    block_rate = round(100 * blocked_count / total, 1) if total else 0
    high_risk_rate = round(100 * high_risk_count / total, 1) if total else 0
    defense_effectiveness = round(100 * blocked_count / detected_count, 1) if detected_count else 0

    return jsonify({
        "success": True,
        "data": {
            "total_tests": total,
            "by_risk_level": by_risk_level,
            "by_attack_type": by_attack_type,
            "by_defense_mode": by_defense_mode_out,
            "timeseries": timeseries,
            "detection_methods": detection_methods,
            "metrics": {
                "average_risk": average_risk,
                "detection_rate": detection_rate,
                "block_rate": block_rate,
                "high_risk_rate": high_risk_rate,
                "defense_effectiveness": defense_effectiveness,
            },
        },
    })


_HISTORY_SORT_FIELDS = {
    "timestamp": SecurityTest.timestamp,
    "risk_score": SecurityTest.risk_score,
    "confidence": SecurityTest.confidence,
    "id": SecurityTest.id,
}


@api_bp.route("/history", methods=["GET"])
@require_auth({"ADMIN", "ANALYST", "VIEWER"})
def history():
    """
    Searchable, filterable, sortable, paginated SecurityTest history.
    Query params: q, attack_type, risk_level, defense_mode, start_date,
    end_date, sort_by (timestamp|risk_score|confidence|id), sort_dir (asc|desc),
    page (default 1), page_size (default 10, max 100).

    Response keeps `data` as the plain list of records (same shape Part 1/2
    consumers expect) and adds a `meta` block with pagination info.
    """
    query = _apply_test_filters(SecurityTest.query)

    search = request.args.get("q", "").strip()
    if search:
        query = query.filter(SecurityTest.prompt.ilike(f"%{search}%"))

    sort_by = request.args.get("sort_by", "timestamp")
    if sort_by not in _HISTORY_SORT_FIELDS:
        raise ValidationError(
            f"Invalid sort_by: {sort_by!r}. Must be one of: {', '.join(_HISTORY_SORT_FIELDS)}."
        )
    sort_dir = request.args.get("sort_dir", "desc")
    if sort_dir not in ("asc", "desc"):
        raise ValidationError("Invalid sort_dir: must be 'asc' or 'desc'.")

    column = _HISTORY_SORT_FIELDS[sort_by]
    query = query.order_by(column.asc() if sort_dir == "asc" else column.desc())

    try:
        page = max(1, int(request.args.get("page", 1)))
        page_size = min(100, max(1, int(request.args.get("page_size", 10))))
    except ValueError:
        raise ValidationError("Fields 'page' and 'page_size' must be integers.")

    total = query.count()
    pages = max(1, (total + page_size - 1) // page_size)
    rows = query.offset((page - 1) * page_size).limit(page_size).all()

    return jsonify({
        "success": True,
        "data": [t.to_dict() for t in rows],
        "meta": {"total": total, "page": page, "page_size": page_size, "pages": pages},
    })


@api_bp.route("/events", methods=["GET"])
@require_auth({"ADMIN", "ANALYST"})
def events():
    """
    Query params (all optional): severity, event_type, page, page_size
    (default 50, max 200). Response keeps `data` as a plain list, plus `meta`.
    """
    query = SecurityEvent.query

    severity = request.args.get("severity")
    if severity and severity != "all":
        query = query.filter(SecurityEvent.severity == severity)

    event_type = request.args.get("event_type")
    if event_type and event_type != "all":
        query = query.filter(SecurityEvent.event_type == event_type)

    query = query.order_by(SecurityEvent.timestamp.desc())

    try:
        page = max(1, int(request.args.get("page", 1)))
        page_size = min(200, max(1, int(request.args.get("page_size", 50))))
    except ValueError:
        raise ValidationError("Fields 'page' and 'page_size' must be integers.")

    total = query.count()
    pages = max(1, (total + page_size - 1) // page_size)
    rows = query.offset((page - 1) * page_size).limit(page_size).all()

    return jsonify({
        "success": True,
        "data": [e.to_dict() for e in rows],
        "meta": {"total": total, "page": page, "page_size": page_size, "pages": pages},
    })


@api_bp.route("/scenarios", methods=["GET"])
@require_auth({"ADMIN", "ANALYST", "VIEWER"})
def scenarios():
    rows = AttackScenario.query.all()
    return jsonify({"success": True, "data": [r.to_dict() for r in rows]})


@api_bp.route("/settings", methods=["GET","POST"])
@require_auth({"ADMIN"})
def settings():
    if request.method=="GET":
        cfg=current_app.config
        return jsonify({"success":True,"data":{
            "rule_weight":cfg.get("RULE_WEIGHT"),"ml_weight":cfg.get("ML_WEIGHT"),"llm_judge_weight":cfg.get("LLM_JUDGE_WEIGHT"),
            "risk_thresholds":{"low":cfg.get("RISK_THRESHOLD_LOW"),"medium":cfg.get("RISK_THRESHOLD_MEDIUM"),"high":cfg.get("RISK_THRESHOLD_HIGH"),"critical":cfg.get("RISK_THRESHOLD_CRITICAL")},
            "defense_mode":cfg.get("DEFAULT_DEFENSE_MODE"),"ml_backend":cfg.get("ML_BACKEND"),"llm_judge":cfg.get("LLM_JUDGE_MODE"),
            "ai_provider":cfg.get("AI_PROVIDER","mock"),
            "llm_judge_enabled":bool(cfg.get("LLM_JUDGE_ENABLED",False)),
            "gemini_model":cfg.get("GEMINI_MODEL","") or "gemini-3.8-flash",
            "gemini_timeout_seconds":cfg.get("GEMINI_TIMEOUT_SECONDS",10),
            "gemini_configured":bool(cfg.get("GEMINI_API_KEY")),
            "rate_limit":cfg.get("RATE_LIMIT"),"canary_protection":cfg.get("CANARY_ENABLED"),"output_filtering":True,
            "audit_signing":bool(cfg.get("AUDIT_SIGNING_KEY")),"tls":bool(cfg.get("ENABLE_TLS")),"demo_mode":bool(cfg.get("DEMO_MODE")),
            "offline_mode":cfg.get("AI_PROVIDER")=="mock" and not cfg.get("LLM_JUDGE_ENABLED",False)
        },"error":None})
    data=_parse_json_body()
    # Runtime settings are intentionally limited to non-secret policy controls.
    allowed={"RULE_WEIGHT","ML_WEIGHT","LLM_JUDGE_WEIGHT","RISK_THRESHOLD_LOW","RISK_THRESHOLD_MEDIUM","RISK_THRESHOLD_HIGH","RISK_THRESHOLD_CRITICAL","DEFAULT_DEFENSE_MODE","ML_BACKEND","AI_PROVIDER","LLM_JUDGE_ENABLED","LLM_JUDGE_MODE","GEMINI_MODEL","GEMINI_TIMEOUT_SECONDS","RATE_LIMIT","CANARY_ENABLED","ENABLE_TLS","DEMO_MODE"}
    for key,value in data.items():
        envkey=key.upper()
        if envkey not in allowed:
            continue
        if envkey=="AI_PROVIDER" and str(value).lower() not in {"mock","gemini","openai"}:
            raise ValidationError("AI_PROVIDER must be mock, gemini, or openai.")
        if envkey=="LLM_JUDGE_MODE" and str(value).lower() not in {"mock","gemini"}:
            raise ValidationError("LLM_JUDGE_MODE must be mock or gemini.")
        if envkey=="LLM_JUDGE_ENABLED":
            value=bool(value)
        if envkey=="GEMINI_TIMEOUT_SECONDS":
            value=max(1,int(value))
        current_app.config[envkey]=value
    return jsonify({"success":True,"data":{"updated":[k.upper() for k in data if k.upper() in allowed]},"error":None})


# ========================= Part 4: Evaluation / Forensics / Reporting ======

@api_bp.route("/evaluation/run", methods=["POST"])
@require_auth({"ADMIN","ANALYST"})
def evaluation_run():
    from services.evaluation_service import run_evaluation
    data=_parse_json_body()
    size=data.get("size",10)
    if size not in (10,25,50,100) and not data.get("dataset_path"):
        raise ValidationError("size must be 10, 25, 50, or 100.")
    result=run_evaluation(size,data.get("dataset_path"))
    # Persist actual metric records, never fabricated values.
    if result.get("status")=="OK":
        from models.model_evaluation import ModelEvaluation
        for name, metrics in result["metrics"].items():
            for metric,value in metrics.items():
                if isinstance(value,(int,float)):
                    db.session.add(ModelEvaluation(model_name=name,metric=metric,value=value,details=json.dumps(metrics)))
        db.session.commit()
    return jsonify({"success":True,"request_id":_request_id(),"data":result,"error":None})

@api_bp.route("/evaluation/metrics", methods=["GET"])
@require_auth({"ADMIN","ANALYST","VIEWER"})
def evaluation_metrics():
    from services.evaluation_service import run_evaluation
    size=min(100,max(1,int(request.args.get("size",10))))
    return jsonify({"success":True,"request_id":_request_id(),"data":run_evaluation(size),"error":None})

@api_bp.route("/feedback", methods=["POST"])
@require_auth({"ADMIN","ANALYST"})
def feedback():
    data=_parse_json_body()
    prompt=_require_prompt(data)
    label=str(data.get("label","")).upper()
    allowed={"TRUE_POSITIVE","FALSE_POSITIVE","TRUE_NEGATIVE","FALSE_NEGATIVE"}
    if label not in allowed: raise ValidationError("label must be TRUE_POSITIVE, FALSE_POSITIVE, TRUE_NEGATIVE, or FALSE_NEGATIVE.")
    from models.feedback_sample import FeedbackSample
    row=FeedbackSample(prompt=prompt,prompt_hash=hashlib.sha256(prompt.encode()).hexdigest(),
        label=label,attack_type=data.get("attack_type"),detector_results=json.dumps(data.get("detector_results",{})),
        analyst=getattr(getattr(__import__("flask").g,"current_user",None),"username",None),feedback=data.get("feedback"))
    db.session.add(row); db.session.commit()
    return jsonify({"success":True,"request_id":_request_id(),"data":{"id":row.id},"error":None})

@api_bp.route("/feedback/export", methods=["GET"])
@require_auth({"ADMIN","ANALYST"})
def feedback_export():
    from models.feedback_sample import FeedbackSample
    rows=FeedbackSample.query.order_by(FeedbackSample.id.asc()).all()
    body="".join(json.dumps({"text":r.prompt,"label":r.label.lower(),"attack_type":r.attack_type},ensure_ascii=False)+"\n" for r in rows)
    return current_app.response_class(body,mimetype="application/x-ndjson",
        headers={"Content-Disposition":"attachment; filename=promptshield_feedback.jsonl"})

@api_bp.route("/security-score", methods=["GET"])
@require_auth({"ADMIN","ANALYST","VIEWER"})
def security_score_part4():
    from services.evaluation_service import posture_from_data
    from models.audit_log import AuditLog
    from models.feedback_sample import FeedbackSample
    result=posture_from_data(db,SecurityTest,AuditLog,FeedbackSample)
    return jsonify({"success":True,"request_id":_request_id(),"data":result,"error":None})

@api_bp.route("/audit/events", methods=["GET"])
@require_auth({"ADMIN","ANALYST","VIEWER"})
def audit_events():
    from models.audit_log import AuditLog
    rows=AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(200).all()
    return jsonify({"success":True,"request_id":_request_id(),"data":[{
        "id":x.id,"timestamp":x.timestamp.isoformat(),"request_id":x.request_id,"attack_type":x.attack_type,
        "risk":x.risk,"decision":x.decision,"source":x.source,"event_hash":x.event_hash,
        "previous_hash":x.previous_hash,"output_status":x.output_status,"canary_status":x.canary_status,
        "latency":json.loads(x.latency or "{}") if x.latency else {}} for x in rows],"error":None})

@api_bp.route("/audit/events/<int:event_id>", methods=["GET"])
@require_auth({"ADMIN","ANALYST","VIEWER"})
def audit_event_detail(event_id):
    from models.audit_log import AuditLog
    row=db.session.get(AuditLog,event_id)
    if not row: return jsonify({"success":False,"error":"Audit event not found."}),404
    def loads(v):
        try:return json.loads(v or "{}")
        except Exception:return {}
    return jsonify({"success":True,"request_id":_request_id(),"data":{
        "id":row.id,"timestamp":row.timestamp.isoformat(),"request_id":row.request_id,
        "authentication":{"user_id":row.user_id,"api_key_id":row.api_key_id},
        "normalization":loads(row.normalization_result),"rule":loads(row.rule_result),
        "ml":loads(row.ml_result),"llm_judge":loads(row.llm_judge_result),
        "hybrid_score":row.hybrid_score,"risk":row.risk,"decision":row.decision,
        "output_status":row.output_status,"canary_status":row.canary_status,
        "latency":loads(row.latency),"previous_hash":row.previous_hash,"event_hash":row.event_hash,
        "details":loads(row.details)}})

@api_bp.route("/reports/<request_id>", methods=["GET"])
@require_auth({"ADMIN","ANALYST","VIEWER"})
def report(request_id):
    from models.audit_log import AuditLog
    row=AuditLog.query.filter_by(request_id=request_id).order_by(AuditLog.id.desc()).first()
    if not row: return jsonify({"success":False,"error":"Request ID not found."}),404
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    buf=io.BytesIO(); doc=SimpleDocTemplate(buf,pagesize=A4); styles=getSampleStyleSheet()
    def pretty(v):
        return json.dumps(v,indent=2,default=str)[:5000]
    data=[Paragraph("PromptShield AI Security Report",styles["Title"]),
          Paragraph(f"Request ID: {request_id}",styles["Normal"]),
          Paragraph(f"Timestamp: {row.timestamp.isoformat()}",styles["Normal"]),
          Spacer(1,12),
          Paragraph(f"Attack Type: {row.attack_type or 'SAFE'}",styles["Normal"]),
          Paragraph(f"Hybrid Risk: {row.hybrid_score if row.hybrid_score is not None else 'NO DATA'}",styles["Normal"]),
          Paragraph(f"Risk: {row.risk if row.risk is not None else 'NO DATA'}",styles["Normal"]),
          Paragraph(f"Decision: {row.decision or 'NO DATA'}",styles["Normal"]),
          Paragraph(f"Output: {row.output_status or 'NO DATA'}",styles["Normal"]),
          Paragraph(f"Canary: {row.canary_status or 'NO DATA'}",styles["Normal"]),
          Paragraph(f"Audit Hash: {row.event_hash}",styles["Normal"]),
          Spacer(1,12), Paragraph("Detector Results",styles["Heading2"]),
          Paragraph(pretty({"rule":row.rule_result,"ml":row.ml_result,"llm_judge":row.llm_judge_result}),styles["Code"])]
    doc.build(data); buf.seek(0)
    return current_app.response_class(buf.getvalue(),mimetype="application/pdf",
        headers={"Content-Disposition":f"inline; filename=promptshield-{request_id}.pdf"})

@api_bp.route("/context/analyze", methods=["POST"])
@require_auth({"ADMIN","ANALYST"})
def context_analyze_part4():
    data=_parse_json_body(); prompt=_require_prompt(data)
    from services.context_isolation import ContextIsolation
    return jsonify({"success":True,"request_id":_request_id(),"data":ContextIsolation().isolate(user_input=prompt,external_content=data.get("external_content",[]),source=data.get("source"),source_type=data.get("source_type")),"error":None})

@api_bp.route("/indirect-injection/analyze", methods=["POST"])
@require_auth({"ADMIN","ANALYST"})
def indirect_injection_analyze():
    data=_parse_json_body(); prompt=_require_prompt(data)
    ext=data.get("external_content",[])
    from services.rule_detector import RuleDetector
    result=RuleDetector().detect(prompt,external_content=ext)
    return jsonify({"success":True,"request_id":_request_id(),"data":result,"error":None})

@api_bp.route("/output/validate", methods=["POST"])
@require_auth({"ADMIN","ANALYST"})
def output_validate_part4():
    data=_parse_json_body()
    output=data.get("output","")
    if not isinstance(output,str): raise ValidationError("output must be a string.")
    from services.output_validator import OutputValidator
    result=OutputValidator().validate(output,system_prompt=current_app.config.get("TARGET_SYSTEM_PROMPT",""),canary_token=data.get("canary_token"))
    return jsonify({"success":True,"request_id":_request_id(),"data":result,"error":None})
