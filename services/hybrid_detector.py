"""Fusion layer for Rule + ML + LLM Judge."""
import time
class HybridDetector:
    DEFAULT_WEIGHTS={"rule":.35,"ml":.40,"llm_judge":.25}
    def __init__(self, rule=None, ml=None, judge=None, weights=None):
        self.rule=rule; self.ml=ml; self.judge=judge; self.weights=weights or dict(self.DEFAULT_WEIGHTS)
    def detect(self,text,normalization=None,external_content=None):
        t=time.perf_counter(); rule=self.rule.detect(text,normalization,external_content) if self.rule else {"available":False}; rule_latency=round((time.perf_counter()-t)*1000,3)
        t=time.perf_counter(); ml=self.ml.detect(text) if self.ml else {"available":False}; ml_latency=round((time.perf_counter()-t)*1000,3)
        t=time.perf_counter(); judge=self.judge.judge(text,rule) if self.judge else {"available":False}; judge_latency=round((time.perf_counter()-t)*1000,3)
        raw={"rule":rule,"ml":ml,"llm_judge":judge}
        vals={}; available=[]
        if rule.get("available"): vals["rule"]=rule.get("score",0)/100; available.append("rule")
        if ml.get("available"): vals["ml"]=(ml.get("probability") or 0); available.append("ml")
        if judge.get("available"): vals["llm_judge"]=(judge.get("risk_score") if judge.get("risk_score") is not None else ((judge.get("risk_score") if judge.get("risk_score") is not None else (judge.get("risk") or 0))))/100; available.append("llm_judge")
        w={k:self.weights[k] for k in available}; total=sum(w.values())
        used={k:round(v/total,4) for k,v in w.items()} if total else {}
        score=round(sum(vals[k]*used[k] for k in available)*100) if available else 0
        classes=[]
        if rule.get("categories"): classes.extend(rule["categories"])
        if judge.get("attack_type") and judge["attack_type"] not in ("SAFE","PROMPT_INJECTION","UNAVAILABLE"): classes.append(judge["attack_type"])
        mapping={"Instruction Override":"INSTRUCTION_OVERRIDE","System Prompt Extraction":"SYSTEM_PROMPT_EXTRACTION","Role Hijacking":"ROLE_HIJACKING","Jailbreak":"JAILBREAK","Information Extraction":"DATA_EXFILTRATION","Secret Extraction":"DATA_EXFILTRATION","Policy Bypass":"CONTEXT_MANIPULATION","Context Manipulation":"CONTEXT_MANIPULATION","Delimiter Manipulation":"CONTEXT_MANIPULATION","Tool Abuse":"TOOL_ABUSE","Obfuscation":"OBFUSCATION","Encoded Payload":"OBFUSCATION","Indirect Injection":"INDIRECT_INJECTION","Multi-Step Manipulation":"MULTI_STEP_ATTACK"}
        classes=[mapping.get(c,c) for c in classes]
        classes=list(dict.fromkeys(classes))
        # Component latency is measured around the actual detector calls above.
        # A zero/unavailable component is represented explicitly, never fabricated.
        return {"rule":rule,"ml":ml,"llm_judge":judge,"rule_score":round(rule.get("score",0),2) if rule.get("available") else None,"ml_score":round((ml.get("probability") or 0)*100,2) if ml.get("available") else None,"llm_judge_score":round(((judge.get("risk_score") if judge.get("risk_score") is not None else (judge.get("risk") or 0))),2) if judge.get("available") else None,"hybrid_score":score,"available_detectors":available,"weights_used":used,"classifications":classes,"latencies":{"rule_latency_ms":rule_latency,"ml_latency_ms":ml_latency,"judge_latency_ms":judge_latency},"detected":score>=50 or any([rule.get("score",0)>=40, bool(judge.get("is_injection")), ml.get("prediction")=="attack"])}
