"""Risk scoring and explainable classification for the hybrid security pipeline."""
RISK_LEVELS=("safe","low","medium","high","critical")

class RiskEngine:
    def __init__(self, weights=None, low=20, medium=40, high=60, critical=80):
        self.thresholds={"low":int(low),"medium":int(medium),"high":int(high),"critical":int(critical)}
        self.weights=weights or {}

    def score_to_level(self, score):
        score=float(score or 0)
        if score <= self.thresholds["low"]: return "safe"
        if score <= self.thresholds["medium"]: return "low"
        if score <= self.thresholds["high"]: return "medium"
        if score <= self.thresholds["critical"]: return "high"
        return "critical"

    def compute(self, signals=None, hybrid=None, context=None):
        if hybrid:
            score=float(hybrid.get("hybrid_score") or 0)
            reasons=[]
            used=hybrid.get("weights_used") or {}
            component_scores={"rule":hybrid.get("rule_score"),"ml":hybrid.get("ml_score"),"llm_judge":hybrid.get("llm_judge_score")}
            labels={"rule":"Rule Detection","ml":"ML Detection","llm_judge":"LLM Judge"}
            for key,val in component_scores.items():
                if val is not None and val > 0:
                    reasons.append({"factor":labels[key],"points":round(val*(used.get(key,0)))})
            norm=(context or {}).get("normalization_risk_adjustment",0)
            if norm: score=min(100,score+norm); reasons.append({"factor":"Obfuscation / Encoding","points":norm})
            flags=(context or {}).get("risk_factors",{})
            for name,pts in flags.items():
                if pts: score=min(100,score+pts); reasons.append({"factor":name.replace("_"," ").title(),"points":pts})
            score=round(min(100,score))
            level=self.score_to_level(score)
            confs=[x for x in [hybrid.get("ml",{}).get("probability"),hybrid.get("llm_judge",{}).get("confidence")] if isinstance(x,(int,float))]
            confidence=round(sum(confs)/len(confs),2) if confs else round(min(.99,score/100),2)
            return {"risk_score":score,"risk_level":level,"confidence":confidence,"indicators":{k:v for k,v in (signals or {}).items()},"recommendations":[],"explanation":{"contributors":reasons,"total":score,"level":level}}
        signals=signals or {}
        vals=[v for v in signals.values() if isinstance(v,(int,float)) and v>0]
        score=round(sum(vals)/len(vals)) if vals else 0
        return {"risk_score":score,"risk_level":self.score_to_level(score),"confidence":round(.4+.5*score/100,2),"indicators":signals,"recommendations":[],"explanation":{"contributors":[],"total":score,"level":self.score_to_level(score)}}

    def decision(self, level):
        return {"safe":"allow","low":"allow_monitor","medium":"warn_sanitize","high":"block_sanitize","critical":"block_alert"}.get(level,"allow")
