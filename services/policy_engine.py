"""Final security policy engine, preserving Part 2 decision strings."""
_LEVEL_ORDER={"safe":0,"low":1,"medium":2,"high":3,"critical":4}
DEFENSE_MODES=("disabled","basic","standard","maximum","strict")
class PolicyEngine:
    DEFENSE_MODES=DEFENSE_MODES
    def decide(self,risk_level,defense_mode="standard",output_risk="safe",canary_status="SAFE",integrity_status="VALID"):
        mode=defense_mode if defense_mode in DEFENSE_MODES else "standard"
        r=_LEVEL_ORDER.get(risk_level,0); o=_LEVEL_ORDER.get(output_risk,0)
        if mode=="disabled":
            final="allow"
        elif canary_status=="LEAKED" or integrity_status=="FAILED" or o>=4:
            final="block"
        elif r>=4:
            final="block"
        elif r>=3:
            final="block" if mode in {"maximum","strict"} else "flag"
        elif r>=2:
            final="flag"
        else:
            final="allow"
        canonical={"allow":"ALLOW","flag":"WARN","block":"BLOCK"}[final]
        return {"final_decision":final,"display_decision":canonical,"defense_mode":mode,
                "risk_level":risk_level,"output_risk":output_risk,"canary_status":canary_status,
                "integrity_status":integrity_status,
                "reason":self.reason(risk_level,final,canary_status,integrity_status)}
    def reason(self,level,decision,canary="SAFE",integrity="VALID"):
        if integrity=="FAILED": return "System prompt integrity verification failed; execution blocked."
        if canary=="LEAKED": return "Canary leakage detected; output blocked and alert required."
        return {"allow":"Risk is within the safe band.","flag":"Risk requires monitoring under the active defense policy.","block":"Risk exceeded the active blocking threshold."}.get(decision,f"Decision based on {level} risk.")
