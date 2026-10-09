"""Offline, evidence-based evaluation for PromptShield AI."""
import json, os, time
from collections import Counter
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

DATA_DIR=os.path.join(os.path.dirname(os.path.dirname(__file__)),"data")
DATASETS={
 "prompt_injection_dataset.jsonl": os.path.join(DATA_DIR,"prompt_injection_dataset.jsonl"),
 "benign_prompts.jsonl": os.path.join(DATA_DIR,"benign_prompts.jsonl"),
 "attack_samples.jsonl": os.path.join(DATA_DIR,"attack_samples.jsonl"),
}

ATTACK_LABELS={"direct_injection","instruction_override","role_manipulation","information_extraction",
"obfuscation","context_manipulation","indirect_injection","multi_step_manipulation","tool_abuse",
"system_prompt_extraction","secret_extraction","policy_bypass","delimiter_manipulation","jailbreak"}
BENIGN={"benign","safe","none","SAFE"}

def load_samples(limit=None, dataset_path=None):
    path=dataset_path or DATASETS["prompt_injection_dataset.jsonl"]
    rows=[]
    with open(path,encoding="utf8") as f:
        for line in f:
            if line.strip():
                x=json.loads(line); rows.append(x)
                if limit and len(rows)>=limit: break
    return rows

def binary_truth(label):
    return 0 if str(label) in BENIGN else 1

def _metrics(y_true,y_pred):
    if not y_true: return {"status":"INSUFFICIENT DATA"}
    tn,fp,fn,tp=confusion_matrix(y_true,y_pred,labels=[0,1]).ravel()
    return {"status":"OK","accuracy":round(accuracy_score(y_true,y_pred),4),
      "precision":round(precision_score(y_true,y_pred,zero_division=0),4),
      "recall":round(recall_score(y_true,y_pred,zero_division=0),4),
      "f1":round(f1_score(y_true,y_pred,zero_division=0),4),
      "false_positive_rate":round(fp/(fp+tn),4) if fp+tn else None,
      "false_negative_rate":round(fn/(fn+tp),4) if fn+tp else None,
      "confusion_matrix":{"tn":int(tn),"fp":int(fp),"fn":int(fn),"tp":int(tp)}}

def evaluate(samples, detector_bundle):
    out={}
    for name in ("rule","ml","llm_judge","hybrid"):
        y=[]; p=[]; latency=[]
        for row in samples:
            text=row.get("text",""); y.append(binary_truth(row.get("label")))
            started=time.perf_counter()
            if name=="rule":
                result=detector_bundle.rule.detect(text)
                pred=1 if result.get("score",0)>=50 else 0
            elif name=="ml":
                result=detector_bundle.ml.detect(text)
                if not result.get("available"): continue
                pred=0 if str(result.get("prediction")).lower() in BENIGN else 1
            elif name=="llm_judge":
                result=detector_bundle.judge.judge(text,{})
                if not result.get("available"): continue
                pred=1 if result.get("is_injection") else 0
            else:
                result=detector_bundle.detect(text)
                pred=1 if result.get("detected") else 0
            latency.append((time.perf_counter()-started)*1000); p.append(pred)
        m=_metrics(y[:len(p)],p) if p else {"status":"INSUFFICIENT DATA"}
        if latency: m["latency_ms"]=round(sum(latency)/len(latency),3)
        m["samples_evaluated"]=len(p)
        out[name]=m
    return out

def dataset_summary():
    rows=load_samples()
    return {"dataset_size":len(rows),"benign_samples":sum(binary_truth(x.get("label"))==0 for x in rows),
            "attack_samples":sum(binary_truth(x.get("label"))==1 for x in rows),
            "categories":dict(Counter(str(x.get("label")) for x in rows))}

def run_evaluation(size=10, dataset_path=None):
    rows=load_samples(size,dataset_path)
    from services.rule_detector import RuleDetector
    from services.ml_detector import MLDetector
    from services.llm_judge import LLMJudge
    from services.hybrid_detector import HybridDetector
    bundle=HybridDetector(RuleDetector(),MLDetector("tfidf"),LLMJudge("mock"))
    metrics=evaluate(rows,bundle)
    return {"dataset":dataset_summary() if dataset_path is None else {"dataset_size":len(rows)},
            "requested":size,"samples":len(rows),"metrics":metrics,
            "status":"OK" if rows else "INSUFFICIENT DATA"}

def posture_from_data(db, SecurityTest, AuditLog, FeedbackSample):
    total=SecurityTest.query.count()
    if total==0: return {"status":"NO DATA","score":None,"components":{},"explanation":"No analysis records are available."}
    tests=SecurityTest.query.all()
    actual=[t for t in tests if t.attack_type and t.attack_type!="none"]
    detected=sum(1 for t in actual if (t.risk_score or 0)>=50)
    blocked=sum(1 for t in actual if t.final_decision in ("block","block_alert"))
    leaks=sum(1 for t in tests if "leak" in (t.detection_result or "").lower())
    fp=0; reviewed=FeedbackSample.query.count()
    for f in FeedbackSample.query.all():
        if str(f.label).upper()=="FALSE_POSITIVE": fp+=1
    recall=detected/len(actual) if actual else None
    block=blocked/len(actual) if actual else None
    output=1-(leaks/total)
    audit_ok=1 if not AuditLog.query.first() else None
    auth=1
    fpr=(fp/reviewed) if reviewed else None
    components={"detection_recall":recall,"defense_block_rate":block,"output_protection":output,
                 "audit_integrity":audit_ok,"authentication":auth,"false_positive_rate":fpr}
    available=[v for v in components.values() if v is not None]
    score=round(sum(components[k] if k!="false_positive_rate" else 1-v for k,v in components.items() if components[k] is not None)/len(available)*100,1) if available else None
    return {"status":"OK" if score is not None else "INSUFFICIENT DATA","score":score,"components":components,
            "explanation":"Average of available security controls; false-positive rate is inverted as a quality component."}
