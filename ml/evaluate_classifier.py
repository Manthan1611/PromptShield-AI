"""Evaluate the trained classifier. No metrics are claimed until this script is run."""
import os, json, joblib
from sklearn.metrics import classification_report, accuracy_score
ROOT=os.path.dirname(os.path.dirname(__file__))
path=os.path.join(os.path.dirname(__file__),"artifacts","tfidf_injection.joblib")
if not os.path.exists(path): print("MODEL STATUS: NOT TRAINED"); raise SystemExit(0)
bundle=joblib.load(path)
rows=[json.loads(x) for x in open(os.path.join(ROOT,"data","prompt_injection_dataset.jsonl"),encoding="utf8") if x.strip()]
X=[r["text"] for r in rows]; y=["attack" if r["label"]!="benign" else "benign" for r in rows]
pred=bundle["classifier"].predict(bundle["vectorizer"].transform(X))
print("Evaluation on supplied dataset (training-set evaluation, not a generalization estimate).")
print("Accuracy:",accuracy_score(y,pred))
print(classification_report(y,pred,zero_division=0))
