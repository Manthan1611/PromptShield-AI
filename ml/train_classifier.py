"""Train the offline TF-IDF + Logistic Regression detector. Metrics are printed only when evaluated."""
import json, os, joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
ROOT=os.path.dirname(os.path.dirname(__file__))
rows=[]
with open(os.path.join(ROOT,"data","prompt_injection_dataset.jsonl"),encoding="utf8") as f:
    rows=[json.loads(x) for x in f if x.strip()]
X=[r["text"] for r in rows]; y=["attack" if r["label"]!="benign" else "benign" for r in rows]
vec=TfidfVectorizer(ngram_range=(1,2),lowercase=True)
Xt=vec.fit_transform(X)
clf=LogisticRegression(max_iter=1000).fit(Xt,y)
out=os.path.join(os.path.dirname(__file__),"artifacts"); os.makedirs(out,exist_ok=True)
joblib.dump({"vectorizer":vec,"classifier":clf,"version":"tfidf-v1"},os.path.join(out,"tfidf_injection.joblib"))
print("TRAINED: tfidf-v1")
