"""Offline ML detector using TF-IDF + Logistic Regression."""
import os, json, hashlib, time
MODEL_DIR=os.path.join(os.path.dirname(os.path.dirname(__file__)),"ml","artifacts")
MODEL_PATH=os.path.join(MODEL_DIR,"tfidf_injection.joblib")
VERSION="tfidf-v1-untrained"

class MLDetector:
    def __init__(self, backend="tfidf"):
        self.backend=backend
    def detect(self, text):
        if self.backend != "tfidf":
            return {"prediction":"UNAVAILABLE","probability":None,"backend":self.backend,"model_version":"unavailable","features":[],"available":False,"status":"UNAVAILABLE"}
        try:
            import joblib
            if not os.path.exists(MODEL_PATH):
                return {"prediction":"NOT TRAINED","probability":None,"backend":"tfidf","model_version":"not-trained","features":[],"available":False,"status":"NOT TRAINED"}
            bundle=joblib.load(MODEL_PATH)
            vec, clf=bundle["vectorizer"],bundle["classifier"]
            X=vec.transform([text or ""])
            probs=clf.predict_proba(X)[0]
            idx=int(probs.argmax())
            pred=str(clf.classes_[idx])
            feats=[f for f,v in zip(vec.get_feature_names_out(), X.toarray()[0]) if v][:12]
            return {"prediction":pred,"probability":round(float(probs[idx]),4),"backend":"tfidf","model_version":bundle.get("version","tfidf"),"features":feats,"available":True,"status":"TRAINED"}
        except Exception as exc:
            return {"prediction":"UNAVAILABLE","probability":None,"backend":"tfidf","model_version":"unavailable","features":[],"available":False,"status":"UNAVAILABLE","error":str(exc)}
