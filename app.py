from flask import Flask, request, render_template, jsonify
import numpy as np
import pandas as pd
import pickle
import os
import warnings

warnings.filterwarnings('ignore')
from feature import FeatureExtraction

app = Flask(__name__)
base_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(base_dir, 'pickle', 'model.pkl')
meta_path = os.path.join(base_dir, 'pickle', 'meta.pkl')

# Load trained Gradient Boosting Classifier
with open(model_path, 'rb') as f:
    gbc = pickle.load(f)

# Load training metadata & model benchmarks
meta_info = {}
if os.path.exists(meta_path):
    with open(meta_path, 'rb') as f:
        meta_info = pickle.load(f)

# Feature Names list
FEATURE_NAMES = FeatureExtraction.FEATURE_NAMES

@app.route("/", methods=["GET", "POST"])
def index():
    prediction_data = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            try:
                # Extract features
                obj = FeatureExtraction(url, live_fetch=True, timeout=2.0)
                feats = obj.getFeaturesList()
                feat_dict = obj.getFeaturesDict()
                
                # Reshape for model inference
                x = np.array(feats).reshape(1, 30)
                # Create DataFrame with exact training column names to avoid warnings
                x_df = pd.DataFrame([feats], columns=FEATURE_NAMES)
                
                y_pred = int(gbc.predict(x_df)[0])
                # Classes: [-1 (Phishing), 1 (Legitimate)]
                # gbc.classes_ is array([-1,  1])
                proba = gbc.predict_proba(x_df)[0]
                y_pro_phishing = float(proba[0])
                y_pro_legit = float(proba[1])

                is_safe = (y_pred == 1)
                safety_score = round(y_pro_legit * 100, 2)
                phishing_risk = round(y_pro_phishing * 100, 2)

                # Determine risk level category
                if safety_score >= 80:
                    risk_badge = "SAFE"
                    risk_color = "emerald"
                elif safety_score >= 45:
                    risk_badge = "SUSPICIOUS"
                    risk_color = "amber"
                else:
                    risk_badge = "MALICIOUS / PHISHING"
                    risk_color = "rose"

                # Categorize features for deep inspection tab
                address_feats = ["UsingIP", "LongURL", "ShortURL", "Symbol@", "Redirecting//", "PrefixSuffix-", "SubDomains", "HTTPSDomainURL"]
                security_feats = ["HTTPS", "DomainRegLen", "NonStdPort", "AgeofDomain", "DNSRecording", "StatsReport"]
                content_feats = ["Favicon", "RequestURL", "AnchorURL", "LinksInScriptTags", "ServerFormHandler", "InfoEmail", "AbnormalURL", "IframeRedirection"]
                behavior_feats = ["WebsiteForwarding", "StatusBarCust", "DisableRightClick", "UsingPopupWindow", "WebsiteTraffic", "PageRank", "GoogleIndex", "LinksPointingToPage"]

                prediction_data = {
                    "url": url,
                    "is_safe": is_safe,
                    "pred_code": y_pred,
                    "safety_score": safety_score,
                    "phishing_risk": phishing_risk,
                    "risk_badge": risk_badge,
                    "risk_color": risk_color,
                    "features_count": len(feats),
                    "feature_details": feat_dict,
                    "categories": {
                        "Address & URL Structure": {k: feat_dict[k] for k in address_feats if k in feat_dict},
                        "Security & Domain Trust": {k: feat_dict[k] for k in security_feats if k in feat_dict},
                        "Webpage Content & Forms": {k: feat_dict[k] for k in content_feats if k in feat_dict},
                        "Behavioral & Traffic": {k: feat_dict[k] for k in behavior_feats if k in feat_dict}
                    }
                }
            except Exception as e:
                prediction_data = {
                    "url": url,
                    "error": str(e)
                }

    return render_template(
        "index.html",
        result=prediction_data,
        meta=meta_info
    )

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """REST API endpoint for automated URL inspection"""
    data = request.get_json(silent=True) or request.form
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided", "status": 400}), 400

    try:
        obj = FeatureExtraction(url, live_fetch=True, timeout=2.0)
        feats = obj.getFeaturesList()
        feat_dict = obj.getFeaturesDict()
        x_df = pd.DataFrame([feats], columns=FEATURE_NAMES)

        y_pred = int(gbc.predict(x_df)[0])
        proba = gbc.predict_proba(x_df)[0]
        y_pro_phishing = float(proba[0])
        y_pro_legit = float(proba[1])

        return jsonify({
            "status": "success",
            "url": url,
            "prediction": "Legitimate" if y_pred == 1 else "Phishing",
            "is_safe": bool(y_pred == 1),
            "safety_percentage": round(y_pro_legit * 100, 2),
            "phishing_risk_percentage": round(y_pro_phishing * 100, 2),
            "features_vector": feats,
            "feature_details": feat_dict
        })
    except Exception as e:
        return jsonify({"error": str(e), "status": 500}), 500

@app.route("/api/models", methods=["GET"])
def api_models():
    """Returns benchmark comparison data across the 5 trained ML models"""
    return jsonify(meta_info)

if __name__ == "__main__":
    print("=" * 65)
    print("  PHISHSHIELD PRO - AI PHISHING URL DETECTION ENGINE")
    print(f"  Primary Model: Gradient Boosting Classifier (Acc: {meta_info.get('primary_accuracy', 97.01)}%)")
    print("  Server running at http://127.0.0.1:5000")
    print("=" * 65)
    app.run(debug=True, port=5000)
