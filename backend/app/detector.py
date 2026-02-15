import os
import joblib
import numpy as np

from app.risk_engine import compute_final_risk
from engine.parser import parse_url
from app.brand_loader import load_brands



# -------------------------------------------------
# Load Model Using Absolute Path
# -------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "ml_model", "phishing_model.pkl")

model = joblib.load(MODEL_PATH)


# -------------------------------------------------
# Hybrid Prediction Pipeline
# -------------------------------------------------

def predict_url(url: str):

    # 1️⃣ Compute Hybrid Risk (Engine + ML)
    result = compute_final_risk(url, model)

    risk_level = result["risk_level"]
    findings = result["findings"]

    # 2️⃣ Brand Whitelist Protection (Improved)
    parsed = parse_url(url)
    domain = parsed["domain"].lower()

    brands = load_brands()

    if domain in [b.lower() for b in brands] and not findings:
        risk_level = "Safe"
        result["risk_score"] = 5

    # 3️⃣ Determine Final Phishing Status
    is_phishing = risk_level in ["Medium", "High"]

    # 4️⃣ Smart Human Summary
    if findings:
        primary_reason = findings[0].get("simple_reason", "Suspicious pattern detected.")
        summary = primary_reason
    else:
        summary = "No strong phishing indicators were detected."

    # 5️⃣ Guidance
    if is_phishing:
        guidance = (
            "This website shows signs of impersonation or deception. "
            "Avoid entering passwords or personal information."
        )
    else:
        guidance = (
            "The website appears safe, but always verify the URL before entering sensitive data."
        )

    return {
        "is_safe": not is_phishing,
        "risk_level": risk_level,
        "risk_score": result["risk_score"],
        "ml_probability": result["ml_probability"],
        "rule_score": result["rule_score"],
        "summary": summary,
        "findings": findings,
        "guidance": guidance
    }
