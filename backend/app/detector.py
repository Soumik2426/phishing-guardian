import os
import joblib
import numpy as np

from ml_model.features import extract_features
from app.explainer import analyze_url, BRANDS, extract_domain_parts


# -------------------------------------------------
# Load Model Using Absolute Path
# -------------------------------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "ml_model", "phishing_model.pkl")

model = joblib.load(MODEL_PATH)


# -------------------------------------------------
# Prediction + Teach-Back Logic
# -------------------------------------------------

def predict_url(url: str):
    features = extract_features(url)
    features_array = np.array([features])

    prob = model.predict_proba(features_array)[0][1]

    threshold = 0.45
    prediction = 1 if prob > threshold else 0

    # -------------------------------------------------
    # Rule-Based Forensic Analysis
    # -------------------------------------------------

    rule_reasons = analyze_url(url)

    # -------------------------------------------------
    # Brand Whitelist Override (Critical Fix)
    # -------------------------------------------------

    real_domain, full_domain, subdomain = extract_domain_parts(url)
    real_domain_lower = real_domain.lower()

    for brand in BRANDS:
        if real_domain_lower == brand.lower():
            # Only override if no spoofing tricks exist
            if not rule_reasons:
                prediction = 0
                prob = 0.05
                break

    # -------------------------------------------------
    # If ML flags phishing but no rule explanation exists
    # -------------------------------------------------

    if prediction == 1 and not rule_reasons:
        rule_reasons.append(
            "The URL structure matches patterns commonly used in phishing attacks."
        )

    # -------------------------------------------------
    # Risk Level Classification
    # -------------------------------------------------

    if prob >= 0.80:
        risk = "High"
    elif prob >= 0.60:
        risk = "Medium"
    elif prob >= threshold:
        risk = "Low"
    else:
        risk = "Safe"

    # -------------------------------------------------
    # Plain-Language Guidance
    # -------------------------------------------------

    if prediction == 1:
        warning = "This link may be a phishing attempt."
        guidance = (
            "Avoid entering personal information. Instead, manually type the official "
            "website address into your browser."
        )
    else:
        warning = "No strong phishing indicators were detected."
        guidance = (
            "This link appears safe, but always verify the website before entering "
            "sensitive information."
        )

    return {
        "is_phishing": bool(prediction),
        "confidence": float(round(prob, 4)),
        "risk_level": risk,
        "warning": warning,
        "reasons": rule_reasons,
        "guidance": guidance
    }
