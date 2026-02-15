import numpy as np
from engine.orchestrator import run_engine
from ml_model.features import extract_features


# -------------------------------
# Severity Weight Mapping
# -------------------------------

SEVERITY_WEIGHTS = {
    "low": 10,
    "medium": 20,
    "high": 35
}


def calculate_rule_score(findings):
    score = 0

    for item in findings:
        severity = item.get("severity", "low")
        score += SEVERITY_WEIGHTS.get(severity, 10)

    return score


def compute_final_risk(url: str, model):
    # -------------------------------
    # 1️⃣ Run Forensic Engine
    # -------------------------------
    engine_result = run_engine(url)
    findings = engine_result["findings"]

    rule_score = calculate_rule_score(findings)

    # -------------------------------
    # 2️⃣ ML Probability
    # -------------------------------
    features = extract_features(url)
    prob = model.predict_proba(np.array([features]))[0][1]

    ml_score = prob * 100

    # -------------------------------
    # 3️⃣ Hybrid Score
    # -------------------------------
    final_score = (0.6 * ml_score) + (0.4 * rule_score)
    final_score = min(100, round(final_score, 2))

    # -------------------------------
    # 4️⃣ Risk Level Classification
    # -------------------------------
    if final_score >= 80:
        risk_level = "High"
    elif final_score >= 60:
        risk_level = "Medium"
    elif final_score >= 30:
        risk_level = "Low"
    else:
        risk_level = "Safe"

    # -------------------------------
    # 5️⃣ Human-Friendly Summary
    # -------------------------------
    if findings:
        summary = "This website shows signs of impersonation or deceptive patterns."
    else:
        summary = "No strong phishing indicators were detected."

    return {
        "url": url,
        "risk_score": final_score,
        "risk_level": risk_level,
        "ml_probability": round(prob, 4),
        "rule_score": rule_score,
        "summary": summary,
        "findings": findings
    }