# app/risk_engine.py

import numpy as np
from engine.orchestrator import run_engine
from engine.parser import parse_url
from engine.breakdown_analysis import compute_breakdown_scores
from ml_model.features import extract_features


def compute_final_risk(url: str, model):

    # -------------------------------------------------
    # 1️⃣ Run Forensic Engine (Findings)
    # -------------------------------------------------
    engine_result = run_engine(url)
    findings = engine_result["findings"]

    parsed = parse_url(url)
    domain = parsed["domain"]

    # -------------------------------------------------
    # 2️⃣ Compute Modular Breakdown Scores
    # -------------------------------------------------
    breakdown = compute_breakdown_scores(url, domain, findings)

    # Average safety score
    avg_safety_score = sum(breakdown.values()) / len(breakdown)

    # Convert safety → risk
    rule_score = 100 - avg_safety_score

    # -------------------------------------------------
    # 3️⃣ ML Probability
    # -------------------------------------------------
    features = extract_features(url)
    prob = model.predict_proba(np.array([features]))[0][1]
    ml_score = prob * 100

    # -------------------------------------------------
    # 4️⃣ Hybrid Score
    # -------------------------------------------------
    final_score = (0.6 * ml_score) + (0.4 * rule_score)
    final_score = min(100, round(final_score, 2))

    # -------------------------------------------------
    # 5️⃣ Risk Level Classification
    # -------------------------------------------------
    if final_score >= 80:
        risk_level = "High"
    elif final_score >= 60:
        risk_level = "Medium"
    elif final_score >= 30:
        risk_level = "Low"
    else:
        risk_level = "Safe"

    return {
        "url": url,
        "risk_score": final_score,
        "risk_level": risk_level,
        "ml_probability": round(prob, 4),
        "rule_score": round(rule_score, 2),
        "findings": findings,
        "breakdown": breakdown
    }