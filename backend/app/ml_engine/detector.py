import os
import joblib
import numpy as np
import boto3

from app.risk_engine import compute_final_risk
from engine.parser import parse_url
from app.brand_loader import load_brands
from app.explanation_builder import build_human_explanation


# -------------------------------------------------
# 0️⃣ Setup Paths
# -------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "ml_model")
MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.pkl")

# S3 Config
BUCKET_NAME = "phishing-guardian-model-bucket"
MODEL_KEY = "phishing_model.pkl"


# -------------------------------------------------
# 1️⃣ Ensure model directory exists
# -------------------------------------------------
os.makedirs(MODEL_DIR, exist_ok=True)


# -------------------------------------------------
# 2️⃣ Download model from S3 (ONLY if not present)
# -------------------------------------------------
if not os.path.exists(MODEL_PATH):
    print("Downloading model from S3...")
    s3 = boto3.client("s3")
    s3.download_file(BUCKET_NAME, MODEL_KEY, MODEL_PATH)
    print("Model downloaded successfully!")


# -------------------------------------------------
# 3️⃣ Load Model
# -------------------------------------------------
model = joblib.load(MODEL_PATH)


def predict_url(url: str):

    # -------------------------------------------------
    # 1️⃣ Compute Hybrid Risk
    # -------------------------------------------------
    result = compute_final_risk(url, model)

    risk_level = result["risk_level"]
    findings = result["findings"]
    breakdown = result["breakdown"]

    parsed = parse_url(url)
    domain = parsed["domain"]
    lower_domain = domain.lower()

    brands = load_brands()
    brand_list = [b.lower() for b in brands]

    # -------------------------------------------------
    # 2️⃣ Strong Brand Whitelist Protection (FIXED)
    # -------------------------------------------------
    if lower_domain in brand_list:

        suspicious_categories = {
            "brand_impersonation",
            "character_substitution",
            "at_symbol_manipulation",
            "unicode_non_ascii",
            "mixed_scripts",
            "case_deception",
            "ip_address"
        }

        has_real_threat = any(
            f.get("category") in suspicious_categories
            for f in findings
        )

        if (
            domain == lower_domain
            and not has_real_threat
            and result["ml_probability"] < 0.85
        ):
            findings = []
            risk_level = "Safe"
            result["risk_score"] = 0
            result["rule_score"] = 0

            breakdown = {
                "domain_structure": 100,
                "ssl_certificate": 100,
                "ip_reputation": 100,
                "phishing_keywords": 100,
                "redirect_chains": 100,
                "domain_age": 100
            }

    # -------------------------------------------------
    # 3️⃣ Determine Final Status
    # -------------------------------------------------
    is_phishing = risk_level in ["Medium", "High"]

    # -------------------------------------------------
    # 4️⃣ Build Human Explanation
    # -------------------------------------------------
    summary = build_human_explanation(url, findings, risk_level)

    # -------------------------------------------------
    # 5️⃣ Guidance
    # -------------------------------------------------
    if is_phishing:
        guidance = (
            "This website shows signs of impersonation or deception. "
            "Avoid entering passwords or personal information."
        )
    else:
        guidance = (
            "The website appears safe, but always verify the URL before entering sensitive data."
        )

    # -------------------------------------------------
    # 6️⃣ Final Response
    # -------------------------------------------------
    return {
        "url": url,
        "is_safe": not is_phishing,
        "risk_level": risk_level,
        "risk_score": result["risk_score"],
        "ml_probability": result["ml_probability"],
        "rule_score": result["rule_score"],
        "summary": summary,
        "findings": findings,
        "guidance": guidance,
        "breakdown": breakdown
    }