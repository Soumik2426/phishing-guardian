# engine/homoglyph_analysis.py

from difflib import SequenceMatcher
from engine.normalization import normalize_domain

SIMILARITY_THRESHOLD = 0.85


def analyze_homoglyph(domain: str, brands: list):
    findings = []

    norm = normalize_domain(domain)
    normalized = norm["normalized"]

    for brand in brands:
        brand_lower = brand.lower()

        similarity = SequenceMatcher(None, normalized, brand_lower).ratio()

        if similarity >= SIMILARITY_THRESHOLD and normalized != brand_lower:
            findings.append({
                "category": "brand_impersonation",
                "severity": "high",
                "simple_reason": f"The domain is very similar to '{brand}', which may confuse users.",
                "similarity_score": round(similarity, 2)
            })

    return findings
