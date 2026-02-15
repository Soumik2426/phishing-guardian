# engine/impersonation.py

from Levenshtein import distance
from difflib import SequenceMatcher


def analyze_impersonation(domain: str, brands: list):
    findings = []

    domain_lower = domain.lower()

    for brand in brands:
        brand_lower = brand.lower()

        similarity = SequenceMatcher(None, domain_lower, brand_lower).ratio()
        edit_dist = distance(domain_lower, brand_lower)

        if similarity > 0.80 and domain_lower != brand_lower:
            findings.append({
                "category": "edit_distance_impersonation",
                "severity": "high",
                "simple_reason": f"The domain closely resembles '{brand}'.",
                "similarity_score": round(similarity, 2),
                "edit_distance": edit_dist
            })

    return findings
