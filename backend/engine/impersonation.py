from Levenshtein import distance
from difflib import SequenceMatcher


def analyze_impersonation(domain: str, brands: list):
    findings = []

    for brand in brands:
        brand_lower = brand.lower()
        domain_lower = domain.lower()

        similarity = SequenceMatcher(None, domain_lower, brand_lower).ratio()
        edit_dist = distance(domain_lower, brand_lower)

        if similarity > 0.85 and domain_lower != brand_lower:

            findings.append({
                "category": "brand_impersonation",
                "severity": "high",
                "attack_type": "typosquatting",
                "brand": brand,
                "similarity_score": round(similarity, 2),
                "edit_distance": edit_dist,
                "original_domain": domain
            })

    return findings