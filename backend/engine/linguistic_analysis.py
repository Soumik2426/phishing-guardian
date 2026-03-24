# engine/linguistic_analysis.py

import math
from app.brand_loader import load_brands


def shannon_entropy(data: str):
    if not data:
        return 0

    prob = [float(data.count(c)) / len(data) for c in set(data)]
    return -sum(p * math.log(p, 2) for p in prob)


def analyze_linguistics(domain: str):

    findings = []

    domain = domain.lower()
    length = len(domain)

    # 🚨 Skip short domains
    if length < 10:
        return findings

    brands = load_brands()

    # 🚨 Skip if domain contains known brand word
    for brand in brands:
        if brand.lower() in domain:
            return findings

    # ---- Calculate metrics ----
    entropy = shannon_entropy(domain)

    vowels = sum(c in "aeiou" for c in domain)
    vowel_ratio = vowels / length if length else 0

    digit_ratio = sum(c.isdigit() for c in domain) / length

    # Long consonant cluster detection
    max_cluster = 0
    current_cluster = 0

    for c in domain:
        if c.isalpha() and c not in "aeiou":
            current_cluster += 1
            max_cluster = max(max_cluster, current_cluster)
        else:
            current_cluster = 0

    # ---- STRICT DGA CONDITIONS ----
    if (
        entropy > 4.0 and
        vowel_ratio < 0.25 and
        (digit_ratio > 0.2 or max_cluster >= 4)
    ):
        findings.append({
            "category": "linguistic_anomaly",
            "severity": "medium",
            "attack_type": "algorithmic_domain"
        })

    return findings