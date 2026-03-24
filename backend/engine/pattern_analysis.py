# engine/pattern_analysis.py

import math


def shannon_entropy(data: str):
    if not data:
        return 0

    prob = [float(data.count(c)) / len(data) for c in dict.fromkeys(list(data))]
    return -sum(p * math.log(p, 2) for p in prob)


def analyze_pattern(domain: str):

    findings = []

    length = len(domain)
    digits = sum(c.isdigit() for c in domain)
    vowels = sum(c in "aeiou" for c in domain.lower())

    digit_ratio = digits / length if length else 0
    vowel_ratio = vowels / length if length else 0
    entropy = shannon_entropy(domain)

    suspicion_score = 0

    # -------------------------------------------------
    # 1️⃣ Digit ratio
    # -------------------------------------------------
    if digit_ratio > 0.4:
        suspicion_score += 1

    # -------------------------------------------------
    # 2️⃣ Very low vowel ratio (hard to pronounce)
    # -------------------------------------------------
    if length > 4 and vowel_ratio < 0.2:
        suspicion_score += 1

    # -------------------------------------------------
    # 3️⃣ High entropy (only if long enough)
    # -------------------------------------------------
    if length > 8 and entropy > 3.5:
        suspicion_score += 1

    # -------------------------------------------------
    # Final Decision
    # -------------------------------------------------
    if suspicion_score >= 2:
        findings.append({
            "category": "random_domain_pattern",
            "severity": "medium",
            "attack_type": "algorithmic_domain",
            "details": {
                "digit_ratio": round(digit_ratio, 2),
                "vowel_ratio": round(vowel_ratio, 2),
                "entropy": round(entropy, 2)
            }
        })

    return findings