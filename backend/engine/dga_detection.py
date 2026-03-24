# engine/dga_detection.py

def analyze_dga_pattern(domain: str):

    findings = []

    length = len(domain)
    digits = sum(c.isdigit() for c in domain)
    letters = sum(c.isalpha() for c in domain)

    digit_ratio = digits / length if length else 0

    # DGA-like structure indicators
    if length >= 8 and digit_ratio > 0.3:
        findings.append({
            "category": "dga_pattern",
            "severity": "high",
            "attack_type": "botnet_generated_domain"
        })

    if length >= 10 and letters == length:
        # Very long all-letter but random
        findings.append({
            "category": "dga_pattern",
            "severity": "medium",
            "attack_type": "algorithmic_domain"
        })

    return findings