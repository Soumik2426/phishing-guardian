# engine/character_substitution.py

COMMON_SUBSTITUTIONS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
    "$": "s",
    "!": "i"
}


def analyze_character_substitution(domain: str):
    findings = []

    normalized = domain.lower()
    substitutions_found = []

    for fake, real in COMMON_SUBSTITUTIONS.items():
        if fake in normalized:
            substitutions_found.append(f"{fake} → {real}")

    if substitutions_found:
        findings.append({
            "category": "character_substitution",
            "severity": "high",
            "simple_reason": "The domain uses numbers or symbols to imitate letters.",
            "substitutions": substitutions_found
        })

    return findings
