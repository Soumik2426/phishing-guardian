# engine/character_substitution.py

from app.ml_engine.brand_loader import load_brands

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
    brands = load_brands()

    # Apply substitutions
    modified = normalized
    substitutions_found = []

    for fake, real in COMMON_SUBSTITUTIONS.items():
        if fake in modified:
            modified = modified.replace(fake, real)
            substitutions_found.append(f"{fake} → {real}")

    # Only flag if substitution makes it match a known brand
    for brand in brands:
        if modified == brand.lower() and normalized != brand.lower():
            findings.append({
                "category": "character_substitution",
                "severity": "high",
                "simple_reason": "The domain uses numbers or symbols to imitate a known brand.",
                "brand": brand,
                "substitutions": substitutions_found
            })
            break

    return findings