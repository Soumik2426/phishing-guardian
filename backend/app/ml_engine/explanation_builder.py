# app/explanation_builder.py

from Levenshtein import editops
from engine.parser import parse_url


def describe_letter_changes(domain: str, brand: str):
    operations = editops(domain, brand)
    explanations = []

    for op, src_pos, dest_pos in operations:

        if op == "insert":
            explanations.append(
                f"The domain is missing the letter '{brand[dest_pos]}'."
            )

        elif op == "delete":
            explanations.append(
                f"The domain contains an extra letter '{domain[src_pos]}'."
            )

        elif op == "replace":
            explanations.append(
                f"The letter '{domain[src_pos]}' is used instead of '{brand[dest_pos]}'."
            )

    return explanations


def build_human_explanation(url: str, findings: list, risk_level: str):

    if not findings:
        return (
            "No signs of phishing or impersonation were detected. "
            "The website appears to be legitimate."
        )

    parsed = parse_url(url)
    domain = parsed["domain"]

    explanations = []
    processed_brands = set()
    detected_attacks = set()

    # Define STRONG attack categories
    strong_attack_categories = {
        "brand_impersonation",
        "character_substitution",
        "at_symbol_manipulation",
        "unicode_non_ascii",
        "mixed_scripts",
        "ip_address",
        "case_deception"
    }

    for item in findings:

        category = item.get("category")
        attack_type = item.get("attack_type")

        if category in strong_attack_categories and attack_type:
            detected_attacks.add(attack_type)

        # ---------- Character Substitution ----------
        if category == "character_substitution":

            brand = item.get("brand")
            substitutions = item.get("substitutions", [])

            if brand and brand not in processed_brands:
                processed_brands.add(brand)

                explanations.append(
                    f"The domain appears to imitate '{brand}' by replacing characters "
                    f"({', '.join(substitutions)}). This is a common phishing technique."
                )

        # ---------- Brand Impersonation ----------
        elif category == "brand_impersonation":

            brand = item.get("brand")
            edit_distance = item.get("edit_distance")

            if brand and brand not in processed_brands:
                processed_brands.add(brand)

                explanations.append(
                    f"The domain closely resembles the official '{brand}' website, "
                    f"which may mislead users."
                )

                if edit_distance == 1:
                    explanations.append(
                        "The domain differs by only one letter from the genuine brand name."
                    )

        # ---------- '@' Manipulation ----------
        elif category == "at_symbol_manipulation":
            explanations.append(
                "The URL contains the '@' symbol, which can hide the actual destination of the link."
            )

        # ---------- Case Deception ----------
        elif category == "case_deception":
            brand = item.get("brand")
            explanations.append(
                f"The domain uses unusual capitalization to resemble '{brand}'."
            )

        # ---------- Unicode / Mixed Scripts ----------
        elif category == "mixed_scripts":
            explanations.append(
                "The domain mixes characters from different writing systems, "
                "which can visually imitate trusted websites."
            )

        elif category == "unicode_non_ascii":
            explanations.append(
                "The domain includes special Unicode characters that may look like normal letters."
            )

        elif category == "ip_address":
            explanations.append(
                "The website uses a raw IP address instead of a standard domain name."
            )

    # -------------------------------------------------
    # Professional & Simple Summary Intro
    # -------------------------------------------------
    explanations = list(dict.fromkeys(explanations))

    if risk_level in ["Medium", "High"]:
        simple_intro = (
            "This website shows clear signs of impersonation or potential phishing. "
        )
        simple_outro = (
            "For your safety, avoid entering passwords, banking details, or personal information on this site."
        )
        return simple_intro + " ".join(explanations) + " " + simple_outro

    # Low risk but minor irregularities
    simple_intro = (
        "Some irregular patterns were observed, but no strong evidence of phishing was detected. "
    )
    return simple_intro + " ".join(explanations)