from Levenshtein import distance
from difflib import SequenceMatcher
import os


# Load brand intelligence
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BRAND_FILE = os.path.join(BASE_DIR, "app", "brands.txt")


def load_brands():
    if not os.path.exists(BRAND_FILE):
        return []
    with open(BRAND_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


BRANDS = load_brands()


def analyze_impersonation(domain: str):
    findings = []

    for brand in BRANDS:
        brand_lower = brand.lower()
        domain_lower = domain.lower()

        similarity = SequenceMatcher(None, domain_lower, brand_lower).ratio()
        edit_dist = distance(domain_lower, brand_lower)

        if similarity > 0.80 and domain_lower != brand_lower:
            findings.append({
                "brand": brand,
                "similarity": similarity,
                "edit_distance": edit_dist
            })

    return findings
