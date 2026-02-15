from urllib.parse import urlparse
from difflib import SequenceMatcher
import re
import os


# -------------------------------------------------
# Load Brands Dynamically from brands.txt
# -------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BRAND_FILE = os.path.join(BASE_DIR, "brands.txt")

def load_brands():
    if not os.path.exists(BRAND_FILE):
        return []
    with open(BRAND_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

BRANDS = load_brands()


SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co",
    "goo.gl", "ow.ly", "buff.ly"
]


# -------------------------------------------------
# Helper Function
# -------------------------------------------------

def extract_domain_parts(url: str):
    parsed = urlparse(url)
    netloc = parsed.netloc.lower()

    parts = netloc.split(".")

    if len(parts) >= 2:
        real_domain = parts[-2]  # only root name (e.g., paypal from paypal.com)
        full_domain = parts[-2] + "." + parts[-1]
    else:
        real_domain = netloc
        full_domain = netloc

    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""

    return real_domain, full_domain, subdomain


# -------------------------------------------------
# Typosquatting Detection
# -------------------------------------------------

def detect_typosquatting(url: str):
    reasons = []
    real_domain, full_domain, _ = extract_domain_parts(url)
    real_domain_lower = real_domain.lower()

    for brand in BRANDS:
        brand_lower = brand.lower()

        # 1️⃣ Exact Match → Genuine (do not flag)
        if real_domain_lower == brand_lower:
            return []

        # 2️⃣ Numeric Substitution Detection
        substitutions = {
            "0": "o",
            "1": "l",
            "3": "e",
            "5": "s"
        }

        modified = real_domain_lower
        substitution_used = []

        for num, char in substitutions.items():
            if num in real_domain_lower:
                modified = modified.replace(num, char)
                substitution_used.append(f"'{num}' instead of '{char}'")

        if modified == brand_lower and substitution_used:
            reasons.append(
                f"The domain '{real_domain}' is trying to imitate '{brand}' "
                f"by using {', '.join(substitution_used)}."
            )
            continue

        # 3️⃣ Minor spelling difference (similarity check)
        similarity = SequenceMatcher(None, real_domain_lower, brand_lower).ratio()

        if similarity > 0.80:
            reasons.append(
                f"The domain '{real_domain}' is very similar to the official brand name '{brand}', "
                f"but the spelling is slightly different. This may indicate typosquatting."
            )

    return reasons


# -------------------------------------------------
# Subdomain Spoofing Detection
# -------------------------------------------------

def detect_subdomain_spoofing(url: str):
    reasons = []
    real_domain, full_domain, subdomain = extract_domain_parts(url)

    for brand in BRANDS:
        brand_lower = brand.lower()
        if brand_lower in subdomain and brand_lower != real_domain.lower():
            reasons.append(
                f"The brand '{brand}' appears in the subdomain, but the actual domain is '{full_domain}'."
            )

    return reasons


# -------------------------------------------------
# Other Detection Rules
# -------------------------------------------------

def detect_punycode(url: str):
    if "xn--" in url.lower():
        return [
            "This URL uses encoded (punycode) characters, which can hide visually deceptive domain names."
        ]
    return []


def detect_shortener(url: str):
    for short in SHORTENERS:
        if short in url.lower():
            return [
                "This is a shortened link that hides the real destination."
            ]
    return []


def detect_ip_usage(url: str):
    pattern = r"(?:\d{1,3}\.){3}\d{1,3}"
    if re.search(pattern, url):
        return [
            "The link uses an IP address instead of a proper domain name."
        ]
    return []


def detect_deceptive_hyphens(url: str):
    if url.count("-") > 2:
        return [
            "The domain uses multiple hyphens, which is common in deceptive phishing URLs."
        ]
    return []


def detect_suspicious_keywords(url: str):
    real_domain, _, _ = extract_domain_parts(url)
    real_domain_lower = real_domain.lower()

    # ✅ If exact brand match → do NOT flag keywords
    for brand in BRANDS:
        if real_domain_lower == brand.lower():
            return []

    # More realistic phishing keywords
    keywords = ["login", "verify", "secure", "update", "confirm"]

    found = [kw for kw in keywords if kw in url.lower()]

    if found:
        return [
            f"The URL contains suspicious words such as: {', '.join(found)}."
        ]

    return []


# -------------------------------------------------
# Main Analyzer
# -------------------------------------------------

def analyze_url(url: str):
    reasons = []

    reasons += detect_typosquatting(url)
    reasons += detect_subdomain_spoofing(url)
    reasons += detect_punycode(url)
    reasons += detect_shortener(url)
    reasons += detect_ip_usage(url)
    reasons += detect_deceptive_hyphens(url)
    reasons += detect_suspicious_keywords(url)

    return reasons
