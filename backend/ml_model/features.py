import re
import math
from urllib.parse import urlparse
from difflib import SequenceMatcher


SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq"]
SUSPICIOUS_EXTENSIONS = [".exe", ".zip", ".scr"]

PHISHING_KEYWORDS = [
    "verify", "login", "update", "secure",
    "account", "bank", "confirm", "password",
    "signin", "support"
]

BRANDS = [
    "paypal", "google", "amazon",
    "microsoft", "facebook", "apple"
]


# -------------------------------------------------
# Helper Functions
# -------------------------------------------------

def has_ip_address(url: str) -> int:
    pattern = r"(?:\d{1,3}\.){3}\d{1,3}"
    return 1 if re.search(pattern, url) else 0


def calculate_entropy(text: str) -> float:
    if not text:
        return 0

    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1

    entropy = 0
    length = len(text)

    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def brand_similarity(url: str) -> float:
    """
    Returns highest similarity score between URL and known brands.
    """
    url_lower = url.lower()
    scores = [SequenceMatcher(None, url_lower, brand).ratio() for brand in BRANDS]
    return max(scores)


# -------------------------------------------------
# Feature Extraction
# -------------------------------------------------

def extract_features(url: str) -> list:
    parsed = urlparse(url)
    url_lower = url.lower()

    # -------- Basic Features --------
    url_length = len(url)
    has_https = 1 if url.startswith("https") else 0
    ip_present = has_ip_address(url)
    suspicious_tld = 1 if any(tld in url_lower for tld in SUSPICIOUS_TLDS) else 0
    keyword_count = sum(keyword in url_lower for keyword in PHISHING_KEYWORDS)
    entropy = calculate_entropy(url)
    has_at_symbol = 1 if "@" in url else 0

    # -------- Structural Features --------
    domain_parts = parsed.netloc.split(".")
    subdomain_count = len(domain_parts) - 2 if len(domain_parts) > 2 else 0

    path = parsed.path
    path_length = len(path)
    directory_depth = path.count("/")

    file_extension_flag = 1 if any(path.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS) else 0
    has_query = 1 if parsed.query else 0

    # -------- NEW INTELLIGENCE FEATURES --------
    digit_count = sum(c.isdigit() for c in url)
    hyphen_count = url.count("-")

    brand_score = brand_similarity(url)

    return [
        url_length,
        has_https,
        ip_present,
        suspicious_tld,
        subdomain_count,
        keyword_count,
        entropy,
        has_at_symbol,
        path_length,
        directory_depth,
        file_extension_flag,
        has_query,
        digit_count,
        hyphen_count,
        brand_score
    ]
