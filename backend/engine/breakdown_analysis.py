# engine/breakdown_analysis.py

import socket
import ssl
import requests
import whois
import datetime
import ipaddress
import math
from urllib.parse import urlparse

from engine.linguistic_analysis import shannon_entropy


# -------------------------------------------------
# Helper: Normalize URL
# -------------------------------------------------

def normalize_url(url: str):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return urlparse(url)


# -------------------------------------------------
# 1️⃣ DOMAIN STRUCTURE SCORE (Mathematical)
# -------------------------------------------------

def compute_domain_structure_score(domain: str, findings: list):
    domain = domain.lower()

    if not domain:
        return 0

    # Entropy normalization
    entropy = shannon_entropy(domain)
    max_entropy = math.log2(len(set(domain))) if len(set(domain)) > 1 else 1
    normalized_entropy = entropy / max_entropy if max_entropy else 0

    # Entropy contributes up to 40% risk
    entropy_penalty = normalized_entropy * 40

    # Impersonation strength (continuous)
    impersonation_strength = 0
    for f in findings:
        if f.get("category") == "brand_impersonation":
            similarity = f.get("similarity_score", 0)
            impersonation_strength = max(impersonation_strength, similarity)

    impersonation_penalty = impersonation_strength * 50

    # Suspicious symbol density
    symbol_count = sum(1 for c in domain if not c.isalnum())
    symbol_ratio = symbol_count / len(domain)
    symbol_penalty = symbol_ratio * 30

    score = 100 - (entropy_penalty + impersonation_penalty + symbol_penalty)

    return max(0, round(score))


# -------------------------------------------------
# 2️⃣ SSL CERTIFICATE SCORE (Universal Law)
# -------------------------------------------------

def compute_ssl_score(url: str):
    parsed = normalize_url(url)

    if parsed.scheme != "https":
        return 0

    try:
        context = ssl.create_default_context()
        with socket.create_connection((parsed.hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=parsed.hostname):
                return 100
    except:
        return 0


# -------------------------------------------------
# 3️⃣ IP REPUTATION SCORE (Infrastructure-Based)
# -------------------------------------------------

def compute_ip_reputation_score(url: str):
    parsed = normalize_url(url)
    host = parsed.hostname

    if not host:
        return 0

    try:
        ip = ipaddress.ip_address(host)

        if ip.is_private or ip.is_loopback or ip.is_reserved:
            return 0

        return 100

    except ValueError:
        # Not raw IP → domain name
        return 100


# -------------------------------------------------
# 4️⃣ PHISHING KEYWORD SCORE (Density-Based)
# -------------------------------------------------

PHISHING_KEYWORDS = [
    "login", "verify", "update", "secure",
    "account", "bank", "reset", "confirm"
]

def compute_keyword_score(url: str):
    url_lower = url.lower()

    count = sum(url_lower.count(kw) for kw in PHISHING_KEYWORDS)
    length = len(url_lower)

    if length == 0:
        return 100

    density = count / length
    penalty = density * 1000   # scaled proportionally

    score = 100 - penalty

    return max(0, round(score))


# -------------------------------------------------
# 5️⃣ REDIRECT CHAIN SCORE (Measured)
# -------------------------------------------------

def compute_redirect_score(url: str):
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        redirect_count = len(response.history)

        if redirect_count == 0:
            return 100

        penalty = min(redirect_count * 20, 100)
        return max(0, 100 - penalty)

    except:
        return 0


# -------------------------------------------------
# 6️⃣ DOMAIN AGE SCORE (WHOIS-Based)
# -------------------------------------------------

def compute_domain_age_score(url: str):
    parsed = normalize_url(url)
    host = parsed.hostname

    if not host:
        return 0

    try:
        w = whois.whois(host)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return 0

        age_days = (datetime.datetime.now() - creation_date).days

        # Continuous scaling (1 year = full trust)
        score = min(100, (age_days / 365) * 100)

        return max(0, round(score))

    except:
        return 0


# -------------------------------------------------
# MASTER BREAKDOWN FUNCTION
# -------------------------------------------------

def compute_breakdown_scores(url: str, domain: str, findings: list):

    breakdown = {
        "domain_structure": compute_domain_structure_score(domain, findings),
        "ssl_certificate": compute_ssl_score(url),
        "ip_reputation": compute_ip_reputation_score(url),
        "phishing_keywords": compute_keyword_score(url),
        "redirect_chains": compute_redirect_score(url),
        "domain_age": compute_domain_age_score(url)
    }

    return breakdown