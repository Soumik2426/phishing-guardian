SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz"]


def analyze_tld(root_domain: str):
    for tld in SUSPICIOUS_TLDS:
        if root_domain.endswith(tld):
            return [{
                "category": "suspicious_tld",
                "severity": "medium",
                "simple_reason": f"The domain uses '{tld}', which is commonly abused in phishing attacks."
            }]

    return []
