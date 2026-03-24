def analyze_subdomain(subdomain: str, brands: list, real_domain: str):
    findings = []

    for brand in brands:
        if brand.lower() in subdomain.lower() and brand.lower() != real_domain.lower():
            findings.append({
                "category": "subdomain_spoofing",
                "severity": "high",
                "simple_reason": f"The brand '{brand}' appears in the subdomain, but the main domain is different."
            })

    return findings
