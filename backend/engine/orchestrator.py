# engine/orchestrator.py

from engine.parser import parse_url
from engine.unicode_analysis import analyze_unicode
from engine.character_substitution import analyze_character_substitution
from engine.homoglyph_analysis import analyze_homoglyph
from engine.impersonation import analyze_impersonation
from engine.entropy_analysis import analyze_entropy
from engine.tld_analysis import analyze_tld
from engine.subdomain_analysis import analyze_subdomain
from engine.ip_analysis import analyze_ip_usage

from app.brand_loader import load_brands


def run_engine(url: str):
    findings = []

    parsed = parse_url(url)
    domain = parsed["domain"]
    root_domain = parsed["root_domain"]
    subdomain = parsed["subdomain"]

    brands = load_brands()

    findings.extend(analyze_character_substitution(domain))
    findings.extend(analyze_homoglyph(domain, brands))
    findings.extend(analyze_impersonation(domain, brands))
    findings.extend(analyze_entropy(domain))
    findings.extend(analyze_tld(root_domain))
    findings.extend(analyze_subdomain(subdomain, brands, domain))
    findings.extend(analyze_ip_usage(url))

    unicode_result = analyze_unicode(parsed["decoded_domain"])

    if unicode_result["contains_non_ascii"]:
        findings.append({
            "category": "unicode_non_ascii",
            "severity": "medium",
            "simple_reason": "The domain contains unusual non-English characters."
        })

    if unicode_result["mixed_scripts"]:
        findings.append({
            "category": "mixed_scripts",
            "severity": "high",
            "simple_reason": "The domain mixes characters from different writing systems."
        })

    return {
        "url": url,
        "total_findings": len(findings),
        "findings": findings
    }
