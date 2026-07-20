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
from engine.pattern_analysis import analyze_pattern
from engine.linguistic_analysis import analyze_linguistics
from engine.dga_detection import analyze_dga_pattern

from app.ml_engine.brand_loader import load_brands


def run_engine(url: str):
    findings = []

    parsed = parse_url(url)
    domain = parsed["domain"]
    lower_domain = domain.lower()
    root_domain = parsed["root_domain"]
    subdomain = parsed["subdomain"]

    brands = load_brands()

    # -------------------------------------------------
    # 1️⃣ Case-Based Deception
    # -------------------------------------------------
    for brand in brands:
        if lower_domain == brand.lower():
            if domain != domain.lower():
                findings.append({
                    "category": "case_deception",
                    "severity": "high",
                    "attack_type": "case_manipulation",
                    "brand": brand,
                    "original_domain": domain
                })

    # -------------------------------------------------
    # 2️⃣ '@' Symbol Manipulation
    # -------------------------------------------------
    if "@" in url:
        findings.append({
            "category": "at_symbol_manipulation",
            "severity": "high",
            "attack_type": "url_obfuscation",
            "original_url": url
        })

    # -------------------------------------------------
    # 3️⃣ Strong Core Detection Modules
    # -------------------------------------------------
    findings.extend(analyze_character_substitution(domain))
    findings.extend(analyze_homoglyph(domain, brands))
    findings.extend(analyze_impersonation(domain, brands))
    findings.extend(analyze_tld(root_domain))
    findings.extend(analyze_subdomain(subdomain, brands, domain))
    findings.extend(analyze_ip_usage(url))

    # -------------------------------------------------
    # 4️⃣ Statistical / Pattern Modules (STRICT FILTER)
    # -------------------------------------------------
    statistical_modules = []

    statistical_modules.extend(analyze_pattern(domain))
    statistical_modules.extend(analyze_linguistics(domain))
    statistical_modules.extend(analyze_dga_pattern(domain))
    statistical_modules.extend(analyze_entropy(domain))

    # Only keep HIGH severity statistical findings
    for f in statistical_modules:
        if f.get("severity") == "high":
            findings.append(f)

    # -------------------------------------------------
    # 5️⃣ Unicode Analysis
    # -------------------------------------------------
    unicode_result = analyze_unicode(parsed["decoded_domain"])

    if unicode_result["contains_non_ascii"]:
        findings.append({
            "category": "unicode_non_ascii",
            "severity": "medium",
            "attack_type": "unicode_obfuscation"
        })

    if unicode_result["mixed_scripts"]:
        findings.append({
            "category": "mixed_scripts",
            "severity": "high",
            "attack_type": "homograph_attack"
        })

    return {
        "url": url,
        "total_findings": len(findings),
        "findings": findings
    }