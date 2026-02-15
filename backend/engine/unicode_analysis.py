import unicodedata


def analyze_unicode(domain: str):
    results = {
        "contains_non_ascii": False,
        "mixed_scripts": False,
        "script_types": set(),
        "case_deception": False,
        "confusable_characters": []
    }

    for char in domain:
        # Detect non-ASCII
        if not char.isascii():
            results["contains_non_ascii"] = True

        # Detect script type
        try:
            name = unicodedata.name(char)
            script = name.split(" ")[0]
            results["script_types"].add(script)
        except ValueError:
            pass

    if len(results["script_types"]) > 1:
        results["mixed_scripts"] = True

    # Detect case-based deception
    if domain.lower() != domain and domain.upper() != domain:
        results["case_deception"] = True

    return results
