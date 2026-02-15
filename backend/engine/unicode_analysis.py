# engine/unicode_analysis.py

import unicodedata


def analyze_unicode(domain: str):
    results = {
        "contains_non_ascii": False,
        "mixed_scripts": False
    }

    scripts = set()

    for char in domain:
        if not char.isascii():
            results["contains_non_ascii"] = True

        try:
            name = unicodedata.name(char)
            script = name.split(" ")[0]
            scripts.add(script)
        except ValueError:
            pass

    if len(scripts) > 1:
        results["mixed_scripts"] = True

    return results
