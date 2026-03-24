# engine/unicode_analysis.py

import unicodedata


def analyze_unicode(domain: str):

    results = {
        "contains_non_ascii": False,
        "mixed_scripts": False,
        "script_types": set(),
    }

    for char in domain:

        # Ignore common safe characters
        if char in {'.', '-', '_'}:
            continue

        # Detect non-ASCII
        if not char.isascii():
            results["contains_non_ascii"] = True

        try:
            name = unicodedata.name(char)

            # Extract script family
            script = name.split(" ")[0]

            # Only track real alphabetic scripts
            if script in {
                "LATIN",
                "CYRILLIC",
                "GREEK",
                "ARABIC",
                "HEBREW",
                "DEVANAGARI"
            }:
                results["script_types"].add(script)

        except ValueError:
            pass

    # -------------------------------------------------
    # Mixed Script Logic (Strict & Correct)
    # -------------------------------------------------
    if len(results["script_types"]) > 1:
        results["mixed_scripts"] = True
    else:
        results["mixed_scripts"] = False

    return results