# engine/normalization.py

import unicodedata
import idna


def normalize_domain(domain: str):
    original = domain

    domain = domain.lower()

    try:
        domain = idna.decode(domain)
    except Exception:
        pass

    domain = unicodedata.normalize("NFKC", domain)

    return {
        "original": original,
        "normalized": domain
    }
