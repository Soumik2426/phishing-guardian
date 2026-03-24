# engine/entropy_analysis.py

import math


def calculate_entropy(text: str):
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


def analyze_entropy(domain: str):
    entropy = calculate_entropy(domain)

    if entropy > 3.5:
        return [{
            "category": "high_entropy",
            "severity": "medium",
            "simple_reason": "The domain appears random and not related to a recognizable brand.",
            "entropy_score": round(entropy, 2)
        }]

    return []
