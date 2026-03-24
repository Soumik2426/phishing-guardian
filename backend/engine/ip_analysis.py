# engine/ip_analysis.py

import re


def analyze_ip_usage(url: str):
    pattern = r"(?:\d{1,3}\.){3}\d{1,3}"

    if re.search(pattern, url):
        return [{
            "category": "ip_address",
            "severity": "high",
            "simple_reason": "The URL uses an IP address instead of a normal domain name."
        }]

    return []
