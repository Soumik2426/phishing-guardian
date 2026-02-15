import tldextract
from urllib.parse import urlparse, unquote
import idna


def parse_url(url: str):
    parsed = urlparse(url)

    # Extract domain components using tldextract
    ext = tldextract.extract(url)

    subdomain = ext.subdomain
    domain = ext.domain
    suffix = ext.suffix

    root_domain = f"{domain}.{suffix}" if suffix else domain

    # Decode punycode if present
    try:
        decoded_domain = idna.decode(root_domain)
    except Exception:
        decoded_domain = root_domain

    path = unquote(parsed.path)
    query = unquote(parsed.query)

    return {
        "original_url": url,
        "protocol": parsed.scheme,
        "subdomain": subdomain,
        "domain": domain,
        "suffix": suffix,
        "root_domain": root_domain,
        "decoded_domain": decoded_domain,
        "path": path,
        "query": query,
        "fragment": parsed.fragment,
        "full_hostname": parsed.netloc
    }
