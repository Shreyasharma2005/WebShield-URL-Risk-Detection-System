import re
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "bank",
    "payment",
    "password",
    "update",
    "confirm",
    "signin",
    "authenticate"
]


def get_domain(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def extract_features(url):

    url = url.lower()

    domain = get_domain(url)

    parsed = urlparse(
        url if url.startswith(("http://", "https://"))
        else "http://" + url
    )

    path = parsed.path

    features = []

    # 1. Total URL length
    features.append(len(url))

    # 2. Domain length
    features.append(len(domain))

    # 3. Number of dots
    features.append(url.count("."))

    # 4. Number of hyphens
    features.append(url.count("-"))

    # 5. Number of special characters
    special_chars = sum(
        1 for char in url
        if char in "@?=&_%"
    )
    features.append(special_chars)

    # 6. HTTPS
    features.append(
        1 if url.startswith("https://") else 0
    )

    # 7. Suspicious keyword count
    keyword_count = sum(
        word in url for word in SUSPICIOUS_KEYWORDS
    )
    features.append(keyword_count)

    # 8. IP address instead of domain
    features.append(
        1 if re.search(
            r"\d+\.\d+\.\d+\.\d+",
            domain
        ) else 0
    )

    # 9. @ symbol
    features.append(
        1 if "@" in url else 0
    )

    # 10. URL depth
    depth = len(
        [part for part in path.split("/") if part]
    )
    features.append(depth)

    # 11. Number of subdomains
    domain_parts = domain.split(".")
    subdomain_count = max(
        0,
        len(domain_parts) - 2
    )
    features.append(subdomain_count)

    # 12. Suspicious TLD
    suspicious_tlds = [
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq"
    ]

    features.append(
        1 if any(
            domain.endswith(tld)
            for tld in suspicious_tlds
        ) else 0
    )

    return features