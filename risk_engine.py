def calculate_url_risk(url):
    url = url.lower()

    score = 0
    reasons = []

    suspicious_keywords = [
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

    # URL length
    if len(url) > 75:
        score += 20
        reasons.append("URL is unusually long")

    elif len(url) > 50:
        score += 10
        reasons.append("URL is longer than usual")

    # Hyphens
    hyphen_count = url.count("-")

    if hyphen_count >= 4:
        score += 20
        reasons.append("URL contains many hyphens")

    elif hyphen_count >= 2:
        score += 10
        reasons.append("URL contains suspicious hyphens")

    # Suspicious keywords
    found_keywords = [
        word for word in suspicious_keywords
        if word in url
    ]

    if len(found_keywords) >= 3:
        score += 25
        reasons.append(
            "Multiple phishing-related keywords detected"
        )

    elif len(found_keywords) >= 1:
        score += 15
        reasons.append(
            "URL contains phishing-related keywords"
        )

    # Domain
    domain_part = url.split("/")[2] if "://" in url else url
    domain_part = domain_part.split(":")[0]

    if domain_part.count(".") >= 4:
        score += 15
        reasons.append("URL contains many subdomains")

    elif domain_part.count(".") >= 3:
        score += 8
        reasons.append("URL contains multiple subdomains")

    # IP address
    import re

    if re.search(
        r"\d+\.\d+\.\d+\.\d+",
        domain_part
    ):
        score += 20
        reasons.append(
            "Website uses an IP address instead of a domain name"
        )

    # @ symbol
    if "@" in url:
        score += 20
        reasons.append(
            "URL contains an @ symbol"
        )

    return min(score, 100), reasons


# ==================================================
# DOMAIN RISK
# ==================================================

def calculate_domain_risk(domain, known_domains):

    domain = domain.lower()

    # Trusted domain
    for trusted in known_domains:

        if (
            domain == trusted
            or domain.endswith("." + trusted)
        ):

            return 0, False, [
                "Domain matches a known trusted domain"
            ]

    # Unknown domain
    score = 20

    reasons = [
        "Domain is not in the trusted domain list"
    ]

    # Hyphens
    if "-" in domain:

        score += 10

        reasons.append(
            "Domain contains hyphens"
        )

    # Subdomains
    if domain.count(".") >= 3:

        score += 10

        reasons.append(
            "Domain contains multiple subdomains"
        )

    return min(score, 100), True, reasons


# ==================================================
# WEBPAGE STRUCTURAL RISK
# ==================================================

def calculate_page_risk(page_analysis):

    if not page_analysis:
        return 0, []

    score = 0
    reasons = []

    forms = page_analysis.get(
        "forms",
        0
    )

    password_fields = page_analysis.get(
        "password_fields",
        0
    )

    iframes = page_analysis.get(
        "iframes",
        0
    )

    external_links = page_analysis.get(
        "external_links",
        0
    )

    external_form_actions = page_analysis.get(
        "external_form_actions",
        0
    )

    https = page_analysis.get(
        "https",
        True
    )


    # --------------------------------------------------
    # Password fields
    # --------------------------------------------------

    if password_fields >= 1:

        score += 15

        reasons.append(
            "Page contains password input fields"
        )


    # --------------------------------------------------
    # Forms
    # --------------------------------------------------

    if forms >= 3:

        score += 10

        reasons.append(
            "Page contains multiple forms"
        )


    # --------------------------------------------------
    # External form submission
    # --------------------------------------------------

    if external_form_actions >= 1:

        score += 25

        reasons.append(
            "Form submits data to an external domain"
        )


    # --------------------------------------------------
    # Iframes
    # --------------------------------------------------

    if iframes >= 3:

        score += 10

        reasons.append(
            "Page contains multiple iframes"
        )


    # --------------------------------------------------
    # External links
    # --------------------------------------------------

    if external_links >= 10:

        score += 5

        reasons.append(
            "Page contains many external links"
        )


    # --------------------------------------------------
    # HTTP instead of HTTPS
    # --------------------------------------------------

    if https is False:

        score += 15

        reasons.append(
            "Website does not use HTTPS"
        )


    return min(score, 100), reasons


# ==================================================
# FINAL RISK
# ==================================================

def calculate_final_risk(
    ml_probability,
    url_risk,
    domain_risk,
    page_risk=0
):
    ml_score = round(ml_probability * 100)

    final_score = (
        (ml_score * 0.40)
        + (url_risk * 0.25)
        + (domain_risk * 0.15)
        + (page_risk * 0.20)
    )

    final_score = round(min(final_score, 100))

    breakdown = {
        "ml_score": ml_score,
        "url_risk": url_risk,
        "domain_risk": domain_risk,
        "page_risk": page_risk
    }

    return final_score, breakdown

