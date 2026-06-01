import difflib
import re

# Known popular domains (you can expand later)
KNOWN_BRANDS = [
    "google.com",
    "facebook.com",
    "amazon.com",
    "microsoft.com",
    "paypal.com",
    "apple.com",
]

# Map common digit/symbol substitutions to letters (typosquatting / homoglyphs)
_HOMOGLYPH_TRANS = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "@": "a",
    }
)

# Minimum string length for fuzzy match (avoid noise on short labels)
_FUZZY_MIN_BRAND_LEN = 4
_FUZZY_RATIO_THRESHOLD = 0.88


def _normalize_homoglyphs(label: str) -> str:
    """Normalize label by mapping common confusable digits to letters."""
    return label.translate(_HOMOGLYPH_TRANS)


def _second_level_label(domain_lower: str) -> str:
    """
    Approximate the registrable 'name' label (e.g. g0ogle from g0ogle.com).
    For sub.domain.com returns 'domain' (second from right before TLD).
    """
    labels = domain_lower.split(".")
    if len(labels) >= 2:
        return labels[-2]
    return labels[0] if labels else ""


def _is_legitimate_brand_host(domain_lower: str, brand: str) -> bool:
    """True if host is the real brand domain or a normal subdomain of it."""
    return domain_lower == brand or domain_lower.endswith("." + brand)


def check_suspicious_domain(domain: str) -> dict:
    score = 0
    reasons = []

    domain_lower = domain.lower().strip()

    # Check for numbers replacing letters (g0ogle, faceb00k)
    if re.search(r"[0-9]", domain_lower):
        score += 2
        reasons.append("Domain contains numeric characters (possible typosquatting)")

    # Check for long domain
    if len(domain_lower) > 25:
        score += 1
        reasons.append("Domain length is unusually long")

    # Check for suspicious characters
    if "-" in domain_lower:
        score += 1
        reasons.append("Domain contains hyphens (common in phishing)")

    # Similarity with known brands (substring, homoglyph-normalized SLD, fuzzy)
    sld = _second_level_label(domain_lower)
    norm_sld = _normalize_homoglyphs(sld)
    brands_flagged = set()

    for brand in KNOWN_BRANDS:
        if _is_legitimate_brand_host(domain_lower, brand):
            continue

        brand_key = brand.split(".")[0]
        if brand in brands_flagged:
            continue

        resembles = False
        detail = ""

        # Original: obvious substring (e.g. "paypal" in hostname, not exact brand domain)
        if brand not in domain_lower and brand_key in domain_lower:
            resembles = True
            detail = f"Domain resembles known brand: {brand}"

        # Homoglyph / digit swap: normalized SLD matches brand (g0ogle -> google)
        elif norm_sld == brand_key and sld != brand_key:
            resembles = True
            detail = f"Domain resembles known brand (typosquatting / homoglyph): {brand}"

        # Fuzzy match on normalized label (e.g. faceb00k vs facebook)
        elif (
            len(brand_key) >= _FUZZY_MIN_BRAND_LEN
            and sld != brand_key
            and norm_sld != brand_key
        ):
            ratio = difflib.SequenceMatcher(None, norm_sld, brand_key).ratio()
            if ratio >= _FUZZY_RATIO_THRESHOLD:
                resembles = True
                detail = f"Domain closely resembles known brand: {brand}"

        if resembles:
            score += 3
            reasons.append(detail)
            brands_flagged.add(brand)

    return {
        "score": score,
        "reasons": reasons,
    }
