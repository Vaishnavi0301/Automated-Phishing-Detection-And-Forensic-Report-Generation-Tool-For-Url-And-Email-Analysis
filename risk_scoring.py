from .domain_checks import check_suspicious_domain


def calculate_risk(whois_data, ssl_data, domain, vt_data, dns_data):
    score = 0
    reasons = []

    # WHOIS age
    if "domain_age_days" in whois_data and whois_data["domain_age_days"]:
        if whois_data["domain_age_days"] < 180:
            score += 2
            reasons.append("Domain is very new")

    # SSL
    if "is_valid" in ssl_data:
        if not ssl_data["is_valid"]:
            score += 2
            reasons.append("SSL certificate is invalid or expired")

    # Domain pattern analysis
    domain_check = check_suspicious_domain(domain)
    score += domain_check["score"]
    reasons.extend(domain_check["reasons"])

    # Error checks
    if "error" in whois_data:
        score += 1
        reasons.append("WHOIS data unavailable")

    # SSL failure handling
    if "error" in ssl_data:
        score += 2

        err_msg = str(ssl_data.get("error", "")).lower()
        if "forcibly closed" in err_msg:
            score += 2
            reasons.append(
                "Server forcibly closed SSL connection (possible malicious behavior)"
            )
        else:
            reasons.append("SSL check failed")

    # VirusTotal check
    if isinstance(vt_data, dict) and "error" not in vt_data:
        malicious = vt_data.get("malicious", 0)
        if malicious > 0:
            score += 5
            reasons.append(
                f"Flagged malicious by {malicious} security vendors (VirusTotal)"
            )
    elif isinstance(vt_data, dict) and "error" in vt_data:
        score += 1
        reasons.append("VirusTotal scan unavailable or failed")

    # DNS failure (no A records)
    a_records = dns_data.get("A_records") if isinstance(dns_data, dict) else None
    if not a_records:
        score += 2
        reasons.append("Domain does not resolve (no A records — suspicious)")

    # Final classification
    if score <= 2:
        risk_level = "LOW"
    elif score <= 5:
        risk_level = "MEDIUM"
    elif score <= 10:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"
        reasons.append("Multiple high-confidence phishing indicators detected")

    return {
        "score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }


def calculate_attachment_risk(vt_data):
    score = 0
    reasons = []

    if isinstance(vt_data, dict) and "error" not in vt_data:
        malicious = vt_data.get("malicious", 0)
        if malicious > 0:
            score += 5
            reasons.append("Malicious attachment detected")
    elif isinstance(vt_data, dict) and "error" in vt_data:
        score += 1
        reasons.append("Attachment VirusTotal scan unavailable or failed")

    if score == 0:
        risk_level = "LOW"
    elif score <= 5:
        risk_level = "MEDIUM"
    elif score <= 10:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    return {
        "score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }