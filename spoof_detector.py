import re
from urllib.parse import urlparse


def extract_domain_from_email(email_address):
    try:
        return email_address.split("@")[-1].lower()
    except:
        return ""


def check_email_spoofing(email_data):
    score = 0
    reasons = []

    sender = email_data.get("from", "")
    urls = email_data.get("urls", [])

    sender_domain = extract_domain_from_email(sender)

    # 🔴 Check 1: suspicious sender format
    if not sender or "@" not in sender:
        score += 2
        reasons.append("Invalid sender email format")

    # 🔴 Check 2: domain mismatch (email vs URL)
    for url in urls:
        try:
            url_domain = urlparse(url).netloc.lower()

            if sender_domain and sender_domain not in url_domain:
                score += 2
                reasons.append(
                    f"Mismatch between sender domain ({sender_domain}) and URL ({url_domain})"
                )
        except:
            continue

    # 🔴 Check 3: suspicious keywords
    suspicious_words = ["urgent", "verify", "suspend", "account"]

    subject = email_data.get("subject", "").lower()

    for word in suspicious_words:
        if word in subject:
            score += 1
            reasons.append(f"Suspicious keyword in subject: {word}")

    return {
        "score": score,
        "reasons": reasons,
        "is_spoofed": score >= 3
    }