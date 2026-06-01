import whois
from datetime import datetime

def get_whois_info(domain: str) -> dict:
    try:
        w = whois.whois(domain)

        creation_date = w.creation_date
        expiration_date = w.expiration_date

        # Handle list values (WHOIS often returns lists)
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        domain_age = None

        # FIX: Handle timezone-aware datetime issue
        if creation_date:
            try:
                if creation_date.tzinfo is not None:
                    creation_date = creation_date.replace(tzinfo=None)

                domain_age = (datetime.now() - creation_date).days
            except Exception:
                domain_age = None

        return {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(creation_date),
            "expiration_date": str(expiration_date),
            "domain_age_days": domain_age
        }

    except Exception as e:
        return {"error": str(e)}