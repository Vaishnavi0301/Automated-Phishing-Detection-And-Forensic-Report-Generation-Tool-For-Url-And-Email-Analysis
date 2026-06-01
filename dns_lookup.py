import dns.resolver

def get_dns_info(domain: str) -> dict:
    """
    Fetch DNS records for a given domain.
    """
    result = {}

    # A Records
    try:
        answers = dns.resolver.resolve(domain, 'A')
        result["A_records"] = [rdata.to_text() for rdata in answers]
    except:
        result["A_records"] = []

    # MX Records
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        result["MX_records"] = [rdata.exchange.to_text() for rdata in answers]
    except:
        result["MX_records"] = []

    return result