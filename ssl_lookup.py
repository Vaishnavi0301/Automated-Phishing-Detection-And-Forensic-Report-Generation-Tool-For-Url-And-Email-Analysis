import ssl
import socket
from datetime import datetime

def get_ssl_info(domain: str) -> dict:
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")

        return {
            "issuer": dict(x[0] for x in cert['issuer']),
            "expiry_date": str(expiry_date),
            "is_valid": expiry_date > datetime.now()
        }

    except Exception as e:
        return {
            "error": str(e),
            "suspicious": True,
        }