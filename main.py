from urllib.parse import urlparse
import json
import os

from url_analyzer.whois_lookup import get_whois_info
from url_analyzer.dns_lookup import get_dns_info
from url_analyzer.ssl_lookup import get_ssl_info
from utils.risk_scoring import calculate_risk, calculate_attachment_risk
from utils.virustotal import scan_url_virustotal, scan_file_virustotal
from report_generator.report import generate_html_report, generate_pdf_report
from email_analyzer.email_parser import parse_email
from email_analyzer.spoof_detector import check_email_spoofing


def extract_domain(input_url: str) -> str:
    """
    Extract domain from URL.
    """
    normalized_url = input_url.strip()

    if "://" not in normalized_url:
        normalized_url = f"http://{normalized_url}"

    parsed_url = urlparse(normalized_url)
    return parsed_url.netloc


def analyze_email(file_path):
    print("\n=== EMAIL ANALYSIS ===\n")

    email_data = parse_email(file_path)
    print("[+] Parsed Email:", email_data)

    spoof_result = check_email_spoofing(email_data)
    print("[+] Spoof Detection:", spoof_result)

    url_results = []

    for url in email_data.get("urls", []):
        try:
            print(f"\n[+] Analyzing URL from email: {url}")

            domain = extract_domain(url)

            whois_data = get_whois_info(domain)
            dns_data = get_dns_info(domain)
            ssl_data = get_ssl_info(domain)
            vt_data = scan_url_virustotal(url)

            risk = calculate_risk(whois_data, ssl_data, domain, vt_data, dns_data)

            url_results.append(
                {
                    "url": url,
                    "domain": domain,
                    "whois": whois_data,
                    "dns": dns_data,
                    "ssl": ssl_data,
                    "virustotal": vt_data,
                    "risk": risk,
                }
            )
        except Exception as e:
            url_results.append(
                {
                    "url": url,
                    "error": str(e)
                }
            )

    attachment_results = []

    for attachment in email_data.get("attachments", []):
        file_path = attachment.get("path")

        if file_path:
            print(f"[+] Scanning attachment: {file_path}")

            vt_result = scan_file_virustotal(file_path)
            risk = calculate_attachment_risk(vt_result)

            attachment_results.append({
                "filename": attachment.get("filename"),
                "vt_result": vt_result,
                "risk": risk
            })

    total_attachment_score = 0
    attachment_reasons = []

    for att in attachment_results:
        vt = att.get("vt_result", {})
        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)

        if malicious > 0:
            total_attachment_score += 5
            attachment_reasons.append(
                f"Attachment {att['filename']} flagged malicious by {malicious} engines"
            )
        elif suspicious > 0:
            total_attachment_score += 3
            attachment_reasons.append(
                f"Attachment {att['filename']} marked suspicious"
            )

    final_score = spoof_result["score"] + total_attachment_score

    if final_score <= 2:
        risk_level = "LOW"
    elif final_score <= 5:
        risk_level = "MEDIUM"
    elif final_score <= 10:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    final_email_risk = {
        "score": final_score,
        "risk_level": risk_level,
        "reasons": spoof_result["reasons"] + attachment_reasons
    }

    return {
        "email_data": email_data,
        "spoof_analysis": spoof_result,
        "url_analysis": url_results,
        "attachment_analysis": attachment_results,
        "final_risk": final_email_risk
    }


def main():
    print("\n=== Phishing Detection Tool ===\n")

    choice = input(
        "Choose input type:\n1. URL\n2. Email (.eml)\nEnter choice (1/2): "
    ).strip()

    if choice == "1":
        user_url = input("Enter URL: ").strip()

        domain = extract_domain(user_url)

        whois_data = get_whois_info(domain)
        dns_data = get_dns_info(domain)
        ssl_data = get_ssl_info(domain)
        vt_data = scan_url_virustotal(user_url)

        risk = calculate_risk(whois_data, ssl_data, domain, vt_data, dns_data)

        result = {
            "url": user_url,
            "domain": domain,
            "whois": whois_data,
            "dns": dns_data,
            "ssl": ssl_data,
            "virustotal": vt_data,
            "risk_analysis": risk,
        }

        print("\n=== URL ANALYSIS RESULT ===")
        print(result)

        os.makedirs("output_reports", exist_ok=True)
        print("\n[+] Generating HTML Report...")
        report_file = generate_html_report(result, f"{domain}_report.html")
        print(f"[+] HTML Report saved to: {report_file}")

        pdf_file = generate_pdf_report(result, f"{domain}_report.pdf")
        print(f"[+] PDF Report saved to: {pdf_file}")
        json_path = f"output_reports/{domain}_report.json"
        with open(json_path, "w") as f:
            json.dump(result, f, indent=4)

        print(f"\n[+] Report saved to: {json_path}")

    elif choice == "2":
        file_path = input("Enter path to .eml file: ").strip()

        email_result = analyze_email(file_path)

        print("\n=== EMAIL ANALYSIS RESULT ===")
        print(email_result)

    else:
        print("Invalid choice")


if __name__ == "__main__":
    main()