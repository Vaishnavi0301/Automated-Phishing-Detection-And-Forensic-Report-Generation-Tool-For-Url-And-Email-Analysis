import os
import uuid
from datetime import datetime

import pdfkit
from jinja2 import Environment, FileSystemLoader
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


def generate_html_report(data, filename="report.html"):
    try:
        template_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template("report_template.html")

        rendered_html = template.render(
            data=data,
            case_id=f"CASE-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            analyst="Automated DFIR Tool",
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            tool_name="Phishing Detection Tool",
        )

        file_path = f"output_reports/{filename}"
        with open(file_path, "w", encoding="utf-8") as report_file:
            report_file.write(rendered_html)

        return file_path
    except Exception as e:
        return f"Error generating HTML: {e}"


def generate_pdf_report(data, filename="report.pdf"):
    try:
        file_path = f"output_reports/{filename}"

        doc = SimpleDocTemplate(file_path, pagesize=A4)
        styles = getSampleStyleSheet()

        elements = []

        elements.append(Paragraph("DIGITAL FORENSIC REPORT", styles['Title']))
        elements.append(Spacer(1, 12))

        case_id = str(uuid.uuid4())[:8]
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        case_table = Table([
            ["Case ID", case_id],
            ["Analyst", "DFIR Analyst"],
            ["Date & Time", timestamp],
            ["Tool", "Phishing Detection Tool"],
        ])

        case_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ]))

        elements.append(case_table)
        elements.append(Spacer(1, 20))

        elements.append(Paragraph("1. Investigation Summary", styles['Heading2']))
        elements.append(Paragraph(f"URL: {data['url']}", styles['Normal']))
        elements.append(Paragraph(f"Risk Level: {data['risk_analysis']['risk_level']}", styles['Normal']))
        elements.append(Spacer(1, 12))

        elements.append(Paragraph("2. Evidence Details", styles['Heading2']))
        elements.append(Paragraph(f"Domain: {data['domain']}", styles['Normal']))
        elements.append(Paragraph(f"IP: {data['dns'].get('A_records')}", styles['Normal']))
        elements.append(Spacer(1, 12))

        elements.append(Paragraph("3. Technical Analysis", styles['Heading2']))

        elements.append(Paragraph("WHOIS:", styles['Heading3']))
        elements.append(Paragraph(str(data['whois']), styles['Normal']))

        elements.append(Paragraph("DNS:", styles['Heading3']))
        elements.append(Paragraph(str(data['dns']), styles['Normal']))

        elements.append(Paragraph("SSL:", styles['Heading3']))
        elements.append(Paragraph(str(data['ssl']), styles['Normal']))

        elements.append(Paragraph("VirusTotal:", styles['Heading3']))
        elements.append(Paragraph(str(data['virustotal']), styles['Normal']))

        elements.append(Spacer(1, 12))

        elements.append(Paragraph("4. Risk Assessment", styles['Heading2']))
        elements.append(Paragraph(f"Score: {data['risk_analysis']['score']}", styles['Normal']))

        for reason in data['risk_analysis']['reasons']:
            elements.append(Paragraph(f"- {reason}", styles['Normal']))

        elements.append(Spacer(1, 12))

        elements.append(Paragraph("5. Final Verdict", styles['Heading2']))
        elements.append(Paragraph(
            f"This URL is classified as {data['risk_analysis']['risk_level']} risk.",
            styles['Normal'],
        ))

        elements.append(Spacer(1, 12))

        elements.append(Paragraph("6. Recommendations", styles['Heading2']))
        elements.append(Paragraph("- Avoid accessing the URL", styles['Normal']))
        elements.append(Paragraph("- Block domain if necessary", styles['Normal']))
        elements.append(Paragraph("- Monitor network traffic", styles['Normal']))

        doc.build(elements)

        return file_path

    except Exception as e:
        return f"Error generating PDF: {e}"


def generate_email_report(data, filename="email_report.html"):
    try:
        template_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template("email_report_template.html")

        report_context = {
            "case_id": str(uuid.uuid4())[:8],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "analyst": "DFIR Analyst",
            "tool": "Phishing Detection Tool",
            "data": data,
        }

        output = template.render(report_context)

        os.makedirs("output_reports", exist_ok=True)
        file_path = os.path.join("output_reports", filename)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(output)

        return file_path

    except Exception as e:
        return f"Error generating email report: {e}"


def generate_email_pdf_report(data, filename="email_report.pdf"):
    try:
        file_path = f"output_reports/{filename}"

        os.makedirs("output_reports", exist_ok=True)

        doc = SimpleDocTemplate(file_path, pagesize=A4)
        styles = getSampleStyleSheet()

        elements = []

        elements.append(Paragraph("EMAIL FORENSIC REPORT", styles["Title"]))
        elements.append(Spacer(1, 12))

        case_id = str(uuid.uuid4())[:8]
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        elements.append(Paragraph(f"Case ID: {case_id}", styles["Normal"]))
        elements.append(Paragraph(f"Date: {timestamp}", styles["Normal"]))
        elements.append(Paragraph("Analyst: DFIR Analyst", styles["Normal"]))

        elements.append(Spacer(1, 12))

        elements.append(Paragraph("Email Details", styles["Heading2"]))
        elements.append(
            Paragraph(f"From: {data['email_data']['from']}", styles["Normal"])
        )
        elements.append(
            Paragraph(f"Subject: {data['email_data']['subject']}", styles["Normal"])
        )

        elements.append(Spacer(1, 12))

        elements.append(Paragraph("Spoof Analysis", styles["Heading2"]))
        elements.append(
            Paragraph(f"Score: {data['spoof_analysis']['score']}", styles["Normal"])
        )

        for reason in data["spoof_analysis"]["reasons"]:
            elements.append(Paragraph(f"- {reason}", styles["Normal"]))

        elements.append(Spacer(1, 12))

        elements.append(Paragraph("URL Analysis", styles["Heading2"]))

        for url in data["url_analysis"]:
            elements.append(Paragraph(f"URL: {url['url']}", styles["Normal"]))
            elements.append(
                Paragraph(f"Risk: {url['risk']['risk_level']}", styles["Normal"])
            )
            elements.append(Spacer(1, 6))

        doc.build(elements)

        return file_path

    except Exception as e:
        return f"Error generating email PDF: {e}"


def generate_email_pdf_from_template(
    data,
    filename="email_report.pdf",
    investigator="DFIR Analyst",
    detected_time=None,
):
    template_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("email_pdf_template.html")

    case_id = str(uuid.uuid4())[:8]
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    date_detected = detected_time if detected_time else current_time
    date_reported = current_time

    urls = data.get("email_data", {}).get("urls", [])

    first_url_analysis = data.get("url_analysis", [{}])[0] if data.get("url_analysis") else {}
    domain = first_url_analysis.get("domain", "N/A")
    dns_data = first_url_analysis.get("dns", {}) if isinstance(first_url_analysis, dict) else {}
    a_records = dns_data.get("A_records", ["N/A"]) if isinstance(dns_data, dict) else ["N/A"]
    if isinstance(a_records, list):
        ip = ", ".join(str(item) for item in a_records) if a_records else "N/A"
    else:
        ip = str(a_records) if a_records else "N/A"

    attachments = []
    for file_data in data.get("attachment_analysis", []):
        risk_level = (
            file_data.get("risk", {}).get("risk_level")
            if isinstance(file_data.get("risk"), dict)
            else None
        )
        attachments.append(
            {
                "filename": file_data.get("filename", "unknown"),
                "risk_level": risk_level or "N/A",
            }
        )

    rendered_html = template.render(
        case_id=case_id,
        date_detected=date_detected,
        date_reported=date_reported,
        reported_by="SOC Team",
        investigator=investigator,
        severity=data.get("final_risk", {}).get("risk_level", "UNKNOWN"),
        status="Resolved",
        email=data.get("email_data", {}),
        spoof=data.get("spoof_analysis", {}),
        urls=urls,
        url_analysis=data.get("url_analysis", []),
        attachments=attachments,
        domain=domain,
        ip=ip,
        attack_type="Phishing Attack",
        root_cause=urls[0] if urls else "N/A",
        verdict=(
            f"This email is classified as {data.get('final_risk', {}).get('risk_level', 'UNKNOWN')} risk."
        ),
        sign_date=current_time,
    )

    os.makedirs("output_reports", exist_ok=True)
    html_path = "output_reports/email_temp.html"
    pdf_path = f"output_reports/{filename}"

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(rendered_html)

    config = pdfkit.configuration(
        wkhtmltopdf=r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe"
    )

    pdfkit.from_file(html_path, pdf_path, configuration=config)

    return pdf_path


def generate_pdf_from_template(
    data,
    filename="report.pdf",
    investigator="DFIR Analyst",
    detected_time=None,
):
    template_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("pdf_template.html")

    case_id = str(uuid.uuid4())[:8]
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    date_detected = detected_time if detected_time else current_time
    date_reported = current_time
    whois_data = data.get("whois", {})
    dns_data = data.get("dns", {})
    ssl_data = data.get("ssl", {})
    vt_data = data.get("virustotal", {})
    risk_data = data.get("risk_analysis", {})

    a_records = dns_data.get("A_records", ["N/A"])
    if isinstance(a_records, list):
        dns_a_records = ", ".join(str(ip) for ip in a_records) if a_records else "N/A"
    else:
        dns_a_records = str(a_records) if a_records else "N/A"

    ssl_status = "Valid"
    if isinstance(ssl_data, dict):
        if ssl_data.get("error"):
            ssl_status = f"Error: {ssl_data.get('error')}"
        elif "valid" in ssl_data:
            ssl_status = "Valid" if ssl_data.get("valid") else "Invalid"

    rendered_html = template.render(
        case_id=case_id,
        date_detected=date_detected,
        date_reported=date_reported,
        severity=risk_data.get("risk_level", "UNKNOWN"),
        urls=[data.get("url", "N/A")],
        domain=data.get("domain", "N/A"),
        ip=dns_a_records,
        whois=whois_data,
        dns=dns_data,
        ssl=ssl_data,
        virustotal=vt_data,
        risk=risk_data,
        root_cause=data.get("url", "N/A"),
        verdict=f"This URL is classified as {risk_data.get('risk_level', 'UNKNOWN')} risk.",
        investigator=investigator,
        sign_date=current_time,
        reported_by="SOC Team",
        status="Resolved",
        attack_type="Phishing Attack",
        whois_creation_date=whois_data.get("creation_date", "N/A"),
        whois_registrar=whois_data.get("registrar", "N/A"),
        dns_a_records=dns_a_records,
        ssl_status=ssl_status,
        vt_malicious=vt_data.get("malicious", 0),
        risk_reasons=risk_data.get("reasons", []),
    )

    os.makedirs("output_reports", exist_ok=True)

    html_path = "output_reports/temp.html"
    pdf_path = f"output_reports/{filename}"

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(rendered_html)

    config = pdfkit.configuration(
        wkhtmltopdf=r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe"
    )

    pdfkit.from_file(html_path, pdf_path, configuration=config)

    return pdf_path