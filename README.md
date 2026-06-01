# Automated Phishing Detection And Forensic Report Generation Tool For URL And Email Analysis

A Digital Forensics and Incident Response (DFIR) tool that performs automated phishing detection for URLs and emails, collects threat intelligence from multiple sources, evaluates phishing indicators, and generates professional forensic investigation reports in HTML and PDF formats.

---

## Overview

URL / Email Input → Threat Intelligence Collection → Domain & Email Analysis → Risk Scoring Engine → Phishing Detection → Evidence Collection → Automated DFIR Report Generation

The tool helps cybersecurity analysts identify phishing attacks by analyzing suspicious URLs, email messages, sender domains, attachments, DNS records, SSL certificates, WHOIS information, and VirusTotal intelligence.

---

## Features

### URL Analysis

* WHOIS domain intelligence lookup
* DNS record analysis (A & MX records)
* SSL certificate validation
* Domain reputation assessment
* Typosquatting and homoglyph detection
* Brand impersonation detection
* VirusTotal URL scanning
* Automated phishing risk scoring

### Email Analysis

* .eml file parsing
* Email header extraction
* Sender verification
* Email spoofing detection
* Suspicious subject keyword analysis
* URL extraction from email content
* Embedded URL phishing analysis
* Attachment extraction and scanning

### Threat Intelligence Integration

* WHOIS Lookup
* DNS Enumeration
* SSL Certificate Inspection
* VirusTotal URL Analysis
* VirusTotal Attachment Scanning

### Forensic Report Generation

* HTML Investigation Reports
* PDF DFIR Reports
* Case ID Generation
* Risk Assessment Summary
* Technical Evidence Collection
* Investigation Timeline Information

### Interactive Dashboard

* Gradio-based Web Interface
* URL Analysis Mode
* Email Analysis Mode
* Investigator Information Tracking
* Report Download Support

---

## System Architecture

Alice/Analyst Input

↓

URL Analysis / Email Analysis

↓

WHOIS Lookup

DNS Lookup

SSL Inspection

VirusTotal Scan

Spoof Detection

Attachment Analysis

↓

Risk Scoring Engine

↓

Threat Classification

↓

Automated DFIR Report Generation

↓

HTML & PDF Reports

---

## Project Structure

```text
Automated-Phishing-Detection-Tool/
│
├── app.py                      # Gradio GUI application
├── main.py                     # Core analysis workflow
│
├── url_analyzer/
│   ├── whois_lookup.py
│   ├── dns_lookup.py
│   ├── ssl_lookup.py
│
├── email_analyzer/
│   ├── email_parser.py
│   └── spoof_detector.py
│
├── utils/
│   ├── risk_scoring.py
│   ├── domain_checks.py
│   └── virustotal.py
│
├── report_generator/
│   └── report.py
│
├── templates/
│   ├── report_template.html
│   ├── email_report_template.html
│   ├── pdf_template.html
│   └── email_pdf_template.html
│
├── attachments/
│
├── output_reports/
│
├── requirements.txt
└── README.md
```

---

## Detection Techniques

### Domain Analysis

The tool identifies suspicious domains using:

* Typosquatting detection
* Homoglyph detection
* Numeric character substitution analysis
* Brand impersonation detection
* Domain length analysis
* Hyphen-based phishing detection

Examples:

```text
g00gle.com
paypa1-login.com
micr0soft-security.com
```

---

### WHOIS Analysis

The system evaluates:

* Domain age
* Registrar information
* Domain creation date
* Domain expiration date

Recently created domains receive higher risk scores because phishing campaigns commonly use newly registered domains.

---

### SSL Certificate Analysis

The tool verifies:

* Certificate validity
* Certificate issuer
* Expiration date
* SSL connection anomalies

Invalid or expired certificates increase phishing risk.

---

### DNS Analysis

Collected DNS information includes:

* A Records
* MX Records

Missing or suspicious DNS configurations contribute to risk assessment.

---

### VirusTotal Integration

The tool submits URLs and attachments to VirusTotal and evaluates:

* Malicious detections
* Suspicious detections
* Harmless verdicts
* Undetected results

Threat intelligence is incorporated into the final phishing score.

---

### Email Spoofing Detection

The email analysis module checks:

* Sender email validity
* Sender domain mismatches
* URL domain inconsistencies
* Suspicious subject keywords

Keywords monitored include:

```text
urgent
verify
suspend
account
```

---

### Attachment Analysis

Attachments extracted from emails are:

* Saved locally
* Submitted to VirusTotal
* Classified according to detection results
* Included in forensic reports

---

## Risk Classification

| Score Range | Risk Level |
| ----------- | ---------- |
| 0 – 2       | LOW        |
| 3 – 5       | MEDIUM     |
| 6 – 10      | HIGH       |
| 11+         | CRITICAL   |

The final risk score combines:

* Domain intelligence
* SSL analysis
* VirusTotal results
* DNS findings
* Email spoofing indicators
* Attachment analysis

---

## Installation

### Clone Repository

```bash
git clone https://github.com/your-username/Automated-Phishing-Detection-And-Forensic-Report-Generation-Tool.git

cd Automated-Phishing-Detection-And-Forensic-Report-Generation-Tool
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configure VirusTotal API Key

Create a `.env` file in the project root:

```env
VIRUSTOTAL_API_KEY=your_api_key_here
```

---

## Usage

### Launch the Dashboard

```bash
python app.py
```

Open the generated Gradio URL in your browser.

---

### URL Analysis

1. Select URL Analysis.
2. Enter the target URL.
3. Enter investigator details.
4. Click Analyze URL.
5. Download generated reports.

---

### Email Analysis

1. Select Email Analysis.
2. Upload an `.eml` file.
3. Enter investigator details.
4. Click Analyze Email.
5. Download generated forensic reports.

---

## Generated Reports

### HTML Report

Contains:

* Case Information
* Risk Assessment
* WHOIS Analysis
* DNS Analysis
* SSL Analysis
* VirusTotal Results
* Final Verdict

### PDF DFIR Report

Contains:

* Case ID
* Investigator Information
* Technical Findings
* Evidence Collection
* Risk Assessment
* Recommendations

---

## Example Output

```text
Risk Level : HIGH
Risk Score : 8

Indicators:
- Domain resembles a known brand
- SSL validation failed
- Domain is newly registered
- VirusTotal flagged malicious activity

Verdict:
Potential phishing website detected.
```

---

## Technologies Used

### Backend

* Python

### User Interface

* Gradio

### Threat Intelligence

* VirusTotal API

### Network Analysis

* WHOIS
* DNS Resolver
* SSL Inspection

### Report Generation

* Jinja2
* ReportLab
* PDFKit

### Additional Libraries

* Requests
* python-whois
* dnspython
* python-dotenv

---

## Future Enhancements

* SPF, DKIM and DMARC validation
* Machine Learning based phishing detection
* Real-time threat intelligence feeds
* Sandbox attachment analysis
* SIEM Integration
* Threat hunting dashboard
* IOC export support

---

## Author

**Vaishnavi**

Cybersecurity & Digital Forensics Project

---

## License

This project is intended for educational, research, and cybersecurity awareness purposes only.
