import html
import json
import os
from pathlib import Path
from urllib.parse import quote

import gradio as gr

from main import analyze_email, extract_domain
from report_generator.report import (
    generate_email_pdf_from_template,
    generate_email_pdf_report,
    generate_email_report,
    generate_html_report,
    generate_pdf_from_template,
    generate_pdf_report,
)
from url_analyzer.dns_lookup import get_dns_info
from url_analyzer.ssl_lookup import get_ssl_info
from url_analyzer.whois_lookup import get_whois_info
from utils.risk_scoring import calculate_risk
from utils.virustotal import scan_url_virustotal


def analyze_url_gui(
    url: str,
    investigator: str = "DFIR Analyst",
    detected_time: str | None = None,
):
    if not url or not url.strip():
        return {"error": "Please enter a URL."}, None, None

    url = url.strip()
    domain = extract_domain(url)

    whois_data = get_whois_info(domain)
    dns_data = get_dns_info(domain)
    ssl_data = get_ssl_info(domain)
    vt_data = scan_url_virustotal(url)

    risk = calculate_risk(whois_data, ssl_data, domain, vt_data, dns_data)

    result = {
        "url": url,
        "domain": domain,
        "whois": whois_data,
        "dns": dns_data,
        "ssl": ssl_data,
        "virustotal": vt_data,
        "risk_analysis": risk,
    }

    os.makedirs("output_reports", exist_ok=True)
    html_file = generate_html_report(result, f"{domain}_report.html")
    pdf_file = generate_pdf_from_template(
        result,
        f"{domain}_report.pdf",
        investigator=investigator or "DFIR Analyst",
        detected_time=detected_time.strip() if detected_time else None,
    )

    return result, html_file, pdf_file


def _uploaded_file_path(file) -> str | None:
    if file is None:
        return None
    if isinstance(file, str):
        return file
    return getattr(file, "name", None) or str(file)


def analyze_email_gui(
    file,
    investigator: str = "DFIR Analyst",
    detected_time: str | None = None,
):
    path = _uploaded_file_path(file)
    if not path:
        return {"error": "Please upload a .eml file."}, None, None

    result = analyze_email(path)
    html_file = generate_email_report(result, "email_report.html")
    pdf_file = generate_email_pdf_from_template(
        result,
        "email_report.pdf",
        investigator=investigator or "DFIR Analyst",
        detected_time=detected_time.strip() if detected_time else None,
    )
    return result, html_file, pdf_file


def _gradio_file_href(local_path: str | None) -> str:
    """Build /gradio_api/file=... URL for a local file (Gradio 6+)."""
    if not local_path:
        return "#"
    abs_p = Path(local_path).resolve()
    if not abs_p.is_file():
        return "#"
    # Use POSIX path so the URL is stable on Windows; quote reserved chars only.
    posix = abs_p.as_posix()
    return "/gradio_api/file=" + quote(posix, safe=":/")


def _build_results_panel_html(
    result: dict,
    html_path: str | None,
    pdf_path: str | None,
) -> str:
    """Single HTML blob: risk, status, JSON, and download links (one UI update)."""
    err = result.get("error")
    if err:
        body = f"""
<div class="pd-result pd-result-error">
  <h3 class="pd-risk-title">Error</h3>
  <p>{html.escape(str(err))}</p>
  <p class="pd-status pd-status-err">Analysis could not complete.</p>
</div>
"""
        return body

    if "risk_analysis" in result:
        ra = result["risk_analysis"]
        level = html.escape(str(ra.get("risk_level", "UNKNOWN")))
        score = html.escape(str(ra.get("score", "")))
        risk_block = f"""
<div class="pd-risk">
  <h3 class="pd-risk-title">Risk level: {level}</h3>
  <p class="pd-risk-score"><strong>Score:</strong> {score}</p>
</div>
"""
    else:
        risk = result.get("final_risk", {"risk_level": "UNKNOWN", "score": 0})
        level = html.escape(str(risk.get("risk_level", "UNKNOWN")))
        score = html.escape(str(risk.get("score", "")))
        risk_block = f"""
<div class="pd-risk">
  <h3 class="pd-risk-title">Risk level: {level}</h3>
  <p class="pd-risk-score"><strong>Score:</strong> {score}</p>
</div>
"""

    json_text = json.dumps(result, indent=2, default=str)
    json_pre = html.escape(json_text)

    html_href = _gradio_file_href(html_path)
    pdf_href = _gradio_file_href(pdf_path)
    html_link = (
        f'<a class="pd-dl" href="{html_href}" download>Download HTML report</a>'
        if html_href != "#"
        else '<span class="pd-dl-missing">HTML report not available</span>'
    )
    pdf_link = (
        f'<a class="pd-dl" href="{pdf_href}" download>Download PDF report</a>'
        if pdf_href != "#"
        else '<span class="pd-dl-missing">PDF report not available</span>'
    )

    return f"""
<div class="pd-result pd-result-ok">
  {risk_block}
  <p class="pd-status pd-status-ok">✅ Analysis complete.</p>
  <div class="pd-downloads">
    {html_link}
    <span class="pd-dl-sep"> · </span>
    {pdf_link}
  </div>
  <details class="pd-json-wrap" open>
    <summary>Analysis result (JSON)</summary>
    <pre class="pd-json">{json_pre}</pre>
  </details>
</div>
"""


def _processing_html() -> str:
    return """
<div class="pd-result pd-processing">
  <p class="pd-status">Processing…</p>
</div>
"""


with gr.Blocks(
    css="""
body {
    background-color: #f5f7fb;
}

#layout-container {
    max-width: 1200px;
    margin: auto;
    padding: 20px;
}

#main-container {
    width: 100%;
}

#form-box {
    background: white;
    padding: 25px;
    border-radius: 12px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.08);
}

#guide-box {
    background: #ffffff;
    padding: 20px;
    border-radius: 12px;
    border-left: 4px solid #3b82f6;
    box-shadow: 0 2px 8px rgba(0,0,0,0.05);
}

button {
    border-radius: 10px !important;
}

.pd-result {
    margin-top: 12px;
    padding: 16px;
    border-radius: 10px;
    border: 1px solid #e5e7eb;
    background: #fafbfc;
}

.pd-processing .pd-status {
    margin: 0;
    font-size: 1.05rem;
}

.pd-risk-title {
    margin: 0 0 8px 0;
    font-size: 1.15rem;
    color: #b91c1c;
}

.pd-risk-score {
    margin: 0;
}

.pd-status-ok {
    color: #15803d;
    font-weight: 600;
    margin: 12px 0 8px 0;
}

.pd-status-err {
    color: #b91c1c;
    margin-top: 8px;
}

.pd-downloads {
    margin: 8px 0 16px 0;
}

.pd-dl {
    color: #2563eb;
    font-weight: 600;
}

.pd-dl-missing {
    color: #6b7280;
    font-size: 0.9rem;
}

.pd-dl-sep {
    color: #9ca3af;
}

.pd-json-wrap summary {
    cursor: pointer;
    font-weight: 600;
    margin-bottom: 8px;
}

.pd-json {
    max-height: 420px;
    overflow: auto;
    font-size: 12px;
    line-height: 1.4;
    padding: 12px;
    background: #1e293b;
    color: #e2e8f0;
    border-radius: 8px;
    white-space: pre-wrap;
    word-break: break-word;
}
"""
) as app:
    gr.Markdown("# \U0001f50d Phishing Detection & DFIR Tool")
    gr.Markdown("\n\n")

    with gr.Row(elem_id="layout-container"):
        with gr.Column(scale=3, elem_id="main-container"):
            with gr.Group(elem_id="form-box"):
                gr.Markdown("## Select Analysis Type")
                with gr.Row():
                    url_mode_button = gr.Button("🔗 URL Analysis", variant="primary")
                    email_mode_button = gr.Button("📧 Email Analysis", variant="secondary")

                gr.Markdown("\n\n")

                with gr.Group(visible=False) as url_section:
                    url_input = gr.Textbox(
                        label="Enter URL",
                        placeholder="https://example.com",
                    )
                    investigator_input = gr.Textbox(
                        label="Investigator Name",
                        placeholder="Enter investigator name",
                    )

                    detected_time_input = gr.Textbox(
                        label="Date/Time Detected",
                        placeholder="YYYY-MM-DD HH:MM:SS",
                    )

                    url_analyze_button = gr.Button("Analyze URL", variant="primary")

                with gr.Group(visible=False) as email_section:
                    email_input = gr.File(
                        label="Upload .eml file",
                        file_types=[".eml"],
                    )
                    email_investigator_input = gr.Textbox(
                        label="Investigator Name",
                        placeholder="Enter investigator name",
                    )
                    email_detected_time_input = gr.Textbox(
                        label="Date/Time Detected",
                        placeholder="YYYY-MM-DD HH:MM:SS",
                    )
                    email_analyze_button = gr.Button("Analyze Email", variant="primary")

                gr.Markdown("\n\n")
                results_panel = gr.HTML(visible=False)

        with gr.Column(scale=1, min_width=220):
            with gr.Group(elem_id="guide-box"):
                gr.Markdown(
                    """
### 📘 How to Use

1. Select Analysis  
2. Enter URL  
3. Enter Investigation Details  
4. Click Analyze  

---

### ⚠️ Notes
- Performs forensic-level analysis  
- Uses VirusTotal & threat intelligence  
- Generates detailed investigation reports  
"""
                )

    def show_url_section():
        return (
            gr.update(visible=True),
            gr.update(visible=False),
            gr.update(variant="primary"),
            gr.update(variant="secondary"),
        )

    def show_email_section():
        return (
            gr.update(visible=False),
            gr.update(visible=True),
            gr.update(variant="secondary"),
            gr.update(variant="primary"),
        )

    def handle_url_analysis(url, investigator, detected_time):
        yield gr.update(value=_processing_html(), visible=True)
        result, html_path, pdf_path = analyze_url_gui(url, investigator, detected_time)
        yield gr.update(
            value=_build_results_panel_html(result, html_path, pdf_path),
            visible=True,
        )

    def handle_email_analysis(file, investigator, detected_time):
        yield gr.update(value=_processing_html(), visible=True)
        result, html_path, pdf_path = analyze_email_gui(file, investigator, detected_time)
        yield gr.update(
            value=_build_results_panel_html(result, html_path, pdf_path),
            visible=True,
        )

    url_mode_button.click(
        fn=show_url_section,
        inputs=[],
        outputs=[url_section, email_section, url_mode_button, email_mode_button],
    )

    email_mode_button.click(
        fn=show_email_section,
        inputs=[],
        outputs=[url_section, email_section, url_mode_button, email_mode_button],
    )

    url_analyze_button.click(
        fn=handle_url_analysis,
        inputs=[url_input, investigator_input, detected_time_input],
        outputs=[results_panel],
    )

    email_analyze_button.click(
        fn=handle_email_analysis,
        inputs=[email_input, email_investigator_input, email_detected_time_input],
        outputs=[results_panel],
    )

if __name__ == "__main__":
    _out = os.path.abspath(os.path.join(os.path.dirname(__file__), "output_reports"))
    os.makedirs(_out, exist_ok=True)
    app.launch(allowed_paths=[_out])
