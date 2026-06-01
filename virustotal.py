"""
VirusTotal URL scan helper.

Uses async analysis: submit URL, then poll until status is "completed".

API key location (pick one):
1) Recommended: file `Phishing_Detection_Tool/.env` with line:
   VIRUSTOTAL_API_KEY=your_key_here
2) Or set the same name as a Windows/macOS/Linux user environment variable.

Never commit the real `.env` file to git.
"""

import os
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

# Load `.env` from the project folder (same folder as main.py)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(_PROJECT_ROOT / ".env")

API_KEY = (os.environ.get("VIRUSTOTAL_API_KEY") or "").strip()

# Polling: VT analysis is async — wait between checks.
_URL_POLL_INTERVAL_SEC = 3
_URL_MAX_POLL_ATTEMPTS = 5   # 5 × 3s ≈ 15s max wait
_FILE_POLL_INTERVAL_SEC = 3
_FILE_MAX_POLL_ATTEMPTS = 15  # 15 × 3s ≈ 45s max wait


def scan_url_virustotal(url: str) -> dict:
    try:
        if not API_KEY:
            return {
                "error": (
                    "VirusTotal API key not configured. "
                    "Create a file named .env in the Phishing_Detection_Tool folder "
                    "(copy from .env.example) and set VIRUSTOTAL_API_KEY=your_key, "
                    "or set that variable in your system environment."
                )
            }

        headers = {"x-apikey": API_KEY}

        # Submit URL
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=30,
        )

        if response.status_code != 200:
            return {
                "error": "Failed to submit URL",
                "status_code": response.status_code,
                "detail": response.text[:500] if response.text else None,
            }

        analysis_id = response.json()["data"]["id"]

        # Poll until analysis completes (VT is asynchronous)
        for _ in range(_URL_MAX_POLL_ATTEMPTS):
            time.sleep(_URL_POLL_INTERVAL_SEC)

            result_response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=30,
            )

            if result_response.status_code != 200:
                continue

            data = result_response.json()
            status = data["data"]["attributes"]["status"]

            if status == "completed":
                stats = data["data"]["attributes"].get("stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                }

        return {"error": "Analysis timeout"}

    except Exception as e:
        return {"error": str(e)}


def scan_file_virustotal(file_path):
    try:
        if not API_KEY:
            return {"error": "API key not configured"}

        headers = {"x-apikey": API_KEY}

        with open(file_path, "rb") as f:
            files = {"file": f}

            response = requests.post(
                "https://www.virustotal.com/api/v3/files",
                headers=headers,
                files=files,
                timeout=60,
            )

        if response.status_code != 200:
            return {"error": "File upload failed", "status": response.status_code}

        analysis_id = response.json()["data"]["id"]

        # Poll result (same logic as URL)
        for _ in range(_FILE_MAX_POLL_ATTEMPTS):
            time.sleep(_FILE_POLL_INTERVAL_SEC)

            result_response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers,
                timeout=30,
            )

            if result_response.status_code != 200:
                continue

            data = result_response.json()
            status = data["data"]["attributes"]["status"]

            if status == "completed":
                stats = data["data"]["attributes"].get("stats", {})

                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                }

        return {"error": "File analysis timeout"}

    except Exception as e:
        return {"error": str(e)}
