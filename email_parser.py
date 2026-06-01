import email
from email import policy
from email.parser import BytesParser
import re
import os


def parse_email(file_path):
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        attachments = extract_attachments(msg)

        email_data = {
            "from": msg["from"],
            "to": msg["to"],
            "subject": msg["subject"],
            "date": msg["date"],
            "body": get_email_body(msg),
            "urls": extract_urls(msg),
            "attachments": attachments
        }

        return email_data

    except Exception as e:
        return {"error": str(e)}


def extract_attachments(msg):
    attachments = []

    try:
        os.makedirs("attachments", exist_ok=True)

        for part in msg.walk():
            filename = part.get_filename()
            content_disposition = (part.get("Content-Disposition") or "").lower()
            content_type = part.get_content_type()

            # Treat real file parts as attachments even when the MIME part is
            # marked as inline or omits an explicit attachment disposition.
            is_attachment = (
                bool(filename)
                or "attachment" in content_disposition
                or ("inline" in content_disposition and content_type != "text/plain")
            )

            if is_attachment and filename:
                file_path = os.path.join("attachments", filename)

                payload = part.get_payload(decode=True)
                if payload is None:
                    continue

                with open(file_path, "wb") as f:
                    f.write(payload)

                attachments.append({
                    "filename": filename,
                    "path": file_path
                })

    except Exception as e:
        attachments.append({"error": str(e)})

    return attachments


def get_email_body(msg):
    try:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    return part.get_content()
        else:
            return msg.get_content()
    except:
        return ""


def extract_urls(msg):
    urls = []
    try:
        body = get_email_body(msg)
        urls = re.findall(r'https?://\S+', body)
    except:
        pass

    return urls