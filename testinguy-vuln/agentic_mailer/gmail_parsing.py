from __future__ import annotations

import base64
import logging
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Optional, Tuple

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


def _b64url_decode(data: str) -> bytes:
    # Gmail uses URL-safe base64 without padding
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _extract_headers(payload: Dict[str, Any]) -> Dict[str, str]:
    headers = {}
    for h in payload.get("headers", []):
        name = h.get("name")
        value = h.get("value")
        if name and value:
            headers[name.lower()] = value
    return headers


def _extract_body_from_part(part: Dict[str, Any]) -> Tuple[str, str]:
    """Return (text, html) aggregated from a MIME part."""
    mime_type = part.get("mimeType", "")
    body = part.get("body", {}) or {}
    data = body.get("data")

    text = ""
    html = ""

    if data:
        try:
            decoded = _b64url_decode(data).decode("utf-8", errors="replace")
        except Exception:
            decoded = ""
        if mime_type == "text/plain":
            text += decoded
        elif mime_type == "text/html":
            html += decoded

    # Recurse into subparts
    for sub in part.get("parts", []) or []:
        t, h = _extract_body_from_part(sub)
        text += t
        html += h

    return text, html


def parse_gmail_message(message: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a Gmail API message resource into normalized fields."""
    payload = message.get("payload", {}) or {}
    headers = _extract_headers(payload)

    subject = headers.get("subject", "")
    from_email = headers.get("from", "")
    to_email = headers.get("to", "")
    date_raw = headers.get("date")
    date_dt: Optional[datetime] = None
    if date_raw:
        try:
            date_dt = parsedate_to_datetime(date_raw)
        except Exception:
            date_dt = None

    text, html = _extract_body_from_part(payload)
    snippet = message.get("snippet", "")

    # Convert HTML to a safe plain-text preview for display (avoid rendering HTML)
    html_as_text = ""
    if html:
        try:
            soup = BeautifulSoup(html, "html.parser")
            html_as_text = soup.get_text(separator="\n")
        except Exception:
            html_as_text = ""

    return {
        "id": message.get("id", ""),
        "thread_id": message.get("threadId"),
        "subject": subject,
        "from_email": from_email,
        "to_email": to_email,
        "date": date_dt,
        "snippet": snippet,
        "body_text": text.strip(),
        "body_html": html.strip(),
        "body_html_text": html_as_text.strip(),
    }
