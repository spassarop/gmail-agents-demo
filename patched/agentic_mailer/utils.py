from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional


def safe_truncate(s: str, limit: int = 1500) -> str:
    if len(s) <= limit:
        return s
    return s[:limit] + "…"


def format_email_list(items) -> str:
    if not items:
        return "No emails matched."
    lines = ["Here are the matching emails:"]
    for idx, it in enumerate(items, start=1):
        d = it.date.isoformat(sep=" ", timespec="minutes") if it.date else "unknown date"
        subj = (it.subject or "(no subject)").strip()
        frm = (it.from_email or "").strip()
        snip = (it.snippet or "").replace("\n", " ").strip()
        lines.append(f"{idx}) [{d}] {subj} — From: {frm} — Snippet: {snip}")
    lines.append("")
    lines.append("Tip: say “read email #1” or “summarize #2”.")
    return "\n".join(lines)


_EMAIL_NUM_RE = re.compile(r"(?:email\s*)?#(\d+)", re.IGNORECASE)


def extract_email_number(text: str) -> Optional[int]:
    m = _EMAIL_NUM_RE.search(text or "")
    if not m:
        return None
    try:
        n = int(m.group(1))
        return n
    except Exception:
        return None


def extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    """Try to extract the first JSON object from an LLM output.

    This is defensive because some models wrap JSON with explanations.
    """
    if not text:
        return None

    # Fast path: the whole string is JSON
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    # Find a balanced {...}
    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start : i + 1]
                try:
                    obj = json.loads(candidate)
                    if isinstance(obj, dict):
                        return obj
                except Exception:
                    return None
    return None


def build_gmail_query(
    *,
    from_email: Optional[str] = None,
    to_email: Optional[str] = None,
    subject: Optional[str] = None,
    newer_than_days: Optional[int] = None,
    older_than_days: Optional[int] = None,
    label: Optional[str] = None,
    raw: Optional[str] = None,
) -> str:
    parts = []
    if raw:
        parts.append(raw)

    if from_email:
        parts.append(f"from:{from_email}")
    if to_email:
        parts.append(f"to:{to_email}")
    if subject:
        # Gmail query uses subject:(...) to match
        parts.append(f"subject:({subject})")
    if newer_than_days is not None:
        parts.append(f"newer_than:{newer_than_days}d")
    if older_than_days is not None:
        parts.append(f"older_than:{older_than_days}d")
    if label:
        # Gmail supports label:<name>
        parts.append(f"label:{label}")

    return " ".join([p for p in parts if p]).strip()
