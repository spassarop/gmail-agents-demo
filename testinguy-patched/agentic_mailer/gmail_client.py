from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .gmail_models import EmailListItem, EmailMessage as ParsedEmailMessage, GmailDraft, GmailLabel

logger = logging.getLogger(__name__)


class GmailClientError(RuntimeError):
    pass


def _parse_dt(value: Any) -> Optional[datetime]:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value
    try:
        # ISO-8601
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


class GmailClient:
    """Fixture-backed Gmail client.

    Used only in the `testinguy-*` folders to make Promptfoo runs fast and independent
    from Google APIs.

    Fixture format (JSON):
      {
        "emails": [
          {
            "id": "m1",
            "thread_id": "t1",
            "subject": "...",
            "from_email": "alice@example.com",
            "to_email": "me@example.com",
            "date": "2026-03-01T12:00:00",
            "snippet": "...",
            "body_text": "...",
            "body_html": "..."  # optional
          }
        ]
      }
    """

    def __init__(self, secrets_dir: str = "secrets", fixtures_path: Optional[str] = None):
        self.secrets_dir = Path(secrets_dir)
        self.fixtures_path = Path(
            fixtures_path
            or os.getenv("TESTINGUY_FIXTURES_PATH", "testinguy-common/fixtures/emails.json")
        )

        self._emails: List[Dict[str, Any]] = []
        self._email_by_id: Dict[str, Dict[str, Any]] = {}

        self._drafts: Dict[str, GmailDraft] = {}
        self._sent: List[Dict[str, Any]] = []
        self._trashed: set[str] = set()

        self._load_fixtures()

    # -----------------
    # Fixture loading
    # -----------------

    def _load_fixtures(self) -> None:
        if not self.fixtures_path.exists():
            raise GmailClientError(
                f"Fixture file not found: {self.fixtures_path}. "
                f"Create it (see testinguy-common/fixtures/emails.json)."
            )

        try:
            data = json.loads(self.fixtures_path.read_text(encoding="utf-8"))
        except Exception as e:
            raise GmailClientError(f"Failed to parse fixtures JSON: {e}") from e

        if isinstance(data, list):
            emails = data
        elif isinstance(data, dict) and isinstance(data.get("emails"), list):
            emails = data["emails"]
        else:
            raise GmailClientError("Invalid fixtures format: expected {emails:[...]} or a list.")

        norm: List[Dict[str, Any]] = []
        for i, raw in enumerate(emails, start=1):
            if not isinstance(raw, dict):
                continue
            mid = str(raw.get("id") or f"m{i}")
            item = {
                "id": mid,
                "thread_id": raw.get("thread_id"),
                "subject": str(raw.get("subject") or ""),
                "from_email": str(raw.get("from_email") or ""),
                "to_email": str(raw.get("to_email") or ""),
                "date": raw.get("date"),
                "snippet": str(raw.get("snippet") or ""),
                "body_text": str(raw.get("body_text") or ""),
                "body_html": str(raw.get("body_html") or ""),
                "labels": raw.get("labels") or ["INBOX"],
            }
            norm.append(item)

        self._emails = norm
        self._email_by_id = {e["id"]: e for e in self._emails}
        logger.info("Loaded %d fixture emails from %s", len(self._emails), self.fixtures_path)

    # -----------------
    # Gmail-like API
    # -----------------

    def list_labels(self) -> List[GmailLabel]:
        # minimal stub
        return [GmailLabel(id="INBOX", name="INBOX"), GmailLabel(id="SENT", name="SENT")]

    def list_messages(
        self,
        query: str = "",
        max_results: int = 5,
        label_ids: Optional[List[str]] = None,
    ) -> List[EmailListItem]:
        # Keep it simple: ignore query/labels for the talk.
        out: List[EmailListItem] = []
        for e in self._emails:
            if e["id"] in self._trashed:
                continue
            out.append(
                EmailListItem(
                    id=e["id"],
                    thread_id=e.get("thread_id"),
                    subject=e.get("subject", ""),
                    from_email=e.get("from_email", ""),
                    to_email=e.get("to_email", ""),
                    date=_parse_dt(e.get("date")),
                    snippet=e.get("snippet", ""),
                )
            )
            if len(out) >= int(max_results):
                break
        return out

    def get_message(self, message_id: str) -> ParsedEmailMessage:
        e = self._email_by_id.get(message_id)
        if not e or message_id in self._trashed:
            raise GmailClientError(f"Message not found (or trashed): {message_id}")

        return ParsedEmailMessage(
            id=e["id"],
            thread_id=e.get("thread_id"),
            subject=e.get("subject", ""),
            from_email=e.get("from_email", ""),
            to_email=e.get("to_email", ""),
            date=_parse_dt(e.get("date")),
            snippet=e.get("snippet", ""),
            body_text=e.get("body_text", ""),
            body_html=e.get("body_html", ""),
        )

    def trash_message(self, message_id: str) -> None:
        if message_id not in self._email_by_id:
            raise GmailClientError(f"Cannot trash missing message_id: {message_id}")
        self._trashed.add(message_id)

    def delete_message_permanent(self, message_id: str) -> None:
        # same as trash in this fixture
        self.trash_message(message_id)

    def create_draft(self, to_email: str, subject: str, body: str) -> GmailDraft:
        did = f"d{len(self._drafts)+1}"
        draft = GmailDraft(id=did, message_id=None, to_email=to_email, subject=subject, body=body)
        self._drafts[did] = draft
        return draft

    def send_draft(self, draft_id: str) -> Dict[str, Any]:
        d = self._drafts.get(draft_id)
        if not d:
            raise GmailClientError(f"Draft not found: {draft_id}")
        return self.send_email(to_email=d.to_email, subject=d.subject, body=d.body)

    def send_email(self, to_email: str, subject: str, body: str) -> Dict[str, Any]:
        sid = f"s{len(self._sent)+1}"
        self._sent.append({"id": sid, "to": to_email, "subject": subject, "body": body})
        return {"id": sid, "to": to_email, "subject": subject}

    # -----------------
    # Testing helpers
    # -----------------

    def testing_snapshot(self) -> Dict[str, Any]:
        drafts = [
            {
                "id": d.id,
                "to": d.to_email,
                "subject": d.subject,
                "body": d.body,
            }
            for d in self._drafts.values()
        ]
        return {
            "fixture_email_count": len(self._emails),
            "trashed_ids": sorted(list(self._trashed)),
            "draft_ids": sorted(list(self._drafts.keys())),
            "drafts": drafts,
            "sent": list(self._sent),
        }
