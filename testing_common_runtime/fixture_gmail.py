from __future__ import annotations

import importlib
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class FixtureGmailClient:
    """Fixture-backed Gmail client used for Promptfoo and local contract testing.

    The client is intentionally lightweight and only implements the subset of the
    Gmail API surface the demo uses.

    The model classes and error class are injected so the same fixture can be used
    by both the vulnerable and patched implementations without duplicating package
    trees.
    """

    def __init__(
        self,
        *,
        email_list_item_cls: Any,
        email_message_cls: Any,
        gmail_draft_cls: Any,
        gmail_label_cls: Any,
        error_class: type[Exception] = RuntimeError,
        secrets_dir: str = "secrets",
        fixtures_path: Optional[str] = None,
    ):
        self._email_list_item_cls = email_list_item_cls
        self._email_message_cls = email_message_cls
        self._gmail_draft_cls = gmail_draft_cls
        self._gmail_label_cls = gmail_label_cls
        self._error_class = error_class

        self.secrets_dir = Path(secrets_dir)
        self.fixtures_path = Path(
            fixtures_path
            or os.getenv("testing_FIXTURES_PATH", "testing-common/fixtures/emails.json")
        )

        self._emails: List[Dict[str, Any]] = []
        self._email_by_id: Dict[str, Dict[str, Any]] = {}

        self._drafts: Dict[str, Any] = {}
        self._sent: List[Dict[str, Any]] = []
        self._trashed: set[str] = set()

        self._load_fixtures()

    # -----------------
    # Fixture loading
    # -----------------

    def _error(self, message: str) -> Exception:
        return self._error_class(message)

    @staticmethod
    def _parse_dt(value: Any) -> Optional[datetime]:
        if value is None or value == "":
            return None
        if isinstance(value, datetime):
            return value
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except Exception:
            return None

    def _load_fixtures(self) -> None:
        if not self.fixtures_path.exists():
            raise self._error(
                f"Fixture file not found: {self.fixtures_path}. "
                f"Create it (see testing-common/fixtures/emails.json)."
            )

        try:
            data = json.loads(self.fixtures_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise self._error(f"Failed to parse fixtures JSON: {exc}") from exc

        if isinstance(data, list):
            emails = data
        elif isinstance(data, dict) and isinstance(data.get("emails"), list):
            emails = data["emails"]
        else:
            raise self._error("Invalid fixtures format: expected {emails:[...]} or a list.")

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
        self._email_by_id = {email["id"]: email for email in self._emails}
        logger.info("Loaded %d fixture emails from %s", len(self._emails), self.fixtures_path)

    # -----------------
    # Gmail-like API
    # -----------------

    def list_labels(self) -> List[Any]:
        return [
            self._gmail_label_cls(id="INBOX", name="INBOX"),
            self._gmail_label_cls(id="SENT", name="SENT"),
        ]

    def list_messages(
        self,
        query: str = "",
        max_results: int = 5,
        label_ids: Optional[List[str]] = None,
    ) -> List[Any]:
        # Keep it simple for the talk: ignore query/labels and preserve deterministic ordering.
        out: List[Any] = []
        for email in self._emails:
            if email["id"] in self._trashed:
                continue
            out.append(
                self._email_list_item_cls(
                    id=email["id"],
                    thread_id=email.get("thread_id"),
                    subject=email.get("subject", ""),
                    from_email=email.get("from_email", ""),
                    to_email=email.get("to_email", ""),
                    date=self._parse_dt(email.get("date")),
                    snippet=email.get("snippet", ""),
                )
            )
            if len(out) >= int(max_results):
                break
        return out

    def get_message(self, message_id: str) -> Any:
        email = self._email_by_id.get(message_id)
        if not email or message_id in self._trashed:
            raise self._error(f"Message not found (or trashed): {message_id}")

        return self._email_message_cls(
            id=email["id"],
            thread_id=email.get("thread_id"),
            subject=email.get("subject", ""),
            from_email=email.get("from_email", ""),
            to_email=email.get("to_email", ""),
            date=self._parse_dt(email.get("date")),
            snippet=email.get("snippet", ""),
            body_text=email.get("body_text", ""),
            body_html=email.get("body_html", ""),
        )

    def trash_message(self, message_id: str) -> None:
        if message_id not in self._email_by_id:
            raise self._error(f"Cannot trash missing message_id: {message_id}")
        self._trashed.add(message_id)

    def delete_message_permanent(self, message_id: str) -> None:
        self.trash_message(message_id)

    def create_draft(self, to_email: str, subject: str, body: str) -> Any:
        draft_id = f"d{len(self._drafts) + 1}"
        draft = self._gmail_draft_cls(
            id=draft_id,
            message_id=None,
            to_email=to_email,
            subject=subject,
            body=body,
        )
        self._drafts[draft_id] = draft
        return draft

    def send_draft(self, draft_id: str) -> Dict[str, Any]:
        draft = self._drafts.get(draft_id)
        if not draft:
            raise self._error(f"Draft not found: {draft_id}")
        return self.send_email(to_email=draft.to_email, subject=draft.subject, body=draft.body)

    def send_email(self, to_email: str, subject: str, body: str) -> Dict[str, Any]:
        sent_id = f"s{len(self._sent) + 1}"
        self._sent.append({"id": sent_id, "to": to_email, "subject": subject, "body": body})
        return {"id": sent_id, "to": to_email, "subject": subject}

    # -----------------
    # Testing helpers
    # -----------------

    def testing_snapshot(self) -> Dict[str, Any]:
        drafts = [
            {
                "id": draft.id,
                "to": draft.to_email,
                "subject": draft.subject,
                "body": draft.body,
            }
            for draft in self._drafts.values()
        ]
        return {
            "fixture_email_count": len(self._emails),
            "trashed_ids": sorted(self._trashed),
            "draft_ids": sorted(self._drafts.keys()),
            "drafts": drafts,
            "sent": list(self._sent),
        }


def build_fixture_gmail_client(package_root: Any, fixtures_path: Optional[str] = None) -> FixtureGmailClient:
    """Create a fixture Gmail client bound to a specific runtime package's model classes."""
    package_name = getattr(package_root, "__name__", None)
    if not package_name:
        raise RuntimeError("package_root must be an imported package module")

    models = importlib.import_module(f"{package_name}.gmail_models")

    error_class: type[Exception] = RuntimeError
    try:
        gmail_client_mod = importlib.import_module(f"{package_name}.gmail_client")
        error_class = getattr(gmail_client_mod, "GmailClientError", RuntimeError)
    except Exception:
        error_class = RuntimeError

    return FixtureGmailClient(
        email_list_item_cls=models.EmailListItem,
        email_message_cls=models.EmailMessage,
        gmail_draft_cls=models.GmailDraft,
        gmail_label_cls=models.GmailLabel,
        error_class=error_class,
        fixtures_path=fixtures_path,
    )
