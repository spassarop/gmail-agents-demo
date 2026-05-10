from __future__ import annotations

import base64
import logging
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Dict, List, Optional

from google.auth.exceptions import RefreshError, TransportError
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from .config import GMAIL_SCOPES
from .gmail_models import EmailListItem, EmailMessage as ParsedEmailMessage, GmailDraft, GmailLabel
from .gmail_parsing import parse_gmail_message

logger = logging.getLogger(__name__)


class GmailClientError(RuntimeError):
    pass


class AuthRequired(RuntimeError):
    """Raised when Gmail needs user authorization that cannot happen silently."""

    def __init__(self, auth_url: str = ""):
        self.auth_url = auth_url
        super().__init__("Gmail authorization required")


class GmailClient:
    def __init__(self, secrets_dir: str = "secrets"):
        self.secrets_dir = Path(secrets_dir)
        self._service = None
        self._pending_flow: Optional[InstalledAppFlow] = None

    def needs_auth(self) -> bool:
        token_path = self.secrets_dir / "token.json"
        cred_path = self.secrets_dir / "credentials.json"
        if not cred_path.exists():
            return False
        if not token_path.exists():
            return True
        try:
            creds = Credentials.from_authorized_user_file(str(token_path), GMAIL_SCOPES)
            return not creds or (not creds.valid and not (creds.expired and creds.refresh_token))
        except Exception:
            return True

    def prepare_auth_url(self, redirect_uri: str) -> str:
        cred_path = self.secrets_dir / "credentials.json"
        if not cred_path.exists():
            raise GmailClientError(f"Missing Gmail OAuth credentials: {cred_path}")
        flow = InstalledAppFlow.from_client_secrets_file(str(cred_path), GMAIL_SCOPES)
        flow.redirect_uri = redirect_uri
        auth_url, _ = flow.authorization_url(
            access_type="offline",
            prompt="consent",
            include_granted_scopes="true",
        )
        self._pending_flow = flow
        logger.info("OAuth flow prepared — auth URL generated")
        return auth_url

    def exchange_code(self, code: str) -> None:
        if self._pending_flow is None:
            raise GmailClientError("No pending OAuth flow — call prepare_auth_url() first")
        try:
            self._pending_flow.fetch_token(code=code)
            creds = self._pending_flow.credentials
        except Exception as exc:
            raise GmailClientError(f"OAuth token exchange failed: {exc}") from exc
        finally:
            self._pending_flow = None
        token_path = self.secrets_dir / "token.json"
        token_path.write_text(creds.to_json(), encoding="utf-8")
        self._service = None
        logger.info("Gmail credentials saved to %s", token_path)

    def invalidate(self) -> None:
        self._service = None

    def service(self):
        if self._service is None:
            self._service = self._build_service()
        return self._service

    def _build_service(self):
        token_path = self.secrets_dir / "token.json"
        cred_path = self.secrets_dir / "credentials.json"

        if not cred_path.exists():
            raise GmailClientError(f"Missing Gmail OAuth credentials: {cred_path}")

        creds: Optional[Credentials] = None
        if token_path.exists():
            try:
                creds = Credentials.from_authorized_user_file(str(token_path), GMAIL_SCOPES)
            except Exception as exc:
                logger.warning("Could not load token.json: %s", exc)
                creds = None

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                logger.info("Refreshing Gmail OAuth token...")
                try:
                    creds.refresh(Request())
                    token_path.write_text(creds.to_json(), encoding="utf-8")
                except (RefreshError, TransportError) as exc:
                    logger.warning("Token refresh failed: %s", exc)
                    raise AuthRequired() from exc
            else:
                raise AuthRequired()

        try:
            return build("gmail", "v1", credentials=creds)
        except Exception as e:
            raise GmailClientError(f"Failed to build Gmail service: {e}") from e

    def list_labels(self) -> List[GmailLabel]:
        try:
            res = self.service().users().labels().list(userId="me").execute()
            labels = res.get("labels", []) or []
            return [GmailLabel(id=l["id"], name=l["name"]) for l in labels if "id" in l and "name" in l]
        except HttpError as e:
            raise GmailClientError(f"Gmail labels.list failed: {e}") from e

    def list_messages(
        self,
        query: str = "",
        max_results: int = 5,
        label_ids: Optional[List[str]] = None,
    ) -> List[EmailListItem]:
        """List messages and return enriched metadata (subject/from/date/snippet)."""
        try:
            req = self.service().users().messages().list(
                userId="me",
                q=query or None,
                maxResults=max_results,
                labelIds=label_ids or None,
            )
            res = req.execute()
            msgs = res.get("messages", []) or []
        except HttpError as e:
            raise GmailClientError(f"Gmail messages.list failed: {e}") from e

        items: List[EmailListItem] = []
        for m in msgs:
            mid = m.get("id")
            if not mid:
                continue
            try:
                full = self.service().users().messages().get(
                    userId="me",
                    id=mid,
                    format="metadata",
                    metadataHeaders=["From", "To", "Subject", "Date"],
                ).execute()
                parsed = parse_gmail_message(full)
                items.append(
                    EmailListItem(
                        id=parsed["id"],
                        thread_id=parsed.get("thread_id"),
                        subject=parsed.get("subject", ""),
                        from_email=parsed.get("from_email", ""),
                        to_email=parsed.get("to_email", ""),
                        date=parsed.get("date"),
                        snippet=parsed.get("snippet", ""),
                    )
                )
            except HttpError as e:
                logger.warning("Failed to fetch metadata for message %s: %s", mid, e)
                continue

        return items

    def get_message(self, message_id: str) -> ParsedEmailMessage:
        try:
            full = self.service().users().messages().get(userId="me", id=message_id, format="full").execute()
        except HttpError as e:
            raise GmailClientError(f"Gmail messages.get failed: {e}") from e

        parsed = parse_gmail_message(full)
        # Vulnerable version intentionally retains raw HTML too
        return ParsedEmailMessage(
            id=parsed["id"],
            thread_id=parsed.get("thread_id"),
            subject=parsed.get("subject", ""),
            from_email=parsed.get("from_email", ""),
            to_email=parsed.get("to_email", ""),
            date=parsed.get("date"),
            snippet=parsed.get("snippet", ""),
            body_text=parsed.get("body_text", ""),
            body_html=parsed.get("body_html", ""),
        )

    def trash_message(self, message_id: str) -> None:
        try:
            self.service().users().messages().trash(userId="me", id=message_id).execute()
        except HttpError as e:
            raise GmailClientError(f"Gmail messages.trash failed: {e}") from e

    def delete_message_permanent(self, message_id: str) -> None:
        try:
            self.service().users().messages().delete(userId="me", id=message_id).execute()
        except HttpError as e:
            raise GmailClientError(f"Gmail messages.delete failed: {e}") from e

    def create_draft(self, to_email: str, subject: str, body: str) -> GmailDraft:
        msg = EmailMessage()
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)

        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
        try:
            res = self.service().users().drafts().create(userId="me", body={"message": {"raw": raw}}).execute()
            draft_id = res.get("id", "")
            message_id = (res.get("message") or {}).get("id")
            return GmailDraft(id=draft_id, message_id=message_id, to_email=to_email, subject=subject, body=body)
        except HttpError as e:
            raise GmailClientError(f"Gmail drafts.create failed: {e}") from e

    def send_draft(self, draft_id: str) -> Dict[str, Any]:
        try:
            return self.service().users().drafts().send(userId="me", body={"id": draft_id}).execute()
        except HttpError as e:
            raise GmailClientError(f"Gmail drafts.send failed: {e}") from e

    def send_email(self, to_email: str, subject: str, body: str) -> Dict[str, Any]:
        msg = EmailMessage()
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)

        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
        try:
            return self.service().users().messages().send(userId="me", body={"raw": raw}).execute()
        except HttpError as e:
            raise GmailClientError(f"Gmail messages.send failed: {e}") from e
