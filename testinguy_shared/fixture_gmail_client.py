from __future__ import annotations

"""Compatibility shim for the shared fixture Gmail client.

The canonical fixture implementation now lives in
`testinguy_common_runtime.fixture_gmail` so the Promptfoo/runtime harness can bind
it to the vulnerable or patched runtime model classes without cloning package
folders.

This module keeps the old import path working while delegating to that canonical
implementation instead of maintaining a second mock client implementation.
"""

from typing import Any, Optional

from testinguy_common_runtime.fixture_gmail import (
    FixtureGmailClient as _CanonicalFixtureGmailClient,
    build_fixture_gmail_client,
)

try:  # pragma: no cover - optional runtime import
    from agentic_mailer.gmail_client import GmailClientError
except Exception:  # pragma: no cover - graceful fallback
    class GmailClientError(RuntimeError):
        pass


class FixtureGmailClient(_CanonicalFixtureGmailClient):
    """Backward-compatible fixture client bound to the vulnerable model classes.

    New code should prefer `testinguy_common_runtime.build_fixture_gmail_client`
    so the correct runtime-specific Pydantic models are injected explicitly.
    """

    def __init__(self, fixtures_path: Optional[str] = None, **kwargs: Any):
        from agentic_mailer.gmail_models import EmailListItem, EmailMessage, GmailDraft, GmailLabel

        defaults = {
            "email_list_item_cls": EmailListItem,
            "email_message_cls": EmailMessage,
            "gmail_draft_cls": GmailDraft,
            "gmail_label_cls": GmailLabel,
            "error_class": GmailClientError,
        }
        defaults.update(kwargs)
        super().__init__(fixtures_path=fixtures_path, **defaults)


__all__ = [
    "FixtureGmailClient",
    "GmailClientError",
    "build_fixture_gmail_client",
]
