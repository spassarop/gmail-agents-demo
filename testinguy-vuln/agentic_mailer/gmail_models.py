from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class EmailListItem(BaseModel):
    id: str
    thread_id: Optional[str] = None
    subject: str = ""
    from_email: str = ""
    to_email: str = ""
    date: Optional[datetime] = None
    snippet: str = ""


class EmailMessage(BaseModel):
    id: str
    thread_id: Optional[str] = None
    subject: str = ""
    from_email: str = ""
    to_email: str = ""
    date: Optional[datetime] = None
    snippet: str = ""
    # Extracted body; we keep both for demos
    body_text: str = ""
    body_html: str = ""


class GmailLabel(BaseModel):
    id: str
    name: str


class GmailDraft(BaseModel):
    id: str
    message_id: Optional[str] = None
    to_email: str
    subject: str
    body: str


class TraceEvent(BaseModel):
    name: str
    data: Dict[str, Any] = Field(default_factory=dict)


class ChatResponse(BaseModel):
    assistant_text: str
    trace: List[TraceEvent] = Field(default_factory=list)
    # Optional confirmation UX (used heavily in patched mode; harmless in vulnerable mode)
    pending_action_id: Optional[str] = None
    pending_action_summary: Optional[str] = None
