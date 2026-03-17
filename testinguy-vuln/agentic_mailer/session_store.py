from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .gmail_models import EmailListItem


@dataclass
class PendingAction:
    id: str
    kind: str
    summary: str
    # For example: {"draft_id": "..."} or {"message_id": "..."}
    payload: dict = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


@dataclass
class SessionState:
    session_id: str
    created_at: float = field(default_factory=time.time)
    last_access: float = field(default_factory=time.time)
    conversation: List[Tuple[str, str]] = field(default_factory=list)  # (role, text)
    last_email_list: List[EmailListItem] = field(default_factory=list)
    pending_actions: Dict[str, PendingAction] = field(default_factory=dict)

    def touch(self) -> None:
        self.last_access = time.time()


class SessionStore:
    def __init__(self, ttl_seconds: int = 60 * 60 * 6):
        self.ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        self._sessions: Dict[str, SessionState] = {}

    def new_session_id(self) -> str:
        return secrets.token_urlsafe(18)

    def get(self, session_id: str) -> Optional[SessionState]:
        with self._lock:
            s = self._sessions.get(session_id)
            if s:
                s.touch()
            return s

    def get_or_create(self, session_id: Optional[str]) -> SessionState:
        with self._lock:
            if session_id and session_id in self._sessions:
                s = self._sessions[session_id]
                s.touch()
                return s

            sid = session_id or self.new_session_id()
            s = SessionState(session_id=sid)
            self._sessions[sid] = s
            return s

    def cleanup(self) -> None:
        now = time.time()
        with self._lock:
            to_del = [sid for sid, s in self._sessions.items() if (now - s.last_access) > self.ttl_seconds]
            for sid in to_del:
                del self._sessions[sid]
