from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

from .schemas import ToolRequest, SendEmailRequest, TrashEmailRequest

logger = logging.getLogger(__name__)


@dataclass
class GateDecision:
    allow: bool
    require_confirmation: bool = False
    reason: str = ""


class IntentGate:
    """Policy middleware ("Intent Gate") for tool invocations.

    Core idea:
    - Treat LLM/agent outputs as untrusted
    - Validate intent/action against allowlist + basic semantic checks
    - Fail closed for anything ambiguous/high-impact
    """

    def __init__(self):
        self.allowed_actions = {
            "LIST_EMAILS",
            "READ_EMAIL",
            "SUMMARIZE_EMAIL",
            "DRAFT_EMAIL",
            "SEND_EMAIL",
            "TRASH_EMAIL",
        }

    def evaluate(self, user_message: str, tool_req: ToolRequest) -> GateDecision:
        action = getattr(tool_req, "action", "")
        if action not in self.allowed_actions:
            return GateDecision(False, reason=f"Action not allowlisted: {action}")

        # High impact: sending email requires HITL confirmation always in this demo
        if isinstance(tool_req, SendEmailRequest):
            # Must be explicitly requested by user (simple heuristic)
            if not self._user_intends_to_send(user_message):
                return GateDecision(False, reason="Blocked: sending email not requested by the user.")
            return GateDecision(True, require_confirmation=True, reason="Send requires human confirmation (HITL).")

        # Moderate impact: trashing email should require explicit delete intent
        if isinstance(tool_req, TrashEmailRequest):
            if not self._user_intends_to_delete(user_message):
                return GateDecision(False, reason="Blocked: trash/delete not clearly requested by the user.")
            return GateDecision(True, require_confirmation=False, reason="Allowed: explicit trash/delete request.")

        # Low impact: list/read/summarize/draft
        return GateDecision(True, require_confirmation=False, reason="Allowed (low-impact action).")

    def _user_intends_to_send(self, text: str) -> bool:
        t = (text or "").lower()
        return any(w in t for w in ["send", "email it", "mail it", "deliver", "shoot an email", "message them"])

    def _user_intends_to_delete(self, text: str) -> bool:
        t = (text or "").lower()
        return any(w in t for w in ["trash", "delete", "remove", "discard"])
