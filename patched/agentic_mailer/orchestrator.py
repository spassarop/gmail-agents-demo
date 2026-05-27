from __future__ import annotations

import re
from typing import Any, List, Optional

from testing_shared.telemetry import add_current_event, instrument_gmail_client, traced

from .config import ModelConfig, OllamaConfig
try:
    from .gmail_client import GmailClient, GmailClientError
except Exception:  # pragma: no cover
    GmailClient = None  # type: ignore[assignment]

    class GmailClientError(RuntimeError):
        pass

from .gmail_models import ChatResponse, TraceEvent
from .logging_setup import get_logger
from .session_store import SessionState

from .agents.management_agent import ManagementAgent
from .agents.summary_agent import SummaryAgent
from .agents.composition_agent import CompositionAgent

from .security.intent_gate import IntentGate
from .security.hitl import HITLManager

from .tools.gateway import ToolGateway

logger = get_logger(__name__)

_CONFIRM_RE = re.compile(r"^/confirm(?:\s+(\S+))?$", re.IGNORECASE)
_CANCEL_RE  = re.compile(r"^/cancel(?:\s+(\S+))?$",  re.IGNORECASE)


class Orchestrator:
    """Patched orchestrator — bootstraps the agent and returns its result.

    handle_chat is a thin shell:
      1. handle HITL /confirm or /cancel commands
      2. delegate entirely to ManagementAgent.run()
      3. wrap the AgentResult in a ChatResponse

    All security controls (provenance guard, IntentGate, sanitization, canary,
    HITL preparation) live in ToolGateway.  The loop and provenance-aware
    result injection live in ManagementAgent.
    """

    def __init__(self, gmail_client: Optional[Any] = None):
        self.mode = "patched"
        base_gmail_client = gmail_client
        if base_gmail_client is None:
            if GmailClient is None:
                raise RuntimeError(
                    "GmailClient unavailable; inject a gmail_client or install Google deps."
                )
            base_gmail_client = GmailClient(secrets_dir="secrets")
        self.gmail = instrument_gmail_client(base_gmail_client, mode=self.mode)

        model_cfg = ModelConfig()
        ollama_cfg = OllamaConfig()

        self.summary_agent    = SummaryAgent(model_cfg, ollama_cfg)
        self.composition_agent = CompositionAgent(model_cfg, ollama_cfg)
        self.management_agent  = ManagementAgent(model_cfg, ollama_cfg)

        self.intent_gate = IntentGate()
        self.hitl        = HITLManager()

        self.gateway = ToolGateway(
            gmail=self.gmail,
            summary_agent=self.summary_agent,
            composition_agent=self.composition_agent,
            intent_gate=self.intent_gate,
            hitl_manager=self.hitl,
        )

    def handle_chat(self, session: SessionState, user_message: str) -> ChatResponse:
        with traced(
            "orchestrator.handle_chat",
            attributes={
                "app.mode": self.mode,
                "chat.session_id": session.session_id,
                "chat.user_message_length": len(user_message or ""),
                "chat.has_email_list": bool(session.last_email_list),
                "hitl.pending_count": len(session.pending_actions),
            },
        ):
            session.conversation.append(("user", user_message))

            # 0) HITL command shortcuts (/confirm, /cancel)
            m = _CONFIRM_RE.match(user_message.strip())
            if m:
                return self._confirm(session, m.group(1))

            m = _CANCEL_RE.match(user_message.strip())
            if m:
                return self._cancel(session, m.group(1))

            # 1) Run the secured agent loop
            result = self.management_agent.run(user_message, session, self.gateway)
            session.conversation.append(("assistant", result.assistant_text))

            return ChatResponse(
                assistant_text=result.assistant_text,
                trace=result.trace,
                pending_action_id=result.pending_action_id,
                pending_action_summary=result.pending_action_summary,
            )

    # ------------------------------------------------------------------
    # HITL command handlers — own their trace, use session state directly
    # ------------------------------------------------------------------

    def _emit(self, trace: List[TraceEvent], name: str, data: Optional[dict] = None) -> None:
        payload = data or {}
        trace.append(TraceEvent(name=name, data=payload))
        add_current_event(name, payload)

    def _confirm(self, session: SessionState, action_id: Optional[str]) -> ChatResponse:
        trace: List[TraceEvent] = []
        with traced("security.hitl.confirm", attributes={"app.mode": self.mode, "hitl.action_id": action_id or ""}):
            if not action_id:
                if len(session.pending_actions) == 1:
                    action_id = next(iter(session.pending_actions.keys()))
                else:
                    return ChatResponse(
                        assistant_text="Which action should I confirm? Usage: /confirm a1",
                        trace=trace,
                    )

            pa = self.hitl.pop(session, action_id)
            if not pa:
                return ChatResponse(
                    assistant_text=f"No pending action found with id {action_id}",
                    trace=trace,
                )

            self._emit(trace, "hitl_confirm", {"id": pa.id, "kind": pa.kind, "summary": pa.summary})

            try:
                if pa.kind == "send_draft":
                    draft_id = str(pa.payload.get("draft_id", ""))
                    res = self.gmail.send_draft(draft_id)
                    self._emit(trace, "gmail_send_draft", {"draft_id": draft_id, "result": res})
                    return ChatResponse(assistant_text="✅ Sent (after confirmation).", trace=trace)

                if pa.kind == "send_email":
                    # SEND_EMAIL path defers all Gmail side-effects until here.
                    to_email = str(pa.payload.get("to_email", ""))
                    subject = str(pa.payload.get("subject", ""))
                    body = str(pa.payload.get("body", ""))
                    if not to_email:
                        return ChatResponse(
                            assistant_text="Pending action missing recipient; cannot send.",
                            trace=trace,
                        )
                    res = self.gmail.send_email(to_email=to_email, subject=subject, body=body)
                    self._emit(
                        trace,
                        "gmail_send_email",
                        {"to": to_email, "subject": subject, "result": res},
                    )
                    return ChatResponse(assistant_text="✅ Sent (after confirmation).", trace=trace)

                if pa.kind == "trash_message":
                    mid = str(pa.payload.get("message_id", ""))
                    email_number = pa.payload.get("email_number")
                    if not mid:
                        return ChatResponse(
                            assistant_text="Pending action missing message_id; cannot trash.",
                            trace=trace,
                        )
                    self.gmail.trash_message(mid)
                    self._emit(trace, "gmail_trash_message", {"id": mid, "email_number": email_number})
                    return ChatResponse(
                        assistant_text=f"🗑️ Moved email #{email_number} to Trash (after confirmation).",
                        trace=trace,
                    )
            except GmailClientError as exc:
                logger.exception("GmailClientError during HITL confirm")
                self._emit(trace, "hitl_confirm_error", {"error": str(exc), "kind": pa.kind})
                return ChatResponse(assistant_text=f"Gmail error during confirmation: {exc}", trace=trace)

            return ChatResponse(
                assistant_text=f"Unknown pending action kind: {pa.kind}",
                trace=trace,
            )

    def _cancel(self, session: SessionState, action_id: Optional[str]) -> ChatResponse:
        trace: List[TraceEvent] = []
        with traced("security.hitl.cancel", attributes={"app.mode": self.mode, "hitl.action_id": action_id or ""}):
            if not action_id:
                if len(session.pending_actions) == 1:
                    action_id = next(iter(session.pending_actions.keys()))
                else:
                    return ChatResponse(
                        assistant_text="Which action should I cancel? Usage: /cancel a1",
                        trace=trace,
                    )

            ok = self.hitl.cancel(session, action_id)
            self._emit(trace, "hitl_cancel", {"id": action_id, "ok": ok})
            return ChatResponse(
                assistant_text="Canceled." if ok else f"No pending action found with id {action_id}",
                trace=trace,
            )
