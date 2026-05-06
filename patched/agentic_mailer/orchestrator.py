from __future__ import annotations

import re
from typing import Any, List, Optional

from testing_shared.telemetry import add_current_event, instrument_gmail_client, traced

from .config import ModelConfig, OllamaConfig
try:
    from .gmail_client import GmailClient, GmailClientError
except Exception:  # pragma: no cover - allows fixture-based evals without Google deps
    GmailClient = None  # type: ignore[assignment]

    class GmailClientError(RuntimeError):
        pass

from .gmail_models import ChatResponse, TraceEvent
from .logging_setup import get_logger
from .session_store import SessionState
from .utils import extract_email_number, format_email_list, safe_truncate

from .agents.management_agent import ManagementAgent
from .agents.summary_agent import SummaryAgent
from .agents.composition_agent import CompositionAgent

from .security.intent_gate import IntentGate
from .security.hitl import HITLManager
from .security.schemas import (
    DraftEmailRequest,
    ListEmailsRequest,
    ReadEmailRequest,
    SummarizeEmailRequest,
    TrashEmailRequest,
    ToolRequest,
)

from .tools.gateway import ToolGateway

logger = get_logger(__name__)

_CONFIRM_RE = re.compile(r"^/confirm(?:\s+(\S+))?$", re.IGNORECASE)
_CANCEL_RE = re.compile(r"^/cancel(?:\s+(\S+))?$", re.IGNORECASE)


class Orchestrator:
    """Patched multi-agent orchestrator.

    After Stage 1: all tool execution, IntentGate checks, sanitization,
    canary detection, and HITL preparation are delegated to ToolGateway.
    The orchestrator handles session routing, management-agent decisions,
    HITL confirm/cancel commands, and building the final ChatResponse.
    """

    def __init__(self, gmail_client: Optional[Any] = None):
        self.mode = "patched"
        base_gmail_client = gmail_client
        if base_gmail_client is None:
            if GmailClient is None:
                raise RuntimeError(
                    "GmailClient dependencies are unavailable; "
                    "install the Google Gmail dependencies or inject a gmail_client."
                )
            base_gmail_client = GmailClient(secrets_dir="secrets")
        self.gmail = instrument_gmail_client(base_gmail_client, mode=self.mode)

        model_cfg = ModelConfig()
        ollama_cfg = OllamaConfig()

        self.summary_agent = SummaryAgent(model_cfg, ollama_cfg)
        self.composition_agent = CompositionAgent(model_cfg, ollama_cfg)
        self.management_agent = ManagementAgent(model_cfg, ollama_cfg)

        self.intent_gate = IntentGate()
        self.hitl = HITLManager()

        self.gateway = ToolGateway(
            gmail=self.gmail,
            summary_agent=self.summary_agent,
            composition_agent=self.composition_agent,
            intent_gate=self.intent_gate,
            hitl_manager=self.hitl,
        )

    def _append_trace(self, trace: List[TraceEvent], name: str, data: Optional[dict] = None) -> None:
        payload = data or {}
        trace.append(TraceEvent(name=name, data=payload))
        add_current_event(name, payload)

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
        ) as span:
            session.conversation.append(("user", user_message))
            trace: List[TraceEvent] = []

            # 0) HITL confirmation commands — handled before anything else
            m = _CONFIRM_RE.match(user_message.strip())
            if m:
                return self._confirm(session, m.group(1), trace)

            m = _CANCEL_RE.match(user_message.strip())
            if m:
                return self._cancel(session, m.group(1), trace)

            # 1) Management agent produces a typed tool request
            email_list_text = format_email_list(session.last_email_list) if session.last_email_list else ""
            tool_req, raw = self.management_agent.decide(user_message, email_list_text=email_list_text)
            self._append_trace(trace, "management_llm_raw", {"text": safe_truncate(raw, 4000)})

            if tool_req is None:
                # Safe-by-default heuristic fallback
                tool_req = self._heuristic_request(user_message)
                self._append_trace(
                    trace,
                    "heuristic_fallback",
                    {"tool": getattr(tool_req, "action", None) if tool_req else None},
                )
                span.set_attribute("tool.request.heuristic_fallback", True)
                if tool_req is None:
                    return ChatResponse(
                        assistant_text=(
                            "I couldn't parse a safe tool request. Try: "
                            "'List my newest 5 emails' or 'Summarize email #1'."
                        ),
                        trace=trace,
                    )

            self._append_trace(
                trace,
                "tool_request_validated",
                {
                    "tool": getattr(tool_req, "action", ""),
                    "args": (
                        getattr(tool_req, "args", None).model_dump()
                        if hasattr(getattr(tool_req, "args", None), "model_dump")
                        else {}
                    ),
                },
            )
            span.set_attribute("tool.request.action", getattr(tool_req, "action", ""))

            # 2) Delegate to gateway (handles IntentGate + sanitize + canary + HITL prep)
            try:
                result = self.gateway.execute(
                    tool_req.action,
                    tool_req.args.model_dump(),
                    session,
                    trace,
                    user_message=user_message,
                )
                span.set_attribute("tool.result.success", result.success)

                return ChatResponse(
                    assistant_text=result.output,
                    trace=trace,
                    pending_action_id=result.pending_action_id,
                    pending_action_summary=result.pending_action_summary,
                )
            except GmailClientError as exc:
                logger.exception("GmailClientError")
                span.set_attribute("error.kind", "gmail")
                return ChatResponse(assistant_text=f"Gmail error: {exc}", trace=trace)
            except Exception as exc:
                logger.exception("Unhandled error in orchestrator")
                span.set_attribute("error.kind", type(exc).__name__)
                return ChatResponse(assistant_text=f"Error: {exc}", trace=trace)

    # ------------------------------------------------------------------
    # HITL command handlers — stay on orchestrator (session state access)
    # ------------------------------------------------------------------

    def _confirm(self, session: SessionState, action_id: Optional[str], trace: List[TraceEvent]) -> ChatResponse:
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

            self._append_trace(trace, "hitl_confirm", {"id": pa.id, "kind": pa.kind, "summary": pa.summary})

            if pa.kind == "send_draft":
                draft_id = str(pa.payload.get("draft_id", ""))
                res = self.gmail.send_draft(draft_id)
                self._append_trace(trace, "gmail_send_draft", {"draft_id": draft_id, "result": res})
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
                self._append_trace(trace, "gmail_trash_message", {"id": mid, "email_number": email_number})
                return ChatResponse(
                    assistant_text=f"🗑️ Moved email #{email_number} to Trash (after confirmation).",
                    trace=trace,
                )

            return ChatResponse(
                assistant_text=f"Unknown pending action kind: {pa.kind}",
                trace=trace,
            )

    def _cancel(self, session: SessionState, action_id: Optional[str], trace: List[TraceEvent]) -> ChatResponse:
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
            self._append_trace(trace, "hitl_cancel", {"id": action_id, "ok": ok})
            if ok:
                return ChatResponse(assistant_text="Canceled.", trace=trace)
            return ChatResponse(
                assistant_text=f"No pending action found with id {action_id}",
                trace=trace,
            )

    # ------------------------------------------------------------------
    # Safe-by-default heuristic fallback
    # ------------------------------------------------------------------

    def _heuristic_request(self, user_message: str) -> Optional[ToolRequest]:
        t = (user_message or "").strip()
        low = t.lower()

        if any(w in low for w in ["list", "show emails", "show my emails", "inbox", "emails from", "emails to"]):
            max_results = 5
            m = re.search(r"(?:last|newest|latest|top)\s+(\d+)", low)
            if m:
                try:
                    max_results = max(1, min(50, int(m.group(1))))
                except Exception:
                    pass

            from_email = to_email = subject = newer_than_days = label = None

            em = re.search(r"from\s+([\w.+-]+@[\w.-]+)", t, re.IGNORECASE)
            if em:
                from_email = em.group(1)
            em = re.search(r"to\s+([\w.+-]+@[\w.-]+)", t, re.IGNORECASE)
            if em:
                to_email = em.group(1)
            sm = re.search(r"subject\s+(?:contains\s+)?['\"]([^'\"]+)['\"]", t, re.IGNORECASE)
            if sm:
                subject = sm.group(1)
            dm = re.search(r"(?:last|past)\s+(\d+)\s+days", low)
            if dm:
                try:
                    newer_than_days = int(dm.group(1))
                except Exception:
                    pass
            if "inbox" in low:
                label = "inbox"

            return ListEmailsRequest(
                action="LIST_EMAILS",
                args={
                    "raw_query": "",
                    "from_email": from_email,
                    "to_email": to_email,
                    "subject": subject,
                    "newer_than_days": newer_than_days,
                    "label": label,
                    "max_results": max_results,
                },
            )

        if "read" in low:
            n = extract_email_number(t)
            if n:
                return ReadEmailRequest(action="READ_EMAIL", args={"email_number": n})
        if "summar" in low:
            n = extract_email_number(t)
            if n:
                return SummarizeEmailRequest(action="SUMMARIZE_EMAIL", args={"email_number": n})
        if any(w in low for w in ["trash", "delete", "remove", "discard"]):
            n = extract_email_number(t)
            if n:
                return TrashEmailRequest(action="TRASH_EMAIL", args={"email_number": n})
        if "draft" in low or "reply" in low:
            n = extract_email_number(t)
            if n:
                return DraftEmailRequest(action="DRAFT_EMAIL", args={"reply_to_email_number": n})

        return None
