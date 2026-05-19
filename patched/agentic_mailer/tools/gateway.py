from __future__ import annotations

import re
import secrets
import uuid
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from pydantic import TypeAdapter

from testing_shared.telemetry import add_current_event, traced

from ..gmail_models import TraceEvent
from ..logging_setup import get_logger
from ..session_store import SessionState
from ..utils import build_gmail_query, format_email_list, safe_truncate
from ..security.intent_gate import IntentGate
from ..security.hitl import HITLManager
from ..security.schemas import (
    DraftEmailRequest,
    ListEmailsRequest,
    ReadEmailRequest,
    SendEmailRequest,
    SummarizeEmailRequest,
    TrashEmailRequest,
    ToolRequest,
)

from .definitions import HandoffEnvelope, HandoffResponse, ToolResult
from ..gmail_client import AuthRequired


def _short_uuid() -> str:
    """8-char hex request ID for correlating A2A envelope ↔ response in traces."""
    return uuid.uuid4().hex[:8]

logger = get_logger(__name__)

_TOOL_ADAPTER = TypeAdapter(ToolRequest)

# Matches literal TOOL_CALL / ARGS syntax that an attacker might embed in email body
# to try to get the syntax reproduced verbatim in the summary output.
_TOOL_SYNTAX_RE = re.compile(
    r"(TOOL_CALL\s*:\s*\w+|ARGS\s*:\s*\{.*?\})",
    re.IGNORECASE | re.DOTALL,
)


class ToolGateway:
    """Patched ToolGateway.

    Adds three layers of defense before every tool dispatch:
    1. Provenance guard — blocks SEND/TRASH when the prior tool result
       came from email content (``last_provenance="email_content"``).
       This is the primary code-level enforcement; it cannot be bypassed
       by crafting email content.
    2. IntentGate — validates tool call against semantic user-intent and
       action-class allowlist.
    3. Sanitization & canary — SUMMARIZE_EMAIL strips TOOL_CALL syntax from
       the email body before it reaches the Summary Agent and checks the
       summary output for the session canary token.

    The ``[UNTRUSTED CONTENT]`` prompt framing is soft guidance only;
    the provenance guard here is the real enforcement.
    """

    def __init__(
        self,
        gmail: Any,
        summary_agent: Any,
        composition_agent: Any,
        intent_gate: IntentGate,
        hitl_manager: HITLManager,
    ) -> None:
        self.gmail = gmail
        self.summary_agent = summary_agent
        self.composition_agent = composition_agent
        self.intent_gate = intent_gate
        self.hitl = hitl_manager
        # Canary: generated once per gateway instance.
        # Embedded in the management agent system prompt.
        # If it appears in summary output the model's context boundary was crossed.
        self._canary: str = secrets.token_hex(8)

    # ------------------------------------------------------------------
    # Public interface — expose canary for management agent embedding
    # ------------------------------------------------------------------

    @property
    def canary(self) -> str:
        return self._canary

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def execute(
        self,
        tool_name: str,
        args: Dict[str, Any],
        session: SessionState,
        trace: List[TraceEvent],
        user_message: str = "",
        last_provenance: str = "system",
    ) -> ToolResult:
        """Validate and dispatch a tool call through all security layers."""
        tool = (tool_name or "").strip().upper()

        # Layer 1 — provenance guard (primary enforcement).
        # Refuses high-impact actions when the previous tool result originated
        # from email content rather than the user.  Cannot be overridden by
        # anything the LLM or email content says.
        if last_provenance == "email_content" and tool in ("SEND_EMAIL", "TRASH_EMAIL"):
            blocked_result = ToolResult(
                tool=tool_name,
                success=False,
                output=(
                    "Blocked: cannot execute a high-impact action that was derived from "
                    "email content rather than an explicit user request."
                ),
                data={"blocked_by": "provenance_check"},
            )
            self._emit(
                trace,
                "tool_result",
                {
                    "tool": tool_name,
                    "blocked_by": "provenance_check",
                    "last_provenance": last_provenance,
                },
            )
            return blocked_result

        # Layer 2 — build typed ToolRequest for IntentGate.
        tool_req = self._build_tool_req(tool_name, args)
        if tool_req is None:
            return ToolResult(
                tool=tool_name,
                success=False,
                output=f"Unknown or invalid tool: {tool_name}",
                data={"error": "unknown_tool"},
            )

        # Layer 2 (cont.) — IntentGate semantic check.
        decision = self.intent_gate.evaluate(user_message, tool_req)
        self._emit(
            trace,
            "intent_gate",
            {
                "allow": decision.allow,
                "require_confirmation": decision.require_confirmation,
                "reason": decision.reason,
            },
        )

        if not decision.allow:
            return ToolResult(
                tool=tool_name,
                success=False,
                output=f"Blocked by Intent Gate: {decision.reason}",
                data={"blocked": True, "reason": decision.reason},
            )

        # Layer 3 — dispatch with optional HITL.
        try:
            return self._dispatch(tool_req, session, trace, user_message, decision)
        except AuthRequired:
            raise  # let auth errors propagate to the server's WS handler
        except Exception as exc:
            logger.exception("ToolGateway.execute error tool=%s", tool_name)
            self._emit(trace, "tool_error", {"tool": tool_name, "error": str(exc)})
            return ToolResult(
                tool=tool_name,
                success=False,
                output=f"Tool error ({tool_name}): {exc}",
                data={"error": str(exc)},
            )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _emit(self, trace: List[TraceEvent], name: str, data: Optional[Dict] = None) -> None:
        payload = data or {}
        trace.append(TraceEvent(name=name, data=payload))
        add_current_event(name, payload)

    def _build_tool_req(self, tool_name: str, args: dict) -> Optional[ToolRequest]:
        try:
            return _TOOL_ADAPTER.validate_python({"action": tool_name, "args": args})
        except Exception as exc:
            logger.warning("ToolGateway._build_tool_req failed tool=%s: %s", tool_name, exc)
            return None

    def _resolve_email_id(self, session: SessionState, email_number: Optional[int]) -> Optional[str]:
        if email_number is None:
            return None
        idx = email_number - 1
        if idx < 0 or idx >= len(session.last_email_list):
            return None
        return session.last_email_list[idx].id

    def _sanitize_email_body(self, text: str) -> tuple[str, int]:
        """Strip TOOL_CALL/ARGS syntax from email body before summarization.

        Returns (sanitized_text, match_count).  This is a gateway-level defense:
        even if the summary agent's own sanitizer misses injected tool syntax,
        the gateway removes it first.
        """
        if not text:
            return text, 0
        sanitized, n = _TOOL_SYNTAX_RE.subn("[redacted]", text)
        return sanitized, n

    def _check_canary(self, text: str, trace: List[TraceEvent]) -> None:
        """Emit a trace event if the session canary appears in summary output.

        The canary is embedded in the management agent system prompt.
        Finding it in email-derived content strongly suggests context leakage.
        This is a signal event only — it does NOT block execution.
        """
        if self._canary and self._canary in (text or ""):
            self._emit(
                trace,
                "canary_leak_detected",
                {
                    "canary": self._canary,
                    "note": (
                        "Summary output contains the system-prompt canary. "
                        "Possible prompt injection or context boundary violation."
                    ),
                },
            )
            logger.warning("Canary token detected in summary output — possible injection.")

    # ------------------------------------------------------------------
    # Dispatch router
    # ------------------------------------------------------------------

    def _dispatch(
        self,
        tool_req: ToolRequest,
        session: SessionState,
        trace: List[TraceEvent],
        user_message: str,
        decision: Any,
    ) -> ToolResult:
        if isinstance(tool_req, ListEmailsRequest):
            return self._dispatch_list_emails(tool_req, session, trace)
        if isinstance(tool_req, ReadEmailRequest):
            return self._dispatch_read_email(tool_req, session, trace)
        if isinstance(tool_req, SummarizeEmailRequest):
            return self._dispatch_summarize_email(tool_req, session, trace)
        if isinstance(tool_req, DraftEmailRequest):
            return self._dispatch_draft_email(tool_req, session, trace, user_message)
        if isinstance(tool_req, TrashEmailRequest):
            if decision.require_confirmation:
                return self._prepare_trash_confirmation(tool_req, session, trace, decision)
            return self._dispatch_trash_email(tool_req, session, trace)
        if isinstance(tool_req, SendEmailRequest):
            # Always requires human confirmation — never dispatched directly.
            return self._prepare_send_confirmation(tool_req, session, trace, decision)
        return ToolResult(
            tool=str(getattr(tool_req, "action", "")),
            success=False,
            output="Unsupported tool.",
            data={},
        )

    # ------------------------------------------------------------------
    # Tool dispatch methods
    # ------------------------------------------------------------------

    def _dispatch_list_emails(
        self,
        req: ListEmailsRequest,
        session: SessionState,
        trace: List[TraceEvent],
    ) -> ToolResult:
        with traced(
            "gateway.list_emails",
            attributes={"app.mode": "patched", "tool.name": "LIST_EMAILS"},
        ):
            a = req.args
            query = build_gmail_query(
                raw=a.raw_query,
                from_email=a.from_email,
                to_email=a.to_email,
                subject=a.subject,
                newer_than_days=a.newer_than_days,
                label=a.label,
            )
            items = self.gmail.list_messages(query=query, max_results=a.max_results)

            ascending = getattr(a, "ascending", False)
            if ascending and items:
                items = sorted(items, key=lambda e: (e.date is None, e.date))

            session.last_email_list = items
            self._emit(
                trace,
                "gmail_list_messages",
                {"count": len(items), "query": query, "max_results": a.max_results, "ascending": ascending},
            )
            return ToolResult(
                tool="LIST_EMAILS",
                success=True,
                output=format_email_list(items),
                data={"count": len(items), "query": query, "max_results": a.max_results, "ascending": ascending},
            )

    def _dispatch_read_email(
        self,
        req: ReadEmailRequest,
        session: SessionState,
        trace: List[TraceEvent],
    ) -> ToolResult:
        with traced(
            "gateway.read_email",
            attributes={
                "app.mode": "patched",
                "tool.name": "READ_EMAIL",
                "email.number": req.args.email_number,
            },
        ):
            mid = self._resolve_email_id(session, req.args.email_number)
            if not mid:
                return ToolResult(
                    tool="READ_EMAIL",
                    success=False,
                    output=(
                        "I couldn't resolve that email number. "
                        "First run 'list my emails' then refer to email #1/#2."
                    ),
                    data={"error": "email_not_found"},
                )

            msg = self.gmail.get_message(mid)
            self._emit(trace, "gmail_get_message", {"id": msg.id, "subject": msg.subject})

            body_preview = safe_truncate(msg.body_text, 4000) or "(no plain-text body found)"
            output = (
                f"Email #{req.args.email_number}\n"
                f"Subject: {msg.subject}\n"
                f"From: {msg.from_email}\n"
                f"To: {msg.to_email}\n\n"
                f"Body (plain text preview):\n{body_preview}"
            )
            return ToolResult(
                tool="READ_EMAIL",
                success=True,
                output=output,
                data={"id": msg.id, "subject": msg.subject},
            )

    def _dispatch_summarize_email(
        self,
        req: SummarizeEmailRequest,
        session: SessionState,
        trace: List[TraceEvent],
    ) -> ToolResult:
        with traced(
            "gateway.summarize_email",
            attributes={
                "app.mode": "patched",
                "tool.name": "SUMMARIZE_EMAIL",
                "email.number": req.args.email_number,
            },
        ):
            mid = self._resolve_email_id(session, req.args.email_number)
            if not mid:
                return ToolResult(
                    tool="SUMMARIZE_EMAIL",
                    success=False,
                    output=(
                        "I couldn't resolve that email number. "
                        "First list emails, then say 'summarize email #1'."
                    ),
                    data={"error": "email_not_found"},
                )

            msg = self.gmail.get_message(mid)
            self._emit(trace, "gmail_get_message", {"id": msg.id, "subject": msg.subject})

            # Layer 3a — sanitize TOOL_CALL syntax from email body before summarization.
            sanitized_body, match_count = self._sanitize_email_body(msg.body_text or "")
            sanitized_html, html_match_count = self._sanitize_email_body(msg.body_html or "")
            total_matches = match_count + html_match_count
            self._emit(
                trace,
                "sanitize_applied",
                {
                    "match_count": total_matches,
                    "note": (
                        "TOOL_CALL/ARGS syntax stripped from email body before summarization."
                        if total_matches > 0
                        else "No tool syntax found in email body."
                    ),
                },
            )

            # Pass sanitized copy to Summary Agent — do not mutate the original.
            sanitized_msg = msg.model_copy(
                update={"body_text": sanitized_body, "body_html": sanitized_html}
            )

            # A2A handoff: Management → Summary Agent
            envelope = HandoffEnvelope(
                from_agent="management",
                to_agent="summary",
                task="summarize",
                payload={"email_id": mid, "subject": msg.subject},
                request_id=_short_uuid(),
            )
            self._emit(trace, "a2a_handoff", asdict(envelope))

            summary = self.summary_agent.summarize(sanitized_msg)
            self._emit(trace, "summary_agent_structured", summary.model_dump())

            # Layer 3b — canary check on summary output.
            summary_text = summary.summary or ""
            self._check_canary(summary_text, trace)

            # A2A response: Summary Agent → Management
            a2a_resp = HandoffResponse(
                from_agent="summary",
                to_agent="management",
                request_id=envelope.request_id,
                result=summary.model_dump(),
                provenance="email_content",
            )
            self._emit(trace, "a2a_response", asdict(a2a_resp))

            # Build user-facing output.
            extra = ""
            if summary.suspicious:
                extra = (
                    "\n\n⚠️  Security note: This email appears to contain instructions that may be "
                    "attempting prompt injection. I treated the content as untrusted and did not "
                    "execute any actions. "
                    f"Signals: {', '.join(summary.prompt_injection_signals) if summary.prompt_injection_signals else '(none)'}"
                )

            output = (
                f"Summary for Email #{req.args.email_number} ({msg.subject}):\n\n"
                f"{summary.summary}\n"
            )
            if summary.key_points:
                output += "\nKey points:\n" + "\n".join(f"- {p}" for p in summary.key_points)
            if summary.action_items:
                output += "\n\nAction items (for you):\n" + "\n".join(
                    f"- {a}" for a in summary.action_items
                )
            output += extra

            return ToolResult(
                tool="SUMMARIZE_EMAIL",
                success=True,
                output=output,
                data=asdict(a2a_resp),
                provenance="email_content",   # mark: downstream provenance guard will check this
            )

    def _dispatch_draft_email(
        self,
        req: DraftEmailRequest,
        session: SessionState,
        trace: List[TraceEvent],
        user_message: str,
    ) -> ToolResult:
        with traced(
            "gateway.draft_email",
            attributes={"app.mode": "patched", "tool.name": "DRAFT_EMAIL"},
        ):
            a = req.args
            to_email = (a.to_email or "").strip()
            subject = (a.subject or "").strip() or "(no subject)"
            body = (a.body or "").strip()

            if a.reply_to_email_number:
                mid = self._resolve_email_id(session, a.reply_to_email_number)
                if not mid:
                    return ToolResult(
                        tool="DRAFT_EMAIL",
                        success=False,
                        output="Couldn't resolve reply_to_email_number. List emails first.",
                        data={"error": "email_not_found"},
                    )
                msg = self.gmail.get_message(mid)
                self._emit(
                    trace,
                    "gmail_get_message_for_reply",
                    {"id": msg.id, "subject": msg.subject},
                )

                # A2A handoff: Management → Composition Agent
                envelope = HandoffEnvelope(
                    from_agent="management",
                    to_agent="composition",
                    task="draft_reply",
                    payload={"email_id": mid, "user_instruction": user_message},
                    request_id=_short_uuid(),
                )
                self._emit(trace, "a2a_handoff", asdict(envelope))

                draft_obj = self.composition_agent.draft_reply(
                    msg,
                    user_instruction=user_message,
                    to_email=to_email or None,
                )
                self._emit(trace, "composition_agent_structured", draft_obj.model_dump())

                # A2A response: Composition Agent → Management
                a2a_resp = HandoffResponse(
                    from_agent="composition",
                    to_agent="management",
                    request_id=envelope.request_id,
                    result=draft_obj.model_dump(),
                    provenance="system",
                )
                self._emit(trace, "a2a_response", asdict(a2a_resp))

                to_email = to_email or draft_obj.to_email
                subject = subject if subject != "(no subject)" else (
                    draft_obj.subject or f"Re: {msg.subject}"
                )
                body = body or draft_obj.body

            if not to_email:
                return ToolResult(
                    tool="DRAFT_EMAIL",
                    success=False,
                    output="I need a recipient. Try: 'Draft an email to alice@example.com about ...'",
                    data={"error": "missing_recipient"},
                )

            gmail_draft = self.gmail.create_draft(to_email=to_email, subject=subject, body=body)
            self._emit(
                trace,
                "gmail_create_draft",
                {"draft_id": gmail_draft.id, "to": to_email, "subject": subject},
            )

            pa = self.hitl.create_pending(
                session=session,
                kind="send_draft",
                summary=f"About to send draft to {to_email} (subject: {subject}). Confirm to send.",
                payload={"draft_id": gmail_draft.id},
            )

            output = (
                f"Created a draft to {to_email}.\n"
                f"Subject: {subject}\n\n"
                f"Body:\n{safe_truncate(body, 3000)}\n\n"
                f"Click Confirm or type: /confirm {pa.id} to send it.\n"
                f"If you only wanted a draft, ignore this prompt."
            )
            return ToolResult(
                tool="DRAFT_EMAIL",
                success=True,
                output=output,
                data={"draft_id": gmail_draft.id, "to": to_email, "subject": subject},
                require_confirmation=True,
                pending_action_id=pa.id,
                pending_action_summary=pa.summary,
            )

    def _dispatch_trash_email(
        self,
        req: TrashEmailRequest,
        session: SessionState,
        trace: List[TraceEvent],
    ) -> ToolResult:
        with traced(
            "gateway.trash_email",
            attributes={
                "app.mode": "patched",
                "tool.name": "TRASH_EMAIL",
                "email.number": req.args.email_number,
            },
        ):
            mid = self._resolve_email_id(session, req.args.email_number)
            if not mid:
                return ToolResult(
                    tool="TRASH_EMAIL",
                    success=False,
                    output="Could not resolve email number for trash.",
                    data={"error": "email_not_found"},
                )
            self.gmail.trash_message(mid)
            self._emit(trace, "gmail_trash_message", {"id": mid, "email_number": req.args.email_number})
            return ToolResult(
                tool="TRASH_EMAIL",
                success=True,
                output=f"Moved email #{req.args.email_number} to Trash.",
                data={"id": mid, "email_number": req.args.email_number},
            )

    def _prepare_trash_confirmation(
        self,
        req: TrashEmailRequest,
        session: SessionState,
        trace: List[TraceEvent],
        decision: Any,
    ) -> ToolResult:
        with traced(
            "gateway.hitl_prepare_trash",
            attributes={"app.mode": "patched", "tool.name": "TRASH_EMAIL", "security.require_confirmation": True},
        ):
            n = req.args.email_number
            mid = self._resolve_email_id(session, n)
            if not mid:
                return ToolResult(
                    tool="TRASH_EMAIL",
                    success=False,
                    output="Could not resolve email number for trash.",
                    data={"error": "email_not_found"},
                )

            subj = "(unknown subject)"
            frm = "(unknown sender)"
            try:
                idx = n - 1
                if 0 <= idx < len(session.last_email_list):
                    it = session.last_email_list[idx]
                    subj = (it.subject or subj).strip()
                    frm = (it.from_email or frm).strip()
            except Exception:
                pass

            pa = self.hitl.create_pending(
                session=session,
                kind="trash_message",
                summary=f"About to move email #{n} to Trash (subject: {subj}). Confirm to proceed.",
                payload={"message_id": mid, "email_number": n, "subject": subj},
            )
            self._emit(
                trace,
                "hitl_prepare_trash",
                {"pending_action_id": pa.id, "message_id": mid, "email_number": n, "subject": subj},
            )

            output = (
                "I will NOT move an email to Trash without confirmation.\n\n"
                f"Email #{n}: {subj}\n"
                f"From: {frm}\n\n"
                f"Click Confirm or type: /confirm {pa.id}\n"
                f"(Gate: {decision.reason})"
            )
            return ToolResult(
                tool="TRASH_EMAIL",
                success=True,
                output=output,
                data={"pending_action_id": pa.id, "email_number": n},
                require_confirmation=True,
                pending_action_id=pa.id,
                pending_action_summary=pa.summary,
            )

    def _prepare_send_confirmation(
        self,
        req: SendEmailRequest,
        session: SessionState,
        trace: List[TraceEvent],
        decision: Any,
    ) -> ToolResult:
        with traced(
            "gateway.hitl_prepare_send",
            attributes={"app.mode": "patched", "tool.name": "SEND_EMAIL", "security.require_confirmation": True},
        ):
            a = req.args
            draft = self.gmail.create_draft(to_email=a.to_email, subject=a.subject, body=a.body)
            self._emit(
                trace,
                "gmail_create_draft_for_send",
                {"draft_id": draft.id, "to": a.to_email, "subject": a.subject},
            )

            pa = self.hitl.create_pending(
                session=session,
                kind="send_draft",
                summary=f"About to send email to {a.to_email} (subject: {a.subject}). Confirm to send.",
                payload={"draft_id": draft.id},
            )

            output = (
                f"I prepared an email, but I will NOT send it without confirmation.\n\n"
                f"To: {a.to_email}\n"
                f"Subject: {a.subject}\n\n"
                f"Body:\n{safe_truncate(a.body, 2500)}\n\n"
                f"Click Confirm or type: /confirm {pa.id}\n"
                f"(Gate: {decision.reason})"
            )
            return ToolResult(
                tool="SEND_EMAIL",
                success=True,
                output=output,
                data={"draft_id": draft.id, "to": a.to_email, "subject": a.subject},
                require_confirmation=True,
                pending_action_id=pa.id,
                pending_action_summary=pa.summary,
            )
