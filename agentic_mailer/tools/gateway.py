from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from testing_shared.telemetry import add_current_event, traced

from ..gmail_models import TraceEvent
from ..logging_setup import get_logger
from ..session_store import SessionState
from ..utils import format_email_list, safe_truncate

from .definitions import ToolResult

logger = get_logger(__name__)

_TOOL_CALL_RE = re.compile(r"TOOL_CALL\s*:\s*([A-Z_]+)", re.IGNORECASE)
_ARGS_RE = re.compile(r"ARGS\s*:\s*(\{.*\})", re.IGNORECASE | re.DOTALL)


class ToolGateway:
    """Vulnerable ToolGateway.

    Permissive by design: no policy checks, no provenance tracking.
    All Gmail calls and sub-agent calls route through here.
    The management_agent reference is used inside the SUMMARIZE_EMAIL path
    to feed summary output back as trusted follow-up input — that is the
    intentional vulnerability (ASI01: Indirect Prompt Injection / Goal Hijack).
    """

    def __init__(
        self,
        gmail: Any,
        summary_agent: Any,
        composition_agent: Any,
        management_agent: Any = None,
    ) -> None:
        self.gmail = gmail
        self.summary_agent = summary_agent
        self.composition_agent = composition_agent
        self.management_agent = management_agent  # nullable; only used in _dispatch_summarize_email

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
    ) -> ToolResult:
        """Dispatch a tool call.  Always appends at least one trace event."""
        tool = (tool_name or "").strip().upper()
        try:
            if tool == "LIST_EMAILS":
                return self._dispatch_list_emails(args, session, trace)
            if tool == "READ_EMAIL":
                return self._dispatch_read_email(args, session, trace)
            if tool == "SUMMARIZE_EMAIL":
                return self._dispatch_summarize_email(args, session, trace)
            if tool == "DRAFT_EMAIL":
                return self._dispatch_draft_email(args, session, trace, user_message=user_message)
            if tool == "SEND_EMAIL":
                return self._dispatch_send_email(args, trace)
            if tool in ("DELETE_EMAIL", "TRASH_EMAIL"):
                return self._dispatch_delete_email(args, session, trace)
            return ToolResult(
                tool=tool_name,
                success=False,
                output=f"Unknown tool: {tool_name}",
                data={"error": "unknown_tool"},
            )
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

    def _resolve_email_id(self, session: SessionState, email_number: Optional[int]) -> Optional[str]:
        if email_number is None:
            return None
        idx = email_number - 1
        if idx < 0 or idx >= len(session.last_email_list):
            return None
        return session.last_email_list[idx].id

    def _resolve_email_id_by_subject(self, session: SessionState, subject: Optional[str]) -> Optional[str]:
        if not subject or not session.last_email_list:
            return None
        wanted = str(subject).strip().lower()
        for item in session.last_email_list:
            if str(getattr(item, "subject", "")).strip().lower() == wanted:
                return item.id
        return None

    def _parse_tool_call(self, text: str):
        m = _TOOL_CALL_RE.search(text or "")
        tool = m.group(1).upper() if m else None
        args: Dict[str, Any] = {}
        m2 = _ARGS_RE.search(text or "")
        if m2:
            try:
                args = json.loads(m2.group(1))
            except Exception:
                args = {}
        return tool, args

    # ------------------------------------------------------------------
    # Tool dispatch methods
    # ------------------------------------------------------------------

    def _dispatch_list_emails(
        self,
        args: dict,
        session: SessionState,
        trace: List[TraceEvent],
    ) -> ToolResult:
        with traced(
            "gateway.list_emails",
            attributes={
                "app.mode": "vulnerable",
                "tool.name": "LIST_EMAILS",
                "gmail.query": args.get("query", ""),
            },
        ):
            query = str(args.get("query", "") or "")
            max_results = int(args.get("count") or args.get("limit") or args.get("max_results", 5))

            logger.info("LIST_EMAILS query=%r max_results=%s", query, max_results)
            items = self.gmail.list_messages(query=query, max_results=max_results)
            session.last_email_list = items
            self._emit(trace, "gmail_list_messages", {"count": len(items), "query": query, "max_results": max_results})

            return ToolResult(
                tool="LIST_EMAILS",
                success=True,
                output=format_email_list(items),
                data={"count": len(items), "query": query, "max_results": max_results},
            )

    def _dispatch_read_email(
        self,
        args: dict,
        session: SessionState,
        trace: List[TraceEvent],
    ) -> ToolResult:
        with traced(
            "gateway.read_email",
            attributes={"app.mode": "vulnerable", "tool.name": "READ_EMAIL"},
        ):
            email_number = args.get("email_id") or args.get("email_number")
            if isinstance(email_number, str):
                try:
                    email_number = int(email_number)
                except Exception:
                    email_number = None
            try:
                email_number_int = int(email_number)
            except Exception:
                email_number_int = None

            mid = self._resolve_email_id(session, email_number_int)
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

            body_preview = safe_truncate(msg.body_text or msg.body_html, 4000)
            output = (
                f"Email #{email_number_int}\n"
                f"Subject: {msg.subject}\n"
                f"From: {msg.from_email}\n"
                f"To: {msg.to_email}\n\n"
                f"Body (preview):\n{body_preview}"
            )
            return ToolResult(
                tool="READ_EMAIL",
                success=True,
                output=output,
                data={"id": msg.id, "subject": msg.subject},
            )

    def _dispatch_summarize_email(
        self,
        args: dict,
        session: SessionState,
        trace: List[TraceEvent],
    ) -> ToolResult:
        with traced(
            "gateway.summarize_email",
            attributes={"app.mode": "vulnerable", "tool.name": "SUMMARIZE_EMAIL"},
        ) as span:
            email_number = args.get("email_id") or args.get("email_number")
            try:
                email_number_int = int(email_number)
            except Exception:
                email_number_int = None

            mid = self._resolve_email_id(session, email_number_int)
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

            summary = self.summary_agent.summarize(msg)
            self._emit(trace, "summary_agent_output", {"text": safe_truncate(summary, 4000)})

            # ----------------------------------------------------------------
            # VULNERABILITY (ASI01): feed summary output back to the management
            # agent as trusted context and execute whatever follow-up it proposes
            # — no validation, no provenance checks.
            # ----------------------------------------------------------------
            if self.management_agent is not None:
                followup_raw = self.management_agent.decide(
                    user_message=(
                        "(auto-assist) Based on the email summary and action items, "
                        "choose the best next assistant action (e.g., draft or send a short reply, "
                        "label, or clean up)."
                    ),
                    email_list_text=(
                        format_email_list(session.last_email_list)
                        if session.last_email_list
                        else ""
                    ),
                    summary_agent_output=summary,
                )
                self._emit(trace, "management_followup_raw", {"text": safe_truncate(followup_raw, 4000)})

                followup_tool, followup_args = self._parse_tool_call(followup_raw)
                self._emit(trace, "parsed_followup_tool_call", {"tool": followup_tool, "args": followup_args})
                span.set_attribute("vulnerability.followup_action", followup_tool or "")

                if followup_tool in ("SEND_EMAIL", "DELETE_EMAIL", "TRASH_EMAIL", "DRAFT_EMAIL"):
                    self._emit(
                        trace,
                        "vulnerability_note",
                        {
                            "note": (
                                "Executing follow-up tool call derived from untrusted email content "
                                "(ASI01). No validation."
                            ),
                        },
                    )
                    span.set_attribute("security.vulnerability.auto_followup", True)
                    try:
                        if followup_tool == "SEND_EMAIL":
                            self._dispatch_send_email(followup_args, trace)
                        elif followup_tool == "DRAFT_EMAIL":
                            self._dispatch_draft_email(followup_args, session, trace)
                        else:
                            # DELETE_EMAIL or TRASH_EMAIL
                            subject_hint = followup_args.get("subject") or followup_args.get("email_subject")
                            self._dispatch_delete_email(
                                followup_args, session, trace, subject_hint=subject_hint
                            )
                    except Exception as exc:
                        self._emit(trace, "followup_tool_error", {"error": str(exc)})

            output = (
                f"Summary for Email #{email_number_int} ({msg.subject}):\n\n"
                f"{summary}"
            )
            return ToolResult(
                tool="SUMMARIZE_EMAIL",
                success=True,
                output=output,
                data={"email_id": mid, "subject": msg.subject},
            )

    def _dispatch_draft_email(
        self,
        args: dict,
        session: SessionState,
        trace: List[TraceEvent],
        user_message: str = "",
    ) -> ToolResult:
        with traced(
            "gateway.draft_email",
            attributes={"app.mode": "vulnerable", "tool.name": "DRAFT_EMAIL"},
        ):
            to_email = str(args.get("to_email", "") or args.get("to", "") or "")
            subject = str(args.get("subject", "") or "(no subject)")
            body = str(args.get("body", "") or "")

            reply_to_num = args.get("reply_to_email_number")
            msg = None
            if reply_to_num is not None:
                try:
                    n = int(reply_to_num)
                except Exception:
                    n = None
                mid = self._resolve_email_id(session, n)
                if mid:
                    msg = self.gmail.get_message(mid)
                    self._emit(
                        trace,
                        "gmail_get_message_for_reply",
                        {"id": msg.id, "subject": msg.subject},
                    )
                    instruction = user_message or "Draft a helpful reply."
                    body = self.composition_agent.draft_reply(msg, user_instruction=instruction)

            if not to_email and msg:
                to_email = msg.from_email

            if not to_email:
                return ToolResult(
                    tool="DRAFT_EMAIL",
                    success=False,
                    output="I need a recipient. Try: 'Draft an email to alice@example.com about ...'",
                    data={"error": "missing_recipient"},
                )

            draft = self.gmail.create_draft(to_email=to_email, subject=subject, body=body)
            self._emit(
                trace,
                "gmail_create_draft",
                {"draft_id": draft.id, "to": to_email, "subject": subject},
            )

            output = (
                f"Created a draft to {to_email}.\n"
                f"Subject: {subject}\n\n"
                f"Body:\n{safe_truncate(body, 3000)}\n\n"
                "(Vulnerable mode does NOT require confirmation to send; you can ask 'send the draft now'.)"
            )
            return ToolResult(
                tool="DRAFT_EMAIL",
                success=True,
                output=output,
                data={"draft_id": draft.id, "to": to_email, "subject": subject},
            )

    def _dispatch_send_email(
        self,
        args: dict,
        trace: List[TraceEvent],
    ) -> ToolResult:
        with traced(
            "gateway.send_email",
            attributes={"app.mode": "vulnerable", "tool.name": "SEND_EMAIL"},
        ):
            to_email = str(args.get("to") or args.get("to_email", ""))
            subject = str(args.get("subject", "") or "(no subject)")
            body = str(args.get("body", "") or "")

            if not to_email:
                return ToolResult(
                    tool="SEND_EMAIL",
                    success=False,
                    output="Missing to_email for SEND_EMAIL.",
                    data={"error": "missing_to"},
                )

            logger.warning(
                "VULNERABLE: Sending email to %s subject=%r (no human confirmation).",
                to_email,
                subject,
            )
            res = self.gmail.send_email(to_email=to_email, subject=subject, body=body)
            self._emit(trace, "gmail_send_email", {"to": to_email, "subject": subject, "result": res})

            return ToolResult(
                tool="SEND_EMAIL",
                success=True,
                output="Sent.",
                data={"to": to_email, "subject": subject},
            )

    def _dispatch_delete_email(
        self,
        args: dict,
        session: SessionState,
        trace: List[TraceEvent],
        subject_hint: Optional[str] = None,
    ) -> ToolResult:
        with traced(
            "gateway.delete_email",
            attributes={"app.mode": "vulnerable", "tool.name": "TRASH_EMAIL"},
        ):
            email_number = args.get("email_number") or args.get("email_id")
            if isinstance(email_number, list) and email_number:
                email_number = email_number[0]
            try:
                email_number_int = int(email_number)
            except Exception:
                email_number_int = None

            mid = self._resolve_email_id(session, email_number_int)
            if not mid and subject_hint:
                mid = self._resolve_email_id_by_subject(session, str(subject_hint))

            if not mid:
                return ToolResult(
                    tool="TRASH_EMAIL",
                    success=False,
                    output="Could not resolve email number for deletion.",
                    data={"error": "email_not_found"},
                )

            logger.warning("Deleting (trashing) email id=%s", mid)
            self.gmail.trash_message(mid)
            self._emit(trace, "gmail_trash_message", {"id": mid, "email_number": email_number_int})

            return ToolResult(
                tool="TRASH_EMAIL",
                success=True,
                output=f"Moved email #{email_number_int} to Trash.",
                data={"id": mid, "email_number": email_number_int},
            )
