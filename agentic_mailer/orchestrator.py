from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from testinguy_shared.telemetry import add_current_event, instrument_gmail_client, traced

from .config import DemoConfig, ModelConfig, OllamaConfig
try:
    from .gmail_client import GmailClient, GmailClientError
except Exception:  # pragma: no cover - allows fixture-based evals without Google deps
    GmailClient = None  # type: ignore[assignment]

    class GmailClientError(RuntimeError):
        pass

from .gmail_models import ChatResponse, TraceEvent
from .logging_setup import get_logger
from .session_store import SessionState
from .utils import build_gmail_query, extract_email_number, format_email_list, safe_truncate

from .agents.management_agent import ManagementAgent
from .agents.summary_agent import SummaryAgent
from .agents.composition_agent import CompositionAgent

logger = get_logger(__name__)

_TOOL_CALL_RE = re.compile(r"TOOL_CALL\s*:\s*([A-Z_]+)", re.IGNORECASE)
_ARGS_RE = re.compile(r"ARGS\s*:\s*(\{.*\})", re.IGNORECASE | re.DOTALL)


class Orchestrator:
    """Vulnerable multi-agent orchestrator."""

    def __init__(self, gmail_client: Optional[Any] = None):
        self.mode = "vulnerable"
        base_gmail_client = gmail_client
        if base_gmail_client is None:
            if GmailClient is None:
                raise RuntimeError("GmailClient dependencies are unavailable; install the Google Gmail dependencies or inject a gmail_client.")
            base_gmail_client = GmailClient(secrets_dir="secrets")
        self.gmail = instrument_gmail_client(base_gmail_client, mode=self.mode)
        model_cfg = ModelConfig()
        ollama_cfg = OllamaConfig()
        demo_cfg = DemoConfig()

        self.summary_agent = SummaryAgent(model_cfg, ollama_cfg)
        self.composition_agent = CompositionAgent(model_cfg, ollama_cfg)
        self.management_agent = ManagementAgent(model_cfg, ollama_cfg, demo_cfg)

    def _append_trace(self, trace: List[TraceEvent], name: str, data: Optional[Dict[str, Any]] = None) -> None:
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
            },
        ) as span:
            session.conversation.append(("user", user_message))
            trace: List[TraceEvent] = []

            # 1) Ask management agent what to do (unstructured)
            email_list_text = format_email_list(session.last_email_list) if session.last_email_list else ""
            mgmt_raw = self.management_agent.decide(user_message, email_list_text=email_list_text)
            self._append_trace(trace, "management_llm_raw", {"text": safe_truncate(mgmt_raw, 4000)})

            tool_name, args = self._parse_tool_call(mgmt_raw)
            self._append_trace(trace, "parsed_tool_call", {"tool": tool_name, "args": args})
            span.set_attribute("tool.request.action", tool_name or "")

            if not tool_name:
                # Fallback heuristics (for demo reliability). Still vulnerable because agent outputs are not validated.
                tool_name, args = self._heuristic_tool(user_message)
                self._append_trace(trace, "heuristic_fallback", {"tool": tool_name, "args": args})
                span.set_attribute("tool.request.heuristic_fallback", True)
                if not tool_name:
                    return ChatResponse(
                        assistant_text="I couldn't determine an action. Try: 'list my emails', 'read email #1', or 'summarize #1'.",
                        trace=trace,
                    )

            try:
                if tool_name == "LIST_EMAILS":
                    return self._list_emails(session, args, trace)
                if tool_name == "READ_EMAIL":
                    return self._read_email(session, args, trace)
                if tool_name == "SUMMARIZE_EMAIL":
                    return self._summarize_email(session, user_message, args, trace)
                if tool_name == "DRAFT_EMAIL":
                    return self._draft_email(session, user_message, args, trace)
                if tool_name == "SEND_EMAIL":
                    return self._send_email(session, args, trace)
                if tool_name in ("DELETE_EMAIL", "TRASH_EMAIL"):
                    return self._delete_email(session, args, trace)

                return ChatResponse(
                    assistant_text=f"Unsupported action: {tool_name}",
                    trace=trace,
                )
            except GmailClientError as exc:
                logger.exception("GmailClientError")
                span.set_attribute("error.kind", "gmail")
                return ChatResponse(assistant_text=f"Gmail error: {exc}", trace=trace)
            except Exception as exc:
                logger.exception("Unhandled error")
                span.set_attribute("error.kind", type(exc).__name__)
                return ChatResponse(assistant_text=f"Error: {exc}", trace=trace)

    def _parse_tool_call(self, text: str) -> Tuple[Optional[str], Dict[str, Any]]:
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

    def _heuristic_tool(self, user_message: str) -> Tuple[Optional[str], Dict[str, Any]]:
        t = (user_message or "").strip()
        low = t.lower()

        # List emails
        if any(w in low for w in ["list", "show emails", "show my emails", "inbox", "emails from", "emails to"]):
            max_results = 5
            m = re.search(r"(?:last|newest|latest|top)\s+(\d+)", low)
            if m:
                try:
                    max_results = max(1, min(50, int(m.group(1))))
                except Exception:
                    pass

            from_email = None
            to_email = None
            subject = None
            newer_than_days = None
            label = None

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

            query = build_gmail_query(
                from_email=from_email,
                to_email=to_email,
                subject=subject,
                newer_than_days=newer_than_days,
                label=label,
            )
            return "LIST_EMAILS", {"query": query, "max_results": max_results}

        # Read email #n
        if "read" in low:
            n = extract_email_number(t)
            if n:
                return "READ_EMAIL", {"email_number": n}

        # Summarize email #n
        if "summar" in low:
            n = extract_email_number(t)
            if n:
                return "SUMMARIZE_EMAIL", {"email_number": n}

        # Delete/trash email #n
        if any(w in low for w in ["trash", "delete", "remove"]):
            n = extract_email_number(t)
            if n:
                return "DELETE_EMAIL", {"email_number": n}

        # Draft
        if "draft" in low or "reply" in low:
            n = extract_email_number(t)
            if n:
                return "DRAFT_EMAIL", {"reply_to_email_number": n}

        return None, {}

    def _resolve_email_id(self, session: SessionState, email_number: Optional[int]) -> Optional[str]:
        if email_number is None:
            return None
        idx = email_number - 1
        if idx < 0 or idx >= len(session.last_email_list):
            return None
        return session.last_email_list[idx].id

    def _list_emails(self, session: SessionState, args: Dict[str, Any], trace: List[TraceEvent]) -> ChatResponse:
        with traced(
            "orchestrator.list_emails",
            attributes={
                "app.mode": self.mode,
                "tool.name": "LIST_EMAILS",
                "gmail.query": args.get("query", ""),
            },
        ):
            query = str(args.get("query", "") or "")
            max_results = int(args.get("count") or args.get("limit") or args.get("max_results", 5))
            label = args.get("label")
            label_ids = None

            # Allow a simple label shortcut in vulnerable mode
            if isinstance(label, str) and label:
                # Gmail API list() expects label IDs, not names; we won't resolve here for simplicity.
                # Users can just use raw query label:inbox, label:sent, etc.
                pass

            logger.info("LIST_EMAILS query=%r max_results=%s", query, max_results)
            items = self.gmail.list_messages(query=query, max_results=max_results, label_ids=label_ids)
            session.last_email_list = items
            self._append_trace(trace, "gmail_list_messages", {"count": len(items), "query": query, "max_results": max_results})
            return ChatResponse(assistant_text=format_email_list(items), trace=trace)

    def _read_email(self, session: SessionState, args: Dict[str, Any], trace: List[TraceEvent]) -> ChatResponse:
        with traced(
            "orchestrator.read_email",
            attributes={
                "app.mode": self.mode,
                "tool.name": "READ_EMAIL",
            },
        ):
            email_number = args.get("email_id")
            if email_number is None:
                # Try extracting from user message-like strings
                email_number = args.get("email_number")
                if isinstance(email_number, str):
                    parsed_email_number = extract_email_number(email_number)
                    if parsed_email_number is not None:
                        email_number = parsed_email_number
            try:
                email_number_int = int(email_number)
            except Exception:
                email_number_int = None

            mid = self._resolve_email_id(session, email_number_int)
            if not mid:
                return ChatResponse(
                    assistant_text="I couldn't resolve that email number. First run 'list my emails' then refer to email #1/#2.",
                    trace=trace,
                )

            msg = self.gmail.get_message(mid)
            self._append_trace(trace, "gmail_get_message", {"id": msg.id, "subject": msg.subject})
            body_preview = safe_truncate(msg.body_text or msg.body_html, 4000)

            assistant_text = (
                f"Email #{email_number_int}\n"
                f"Subject: {msg.subject}\n"
                f"From: {msg.from_email}\n"
                f"To: {msg.to_email}\n\n"
                f"Body (preview):\n{body_preview}"
            )
            return ChatResponse(assistant_text=assistant_text, trace=trace)

    def _summarize_email(self, session: SessionState, user_message: str, args: Dict[str, Any], trace: List[TraceEvent]) -> ChatResponse:
        with traced(
            "orchestrator.summarize_email",
            attributes={
                "app.mode": self.mode,
                "tool.name": "SUMMARIZE_EMAIL",
            },
        ) as span:
            email_number = args.get("email_id") or args.get("email_number")
            if email_number is None:
                email_number = extract_email_number(user_message)
            try:
                email_number_int = int(email_number)
            except Exception:
                email_number_int = None

            mid = self._resolve_email_id(session, email_number_int)
            if not mid:
                return ChatResponse(
                    assistant_text="I couldn't resolve that email number. First list emails, then say 'summarize email #1'.",
                    trace=trace,
                )

            msg = self.gmail.get_message(mid)
            self._append_trace(trace, "gmail_get_message", {"id": msg.id, "subject": msg.subject})

            summary = self.summary_agent.summarize(msg)
            self._append_trace(trace, "summary_agent_output", {"text": safe_truncate(summary, 4000)})

            # VULNERABILITY: feed summary output back to management agent as trusted input
            # and execute whatever tool call it emits next (NO validation / NO intent checks).
            followup = self.management_agent.decide(
                user_message="(auto-assist) Based on the email summary and action items, choose the best next assistant action (e.g., draft or send a short reply, label, or clean up).",
                email_list_text=format_email_list(session.last_email_list) if session.last_email_list else "",
                summary_agent_output=summary,
            )
            self._append_trace(trace, "management_followup_raw", {"text": safe_truncate(followup, 4000)})

            tool_name, args2 = self._parse_tool_call(followup)
            self._append_trace(trace, "parsed_followup_tool_call", {"tool": tool_name, "args": args2})
            span.set_attribute("vulnerability.followup_action", tool_name or "")

            if tool_name in ("SEND_EMAIL", "DELETE_EMAIL", "TRASH_EMAIL", "DRAFT_EMAIL"):
                self._append_trace(
                    trace,
                    "vulnerability_note",
                    {"note": "Executing follow-up tool call derived from untrusted email content (ASI01). No validation."},
                )
                span.set_attribute("security.vulnerability.auto_followup", True)

                try:
                    if tool_name == "SEND_EMAIL":
                        to_email = str(args2.get("to", "") or args2.get("to_email", "") or "")
                        subject = str(args2.get("subject", "") or "(no subject)")
                        body = str(args2.get("body", "") or "")
                        res = self.gmail.send_email(to_email=to_email, subject=subject, body=body)
                        self._append_trace(trace, "gmail_send_email", {"to": to_email, "subject": subject, "result": res})
                    elif tool_name == "DRAFT_EMAIL":
                        to_email = str(args2.get("to", "") or args2.get("to_email", "") or "")
                        subject = str(args2.get("subject", "") or "(no subject)")
                        body = str(args2.get("body", "") or "")
                        draft = self.gmail.create_draft(to_email=to_email, subject=subject, body=body)
                        self._append_trace(trace, "gmail_create_draft", {"draft_id": draft.id, "to": to_email, "subject": subject})
                    else:
                        email_number2 = args2.get("email_number") or args2.get("email_id") or (
                            args2.get("email_ids")[0]
                            if type(args2.get("email_ids")) is list and len(args2.get("email_ids")) > 0
                            else None
                        )
                        try:
                            email_number2_int = int(email_number2)
                        except Exception:
                            email_number2_int = None
                        mid2 = self._resolve_email_id(session, email_number2_int)
                        if mid2:
                            self.gmail.trash_message(mid2)
                            self._append_trace(trace, "gmail_trash_message", {"id": mid2})
                except GmailClientError as exc:
                    self._append_trace(trace, "followup_tool_error", {"error": str(exc)})

            # Respond to user with just the summary (the dangerous side-effect is visible in trace/logs)
            assistant_text = (
                f"Summary for Email #{email_number_int} ({msg.subject}):\\n\\n"
                f"{summary}"
            )
            return ChatResponse(assistant_text=assistant_text, trace=trace)

    def _draft_email(self, session: SessionState, user_message: str, args: Dict[str, Any], trace: List[TraceEvent]) -> ChatResponse:
        with traced(
            "orchestrator.draft_email",
            attributes={
                "app.mode": self.mode,
                "tool.name": "DRAFT_EMAIL",
            },
        ):
            to_email = str(args.get("to_email", "") or "")
            subject = str(args.get("subject", "") or "(no subject)")
            body = str(args.get("body", "") or "")

            # Optionally draft a reply to an email # with help of composition agent
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
                    self._append_trace(trace, "gmail_get_message_for_reply", {"id": msg.id, "subject": msg.subject})
                    body = self.composition_agent.draft_reply(msg, user_instruction=user_message)

            if not to_email and msg:
                # best-effort: reply to the sender
                to_email = msg.from_email

            if not to_email:
                return ChatResponse(
                    assistant_text="I need a recipient. Try: 'Draft an email to alice@example.com about ...'",
                    trace=trace,
                )

            draft = self.gmail.create_draft(to_email=to_email, subject=subject, body=body)
            self._append_trace(trace, "gmail_create_draft", {"draft_id": draft.id, "to": to_email, "subject": subject})
            assistant_text = (
                f"Created a draft to {to_email}.\n"
                f"Subject: {subject}\n\n"
                f"Body:\n{safe_truncate(body, 3000)}\n\n"
                f"(Vulnerable mode does NOT require confirmation to send; you can ask 'send the draft now'.)"
            )
            return ChatResponse(assistant_text=assistant_text, trace=trace)

    def _send_email(self, session: SessionState, args: Dict[str, Any], trace: List[TraceEvent]) -> ChatResponse:
        with traced(
            "orchestrator.send_email",
            attributes={
                "app.mode": self.mode,
                "tool.name": "SEND_EMAIL",
            },
        ):
            to_email = str(args.get("to") or args.get("to_email", ""))
            subject = str(args.get("subject", "") or "(no subject)")
            body = str(args.get("body", "") or "")

            if not to_email:
                return ChatResponse(assistant_text="Missing to_email for SEND_EMAIL.", trace=trace)

            logger.warning("VULNERABLE: Sending email to %s subject=%r (no human confirmation).", to_email, subject)
            res = self.gmail.send_email(to_email=to_email, subject=subject, body=body)
            self._append_trace(trace, "gmail_send_email", {"to": to_email, "subject": subject, "result": res})
            return ChatResponse(assistant_text="Sent.", trace=trace)

    def _delete_email(self, session: SessionState, args: Dict[str, Any], trace: List[TraceEvent]) -> ChatResponse:
        with traced(
            "orchestrator.delete_email",
            attributes={
                "app.mode": self.mode,
                "tool.name": "TRASH_EMAIL",
            },
        ):
            email_number = args.get("email_number")
            try:
                email_number_int = int(email_number)
            except Exception:
                email_number_int = None

            mid = self._resolve_email_id(session, email_number_int)
            if not mid:
                return ChatResponse(assistant_text="Could not resolve email number for deletion.", trace=trace)

            logger.warning("Deleting (trashing) email id=%s", mid)
            self.gmail.trash_message(mid)
            self._append_trace(trace, "gmail_trash_message", {"id": mid})
            return ChatResponse(assistant_text=f"Moved email #{email_number_int} to Trash.", trace=trace)
