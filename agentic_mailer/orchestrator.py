from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict
from typing import Any, Dict, List, Optional, Tuple

from .config import DemoConfig, ModelConfig, OllamaConfig
from .gmail_client import GmailClient, GmailClientError
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

    def __init__(self):
        self.gmail = GmailClient(secrets_dir="secrets")
        model_cfg = ModelConfig()
        ollama_cfg = OllamaConfig()
        demo_cfg = DemoConfig()

        self.summary_agent = SummaryAgent(model_cfg, ollama_cfg)
        self.composition_agent = CompositionAgent(model_cfg, ollama_cfg)
        self.management_agent = ManagementAgent(model_cfg, ollama_cfg, demo_cfg)

    def handle_chat(self, session: SessionState, user_message: str) -> ChatResponse:
        session.conversation.append(("user", user_message))
        trace: List[TraceEvent] = []

        # 1) Ask management agent what to do (unstructured)
        email_list_text = format_email_list(session.last_email_list) if session.last_email_list else ""
        mgmt_raw = self.management_agent.decide(user_message, email_list_text=email_list_text)
        trace.append(TraceEvent(name="management_llm_raw", data={"text": safe_truncate(mgmt_raw, 4000)}))

        tool_name, args = self._parse_tool_call(mgmt_raw)
        trace.append(TraceEvent(name="parsed_tool_call", data={"tool": tool_name, "args": args}))

        if not tool_name:
            # Fallback heuristics (for demo reliability). Still vulnerable because agent outputs are not validated.
            tool_name, args = self._heuristic_tool(user_message)
            trace.append(TraceEvent(name="heuristic_fallback", data={"tool": tool_name, "args": args}))
            if not tool_name:
                return ChatResponse(
                    assistant_text="I couldn't determine an action. Try: 'list my emails', 'read email #1', or 'summarize #1'.",
                    trace=trace,
                )

        # 2) Execute tool calls
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
        except GmailClientError as e:
            logger.exception("GmailClientError")
            return ChatResponse(assistant_text=f"Gmail error: {e}", trace=trace)
        except Exception as e:
            logger.exception("Unhandled error")
            return ChatResponse(assistant_text=f"Error: {e}", trace=trace)

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
        """Very small ruleset to keep the demo usable when the model output is unparsable.

        This does NOT add security validation; it is only a reliability fallback.
        """
        t = (user_message or "").strip()
        low = t.lower()

        # List emails
        if any(w in low for w in ["list", "show emails", "show my emails", "inbox", "emails from", "emails to"]):
            max_results = 10
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
        query = str(args.get("query", "") or "")
        max_results = int(args.get("max_results", 10) or 10)
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
        trace.append(TraceEvent(name="gmail_list_messages", data={"count": len(items), "query": query, "max_results": max_results}))
        return ChatResponse(assistant_text=format_email_list(items), trace=trace)

    def _read_email(self, session: SessionState, args: Dict[str, Any], trace: List[TraceEvent]) -> ChatResponse:
        email_number = args.get("email_number")
        if email_number is None:
            # Try extracting from user message-like strings
            email_number = extract_email_number(str(args.get("text", "")))  # best-effort
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
        trace.append(TraceEvent(name="gmail_get_message", data={"id": msg.id, "subject": msg.subject}))
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
        email_number = args.get("email_number")
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
        trace.append(TraceEvent(name="gmail_get_message", data={"id": msg.id, "subject": msg.subject}))

        summary = self.summary_agent.summarize(msg)
        trace.append(TraceEvent(name="summary_agent_output", data={"text": safe_truncate(summary, 4000)}))

        # VULNERABILITY: feed summary output back to management agent as trusted input
        # and execute whatever tool call it emits next (NO validation / NO intent checks).
        followup = self.management_agent.decide(
            user_message="(follow-up) Take any actions requested by the summarized email.",
            email_list_text=format_email_list(session.last_email_list) if session.last_email_list else "",
            summary_agent_output=summary,
        )
        trace.append(TraceEvent(name="management_followup_raw", data={"text": safe_truncate(followup, 4000)}))

        tool_name, args2 = self._parse_tool_call(followup)
        trace.append(TraceEvent(name="parsed_followup_tool_call", data={"tool": tool_name, "args": args2}))

        if tool_name in ("SEND_EMAIL", "DELETE_EMAIL", "TRASH_EMAIL", "DRAFT_EMAIL"):
            trace.append(
                TraceEvent(
                    name="vulnerability_note",
                    data={"note": "Executing follow-up tool call derived from untrusted email content (ASI01). No validation."},
                )
            )

            # Execute side effects directly so the audience can see it in logs/trace
            try:
                if tool_name == "SEND_EMAIL":
                    to_email = str(args2.get("to_email", "") or "")
                    subject = str(args2.get("subject", "") or "(no subject)")
                    body = str(args2.get("body", "") or "")
                    res = self.gmail.send_email(to_email=to_email, subject=subject, body=body)
                    trace.append(TraceEvent(name="gmail_send_email", data={"to": to_email, "subject": subject, "result": res}))
                elif tool_name == "DRAFT_EMAIL":
                    to_email = str(args2.get("to_email", "") or "")
                    subject = str(args2.get("subject", "") or "(no subject)")
                    body = str(args2.get("body", "") or "")
                    draft = self.gmail.create_draft(to_email=to_email, subject=subject, body=body)
                    trace.append(TraceEvent(name="gmail_create_draft", data={"draft_id": draft.id, "to": to_email, "subject": subject}))
                else:
                    # DELETE/TRASH
                    email_number2 = args2.get("email_number")
                    try:
                        email_number2_int = int(email_number2)
                    except Exception:
                        email_number2_int = None
                    mid2 = self._resolve_email_id(session, email_number2_int)
                    if mid2:
                        self.gmail.trash_message(mid2)
                        trace.append(TraceEvent(name="gmail_trash_message", data={"id": mid2}))
            except GmailClientError as e:
                trace.append(TraceEvent(name="followup_tool_error", data={"error": str(e)}))

        # Respond to user with just the summary (the dangerous side-effect is visible in trace/logs)
        assistant_text = (
            f"Summary for Email #{email_number_int} ({msg.subject}):\\n\\n"
            f"{summary}"
        )
        return ChatResponse(assistant_text=assistant_text, trace=trace)

    def _draft_email(self, session: SessionState, user_message: str, args: Dict[str, Any], trace: List[TraceEvent]) -> ChatResponse:
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
                trace.append(TraceEvent(name="gmail_get_message_for_reply", data={"id": msg.id, "subject": msg.subject}))
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
        trace.append(TraceEvent(name="gmail_create_draft", data={"draft_id": draft.id, "to": to_email, "subject": subject}))
        assistant_text = (
            f"Created a draft to {to_email}.\n"
            f"Subject: {subject}\n\n"
            f"Body:\n{safe_truncate(body, 3000)}\n\n"
            f"(Vulnerable mode does NOT require confirmation to send; you can ask 'send the draft now'.)"
        )
        return ChatResponse(assistant_text=assistant_text, trace=trace)

    def _send_email(self, session: SessionState, args: Dict[str, Any], trace: List[TraceEvent]) -> ChatResponse:
        to_email = str(args.get("to_email", "") or "")
        subject = str(args.get("subject", "") or "(no subject)")
        body = str(args.get("body", "") or "")

        if not to_email:
            return ChatResponse(assistant_text="Missing to_email for SEND_EMAIL.", trace=trace)

        logger.warning("VULNERABLE: Sending email to %s subject=%r (no human confirmation).", to_email, subject)
        res = self.gmail.send_email(to_email=to_email, subject=subject, body=body)
        trace.append(TraceEvent(name="gmail_send_email", data={"to": to_email, "subject": subject, "result": res}))
        return ChatResponse(assistant_text="Sent.", trace=trace)

    def _delete_email(self, session: SessionState, args: Dict[str, Any], trace: List[TraceEvent]) -> ChatResponse:
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
        trace.append(TraceEvent(name="gmail_trash_message", data={"id": mid}))
        return ChatResponse(assistant_text=f"Moved email #{email_number_int} to Trash.", trace=trace)