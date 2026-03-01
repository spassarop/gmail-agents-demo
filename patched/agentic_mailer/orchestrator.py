from __future__ import annotations

import re
from typing import List, Optional

from .config import ModelConfig, OllamaConfig
from .gmail_client import GmailClient, GmailClientError
from .gmail_models import ChatResponse, TraceEvent
from .logging_setup import get_logger
from .session_store import SessionState
from .utils import build_gmail_query, extract_email_number, format_email_list, safe_truncate

from .agents.management_agent import ManagementAgent
from .agents.summary_agent import SummaryAgent
from .agents.composition_agent import CompositionAgent

from .security.intent_gate import IntentGate
from .security.hitl import HITLManager
from .security.schemas import (
    DraftEmailRequest,
    ListEmailsRequest,
    ReadEmailRequest,
    SendEmailRequest,
    SummarizeEmailRequest,
    TrashEmailRequest,
    ToolRequest,
)

logger = get_logger(__name__)

_CONFIRM_RE = re.compile(r"^/confirm(?:\s+(\S+))?$", re.IGNORECASE)
_CANCEL_RE = re.compile(r"^/cancel(?:\s+(\S+))?$", re.IGNORECASE)


class Orchestrator:
    """Patched multi-agent orchestrator (Intent Gate + HITL + Structured tool invocation)."""

    def __init__(self):
        self.gmail = GmailClient(secrets_dir="secrets")
        model_cfg = ModelConfig()
        ollama_cfg = OllamaConfig()

        self.summary_agent = SummaryAgent(model_cfg, ollama_cfg)
        self.composition_agent = CompositionAgent(model_cfg, ollama_cfg)
        self.management_agent = ManagementAgent(model_cfg, ollama_cfg)

        self.intent_gate = IntentGate()
        self.hitl = HITLManager()

    def handle_chat(self, session: SessionState, user_message: str) -> ChatResponse:
        session.conversation.append(("user", user_message))
        trace: List[TraceEvent] = []

        # 0) HITL confirmation commands
        m = _CONFIRM_RE.match(user_message.strip())
        if m:
            action_id = m.group(1)
            return self._confirm(session, action_id, trace)

        m = _CANCEL_RE.match(user_message.strip())
        if m:
            action_id = m.group(1)
            return self._cancel(session, action_id, trace)

        # 1) Ask management agent for a structured tool request
        email_list_text = format_email_list(session.last_email_list) if session.last_email_list else ""
        tool_req, raw = self.management_agent.decide(user_message, email_list_text=email_list_text)
        trace.append(TraceEvent(name="management_llm_raw", data={"text": safe_truncate(raw, 4000)}))

        if tool_req is None:
            # Heuristic fallback (safe-by-default): only low-impact actions are inferred.
            tool_req = self._heuristic_request(user_message)
            trace.append(TraceEvent(name="heuristic_fallback", data={"tool": getattr(tool_req, 'action', None) if tool_req else None}))
            if tool_req is None:
                return ChatResponse(
                    assistant_text="I couldn't parse a safe tool request. Try: “List my newest 5 emails” or “Summarize email #1”.",
                    trace=trace,
                )

        trace.append(TraceEvent(name="tool_request_validated", data={"tool": getattr(tool_req, 'action', ''), "args": getattr(tool_req, 'args', None).model_dump() if hasattr(getattr(tool_req,'args',None),'model_dump') else {}}))

        # 2) Intent Gate check
        decision = self.intent_gate.evaluate(user_message, tool_req)
        trace.append(TraceEvent(name="intent_gate", data={"allow": decision.allow, "require_confirmation": decision.require_confirmation, "reason": decision.reason}))

        if not decision.allow:
            return ChatResponse(
                assistant_text=f"Blocked by Intent Gate: {decision.reason}",
                trace=trace,
            )

        # 3) Execute tool request with HITL for high-impact actions
        try:
            if isinstance(tool_req, ListEmailsRequest):
                return self._list_emails(session, tool_req, trace)

            if isinstance(tool_req, ReadEmailRequest):
                return self._read_email(session, tool_req, trace)

            if isinstance(tool_req, SummarizeEmailRequest):
                return self._summarize_email(session, tool_req, trace)

            if isinstance(tool_req, DraftEmailRequest):
                return self._draft_email(session, user_message, tool_req, trace)

            if isinstance(tool_req, TrashEmailRequest):
                if decision.require_confirmation:
                    return self._prepare_trash_with_confirmation(session, tool_req, decision.reason, trace)
                return self._trash_email(session, tool_req, trace)

            if isinstance(tool_req, SendEmailRequest):
                # HITL: always require confirmation before sending
                return self._prepare_send_with_confirmation(session, tool_req, decision.reason, trace)

            return ChatResponse(assistant_text=f"Unsupported action: {getattr(tool_req, 'action', '')}", trace=trace)

        except GmailClientError as e:
            logger.exception("GmailClientError")
            return ChatResponse(assistant_text=f"Gmail error: {e}", trace=trace)
        except Exception as e:
            logger.exception("Unhandled error")
            return ChatResponse(assistant_text=f"Error: {e}", trace=trace)

    # -------------------------
    # Tool execution helpers
    # -------------------------


    def _heuristic_request(self, user_message: str) -> Optional[ToolRequest]:
        """Safe-by-default heuristics when the management model output is unparsable.

        Only low/medium impact actions are inferred. We do NOT infer SEND_EMAIL.
        """
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

        # Read
        if "read" in low:
            n = extract_email_number(t)
            if n:
                return ReadEmailRequest(action="READ_EMAIL", args={"email_number": n})

        # Summarize
        if "summar" in low:
            n = extract_email_number(t)
            if n:
                return SummarizeEmailRequest(action="SUMMARIZE_EMAIL", args={"email_number": n})

        # Trash/delete
        if any(w in low for w in ["trash", "delete", "remove", "discard"]):
            n = extract_email_number(t)
            if n:
                return TrashEmailRequest(action="TRASH_EMAIL", args={"email_number": n})

        # Draft/reply
        if "draft" in low or "reply" in low:
            n = extract_email_number(t)
            if n:
                return DraftEmailRequest(action="DRAFT_EMAIL", args={"reply_to_email_number": n})

        return None


    def _resolve_email_id(self, session: SessionState, email_number: int) -> Optional[str]:
        idx = email_number - 1
        if idx < 0 or idx >= len(session.last_email_list):
            return None
        return session.last_email_list[idx].id

    def _list_emails(self, session: SessionState, req: ListEmailsRequest, trace: List[TraceEvent]) -> ChatResponse:
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
        session.last_email_list = items
        trace.append(TraceEvent(name="gmail_list_messages", data={"count": len(items), "query": query, "max_results": a.max_results}))
        return ChatResponse(assistant_text=format_email_list(items), trace=trace)

    def _read_email(self, session: SessionState, req: ReadEmailRequest, trace: List[TraceEvent]) -> ChatResponse:
        mid = self._resolve_email_id(session, req.args.email_number)
        if not mid:
            return ChatResponse(
                assistant_text="I couldn't resolve that email number. First run 'list my emails' then refer to email #1/#2.",
                trace=trace,
            )
        msg = self.gmail.get_message(mid)
        trace.append(TraceEvent(name="gmail_get_message", data={"id": msg.id, "subject": msg.subject}))
        body_preview = safe_truncate(msg.body_text, 4000) or "(no plain-text body found)"
        assistant_text = (
            f"Email #{req.args.email_number}\n"
            f"Subject: {msg.subject}\n"
            f"From: {msg.from_email}\n"
            f"To: {msg.to_email}\n\n"
            f"Body (plain text preview):\n{body_preview}"
        )
        return ChatResponse(assistant_text=assistant_text, trace=trace)

    def _summarize_email(self, session: SessionState, req: SummarizeEmailRequest, trace: List[TraceEvent]) -> ChatResponse:
        mid = self._resolve_email_id(session, req.args.email_number)
        if not mid:
            return ChatResponse(
                assistant_text="I couldn't resolve that email number. First list emails, then say 'summarize email #1'.",
                trace=trace,
            )
        msg = self.gmail.get_message(mid)
        trace.append(TraceEvent(name="gmail_get_message", data={"id": msg.id, "subject": msg.subject}))

        summary = self.summary_agent.summarize(msg)
        trace.append(TraceEvent(name="summary_agent_structured", data=summary.model_dump()))

        extra = ""
        if summary.suspicious:
            extra = (
                "\n\n⚠️  Security note: This email appears to contain instructions that may be attempting prompt injection. "
                "I treated the content as untrusted and did not execute any actions. "
                f"Signals: {', '.join(summary.prompt_injection_signals) if summary.prompt_injection_signals else '(none)'}"
            )

        assistant_text = (
            f"Summary for Email #{req.args.email_number} ({msg.subject}):\n\n"
            f"{summary.summary}\n"
        )
        if summary.key_points:
            assistant_text += "\nKey points:\n" + "\n".join([f"- {p}" for p in summary.key_points])
        if summary.action_items:
            assistant_text += "\n\nAction items (for you):\n" + "\n".join([f"- {a}" for a in summary.action_items])
        assistant_text += extra

        return ChatResponse(assistant_text=assistant_text, trace=trace)

    def _draft_email(self, session: SessionState, user_message: str, req: DraftEmailRequest, trace: List[TraceEvent]) -> ChatResponse:
        a = req.args

        to_email = (a.to_email or "").strip()
        subject = (a.subject or "").strip() or "(no subject)"
        body = (a.body or "").strip()

        if a.reply_to_email_number:
            mid = self._resolve_email_id(session, a.reply_to_email_number)
            if not mid:
                return ChatResponse(assistant_text="Couldn't resolve reply_to_email_number. List emails first.", trace=trace)
            msg = self.gmail.get_message(mid)
            trace.append(TraceEvent(name="gmail_get_message_for_reply", data={"id": msg.id, "subject": msg.subject}))

            draft = self.composition_agent.draft_reply(msg, user_instruction=user_message, to_email=to_email or None)
            trace.append(TraceEvent(name="composition_agent_structured", data=draft.model_dump()))
            to_email = to_email or draft.to_email
            subject = subject if subject != "(no subject)" else (draft.subject or f"Re: {msg.subject}")
            body = body or draft.body

        if not to_email:
            return ChatResponse(assistant_text="I need a recipient. Try: 'Draft an email to alice@example.com about ...'", trace=trace)

        gmail_draft = self.gmail.create_draft(to_email=to_email, subject=subject, body=body)
        trace.append(TraceEvent(name="gmail_create_draft", data={"draft_id": gmail_draft.id, "to": to_email, "subject": subject}))

        pending_action_id = None
        pending_action_summary = None
        if "send" in (user_message or "").lower():
            pa = self.hitl.create_pending(
                session=session,
                kind="send_draft",
                summary=f"About to send draft to {to_email} (subject: {subject}). Confirm to send.",
                payload={"draft_id": gmail_draft.id},
            )
            pending_action_id = pa.id
            pending_action_summary = pa.summary

        assistant_text = (
            f"Created a draft to {to_email}.\n"
            f"Subject: {subject}\n\n"
            f"Body:\n{safe_truncate(body, 3000)}\n\n"
            + ("Click Confirm to send now.\n" if pending_action_id else f"To send it, say: “send email to {to_email}” (then confirm).")
        )
        return ChatResponse(assistant_text=assistant_text, trace=trace, pending_action_id=pending_action_id, pending_action_summary=pending_action_summary)

    def _trash_email(self, session: SessionState, req: TrashEmailRequest, trace: List[TraceEvent]) -> ChatResponse:
        mid = self._resolve_email_id(session, req.args.email_number)
        if not mid:
            return ChatResponse(assistant_text="Could not resolve email number for trash.", trace=trace)
        self.gmail.trash_message(mid)
        trace.append(TraceEvent(name="gmail_trash_message", data={"id": mid}))
        return ChatResponse(assistant_text=f"Moved email #{req.args.email_number} to Trash.", trace=trace)

    def _prepare_trash_with_confirmation(
        self, session: SessionState, req: TrashEmailRequest, gate_reason: str, trace: List[TraceEvent]
    ) -> ChatResponse:
        """HITL flow for destructive operations (trash/delete)."""
        n = req.args.email_number
        mid = self._resolve_email_id(session, n)
        if not mid:
            return ChatResponse(assistant_text="Could not resolve email number for trash.", trace=trace)

        # Pull best-effort context from last list for UX.
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

        trace.append(
            TraceEvent(
                name="hitl_prepare_trash",
                data={"pending_action_id": pa.id, "message_id": mid, "email_number": n, "subject": subj},
            )
        )

        assistant_text = (
            "I will NOT move an email to Trash without confirmation.\n\n"
            f"Email #{n}: {subj}\n"
            f"From: {frm}\n\n"
            f"Click Confirm or type: /confirm {pa.id}\n"
            f"(Gate: {gate_reason})"
        )

        return ChatResponse(
            assistant_text=assistant_text,
            trace=trace,
            pending_action_id=pa.id,
            pending_action_summary=pa.summary,
        )

    # -------------------------
    # HITL send flow
    # -------------------------

    def _prepare_send_with_confirmation(self, session: SessionState, req: SendEmailRequest, gate_reason: str, trace: List[TraceEvent]) -> ChatResponse:
        a = req.args
        # Create a Gmail draft first (safe-ish) and require confirmation to send
        draft = self.gmail.create_draft(to_email=a.to_email, subject=a.subject, body=a.body)
        trace.append(TraceEvent(name="gmail_create_draft_for_send", data={"draft_id": draft.id, "to": a.to_email, "subject": a.subject}))

        pa = self.hitl.create_pending(
            session=session,
            kind="send_draft",
            summary=f"About to send email to {a.to_email} (subject: {a.subject}). Confirm to send.",
            payload={"draft_id": draft.id},
        )

        assistant_text = (
            f"I prepared an email, but I will NOT send it without confirmation.\n\n"
            f"To: {a.to_email}\n"
            f"Subject: {a.subject}\n\n"
            f"Body:\n{safe_truncate(a.body, 2500)}\n\n"
            f"Click Confirm or type: /confirm {pa.id}\n"
            f"(Gate: {gate_reason})"
        )

        return ChatResponse(
            assistant_text=assistant_text,
            trace=trace,
            pending_action_id=pa.id,
            pending_action_summary=pa.summary,
        )

    def _confirm(self, session: SessionState, action_id: Optional[str], trace: List[TraceEvent]) -> ChatResponse:
        if not action_id:
            # convenience: if only one pending action, confirm it
            if len(session.pending_actions) == 1:
                action_id = next(iter(session.pending_actions.keys()))
            else:
                return ChatResponse(assistant_text="Which action should I confirm? Usage: /confirm a1", trace=trace)

        pa = self.hitl.pop(session, action_id)
        if not pa:
            return ChatResponse(assistant_text=f"No pending action found with id {action_id}", trace=trace)

        trace.append(TraceEvent(name="hitl_confirm", data={"id": pa.id, "kind": pa.kind, "summary": pa.summary}))

        if pa.kind == "send_draft":
            draft_id = str(pa.payload.get("draft_id", ""))
            res = self.gmail.send_draft(draft_id)
            trace.append(TraceEvent(name="gmail_send_draft", data={"draft_id": draft_id, "result": res}))
            return ChatResponse(assistant_text="✅ Sent (after confirmation).", trace=trace)

        if pa.kind == "trash_message":
            mid = str(pa.payload.get("message_id", ""))
            email_number = pa.payload.get("email_number")
            if not mid:
                return ChatResponse(assistant_text="Pending action missing message_id; cannot trash.", trace=trace)
            self.gmail.trash_message(mid)
            trace.append(TraceEvent(name="gmail_trash_message", data={"id": mid, "email_number": email_number}))
            return ChatResponse(assistant_text=f"🗑️ Moved email #{email_number} to Trash (after confirmation).", trace=trace)

        return ChatResponse(assistant_text=f"Unknown pending action kind: {pa.kind}", trace=trace)

    def _cancel(self, session: SessionState, action_id: Optional[str], trace: List[TraceEvent]) -> ChatResponse:
        if not action_id:
            if len(session.pending_actions) == 1:
                action_id = next(iter(session.pending_actions.keys()))
            else:
                return ChatResponse(assistant_text="Which action should I cancel? Usage: /cancel a1", trace=trace)

        ok = self.hitl.cancel(session, action_id)
        trace.append(TraceEvent(name="hitl_cancel", data={"id": action_id, "ok": ok}))
        if ok:
            return ChatResponse(assistant_text="Canceled.", trace=trace)
        return ChatResponse(assistant_text=f"No pending action found with id {action_id}", trace=trace)