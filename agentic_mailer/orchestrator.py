from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from testing_shared.telemetry import add_current_event, instrument_gmail_client, traced

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
from .utils import build_gmail_query, extract_email_number, format_email_list

from .agents.management_agent import ManagementAgent
from .agents.summary_agent import SummaryAgent
from .agents.composition_agent import CompositionAgent
from .tools.gateway import ToolGateway

logger = get_logger(__name__)

_TOOL_CALL_RE = re.compile(r"TOOL_CALL\s*:\s*([A-Z_]+)", re.IGNORECASE)
_ARGS_RE = re.compile(r"ARGS\s*:\s*(\{.*\})", re.IGNORECASE | re.DOTALL)


class Orchestrator:
    """Vulnerable multi-agent orchestrator.

    After Stage 1: all tool execution is delegated to ToolGateway.
    The orchestrator handles session management, management-agent decisions,
    heuristic fallback, and building the final ChatResponse.
    """

    def __init__(self, gmail_client: Optional[Any] = None):
        self.mode = "vulnerable"
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
        demo_cfg = DemoConfig()

        self.summary_agent = SummaryAgent(model_cfg, ollama_cfg)
        self.composition_agent = CompositionAgent(model_cfg, ollama_cfg)
        self.management_agent = ManagementAgent(model_cfg, ollama_cfg, demo_cfg)

        self.gateway = ToolGateway(
            gmail=self.gmail,
            summary_agent=self.summary_agent,
            composition_agent=self.composition_agent,
            management_agent=self.management_agent,
        )

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

            # 1) Ask management agent what to do (unstructured text + regex)
            email_list_text = format_email_list(session.last_email_list) if session.last_email_list else ""
            mgmt_raw = self.management_agent.decide(user_message, email_list_text=email_list_text)
            self._append_trace(trace, "management_llm_raw", {"text": mgmt_raw})

            tool_name, args = self._parse_tool_call(mgmt_raw)
            self._append_trace(trace, "parsed_tool_call", {"tool": tool_name, "args": args})
            span.set_attribute("tool.request.action", tool_name or "")

            if not tool_name:
                # Heuristic fallback (still vulnerable — no validation)
                tool_name, args = self._heuristic_tool(user_message)
                self._append_trace(trace, "heuristic_fallback", {"tool": tool_name, "args": args})
                span.set_attribute("tool.request.heuristic_fallback", True)
                if not tool_name:
                    return ChatResponse(
                        assistant_text=(
                            "I couldn't determine an action. "
                            "Try: 'list my emails', 'read email #1', or 'summarize #1'."
                        ),
                        trace=trace,
                    )

            # 2) Delegate all execution to the gateway
            try:
                result = self.gateway.execute(
                    tool_name, args, session, trace, user_message=user_message
                )
                span.set_attribute("tool.result.success", result.success)
                return ChatResponse(assistant_text=result.output, trace=trace)
            except GmailClientError as exc:
                logger.exception("GmailClientError")
                span.set_attribute("error.kind", "gmail")
                return ChatResponse(assistant_text=f"Gmail error: {exc}", trace=trace)
            except Exception as exc:
                logger.exception("Unhandled error in orchestrator")
                span.set_attribute("error.kind", type(exc).__name__)
                return ChatResponse(assistant_text=f"Error: {exc}", trace=trace)

    # ------------------------------------------------------------------
    # Parsing helpers (owned by orchestrator — used before gateway)
    # ------------------------------------------------------------------

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

            query = build_gmail_query(
                from_email=from_email,
                to_email=to_email,
                subject=subject,
                newer_than_days=newer_than_days,
                label=label,
            )
            return "LIST_EMAILS", {"query": query, "max_results": max_results}

        if "read" in low:
            n = extract_email_number(t)
            if n:
                return "READ_EMAIL", {"email_number": n}
        if "summar" in low:
            n = extract_email_number(t)
            if n:
                return "SUMMARIZE_EMAIL", {"email_number": n}
        if any(w in low for w in ["trash", "delete", "remove"]):
            n = extract_email_number(t)
            if n:
                return "DELETE_EMAIL", {"email_number": n}
        if "draft" in low or "reply" in low:
            n = extract_email_number(t)
            if n:
                return "DRAFT_EMAIL", {"reply_to_email_number": n}

        return None, {}
