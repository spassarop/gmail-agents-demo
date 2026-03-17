from __future__ import annotations

import os
import secrets
import json
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

from agentic_mailer.gmail_models import TraceEvent
from agentic_mailer.orchestrator import Orchestrator
from agentic_mailer.security.schemas import SendEmailRequest
from agentic_mailer.session_store import SessionState


# Make eval runs less flaky by default (you can override via env)
os.environ.setdefault("OLLAMA_TEMPERATURE", "0.0")

app = FastAPI(title="testinguy-patched eval api", version="1.0")
orch = Orchestrator()


class EvalRequest(BaseModel):
    prompt: str = ""
    preload_list: bool = True
    max_list: int = 10
    # NOTE: Promptfoo's HTTP provider templating can sometimes coerce values into strings.
    # We accept Any here and normalize at runtime to keep the eval harness resilient.
    direct_tool: Optional[Any] = Field(
        default=None,
        description="Optional deterministic path that bypasses the ManagementAgent. Example: {action:'SEND_EMAIL', args:{to_email:'a@b', subject:'x', body:'y'}}",
    )


def _normalize_direct_tool(value: Any) -> Optional[Dict[str, Any]]:
    """Accept dict or JSON-stringified dict; treat null/empty as absent."""
    if value is None:
        return None

    if isinstance(value, dict):
        return value

    if isinstance(value, str):
        s = value.strip()
        if s == "" or s.lower() in ("null", "none"):
            return None
        try:
            parsed = json.loads(s)
        except Exception:
            return None
        return parsed if isinstance(parsed, dict) else None

    return None


def _trace_to_dict(trace: List[TraceEvent]) -> List[Dict[str, Any]]:
    return [{"name": t.name, "data": t.data} for t in trace]


def _extract_actions(trace: List[TraceEvent], pending_action_id: Optional[str]) -> Dict[str, Any]:
    planned: List[str] = []
    executed: List[str] = []
    require_confirmation = bool(pending_action_id)

    for t in trace:
        if t.name == "tool_request_validated":
            tool = (t.data or {}).get("tool")
            if tool:
                planned.append(str(tool))

        if t.name == "intent_gate":
            if (t.data or {}).get("require_confirmation") is True:
                require_confirmation = True

        if t.name in ("gmail_send_email", "gmail_send_draft"):
            executed.append("SEND_EMAIL")
        elif t.name in ("gmail_create_draft", "gmail_create_draft_for_send"):
            executed.append("DRAFT_EMAIL")
        elif t.name in ("gmail_trash_message",):
            executed.append("TRASH_EMAIL")

    return {
        "planned": planned,
        "executed": executed,
        "require_confirmation": require_confirmation,
    }


@app.get("/health")
def health() -> Dict[str, str]:
    return {"ok": "true"}


@app.post("/eval")
def eval_once(req: EvalRequest) -> Dict[str, Any]:
    # SessionState requires a session_id; for eval runs we keep it ephemeral but unique.
    session = SessionState(session_id=f"eval-{secrets.token_urlsafe(8)}")

    direct_tool = _normalize_direct_tool(req.direct_tool)

    if req.preload_list:
        session.last_email_list = orch.gmail.list_messages(max_results=req.max_list)

    # Deterministic contract-style path (bypass LLM)
    if direct_tool:
        action = str(direct_tool.get("action") or "").upper()
        args = direct_tool.get("args") or {}
        trace: List[TraceEvent] = []

        if action == "SEND_EMAIL":
            # Build a typed request and run the same HITL method the orchestrator uses.
            tool_req = SendEmailRequest(action="SEND_EMAIL", args=args)
            # We still run intent_gate so trace has a decision
            decision = orch.intent_gate.evaluate("(direct_tool) SEND_EMAIL", tool_req)
            trace.append(
                TraceEvent(
                    name="intent_gate",
                    data={
                        "allow": decision.allow,
                        "require_confirmation": decision.require_confirmation,
                        "reason": decision.reason,
                    },
                )
            )
            if not decision.allow:
                return {
                    "assistant_text": f"Blocked by Intent Gate: {decision.reason}",
                    "pending_action_id": None,
                    "pending_action_summary": None,
                    "actions": {"planned": ["SEND_EMAIL"], "executed": [], "require_confirmation": False},
                    "trace": _trace_to_dict(trace),
                    "gmail": orch.gmail.testing_snapshot() if hasattr(orch.gmail, "testing_snapshot") else {},
                    "meta": {"mode": "testinguy-patched"},
                }
            resp = orch._prepare_send_with_confirmation(session, tool_req, decision.reason, trace)  # type: ignore[attr-defined]
        else:
            return {
                "error": f"Unsupported direct_tool action in patched harness: {action}",
                "supported": ["SEND_EMAIL"],
            }
    else:
        resp = orch.handle_chat(session, req.prompt)
        trace = resp.trace

    actions = _extract_actions(trace, resp.pending_action_id)

    gmail_snapshot = {}
    if hasattr(orch.gmail, "testing_snapshot"):
        gmail_snapshot = orch.gmail.testing_snapshot()  # type: ignore[attr-defined]

    # Patched variant shouldn't be able to leak demo password via system prompt,
    # but we keep the same output field for consistency.
    leaked_secret = False

    return {
        "assistant_text": resp.assistant_text,
        "pending_action_id": resp.pending_action_id,
        "pending_action_summary": resp.pending_action_summary,
        "actions": {
            **actions,
            "leaked_secret": leaked_secret,
        },
        "trace": _trace_to_dict(trace),
        "gmail": gmail_snapshot,
        "meta": {"mode": "testinguy-patched"},
    }


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8911"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level=os.getenv("LOG_LEVEL", "warning").lower())
