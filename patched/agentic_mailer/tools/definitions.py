from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ToolSpec:
    name: str
    description: str
    args_schema: str


TOOL_SPECS = [
    ToolSpec(
        name="LIST_EMAILS",
        description="List emails from the mailbox matching optional filters.",
        args_schema='{"query": "string (optional Gmail query)", "max_results": "int 1-50"}',
    ),
    ToolSpec(
        name="READ_EMAIL",
        description="Fetch and display the full content of a specific email by its list position.",
        args_schema='{"email_number": "int >= 1 (index from the last LIST_EMAILS result)"}',
    ),
    ToolSpec(
        name="SUMMARIZE_EMAIL",
        description="Summarize a specific email, extracting key points and action items.",
        args_schema='{"email_number": "int >= 1"}',
    ),
    ToolSpec(
        name="DRAFT_EMAIL",
        description="Create a draft email, optionally as a reply to an existing email.",
        args_schema=(
            '{"to_email": "string|null", "subject": "string|null", '
            '"body": "string|null", "reply_to_email_number": "int|null"}'
        ),
    ),
    ToolSpec(
        name="SEND_EMAIL",
        description="Send an email immediately. HIGH IMPACT — only when explicitly requested by the user.",
        args_schema='{"to_email": "string", "subject": "string", "body": "string"}',
    ),
    ToolSpec(
        name="TRASH_EMAIL",
        description="Move an email to Trash. MODERATE IMPACT — only when the user explicitly requests deletion.",
        args_schema='{"email_number": "int >= 1"}',
    ),
]


@dataclass
class ToolResult:
    """Returned by ToolGateway.execute() for every tool call."""

    tool: str
    success: bool
    output: str            # human-readable text returned to the agent / shown to the user
    data: dict = field(default_factory=dict)   # structured payload for trace events
    provenance: str = "system"                 # "system" | "email_content" — set by Stage 3+

    # HITL fields — only set by the patched gateway; always False/None in the vulnerable runtime
    require_confirmation: bool = False
    pending_action_id: Optional[str] = None
    pending_action_summary: Optional[str] = None


# ---------------------------------------------------------------------------
# A2A typed handoff messages — Stage 4
# ---------------------------------------------------------------------------

@dataclass
class HandoffEnvelope:
    """Sent by the gateway *before* calling a sub-agent.

    The Management Agent decides what task to delegate and when; the gateway
    wraps each sub-agent invocation in this envelope so the interaction is
    fully observable in the trace.

    Fields
    ------
    from_agent  : always "management" in the current architecture
    to_agent    : "summary" | "composition"
    task        : "summarize" | "draft_reply"
    payload     : task-specific context (email_id, user_instruction, …)
    request_id  : short hex string for correlating envelope ↔ response
    """

    from_agent: str
    to_agent: str
    task: str
    payload: dict
    request_id: str


@dataclass
class HandoffResponse:
    """Returned by the gateway *after* a sub-agent completes.

    Carries the structured result and provenance so the management agent
    loop can inject it correctly (untrusted for summary, trusted for draft).

    Fields
    ------
    from_agent  : "summary" | "composition"
    to_agent    : "management"
    request_id  : matches the corresponding HandoffEnvelope.request_id
    result      : sub-agent output as a plain dict for JSON-safe tracing
    provenance  : "email_content" for Summary Agent, "system" for Composition
    """

    from_agent: str
    to_agent: str
    request_id: str
    result: dict
    provenance: str
