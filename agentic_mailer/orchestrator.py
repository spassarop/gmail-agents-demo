from __future__ import annotations

from typing import Any, Optional

from testing_shared.telemetry import instrument_gmail_client, traced

from .config import DemoConfig, ModelConfig, OllamaConfig
try:
    from .gmail_client import GmailClient, GmailClientError
except Exception:  # pragma: no cover
    GmailClient = None  # type: ignore[assignment]

    class GmailClientError(RuntimeError):
        pass

from .gmail_models import ChatResponse
from .logging_setup import get_logger
from .session_store import SessionState

from .agents.management_agent import ManagementAgent
from .agents.summary_agent import SummaryAgent
from .agents.composition_agent import CompositionAgent
from .tools.gateway import ToolGateway

logger = get_logger(__name__)


class Orchestrator:
    """Vulnerable orchestrator — bootstraps the agent and returns its result.

    handle_chat is a thin shell:
      1. append user turn to conversation
      2. delegate entirely to ManagementAgent.run()
      3. wrap the AgentResult in a ChatResponse

    All tool execution, vulnerability logic, and trace emission live in
    ManagementAgent (the loop) and ToolGateway (the dispatcher).
    """

    def __init__(self, gmail_client: Optional[Any] = None):
        self.mode = "vulnerable"
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
        demo_cfg = DemoConfig()

        self.summary_agent = SummaryAgent(model_cfg, ollama_cfg)
        self.composition_agent = CompositionAgent(model_cfg, ollama_cfg)
        self.management_agent = ManagementAgent(model_cfg, ollama_cfg, demo_cfg)

        self.gateway = ToolGateway(
            gmail=self.gmail,
            summary_agent=self.summary_agent,
            composition_agent=self.composition_agent,
        )

    def handle_chat(self, session: SessionState, user_message: str) -> ChatResponse:
        with traced(
            "orchestrator.handle_chat",
            attributes={
                "app.mode": self.mode,
                "chat.session_id": session.session_id,
                "chat.user_message_length": len(user_message or ""),
                "chat.has_email_list": bool(session.last_email_list),
            },
        ):
            session.conversation.append(("user", user_message))
            result = self.management_agent.run(user_message, session, self.gateway)
            session.conversation.append(("assistant", result.assistant_text))
            return ChatResponse(assistant_text=result.assistant_text, trace=result.trace)
