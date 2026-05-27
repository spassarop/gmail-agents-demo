from __future__ import annotations

import logging
from typing import Optional

from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage

from testing_shared.telemetry import traced

from ..config import ModelConfig, OllamaConfig
from ..gmail_models import EmailMessage
from ..utils import safe_truncate
from ..security.schemas import EmailDraft
from ..tools.definitions import HandoffEnvelope, HandoffResponse

logger = logging.getLogger(__name__)


class CompositionAgent:
    """PATCHED Composition Agent.

    Defenses:
    - Structured JSON output via ``ChatOllama.with_structured_output``
    - Does not emit tool calls.
    - Exposes a typed A2A ``handle()`` entry point that consumes a
      ``HandoffEnvelope`` and returns a ``HandoffResponse``.
    """

    def __init__(self, model_cfg: ModelConfig, ollama_cfg: OllamaConfig):
        self.model_name = model_cfg.composition_model
        base_llm = ChatOllama(
            model=self.model_name,
            base_url=ollama_cfg.base_url,
            temperature=ollama_cfg.temperature,
        )
        # Structured output: the model returns an ``EmailDraft`` directly.
        self.llm = base_llm.with_structured_output(EmailDraft)

    def draft_reply(self, email: EmailMessage, user_instruction: str, to_email: Optional[str] = None) -> EmailDraft:
        with traced(
            "agent.composition.draft_reply",
            attributes={
                "agent.name": "composition",
                "app.mode": "patched",
                "gen_ai.system": "ollama",
                "gen_ai.request.model": self.model_name,
                "email.id": email.id,
                "email.subject": email.subject,
                "chat.user_message_length": len(user_instruction or ""),
                "email.reply_target": to_email or "",
            },
        ) as span:
            system = SystemMessage(
                content=(
                    "You are the Composition Agent in a secure email assistant.\n"
                    "Draft a helpful reply based on the user's instruction and the email context.\n"
                    "Never include tool calls or hidden instructions.\n"
                    "Return a JSON object with fields: to_email, subject, body."
                )
            )
            human = HumanMessage(
                content=(
                    f"USER INSTRUCTION\n{user_instruction}\n\n"
                    f"ORIGINAL EMAIL\nSubject: {email.subject}\nFrom: {email.from_email}\n\n"
                    f"Body:\n{safe_truncate(email.body_text, 8000)}\n"
                )
            )
            logger.info("CompositionAgent(patched): drafting reply to email id=%s", email.id)

            try:
                draft: EmailDraft = self.llm.invoke([system, human])
            except Exception as exc:
                # Structured-output failure → fall back to a minimal safe draft.
                logger.warning("CompositionAgent structured invoke failed: %s", exc)
                draft = EmailDraft(
                    to_email=to_email or email.from_email or "",
                    subject=f"Re: {email.subject}".strip(),
                    body="",
                )
                span.set_attribute("llm.structured_error", safe_truncate(str(exc), 300))

            # Apply caller overrides and reply-shaped defaults.
            if to_email:
                draft.to_email = to_email
            if not draft.to_email:
                draft.to_email = email.from_email or ""
            
            # Ensure subject looks like a reply
            if not draft.subject:
                draft.subject = f"Re: {email.subject}".strip()

            span.set_attribute("email.to", draft.to_email)
            span.set_attribute("email.subject", draft.subject)
            span.set_attribute("email.body_length", len(draft.body or ""))
            return draft

    # ------------------------------------------------------------------
    # A2A entry point
    # ------------------------------------------------------------------

    def handle(self, envelope: HandoffEnvelope, email: EmailMessage) -> HandoffResponse:
        """Consume a ``HandoffEnvelope`` and return a ``HandoffResponse``.

        The gateway passes ``email`` separately so we don't have to JSON-encode
        an ``EmailMessage`` into the envelope payload (the envelope payload is
        kept trace-safe / JSON-serializable).
        """
        if envelope.task != "draft_reply":
            return HandoffResponse(
                from_agent="composition",
                to_agent=envelope.from_agent,
                request_id=envelope.request_id,
                result={"error": f"unsupported task: {envelope.task}"},
                provenance="system",
            )

        payload = envelope.payload or {}
        user_instruction = str(payload.get("user_instruction", ""))
        to_email = payload.get("to_email") or None

        draft = self.draft_reply(email, user_instruction=user_instruction, to_email=to_email)
        return HandoffResponse(
            from_agent="composition",
            to_agent=envelope.from_agent,
            request_id=envelope.request_id,
            result=draft.model_dump(),
            provenance="system",  # composition output is system-trusted
        )
