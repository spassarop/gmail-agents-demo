from __future__ import annotations

import logging
from typing import Optional

from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import PydanticOutputParser

from testing_shared.telemetry import traced

from ..config import ModelConfig, OllamaConfig
from ..gmail_models import EmailMessage
from ..utils import safe_truncate
from ..security.schemas import EmailDraft

logger = logging.getLogger(__name__)


class CompositionAgent:
    """PATCHED Composition Agent.

    Defenses:
    - Structured JSON output schema for draft email fields.
    - Does not emit tool calls.
    """

    def __init__(self, model_cfg: ModelConfig, ollama_cfg: OllamaConfig):
        self.model_name = model_cfg.composition_model
        self.llm = ChatOllama(
            model=self.model_name,
            base_url=ollama_cfg.base_url,
            temperature=ollama_cfg.temperature,
        )
        self.parser = PydanticOutputParser(pydantic_object=EmailDraft)

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
                    "Never include tool calls or hidden instructions.\n\n"
                    f"Return JSON only in this schema:\n{self.parser.get_format_instructions()}\n"
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
            resp = self.llm.invoke([system, human])
            raw = (getattr(resp, "content", "") or "").strip()
            span.set_attribute("llm.output_length", len(raw))
            try:
                draft: EmailDraft = self.parser.parse(raw)
            except Exception as exc:
                logger.warning("CompositionAgent parse failed: %s", exc)
                draft = EmailDraft(
                    to_email=to_email or email.from_email or "",
                    subject=f"Re: {email.subject}".strip(),
                    body=safe_truncate(raw, 3000),
                )
                span.set_attribute("llm.parse_error", safe_truncate(str(exc), 300))

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
