from __future__ import annotations

import logging
from typing import Optional

from langchain_community.chat_models import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import PydanticOutputParser

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
        self.llm = ChatOllama(
            model=model_cfg.composition_model,
            base_url=ollama_cfg.base_url,
            temperature=ollama_cfg.temperature,
        )
        self.parser = PydanticOutputParser(pydantic_object=EmailDraft)

    def draft_reply(self, email: EmailMessage, user_instruction: str, to_email: Optional[str] = None) -> EmailDraft:
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
        try:
            draft: EmailDraft = self.parser.parse(raw)
        except Exception as e:
            logger.warning("CompositionAgent parse failed: %s", e)
            draft = EmailDraft(
                to_email=to_email or email.from_email or "",
                subject=f"Re: {email.subject}".strip(),
                body=safe_truncate(raw, 3000),
            )

        if to_email:
            draft.to_email = to_email
        if not draft.to_email:
            draft.to_email = email.from_email or ""

        # Ensure subject looks like a reply
        if not draft.subject:
            draft.subject = f"Re: {email.subject}".strip()

        return draft
