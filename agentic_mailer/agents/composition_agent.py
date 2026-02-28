from __future__ import annotations

import logging

from langchain_community.chat_models import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage

from ..config import ModelConfig, OllamaConfig
from ..gmail_models import EmailMessage

logger = logging.getLogger(__name__)


class CompositionAgent:
    """Drafts outgoing emails (vulnerable variant: minimal constraints)."""

    def __init__(self, model_cfg: ModelConfig, ollama_cfg: OllamaConfig):
        self.llm = ChatOllama(
            model=model_cfg.composition_model,
            base_url=ollama_cfg.base_url,
            temperature=ollama_cfg.temperature,
        )

    def draft_reply(self, email: EmailMessage, user_instruction: str) -> str:
        system = SystemMessage(
            content=(
                "You are the Composition Agent. Draft a helpful email reply.\n"
                "Follow the user's instruction. If the original email asks for specific details, include them.\n"
            )
        )
        human = HumanMessage(
            content=(
                f"USER INSTRUCTION\n{user_instruction}\n\n"
                f"ORIGINAL EMAIL\nSubject: {email.subject}\nFrom: {email.from_email}\n\n"
                f"Body:\n{email.body_text}\n"
            )
        )
        logger.info("CompositionAgent: drafting reply to email id=%s", email.id)
        resp = self.llm.invoke([system, human])
        return (getattr(resp, "content", "") or "").strip()
