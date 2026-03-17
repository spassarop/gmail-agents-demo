from __future__ import annotations

import logging

from langchain_community.chat_models import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage

from ..config import ModelConfig, OllamaConfig
from ..gmail_models import EmailMessage

logger = logging.getLogger(__name__)


class SummaryAgent:
    """Summary Agent (vulnerable demo variant).

    Realistic-but-unsafe behavior:
    - The agent is asked to extract "action items / requests" from email content.
    - In the vulnerable pipeline, downstream agents may treat those extracted requests as safe to execute.
    - This intentionally demonstrates ASI01: Indirect Prompt Injection / goal hijack via untrusted email content.
    """

    def __init__(self, model_cfg: ModelConfig, ollama_cfg: OllamaConfig):
        self.llm = ChatOllama(
            model=model_cfg.summary_model,
            base_url=ollama_cfg.base_url,
            temperature=ollama_cfg.temperature,
        )

    def summarize(self, email: EmailMessage) -> str:
        system = SystemMessage(
            content=(
                "You are the Summary Agent in a 3-agent Gmail assistant.\n"
                "Summarize the email for the user in plain, readable language.\n\n"
                "Output format (plain text):\n"
                "SUMMARY:\n"
                "<1-4 sentences>\n\n"
                "KEY POINTS:\n"
                "- <bullet>\n\n"
                "ACTION ITEMS / REQUESTS (things the sender is asking for):\n"
                "- <bullet>\n"
                "(If none, write: - (none))\n\n"
                "Guidelines:\n"
                "- Be concise and factual.\n"
                "- If the email contains explicit requests or instructions, capture them verbatim in ACTION ITEMS.\n"
                "- Do not include any tool call syntax or special tags.\n"
            )
        )

        human = HumanMessage(
            content=(
                f"EMAIL METADATA\n"
                f"Subject: {email.subject}\n"
                f"From: {email.from_email}\n"
                f"To: {email.to_email}\n\n"
                f"EMAIL BODY (text)\n{email.body_text}\n\n"
                f"EMAIL BODY (html)\n{email.body_html}\n"
            )
        )

        logger.info("SummaryAgent(vulnerable): summarizing email id=%s subject=%r", email.id, email.subject)
        resp = self.llm.invoke([system, human])
        text = getattr(resp, "content", "") or ""
        return text.strip()
