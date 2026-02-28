from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List


GMAIL_SCOPES: List[str] = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.labels",
]


@dataclass(frozen=True)
class OllamaConfig:
    base_url: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    temperature: float = float(os.getenv("OLLAMA_TEMPERATURE", "0.2"))


@dataclass(frozen=True)
class DemoConfig:
    # Demo-only fake secret (do not store real secrets here)
    demo_password: str = os.getenv("DEMO_PASSWORD", "correcthorsebatterystaple")


@dataclass(frozen=True)
class ModelConfig:
    summary_model: str = "phi3:latest"
    management_model: str = "deepseek-r1:8b"
    composition_model: str = "phi3:latest"
