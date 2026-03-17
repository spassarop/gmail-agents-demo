from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional


def configure_logging(log_level: Optional[str] = None) -> None:
    """Configure console + rotating file logging.

    This is intentionally verbose for demos:
    - agent decisions
    - tool calls
    - (patched mode) security gate evaluations
    """
    level_name = (log_level or os.getenv("LOG_LEVEL", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)

    log_dir = Path(os.getenv("LOG_DIR", "logs"))
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "agentic_demo.log"

    root = logging.getLogger()
    root.setLevel(level)

    # Prevent duplicate handlers if configure_logging is called multiple times
    if root.handlers:
        return

    fmt = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    formatter = logging.Formatter(fmt)

    # Console
    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(formatter)

    # Rotating file
    fh = RotatingFileHandler(str(log_file), maxBytes=5_000_000, backupCount=5, encoding="utf-8")
    fh.setLevel(level)
    fh.setFormatter(formatter)

    root.addHandler(ch)
    root.addHandler(fh)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
