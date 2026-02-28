#!/usr/bin/env python3
"""Run the demo web server.

Usage:
  python run.py --mode vulnerable
  python run.py --mode patched

Implementation trick:
- Both versions use the SAME Python package name: `agentic_mailer`
- Patched code lives in `patched/agentic_mailer`
- When --mode patched is used, we prepend `patched/` to sys.path
  so `import agentic_mailer` resolves to the patched implementation.

This also enables a live on-screen diff workflow:
- copy patched/agentic_mailer/* -> agentic_mailer/*
- restart
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv


def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=["vulnerable", "patched"],
        default="vulnerable",
        help="Run the vulnerable or patched implementation.",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent
    if args.mode == "patched":
        patched_path = str(project_root / "patched")
        # Prepend patched folder so it wins import resolution
        sys.path.insert(0, patched_path)

    # Import after sys.path mutation
    from agentic_mailer.ui.server import create_app  # type: ignore
    import uvicorn

    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "8000"))

    app = create_app(mode=args.mode)

    uvicorn.run(app, host=host, port=port, log_level=os.getenv("LOG_LEVEL", "info").lower())


if __name__ == "__main__":
    main()
