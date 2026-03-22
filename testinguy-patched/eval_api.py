from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request
from pydantic import BaseModel, Field

# Make eval runs less flaky by default
os.environ.setdefault("OLLAMA_TEMPERATURE", "0.0")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from testinguy_common_runtime.patched_harness import run_eval

app = FastAPI(title="testinguy-patched eval api", version="2.1")


class EvalRequest(BaseModel):
    prompt: str = ""
    preload_list: bool = True
    max_list: int = 10
    direct_tool: Optional[Any] = Field(
        default=None,
        description="Optional deterministic path that bypasses the ManagementAgent. Example: {action:'SEND_EMAIL', args:{to_email:'a@b', subject:'x', body:'y'}}",
    )


EvalRequest.model_rebuild()


@app.get("/health")
def health() -> Dict[str, str]:
    return {"ok": "true"}


@app.post("/eval")
def eval_once(req: EvalRequest, request: Request) -> Dict[str, Any]:
    return run_eval(
        prompt=req.prompt,
        preload_list=req.preload_list,
        max_list=req.max_list,
        direct_tool=req.direct_tool,
        fixtures_path=str(PROJECT_ROOT / "testinguy-common" / "fixtures" / "emails.json"),
        repo_root=str(PROJECT_ROOT),
        traceparent=request.headers.get("traceparent"),
        tracestate=request.headers.get("tracestate"),
        service_name="testinguy-patched-eval",
    )


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8911"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level=os.getenv("LOG_LEVEL", "warning").lower())
