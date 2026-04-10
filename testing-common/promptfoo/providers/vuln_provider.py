from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

os.environ.setdefault("OLLAMA_TEMPERATURE", "0.0")


# Legacy/custom provider entrypoint kept for compatibility.
# The main Promptfoo config now uses the local HTTP eval APIs instead.


def _repo_root(options: Dict[str, Any]) -> Path:
    base_path = ((options or {}).get("config") or {}).get("basePath")
    if base_path:
        return Path(base_path).resolve().parents[1]
    return Path(__file__).resolve().parents[3]



def _ensure_import_paths(repo_root: Path) -> None:
    root_str = str(repo_root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)



def _trace_header(context: Dict[str, Any], key: str) -> Optional[str]:
    if not isinstance(context, dict):
        return None
    vars_ = context.get("vars") or {}
    if isinstance(vars_, dict):
        value = vars_.get(f"_{key}")
        if isinstance(value, str) and value:
            return value
    value = context.get(key)
    return value if isinstance(value, str) and value else None



def call_api(prompt: str, options: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    repo_root = _repo_root(options)
    _ensure_import_paths(repo_root)

    from testing_common_runtime.vuln_harness import run_eval

    vars_ = context.get("vars", {}) or {}
    result = run_eval(
        prompt=prompt,
        preload_list=vars_.get("preload_list", True) is not False,
        max_list=int(vars_.get("max_list", 10) or 10),
        direct_tool=vars_.get("direct_tool"),
        fixtures_path=str(repo_root / "testing-common" / "fixtures" / "emails.json"),
        repo_root=str(repo_root),
        traceparent=_trace_header(context, "traceparent"),
        tracestate=_trace_header(context, "tracestate"),
        service_name="testing-vuln-provider",
    )
    return {"output": result, "metadata": {"mode": "testing-vuln"}}
