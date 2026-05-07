from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from testing_shared.telemetry import (
    begin_trace_capture,
    end_trace_capture,
    ensure_tracing,
    extract_remote_context,
    traced,
)

from .common_eval import gmail_snapshot_of, new_eval_session_id, normalize_direct_tool, trace_to_dict
from .fixture_gmail import build_fixture_gmail_client
from .package_loader import load_runtime_package, runtime_package_info


DEFAULT_SERVICE_NAME = "testing-vuln-eval"


def _repo_root_path(repo_root: Optional[str]) -> Path:
    if repo_root:
        return Path(repo_root).resolve()
    return Path(__file__).resolve().parents[1]



def _load_runtime(repo_root: Path):
    runtime_pkg = load_runtime_package("vuln", repo_root)
    alias, _package_dir = runtime_package_info("vuln", repo_root)
    orchestrator_mod = importlib.import_module(f"{alias}.orchestrator")
    models_mod = importlib.import_module(f"{alias}.gmail_models")
    session_mod = importlib.import_module(f"{alias}.session_store")
    config_mod = importlib.import_module(f"{alias}.config")
    return runtime_pkg, orchestrator_mod, models_mod, session_mod, config_mod



def extract_actions(trace: List[Any]) -> Dict[str, Any]:
    """Return factual planned/executed tool lists — no verdicts, no attack signals.

    Verdict computation lives in ``testing_common_runtime.verdicts``.
    """
    planned: set = set()
    executed: set = set()

    for item in trace:
        name = getattr(item, "name", "") or ""
        data = getattr(item, "data", {}) or {}

        # tool_result: agent loop emits this after every gateway call.
        # data.tool is what the agent planned to call.
        if name == "tool_result":
            t = data.get("tool", "")
            if t:
                planned.add(str(t))

        # a2a_response: sub-agent completed — from_agent identifies which.
        if name == "a2a_response":
            fa = data.get("from_agent", "")
            if fa == "summary":
                executed.add("SUMMARIZE_EMAIL")
            elif fa == "composition":
                executed.add("DRAFT_EMAIL")

        # Gmail side-effect events — ground truth for what actually executed.
        if name in ("gmail_send_email", "gmail_send_draft"):
            executed.add("SEND_EMAIL")
        if name in ("gmail_create_draft", "gmail_create_draft_for_send"):
            executed.add("DRAFT_EMAIL")
        if name == "gmail_trash_message":
            executed.add("TRASH_EMAIL")
        if name == "gmail_get_message":
            executed.add("READ_EMAIL")
        if name == "gmail_list_messages":
            executed.add("LIST_EMAILS")

    return {"planned": sorted(planned), "executed": sorted(executed)}



def _build_result(
    *,
    mode: str,
    trace: Optional[List[Any]] = None,
    assistant_text: Optional[str] = None,
    pending_action_id: Optional[str] = None,
    pending_action_summary: Optional[str] = None,
    actions: Optional[Dict[str, Any]] = None,
    gmail_snapshot: Optional[Dict[str, Any]] = None,
    meta_extra: Optional[Dict[str, Any]] = None,
    **extra: Any,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "assistant_text": assistant_text,
        "pending_action_id": pending_action_id,
        "pending_action_summary": pending_action_summary,
        "actions": actions or {},
        "trace": trace_to_dict(trace or []),
        "gmail": gmail_snapshot or {},
        "meta": {"mode": mode, **(meta_extra or {})},
    }
    result.update(extra)
    return result



def run_eval(
    *,
    prompt: str,
    preload_list: bool = True,
    max_list: int = 10,
    direct_tool: Optional[Any] = None,
    fixtures_path: Optional[str] = None,
    repo_root: Optional[str] = None,
    traceparent: Optional[str] = None,
    tracestate: Optional[str] = None,
    service_name: str = DEFAULT_SERVICE_NAME,
    export_endpoint: Optional[str] = None,
) -> Dict[str, Any]:
    repo_root_path = _repo_root_path(repo_root)
    ensure_tracing(
        service_name=service_name,
        export_endpoint=export_endpoint,
        force_export=bool(traceparent or tracestate),
    )
    remote_context = extract_remote_context(traceparent, tracestate)
    capture_id, capture_token = begin_trace_capture()

    result: Dict[str, Any]
    try:
        with traced(
            "testing.eval_run",
            context=remote_context,
            attributes={
                "testing.mode": "testing-vuln",
                "testing.preload_list": preload_list,
                "testing.max_list": max_list,
                "testing.direct_tool": normalize_direct_tool(direct_tool),
                "testing.traceparent_received": bool(traceparent),
                "testing.repo_root": str(repo_root_path),
            },
        ):
            runtime_pkg, orchestrator_mod, models_mod, session_mod, config_mod = _load_runtime(repo_root_path)

            Orchestrator = orchestrator_mod.Orchestrator
            TraceEvent = models_mod.TraceEvent
            SessionState = session_mod.SessionState
            DemoConfig = config_mod.DemoConfig

            fixture_client = build_fixture_gmail_client(runtime_pkg, fixtures_path=fixtures_path)
            orchestrator = Orchestrator(gmail_client=fixture_client)
            session = SessionState(session_id=new_eval_session_id())
            normalized_direct_tool = normalize_direct_tool(direct_tool)

            if preload_list:
                session.last_email_list = orchestrator.gmail.list_messages(max_results=max_list)

            if normalized_direct_tool:
                action = str(normalized_direct_tool.get("action") or "").upper()
                args = normalized_direct_tool.get("args") or {}
                trace: List[Any] = []

                # Route through the gateway — all tool dispatch moved there in Stage 1.
                if action in ("SEND_EMAIL", "TRASH_EMAIL", "DELETE_EMAIL"):
                    tool_result = orchestrator.gateway.execute(action, args, session, trace)
                    response = type("_R", (), {
                        "assistant_text": tool_result.output,
                        "pending_action_id": tool_result.pending_action_id,
                        "pending_action_summary": tool_result.pending_action_summary,
                    })()
                else:
                    result = _build_result(
                        mode="testing-vuln",
                        trace=trace,
                        assistant_text="",
                        actions={"planned": [action], "executed": []},
                        gmail_snapshot=gmail_snapshot_of(orchestrator.gmail),
                        meta_extra={"traceparent_received": bool(traceparent)},
                        error=f"Unsupported direct_tool action in vuln harness: {action}",
                        supported=["SEND_EMAIL", "TRASH_EMAIL"],
                    )
                    response = None
            else:
                response = orchestrator.handle_chat(session, prompt)
                trace = response.trace

            if response is not None:
                actions = extract_actions(trace)
                gmail_snapshot = gmail_snapshot_of(orchestrator.gmail)
                secret = DemoConfig().demo_password

                result = _build_result(
                    mode="testing-vuln",
                    trace=trace,
                    assistant_text=response.assistant_text,
                    pending_action_id=response.pending_action_id,
                    pending_action_summary=response.pending_action_summary,
                    actions=actions,
                    gmail_snapshot=gmail_snapshot,
                    # demo_password in meta so compute_test_verdicts can check secret leaks
                    meta_extra={"traceparent_received": bool(traceparent), "demo_password": secret},
                )
    finally:
        otel_trace = end_trace_capture(capture_id, capture_token)

    result["otel_trace"] = otel_trace
    return result
