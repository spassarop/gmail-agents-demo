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

from .common_eval import detect_secret_leak, gmail_snapshot_of, new_eval_session_id, normalize_direct_tool, trace_to_dict
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
    """Extract factual planned/executed tool lists from the trace.

    Detects events from both the Stage 2+ agent loop (tool_call, tool_result,
    heuristic_fallback) and the legacy Stage 1 orchestrator events
    (parsed_tool_call) for graceful backward compatibility.
    """
    planned: set[str] = set()
    executed: set[str] = set()
    had_summarize = False  # used by compute_test_verdicts (Stage 5) via callers

    for item in trace:
        name = getattr(item, "name", None)
        data = getattr(item, "data", None) or {}

        # ── Stage 2+ loop events ─────────────────────────────────────
        if name == "tool_call":
            # Emitted by ManagementAgent.run() before each gateway call
            tool = data.get("tool", "")
            if tool:
                planned.add(str(tool))

        if name == "tool_result":
            # Emitted by ManagementAgent.run() after each gateway call
            tool = data.get("tool", "")
            if tool == "SUMMARIZE_EMAIL":
                had_summarize = True

        if name == "heuristic_fallback":
            # Emitted when the model gave no tool call on turn 0
            tool = data.get("tool")
            if tool:
                planned.add(str(tool))

        # ── Legacy Stage 1 orchestrator events (backward compat) ─────
        if name == "parsed_tool_call":
            tool = data.get("tool")
            if tool:
                planned.add(str(tool))

        # summary_agent_output is still emitted by the gateway (both stages)
        if name == "summary_agent_output":
            had_summarize = True

        # ── Gmail side-effect events (emitted by gateway, both stages) ─
        if name in ("gmail_send_email", "gmail_send_draft"):
            executed.add("SEND_EMAIL")
        elif name in ("gmail_create_draft", "gmail_create_draft_for_send"):
            executed.add("DRAFT_EMAIL")
        elif name == "gmail_trash_message":
            executed.add("TRASH_EMAIL")
        elif name == "gmail_get_message":
            executed.add("READ_EMAIL")
        elif name == "gmail_list_messages":
            executed.add("LIST_EMAILS")

    return {
        "planned": sorted(planned),
        "executed": sorted(executed),
        # had_summarize is a factual observation used by compute_test_verdicts
        # (Stage 5); harness callers can include it or ignore it.
        "had_summarize": had_summarize,
    }



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
                trace: List[Any] = [TraceEvent(name="parsed_tool_call", data={"tool": action, "args": args})]

                if action == "SEND_EMAIL":
                    response = orchestrator._send_email(session, args, trace)  # type: ignore[attr-defined]
                elif action in ("TRASH_EMAIL", "DELETE_EMAIL"):
                    response = orchestrator._delete_email(session, args, trace)  # type: ignore[attr-defined]
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
                leaked_secret = detect_secret_leak(secret, response.assistant_text, gmail_snapshot)

                result = _build_result(
                    mode="testing-vuln",
                    trace=trace,
                    assistant_text=response.assistant_text,
                    pending_action_id=response.pending_action_id,
                    pending_action_summary=response.pending_action_summary,
                    actions={**actions, "leaked_secret": leaked_secret},
                    gmail_snapshot=gmail_snapshot,
                    meta_extra={"traceparent_received": bool(traceparent)},
                )
    finally:
        otel_trace = end_trace_capture(capture_id, capture_token)

    result["otel_trace"] = otel_trace
    return result
