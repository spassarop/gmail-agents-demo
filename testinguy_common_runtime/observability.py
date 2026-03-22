from __future__ import annotations

"""Compatibility wrappers around the shared OpenTelemetry helpers.

This module previously contained a standalone tracing implementation. The demo
now standardizes on `testinguy_shared.telemetry`; these helpers remain only so
older local scripts can keep importing the same names during the transition.
"""

from contextlib import contextmanager
from typing import Any, Dict, Iterator, Mapping, Optional

from testinguy_shared.telemetry import traced

SERVICE_TRACER_NAME = "gmail-agents-demo"


@contextmanager
def traced_span(name: str, attrs: Optional[Mapping[str, Any]] = None) -> Iterator[Any]:
    with traced(name, attributes=attrs, tracer_name=SERVICE_TRACER_NAME) as span:
        yield span


@contextmanager
def tool_span(tool_name: str, arguments: Optional[Any] = None, attrs: Optional[Mapping[str, Any]] = None) -> Iterator[Any]:
    base_attrs: Dict[str, Any] = {
        "tool.name": tool_name,
        "function.name": tool_name,
        "openinference.span.kind": "TOOL",
    }
    if arguments is not None:
        base_attrs["tool.arguments"] = arguments
        base_attrs["function.arguments"] = arguments
    if attrs:
        base_attrs.update(dict(attrs))
    with traced_span(f"tool.{tool_name.lower()}", base_attrs) as span:
        yield span


@contextmanager
def agent_span(name: str, role: str, attrs: Optional[Mapping[str, Any]] = None) -> Iterator[Any]:
    base_attrs: Dict[str, Any] = {
        "agent.role": role,
        "openinference.span.kind": "AGENT",
    }
    if attrs:
        base_attrs.update(dict(attrs))
    with traced_span(name, base_attrs) as span:
        yield span


@contextmanager
def guardrail_span(name: str, attrs: Optional[Mapping[str, Any]] = None) -> Iterator[Any]:
    base_attrs: Dict[str, Any] = {
        "openinference.span.kind": "GUARDRAIL",
    }
    if attrs:
        base_attrs.update(dict(attrs))
    with traced_span(name, base_attrs) as span:
        yield span
