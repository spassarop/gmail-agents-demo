from __future__ import annotations

import contextlib
import contextvars
import json
import os
import threading
import uuid
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

_OTEL_AVAILABLE = False
_OTEL_SDK_AVAILABLE = False

try:  # pragma: no cover - optional dependency
    from opentelemetry import trace
    from opentelemetry.propagate import extract
    from opentelemetry.trace import SpanKind, Status, StatusCode

    _OTEL_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    trace = None  # type: ignore[assignment]
    extract = None  # type: ignore[assignment]
    SpanKind = None  # type: ignore[assignment]
    Status = None  # type: ignore[assignment]
    StatusCode = None  # type: ignore[assignment]

try:  # pragma: no cover - optional dependency
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import ReadableSpan, SpanProcessor, TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor

    _OTEL_SDK_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency
    OTLPSpanExporter = None  # type: ignore[assignment]
    Resource = None  # type: ignore[assignment]
    ReadableSpan = Any  # type: ignore[assignment]
    SpanProcessor = object  # type: ignore[assignment]
    TracerProvider = None  # type: ignore[assignment]
    SimpleSpanProcessor = None  # type: ignore[assignment]

_TRACING_LOCK = threading.Lock()
_TRACING_CONFIGURED = False
_TRACER_PROVIDER = None
_OTLP_EXPORTER_ENABLED = False
_CAPTURE_LOCK = threading.Lock()
_CAPTURE_ID: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("testinguy_capture_id", default=None)
_CAPTURES: Dict[str, list[dict[str, Any]]] = {}


class _NoopSpan:
    def set_attribute(self, *args: Any, **kwargs: Any) -> None:
        return None

    def set_attributes(self, *args: Any, **kwargs: Any) -> None:
        return None

    def add_event(self, *args: Any, **kwargs: Any) -> None:
        return None

    def record_exception(self, *args: Any, **kwargs: Any) -> None:
        return None

    def set_status(self, *args: Any, **kwargs: Any) -> None:
        return None


def _safe_truncate(value: str, limit: int = 512) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "…"


def _normalize_attr_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _safe_truncate(value)
    if isinstance(value, bytes):
        return _safe_truncate(value.decode("utf-8", errors="replace"))
    if isinstance(value, Mapping):
        return _safe_truncate(json.dumps({str(k): _normalize_attr_value(v) for k, v in value.items()}, ensure_ascii=False))
    if isinstance(value, (list, tuple, set)):
        normalized: list[Any] = []
        for item in value:
            n = _normalize_attr_value(item)
            if n is not None:
                normalized.append(n)
        return normalized
    return _safe_truncate(str(value))


def _normalized_attributes(attributes: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    if not attributes:
        return {}
    out: Dict[str, Any] = {}
    for key, value in attributes.items():
        if value is None:
            continue
        norm = _normalize_attr_value(value)
        if norm is not None:
            out[str(key)] = norm
    return out


def _default_openinference_kind(name: str, attrs: Mapping[str, Any]) -> Optional[str]:
    if name.startswith("security."):
        return "GUARDRAIL"
    if name.startswith("agent."):
        return "AGENT"
    if name.startswith("gmail.") or "tool.name" in attrs:
        return "TOOL"
    return None


def _augment_attributes(name: str, attributes: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    out = _normalized_attributes(attributes)

    tool_name = out.get("tool.name")
    if tool_name and "function.name" not in out:
        out["function.name"] = tool_name

    if "openinference.span.kind" not in out:
        kind = _default_openinference_kind(name, out)
        if kind:
            out["openinference.span.kind"] = kind

    return out


class CurrentTraceCaptureProcessor(SpanProcessor):
    """Capture ended spans for the current request.

    This is a lightweight, local helper so the eval APIs can return a serialized
    copy of the spans in their JSON response in addition to forwarding them via OTLP.
    """

    def on_start(self, span: Any, parent_context: Any = None) -> None:  # pragma: no cover - trivial
        return None

    def on_end(self, span: ReadableSpan) -> None:  # pragma: no cover - exercised indirectly
        capture_id = _CAPTURE_ID.get()
        if not capture_id:
            return
        payload = serialize_readable_span(span)
        with _CAPTURE_LOCK:
            _CAPTURES.setdefault(capture_id, []).append(payload)

    def shutdown(self) -> None:  # pragma: no cover - trivial
        return None

    def force_flush(self, timeout_millis: int = 30000) -> bool:  # pragma: no cover - trivial
        return True


def _resolve_export_endpoint(export_endpoint: Optional[str], force_export: bool) -> Optional[str]:
    raw = export_endpoint or os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if raw:
        raw = raw.rstrip("/")
        return raw if raw.endswith("/v1/traces") else f"{raw}/v1/traces"
    if force_export:
        return "http://127.0.0.1:4318/v1/traces"
    return None


def ensure_tracing(service_name: str, export_endpoint: Optional[str] = None, force_export: bool = False) -> bool:
    """Configure a process-wide tracer provider once.

    The app keeps working if OpenTelemetry dependencies are absent; in that case
    instrumentation becomes a no-op.
    """

    global _TRACING_CONFIGURED, _TRACER_PROVIDER, _OTLP_EXPORTER_ENABLED

    if not (_OTEL_AVAILABLE and _OTEL_SDK_AVAILABLE):
        return False

    with _TRACING_LOCK:
        endpoint = _resolve_export_endpoint(export_endpoint=export_endpoint, force_export=force_export)

        if _TRACING_CONFIGURED:
            if endpoint and not _OTLP_EXPORTER_ENABLED and _TRACER_PROVIDER is not None:
                _TRACER_PROVIDER.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
                _OTLP_EXPORTER_ENABLED = True
            return True

        resource = Resource.create(
            {
                "service.name": service_name,
                "service.version": os.getenv("APP_VERSION", "1.0.0"),
                "deployment.environment": os.getenv("APP_ENV", "local"),
            }
        )
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(CurrentTraceCaptureProcessor())

        if endpoint:
            provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
            _OTLP_EXPORTER_ENABLED = True

        trace.set_tracer_provider(provider)
        _TRACER_PROVIDER = provider
        _TRACING_CONFIGURED = True
        return True


def extract_remote_context(traceparent: Optional[str], tracestate: Optional[str] = None) -> Any:
    if not (_OTEL_AVAILABLE and extract and traceparent):
        return None
    carrier = {"traceparent": traceparent}
    if tracestate:
        carrier["tracestate"] = tracestate
    return extract(carrier)


@contextlib.contextmanager
def traced(
    name: str,
    *,
    attributes: Optional[Mapping[str, Any]] = None,
    context: Any = None,
    kind: Any = None,
    tracer_name: str = "testinguy.agentic_demo",
):
    """Create a traced span when OpenTelemetry is available.

    When tracing is not configured, this yields a lightweight no-op span object so
    callers can keep using a unified interface.
    """

    if not _OTEL_AVAILABLE:
        yield _NoopSpan()
        return

    tracer = trace.get_tracer(tracer_name)
    span_kind = kind if kind is not None else SpanKind.INTERNAL

    with tracer.start_as_current_span(name, context=context, kind=span_kind) as span:
        set_span_attributes(span, _augment_attributes(name, attributes))
        try:
            yield span
        except Exception as exc:  # pragma: no cover - error path
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            raise


def set_span_attributes(span: Any, attributes: Optional[Mapping[str, Any]]) -> None:
    if not span or not attributes:
        return
    for key, value in _normalized_attributes(attributes).items():
        try:
            span.set_attribute(key, value)
        except Exception:  # pragma: no cover - defensive
            continue


def set_current_attributes(attributes: Optional[Mapping[str, Any]]) -> None:
    if not (_OTEL_AVAILABLE and trace):
        return
    span = trace.get_current_span()
    set_span_attributes(span, attributes)


def add_current_event(name: str, attributes: Optional[Mapping[str, Any]] = None) -> None:
    if not (_OTEL_AVAILABLE and trace):
        return
    span = trace.get_current_span()
    if not span:
        return
    try:
        span.add_event(name, attributes=_normalized_attributes(attributes))
    except Exception:  # pragma: no cover - defensive
        return


def begin_trace_capture() -> Tuple[str, contextvars.Token[Optional[str]]]:
    capture_id = uuid.uuid4().hex
    with _CAPTURE_LOCK:
        _CAPTURES[capture_id] = []
    token = _CAPTURE_ID.set(capture_id)
    return capture_id, token


def end_trace_capture(capture_id: str, token: contextvars.Token[Optional[str]]) -> Dict[str, Any]:
    try:
        _CAPTURE_ID.reset(token)
    except Exception:  # pragma: no cover - defensive
        pass

    with _CAPTURE_LOCK:
        spans = _CAPTURES.pop(capture_id, [])

    spans = sorted(spans, key=lambda item: (item.get("startTime") or 0, item.get("name") or ""))
    return {
        "spans": spans,
        "spanCount": len(spans),
    }


def serialize_readable_span(span: ReadableSpan) -> Dict[str, Any]:
    trace_id = ""
    span_id = ""
    parent_span_id = None

    try:
        trace_id = f"{span.context.trace_id:032x}"
        span_id = f"{span.context.span_id:016x}"
        if span.parent is not None:
            parent_span_id = f"{span.parent.span_id:016x}"
    except Exception:  # pragma: no cover - defensive
        pass

    events: list[dict[str, Any]] = []
    for event in getattr(span, "events", []) or []:
        events.append(
            {
                "name": getattr(event, "name", ""),
                "attributes": _normalized_attributes(getattr(event, "attributes", {}) or {}),
            }
        )

    status_code = None
    status_name = None
    status_message = None
    try:
        status_code = int(span.status.status_code.value)
        status_name = span.status.status_code.name
        status_message = getattr(span.status, "description", None)
    except Exception:  # pragma: no cover - defensive
        pass

    start_ns = getattr(span, "start_time", None)
    end_ns = getattr(span, "end_time", None)
    start_ms = int(start_ns / 1_000_000) if isinstance(start_ns, int) else None
    end_ms = int(end_ns / 1_000_000) if isinstance(end_ns, int) else None

    return {
        "name": span.name,
        "traceId": trace_id,
        "spanId": span_id,
        "parentSpanId": parent_span_id,
        "kind": getattr(getattr(span, "kind", None), "name", str(getattr(span, "kind", ""))),
        "startTime": start_ms,
        "endTime": end_ms,
        "durationMs": (end_ms - start_ms) if start_ms is not None and end_ms is not None else None,
        "statusCode": status_code,
        "statusName": status_name,
        "statusMessage": status_message,
        "attributes": _normalized_attributes(getattr(span, "attributes", {}) or {}),
        "events": events,
    }


class InstrumentedGmailClient:
    """Wrap a Gmail-like client and emit tool-oriented spans."""

    def __init__(self, inner: Any, mode: str):
        self._inner = inner
        self._mode = mode

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def list_labels(self):
        with traced(
            "gmail.list_labels",
            kind=SpanKind.CLIENT if _OTEL_AVAILABLE else None,
            attributes={
                "app.mode": self._mode,
                "tool.name": "LIST_LABELS",
                "function.name": "gmail.list_labels",
            },
        ) as span:
            labels = self._inner.list_labels()
            set_span_attributes(span, {"gmail.label_count": len(labels)})
            return labels

    def list_messages(self, query: str = "", max_results: int = 5, label_ids: Optional[list[str]] = None):
        with traced(
            "gmail.list_messages",
            kind=SpanKind.CLIENT if _OTEL_AVAILABLE else None,
            attributes={
                "app.mode": self._mode,
                "tool.name": "LIST_EMAILS",
                "function.name": "gmail.list_messages",
                "gmail.query": query,
                "gmail.max_results": max_results,
                "gmail.label_ids": label_ids or [],
            },
        ) as span:
            items = self._inner.list_messages(query=query, max_results=max_results, label_ids=label_ids)
            set_span_attributes(span, {"gmail.result_count": len(items)})
            return items

    def get_message(self, message_id: str):
        with traced(
            "gmail.get_message",
            kind=SpanKind.CLIENT if _OTEL_AVAILABLE else None,
            attributes={
                "app.mode": self._mode,
                "tool.name": "READ_EMAIL",
                "function.name": "gmail.get_message",
                "gmail.message_id": message_id,
            },
        ) as span:
            msg = self._inner.get_message(message_id)
            set_span_attributes(
                span,
                {
                    "email.subject": getattr(msg, "subject", ""),
                    "email.from": getattr(msg, "from_email", ""),
                    "email.body_length": len(getattr(msg, "body_text", "") or ""),
                },
            )
            return msg

    def trash_message(self, message_id: str) -> None:
        with traced(
            "gmail.trash_message",
            kind=SpanKind.CLIENT if _OTEL_AVAILABLE else None,
            attributes={
                "app.mode": self._mode,
                "tool.name": "TRASH_EMAIL",
                "function.name": "gmail.trash_message",
                "gmail.message_id": message_id,
            },
        ):
            self._inner.trash_message(message_id)

    def delete_message_permanent(self, message_id: str) -> None:
        with traced(
            "gmail.delete_message_permanent",
            kind=SpanKind.CLIENT if _OTEL_AVAILABLE else None,
            attributes={
                "app.mode": self._mode,
                "tool.name": "DELETE_EMAIL",
                "function.name": "gmail.delete_message_permanent",
                "gmail.message_id": message_id,
            },
        ):
            self._inner.delete_message_permanent(message_id)

    def create_draft(self, to_email: str, subject: str, body: str):
        with traced(
            "gmail.create_draft",
            kind=SpanKind.CLIENT if _OTEL_AVAILABLE else None,
            attributes={
                "app.mode": self._mode,
                "tool.name": "DRAFT_EMAIL",
                "function.name": "gmail.create_draft",
                "email.to": to_email,
                "email.subject": subject,
                "email.body_length": len(body or ""),
            },
        ) as span:
            draft = self._inner.create_draft(to_email=to_email, subject=subject, body=body)
            set_span_attributes(span, {"gmail.draft_id": getattr(draft, "id", "")})
            return draft

    def send_draft(self, draft_id: str):
        with traced(
            "gmail.send_draft",
            kind=SpanKind.CLIENT if _OTEL_AVAILABLE else None,
            attributes={
                "app.mode": self._mode,
                "tool.name": "SEND_EMAIL",
                "function.name": "gmail.send_draft",
                "gmail.draft_id": draft_id,
            },
        ):
            return self._inner.send_draft(draft_id)

    def send_email(self, to_email: str, subject: str, body: str):
        with traced(
            "gmail.send_email",
            kind=SpanKind.CLIENT if _OTEL_AVAILABLE else None,
            attributes={
                "app.mode": self._mode,
                "tool.name": "SEND_EMAIL",
                "function.name": "gmail.send_email",
                "email.to": to_email,
                "email.subject": subject,
                "email.body_length": len(body or ""),
            },
        ):
            return self._inner.send_email(to_email=to_email, subject=subject, body=body)


def instrument_gmail_client(client: Any, mode: str) -> Any:
    if isinstance(client, InstrumentedGmailClient):
        return client
    return InstrumentedGmailClient(client, mode=mode)
