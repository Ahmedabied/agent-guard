"""OpenTelemetry spans for the guard's decisions (optional: the otel extra).

Off unless the standard OTLP setting is in the environment (OTEL_EXPORTER_OTLP_ENDPOINT or
OTEL_EXPORTER_OTLP_TRACES_ENDPOINT). Then every judged call gets one span, `agent-guard tools/call <tool>`, with
the decision and the rule. Its parent is the trace context the client put in the request's `_meta` (MCP's W3C
`traceparent`), so in the agent's own trace a blocked call shows the guard's span and no server span.

What a span carries: the method, tool name, decision, rule, the policy's reason and the request id. Never the
arguments or a resource uri: those can hold anything, and the audit log's scrubber does not reach a tracing
backend. Recording a span happens after the decision, and any error in it is swallowed, so tracing can neither
change a decision nor fail one.
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any

_tracer: Any = None
_provider: Any = None


def enabled() -> bool:
    return _tracer is not None


def setup() -> bool:
    """Turn tracing on when the environment asks for OTLP export. True if it is on."""
    global _tracer, _provider
    if not (os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT") or os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")):
        return False
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as e:
        print(f"agent-guard: OTLP endpoint set but tracing needs the otel extra ({e.name} is missing); "
              "tracing is off", file=sys.stderr, flush=True)
        return False
    name = os.environ.get("OTEL_SERVICE_NAME") or "agent-guard"
    provider = TracerProvider(resource=Resource.create({"service.name": name}))
    # Short delays and timeouts: spans leave within a second, and a collector that is down holds up exit 5 s at most.
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(timeout=5), schedule_delay_millis=1000,
                                                   export_timeout_millis=5000))
    use(provider)
    return True


def use(provider: Any) -> None:
    """Record spans with this TracerProvider (setup() builds one from the environment; tests pass their own)."""
    global _tracer, _provider
    _provider = provider
    _tracer = provider.get_tracer("agent-guard") if provider is not None else None


def shutdown() -> None:
    """Send what is buffered. The CLI calls this before it exits."""
    global _tracer
    if _provider is not None:
        try:
            _provider.shutdown()
        except Exception:  # noqa: BLE001
            pass
    _tracer = None


def _parent(msg: dict) -> Any:
    params = msg.get("params")
    meta = params.get("_meta") if isinstance(params, dict) else None
    if not isinstance(meta, dict) or not isinstance(meta.get("traceparent"), str):
        return None
    from opentelemetry.propagate import extract
    from opentelemetry.trace import get_current_span

    carrier = {k: v for k, v in meta.items() if k in ("traceparent", "tracestate") and isinstance(v, str)}
    ctx = extract(carrier)
    return ctx if get_current_span(ctx).get_span_context().is_valid else None


def decision(msg: dict, name: Any, action: str, rule: str | None, reason: str | None, start_ns: int,
             approval: bool | None = None) -> None:
    """Record one decision as a finished span, from start_ns (time.time_ns) to now."""
    if _tracer is None:
        return
    try:
        method = msg.get("method")
        tool = name if isinstance(name, str) else None
        label = "approval" if approval is not None else method
        attributes: dict[str, Any] = {"mcp.method.name": method if isinstance(method, str) else "",
                                      "agent_guard.decision": action}
        if method == "tools/call" and tool:
            attributes["gen_ai.tool.name"] = tool
        if rule:
            attributes["agent_guard.rule"] = rule
        if reason and action != "allow":
            attributes["agent_guard.reason"] = reason[:500]
        if approval is not None:
            attributes["agent_guard.approved"] = approval
        if "id" in msg and isinstance(msg["id"], (str, int)) and not isinstance(msg["id"], bool):
            attributes["jsonrpc.request.id"] = str(msg["id"])
        target = f" {tool}" if method == "tools/call" and tool else ""
        span = _tracer.start_span(f"agent-guard {label}{target}", context=_parent(msg), start_time=start_ns,
                                  attributes=attributes)
        span.end(end_time=max(time.time_ns(), start_ns))
    except Exception:  # noqa: BLE001  tracing must never touch a decision
        pass
