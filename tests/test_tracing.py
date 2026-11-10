"""Guard decisions as OpenTelemetry spans: what they carry, where they hang in the agent's trace, and that
tracing can never change or fail a decision."""

import base64
import json
import os
import subprocess
import sys
import time
from contextlib import contextmanager

import pytest

pytest.importorskip("opentelemetry.sdk")
from opentelemetry.sdk.trace import TracerProvider  # noqa: E402
from opentelemetry.sdk.trace.export import SimpleSpanProcessor  # noqa: E402
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter  # noqa: E402

from agent_guard import tracing  # noqa: E402
from agent_guard.judge import Judge  # noqa: E402
from agent_guard.policy import Policy  # noqa: E402

POLICY = Policy.from_yaml("""
default: deny
guard_resources: true
ask: {via: deny}
rules:
  - {name: no-etc, tool: delete_file, args: {path: {under: /etc}}, decision: deny, reason: nothing under /etc}
  - {name: confirm, tool: send_mail, decision: ask}
  - {name: files, tool: [read_file, delete_file, resources/read], decision: allow}
""")
TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
PARENT = "00f067aa0ba902b7"
ALLOWED_KEYS = {"mcp.method.name", "gen_ai.tool.name", "agent_guard.decision", "agent_guard.rule",
                "agent_guard.reason", "agent_guard.approved", "jsonrpc.request.id"}


@pytest.fixture
def spans():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracing.use(provider)
    yield exporter
    tracing.use(None)


def call(name, args, i=1, meta=None, method="tools/call"):
    params = {"uri": args} if method == "resources/read" else {"name": name, "arguments": args}
    if meta is not None:
        params["_meta"] = meta
    return {"jsonrpc": "2.0", "id": i, "method": method, "params": params}


def test_a_decision_becomes_a_child_of_the_clients_span(spans):
    judge = Judge(POLICY)
    meta = {"traceparent": f"00-{TRACE}-{PARENT}-01", "io.modelcontextprotocol/protocolVersion": "2026-07-28"}
    assert judge.call(call("read_file", {"path": "/srv/a"}, 1, meta)).action == "allow"
    assert judge.call(call("delete_file", {"path": "/etc/passwd"}, 2, meta)).action == "deny"
    allowed, denied = spans.get_finished_spans()
    assert allowed.name == "agent-guard tools/call read_file" and denied.name == "agent-guard tools/call delete_file"
    for s in (allowed, denied):
        assert format(s.context.trace_id, "032x") == TRACE and format(s.parent.span_id, "016x") == PARENT
    assert dict(allowed.attributes) == {"mcp.method.name": "tools/call", "gen_ai.tool.name": "read_file",
                                        "agent_guard.decision": "allow", "agent_guard.rule": "files",
                                        "jsonrpc.request.id": "1"}
    assert denied.attributes["agent_guard.decision"] == "deny" and denied.attributes["agent_guard.rule"] == "no-etc"
    assert denied.attributes["agent_guard.reason"] == "nothing under /etc"


def test_spans_never_carry_arguments_or_uris(spans):
    judge = Judge(POLICY)
    judge.call(call("read_file", {"path": "/srv/secret-plan.txt", "token": "tok-123"}))
    judge.call(call(None, "file:///srv/private/notes.md", 2, method="resources/read"))
    judge.call(call("delete_file", "not an object", 3))  # malformed
    judge.call(call(None, "file://admin:hunter2@private-host/srv/a", 4, method="resources/read"))  # refused, quotes it
    for s in spans.get_finished_spans():
        assert set(s.attributes) <= ALLOWED_KEYS
        flat = json.dumps(dict(s.attributes)) + s.name
        assert "secret-plan" not in flat and "tok-123" not in flat and "private/notes" not in flat
        assert "hunter2" not in flat and "private-host" not in flat
    names = [s.name for s in spans.get_finished_spans()]
    assert names == ["agent-guard tools/call read_file", "agent-guard resources/read",
                     "agent-guard tools/call delete_file", "agent-guard resources/read"]


def test_spans_never_carry_a_prompts_name_or_arguments(spans):
    judge = Judge(Policy.from_yaml("""
default: deny
guard_prompts: true
rules:
  - {name: no-keys, tool: prompts/get, args: {arguments.q: {glob: "tok-*"}}, decision: deny, reason: no keys}
  - {name: prompts, tool: prompts/get, decision: allow}
"""))
    def get(name, args, i):
        return {"jsonrpc": "2.0", "id": i, "method": "prompts/get", "params": {"name": name, "arguments": args}}
    assert judge.call(get("quarterly-secret-plan", {"q": "hello-private"}, 1)).action == "allow"
    assert judge.call(get("quarterly-secret-plan", {"q": "tok-456"}, 2)).action == "deny"
    assert judge.call(get("quarterly-secret-plan", "tok-789", 3)).action == "deny"  # malformed
    assert judge.call(call("prompts/get", {"q": "tok-000"}, 4)).action == "deny"  # a tool by the reserved name
    for s in spans.get_finished_spans():
        assert set(s.attributes) <= ALLOWED_KEYS
        flat = json.dumps(dict(s.attributes)) + s.name
        assert "secret-plan" not in flat and "private" not in flat and "tok-" not in flat
    assert [s.name for s in spans.get_finished_spans()] == ["agent-guard prompts/get"] * 3 + \
        ["agent-guard tools/call prompts/get"]
    assert [s.attributes["agent_guard.rule"] for s in spans.get_finished_spans()] == \
        ["prompts", "no-keys", "malformed", "reserved"]


def test_client_chosen_names_and_ids_are_capped(spans):
    Judge(POLICY).call(call("x" * 5000, {}, "i" * 5000))
    [s] = spans.get_finished_spans()
    assert len(s.attributes["gen_ai.tool.name"]) == 200 and len(s.attributes["jsonrpc.request.id"]) == 100
    assert len(s.name) < 250


def test_no_or_broken_trace_context_gives_a_root_span(spans):
    judge = Judge(POLICY)
    judge.call(call("read_file", {}, 1))
    judge.call(call("read_file", {}, 2, {"traceparent": "00-zzzz-yyyy-01"}))
    judge.call(call("read_file", {}, 3, {"traceparent": ["not", "a", "string"]}))
    assert [s.parent for s in spans.get_finished_spans()] == [None, None, None]


def test_an_ask_records_the_question_and_the_answer(spans):
    judge = Judge(POLICY)
    msg = call("send_mail", {"to": "x"})
    v = judge.call(msg)
    assert v.action == "ask" and judge.ask(msg, v).action == "deny"
    asked, answered = spans.get_finished_spans()
    assert asked.attributes["agent_guard.decision"] == "ask"
    assert answered.name == "agent-guard approval tools/call send_mail" or answered.name.startswith("agent-guard approval")
    assert answered.attributes["agent_guard.approved"] is False


class Exploding:
    def start_span(self, *a, **k):
        raise RuntimeError("tracing backend on fire")


def test_tracing_errors_never_change_a_decision():
    judge = Judge(POLICY)
    tracing._tracer = Exploding()
    try:
        assert judge.call(call("read_file", {})).action == "allow"
        assert judge.call(call("delete_file", {"path": "/etc/x"})).action == "deny"
    finally:
        tracing._tracer = None


# ---- one trace across the agent, the guard and the server --------------------------------------------------------

CALLS = (("read_file", {"path": "/srv/a"}), ("drop_database", {"name": "prod"}))  # the rig allows one, denies one
_client = None


def client_tracing():
    """The agent's own tracing, shared by the tests below: OpenTelemetry lets the global provider be set once per
    process. The SDK client puts the span that is current into each request's _meta."""
    global _client
    from opentelemetry import trace

    if _client is None:
        exporter, provider = InMemorySpanExporter(), TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _client = (provider, exporter)
    _client[1].clear()
    return _client


@contextmanager
def one_trace(tmp_path):
    """The gateway in front of an SDK server, both exporting to a stand-in collector. Gives the rig and a dict that
    holds, once the block ends, what the two of them sent: trace id -> [(service, span name, span id, parent id)]."""
    from test_gateway import Rig, free_port, wait_port
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

    port, out = free_port(), tmp_path / "otlp.b64"
    collector = subprocess.Popen([sys.executable, os.path.join(os.path.dirname(__file__), "fake_collector.py"),
                                  str(port), str(out)], stderr=subprocess.DEVNULL)
    wait_port(port, collector)
    env = {"OTEL_EXPORTER_OTLP_ENDPOINT": f"http://127.0.0.1:{port}"}
    old = {k: os.environ.get(k) for k in env}
    os.environ.update(env)  # the SDK server inherits it from here
    try:
        r = Rig(tmp_path, upstream="sdk", mode="json", env=env)
    finally:
        for k, v in old.items():
            os.environ.pop(k) if v is None else os.environ.__setitem__(k, v)
    seen: dict = {}
    try:
        yield r, seen
    finally:
        r.close()  # both flush their spans on the way out
        for _ in range(50):
            if out.exists() and out.read_text().count("\n") >= 2:
                break
            time.sleep(0.1)
        collector.terminate()
        collector.wait()
        for line in out.read_text().split() if out.exists() else ():
            req = ExportTraceServiceRequest.FromString(base64.b64decode(line))
            for rs in req.resource_spans:
                service = next(a.value.string_value for a in rs.resource.attributes if a.key == "service.name")
                for ss in rs.scope_spans:
                    for s in ss.spans:
                        seen.setdefault(s.trace_id.hex(), []).append(
                            (service, s.name, s.span_id.hex(), s.parent_span_id.hex()))


def test_agent_guard_and_server_in_one_trace(tmp_path):
    pytest.importorskip("mcp")
    pytest.importorskip("opentelemetry.exporter.otlp.proto.http")
    import anyio
    from mcp.client.client import Client

    tracer = client_tracing()[0].get_tracer("agent")
    ids = {}

    async def session(url):
        async with Client(url, mode="auto") as c:
            for name, args in CALLS:
                with tracer.start_as_current_span(f"agent step {name}") as step:
                    ids[name] = format(step.get_span_context().trace_id, "032x")
                    await c.call_tool(name, args)

    with one_trace(tmp_path) as (r, seen):
        anyio.run(session, r.url)
    names = {t: [(service, name) for service, name, _, _ in spans] for t, spans in seen.items()}
    assert ("agent-guard", "agent-guard tools/call read_file") in names[ids["read_file"]]
    assert ("sdk-demo-server", "tools/call read_file") in names[ids["read_file"]]
    assert names[ids["drop_database"]] == [("agent-guard", "agent-guard tools/call drop_database")]  # no server span


def test_with_agent_otel_a_decision_hangs_under_the_tool_call_that_caused_it(tmp_path):
    """agent-otel (github.com/Ahmedabied/agent-otel) records the agent's side of a run: the run, its model calls and
    its tool calls. The tool span is the current one when the SDK client sends the call, so the guard's decision
    lands under it with no glue between the two: one trace says what the agent tried and what the guard decided."""
    ao = pytest.importorskip("agent_otel")
    pytest.importorskip("mcp")
    pytest.importorskip("opentelemetry.exporter.otlp.proto.http")
    import anyio
    from mcp.client.client import Client

    provider, exporter = client_tracing()
    ao.configure(tracer_provider=provider)

    async def session(url):
        async with Client(url, mode="auto") as c:
            with ao.agent("ops-agent"):
                for name, args in CALLS:
                    with ao.tool_call(name):
                        await c.call_tool(name, args)

    try:
        with one_trace(tmp_path) as (r, seen):
            anyio.run(session, r.url)
    finally:
        ao.configure()
    agent_side = {s.name: s for s in exporter.get_finished_spans()}
    parent_of = {format(s.context.span_id, "016x"): format(s.parent.span_id, "016x") if s.parent else ""
                 for s in exporter.get_finished_spans()}
    run = agent_side["invoke_agent ops-agent"]
    sent = seen[format(run.context.trace_id, "032x")]  # the whole run is one trace
    for name in ("read_file", "drop_database"):
        tool = format(agent_side[f"execute_tool {name}"].context.span_id, "016x")
        up = next(parent for _, span, _, parent in sent if span == f"agent-guard tools/call {name}")
        while up in parent_of and up != tool:  # past any span the SDK client made for the request itself
            up = parent_of[up]
        assert up == tool
    assert ("sdk-demo-server", "tools/call read_file") in [(service, span) for service, span, _, _ in sent]
    assert not [span for service, span, _, _ in sent if service == "sdk-demo-server" and "drop_database" in span]


def test_a_collector_that_is_down_changes_nothing(tmp_path):
    pytest.importorskip("opentelemetry.exporter.otlp.proto.http")
    from test_gateway import CALL, Rig, free_port

    dead = free_port()  # nothing listens here
    r = Rig(tmp_path, env={"OTEL_EXPORTER_OTLP_ENDPOINT": f"http://127.0.0.1:{dead}"})
    try:
        t0 = time.perf_counter()
        ok = r.post(CALL)
        denied = r.post({**CALL, "id": 2, "params": {"name": "drop_database", "arguments": {}}})
        assert time.perf_counter() - t0 < 1
        assert ok.json()["result"]["content"][0]["text"] == "ran read_file"
        assert denied.json()["result"]["isError"] is True
        time.sleep(1.5)  # the first export attempt fails in the background
        assert r.post({**CALL, "id": 3}).status_code == 200
    finally:
        t0 = time.perf_counter()
        r.close()
        assert time.perf_counter() - t0 < 9  # gives up on the last spans instead of hanging
