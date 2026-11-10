"""agent-guard serve: the HTTP gateway. Each refusal is checked at the upstream too: what the gateway refuses
must never arrive there."""

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

httpx2 = pytest.importorskip("httpx2")
pytest.importorskip("starlette")
pytest.importorskip("uvicorn")
anyio = pytest.importorskip("anyio")

from agent_guard.audit import verify  # noqa: E402

HERE = Path(__file__).parent
POLICY = """
default: deny
hide_denied_tools: true
rules:
  - {name: no-etc, tool: delete_file, args: {path: {under: /etc}}, decision: deny, reason: nothing under /etc}
  - {name: burst, tool: read_file, rate: 5/minute, decision: deny, reason: more than 5 reads a minute}
  - {name: files, tool: [read_file, delete_file, "lire_*", forecast], decision: allow}
"""
CALL = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "/a"}}}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port: int, proc: subprocess.Popen) -> None:
    for _ in range(200):
        if proc.poll() is not None:
            raise RuntimeError(f"process exited {proc.returncode}: {proc.stderr.read().decode()[:2000]}")
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.1).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"nothing listening on {port}")


class Rig:
    """An upstream (fake or the SDK's) and the gateway in front of it."""

    def __init__(self, tmp_path, upstream="fake", mode="json", policy=POLICY, extra=(), env=None):
        self.tmp = tmp_path
        self.procs = []
        self.upstream_log = tmp_path / "upstream.jsonl"
        self.audit = tmp_path / "audit.jsonl"
        (tmp_path / "guard.yaml").write_text(policy)
        up = free_port()
        if upstream == "fake":
            self._start([sys.executable, str(HERE / "fake_upstream.py"), str(up), str(self.upstream_log)], up)
            url = f"http://127.0.0.1:{up}/{mode}"
        else:
            self._start([sys.executable, str(HERE / "sdk_http_server.py"), str(up), mode], up)
            url = f"http://127.0.0.1:{up}/mcp"
        self.port = free_port()
        self.url = f"http://127.0.0.1:{self.port}/mcp"
        self._start([sys.executable, "-m", "agent_guard", "serve", "-q", "-p", str(tmp_path / "guard.yaml"),
                     "--upstream", url, "--listen", f"127.0.0.1:{self.port}", "--log", str(self.audit), *extra],
                    self.port, env)

    def _start(self, cmd, port, env=None):
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                             env={**os.environ, **(env or {})})
        self.procs.append(p)
        wait_port(port, p)

    def post(self, body, headers=None, raw=None):
        h = [("content-type", "application/json"), ("accept", "application/json, text/event-stream")]
        h += list(headers.items()) if isinstance(headers, dict) else list(headers or [])
        content = raw if raw is not None else json.dumps(body).encode()
        return httpx2.post(self.url, content=content, headers=h, timeout=10)

    def upstream_requests(self):
        if not self.upstream_log.exists():
            return []
        return [json.loads(line) for line in self.upstream_log.read_text().splitlines()]

    def audit_entries(self):
        return [json.loads(line) for line in self.audit.read_text().splitlines()] if self.audit.exists() else []

    def close(self):
        for p in self.procs:
            p.terminate()
        for p in self.procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()


@pytest.fixture
def rig(tmp_path, request):
    rigs = []

    def make(**kw):
        r = Rig(tmp_path, **kw)
        rigs.append(r)
        return r

    yield make
    for r in rigs:
        r.close()


# ---- the official SDK on both sides ---------------------------------------------------------------------------

@pytest.mark.parametrize("answers", ["sse", "json"])
@pytest.mark.parametrize("mode", ["legacy", "auto"])
def test_sdk_client_through_gateway(rig, mode, answers):
    pytest.importorskip("mcp")
    from mcp.client.client import Client

    r = rig(upstream="sdk", mode=answers)
    seen = {}

    async def session():
        async with Client(r.url, mode=mode) as c:
            seen["tools"] = sorted(t.name for t in (await c.list_tools()).tools)
            seen["read"] = await c.call_tool("read_file", {"path": "/srv/a.txt"})
            seen["delete"] = await c.call_tool("delete_file", {"path": "/etc/passwd"})
            seen["drop"] = await c.call_tool("drop_database", {"name": "prod"})

    anyio.run(session)
    assert seen["tools"] == ["delete_file", "forecast", "read_file"]  # drop_database is hidden
    assert not seen["read"].is_error and seen["read"].content[0].text == "contents of /srv/a.txt"
    assert seen["delete"].is_error and "nothing under /etc" in seen["delete"].content[0].text
    assert seen["drop"].is_error and "default is deny" in seen["drop"].content[0].text
    events = [(e["event"], e.get("tool"), e.get("decision", e.get("ok"))) for e in r.audit_entries()]
    assert events == [("call", "read_file", "allow"), ("result", "read_file", True),
                      ("call", "delete_file", "deny"), ("call", "drop_database", "deny")]
    assert verify(r.audit).ok


# ---- what the upstream receives --------------------------------------------------------------------------------

def test_upstream_gets_the_judged_message_and_only_mcp_headers(rig):
    r = rig(extra=["--upstream-header", "Authorization=UP_TOKEN"], env={"UP_TOKEN": "Bearer upstream-secret-1"})
    raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/a"}}}'
    res = r.post(None, raw=b"  " + raw.replace(b",", b", "), headers=[
        ("authorization", "Bearer client-secret-2"), ("cookie", "sid=cookie-secret-3"),
        ("x-forwarded-for", "10.0.0.1"), ("mcp-session-id", "session-secret-4"), ("mcp-param-region", "eu")])
    assert res.status_code == 200 and res.json()["result"]["content"][0]["text"] == "ran read_file"
    [got] = r.upstream_requests()
    headers = dict(got["headers"])
    assert got["body"] == raw.decode()  # re-serialised from the parse the policy judged
    assert headers["authorization"] == "Bearer upstream-secret-1"  # the client's own token is never forwarded
    assert "cookie" not in headers and "x-forwarded-for" not in headers
    assert headers["mcp-session-id"] == "session-secret-4"
    assert "mcp-param-region" not in headers  # the gateway builds these itself, and only on 2026-07-28
    log = r.audit.read_text()
    for secret in ("upstream-secret-1", "client-secret-2", "cookie-secret-3", "session-secret-4"):
        assert secret not in log


def test_sse_answers_pass_through_with_the_result_logged(rig):
    r = rig(mode="sse")
    res = r.post(CALL)
    assert res.headers["content-type"].startswith("text/event-stream")
    events = [e for e in res.text.split("\n\n") if e.strip()]
    assert events[0] == ": ping" and '"notifications/message"' in events[1]
    assert json.loads(events[2].split("data: ", 1)[1])["result"]["content"][0]["text"] == "ran read_file"
    assert [(e["event"], e.get("ok")) for e in r.audit_entries()] == [("call", None), ("result", True)]
    listed = r.post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    data = [e for e in listed.text.split("\n\n") if e.startswith("event: message\nid: 7")][0]
    assert [t["name"] for t in json.loads(data.split("data: ", 1)[1])["result"]["tools"]] == ["read_file", "forecast"]


# ---- Mcp-Param headers (2026-07-28) ----------------------------------------------------------------------------

META = {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
MODERN = {"mcp-protocol-version": "2026-07-28", "mcp-method": "tools/call", "mcp-name": "forecast"}


def forecast(region, i=1):
    return {"jsonrpc": "2.0", "id": i, "method": "tools/call",
            "params": {"name": "forecast", "arguments": {"region": region}, "_meta": META}}


@pytest.mark.parametrize("mode", ["legacy", "auto"])
def test_sdk_mcp_param_headers_are_rebuilt_so_the_server_accepts_them(rig, mode):
    pytest.importorskip("mcp")
    from mcp.client.client import Client

    r = rig(upstream="sdk", mode="json")
    seen = {}

    async def session():
        async with Client(r.url, mode=mode) as c:
            seen["r"] = await c.call_tool("forecast", {"region": "eu-west é", "days": 3})

    anyio.run(session)  # on 2026-07-28 the SDK server refuses a call whose Mcp-Param headers are missing or wrong
    assert not seen["r"].is_error and seen["r"].content[0].text == "sunny in eu-west é for 3 days"


def test_a_forged_mcp_param_header_is_replaced_by_the_judged_value(rig):
    r = rig()
    listed = r.post({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"_meta": META}},
                    headers={"mcp-protocol-version": "2026-07-28", "mcp-method": "tools/list"})
    assert listed.status_code == 200
    res = r.post(forecast("eu", 2), headers={**MODERN, "mcp-param-region": "us"})
    assert res.status_code == 200 and res.json()["result"]["content"][0]["text"] == "ran forecast"
    calls = [q for q in r.upstream_requests() if '"tools/call"' in q["body"]]
    assert [[v for k, v in q["headers"] if k == "mcp-param-region"] for q in calls] == [["eu"]]
    assert sum('"tools/list"' in q["body"] for q in r.upstream_requests()) == 1  # learned from the client's list


def test_the_gateway_looks_up_a_schema_it_has_not_seen(rig):
    r = rig()
    res = r.post(forecast("åland"), headers={**MODERN, "mcp-param-region": "anything"})
    assert res.status_code == 200
    first, call = r.upstream_requests()
    listing = json.loads(first["body"])
    assert listing["method"] == "tools/list"
    assert listing["params"]["_meta"]["io.modelcontextprotocol/clientInfo"]["name"] == "agent-guard"  # not the client's
    from agent_guard.params import decode
    assert decode(dict(call["headers"])["mcp-param-region"]) == "åland"


def test_mcp_param_headers_for_a_tool_the_server_does_not_list_are_refused(rig):
    r = rig()
    body = {**forecast("eu"), "params": {"name": "lire_secret", "arguments": {"path": "/a"}, "_meta": META}}
    res = r.post(body, headers={**MODERN, "mcp-name": "lire_secret", "mcp-param-path": "/etc/passwd"})
    assert res.status_code == 400 and res.json()["error"]["code"] == -32020
    assert [json.loads(q["body"])["method"] for q in r.upstream_requests()] == ["tools/list"]  # never the call
    assert r.audit_entries()[-1]["error"].startswith("refused: cannot check the Mcp-Param headers")
    again = r.post({**body, "id": 2}, headers={**MODERN, "mcp-name": "lire_secret", "mcp-param-path": "/etc/passwd"})
    assert again.status_code == 400 and len(r.upstream_requests()) == 1  # the miss is remembered for a while


def test_a_denied_call_sends_nothing_upstream_not_even_a_schema_lookup(rig):
    r = rig()
    body = {**forecast("eu"), "params": {"name": "drop_database", "arguments": {"name": "prod"}, "_meta": META}}
    res = r.post(body, headers={**MODERN, "mcp-name": "drop_database", "mcp-param-name": "prod"})
    assert res.status_code == 200 and res.json()["result"]["isError"] is True
    assert r.upstream_requests() == []


def test_a_listed_tool_without_annotations_gets_no_mcp_param_headers(rig):
    r = rig()
    res = r.post(CALL | {"params": {**CALL["params"], "_meta": META}},
                 headers={**MODERN, "mcp-name": "read_file", "mcp-param-path": "/etc/passwd"})
    assert res.status_code == 200
    call = [q for q in r.upstream_requests() if '"tools/call"' in q["body"]][0]
    assert not [k for k, _ in call["headers"] if k.startswith("mcp-param-")]


# ---- refusals: none of them reaches the upstream ----------------------------------------------------------------

@pytest.mark.parametrize("headers, why", [
    ({"mcp-method": "tools/list"}, "Mcp-Method"),
    ({"mcp-name": "list_files"}, "Mcp-Name"),
    ({"mcp-name": "=?base64?bGlzdF9maWxlcw==?="}, "Mcp-Name"),  # list_files, encoded
    ([("mcp-name", "read_file"), ("mcp-name", "delete_file")], "more than once"),
    ({"mcp-protocol-version": "2025-11-25"}, "MCP-Protocol-Version"),
])
def test_routing_headers_must_match_the_body(rig, headers, why):
    r = rig()
    body = {**CALL, "params": {**CALL["params"], "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}}}
    res = r.post(body, headers=headers)
    assert res.status_code == 400 and res.json()["error"]["code"] == -32020 and why in res.json()["error"]["message"]
    assert r.upstream_requests() == []


def test_matching_routing_headers_pass_encoded_as_the_sdk_does(rig):
    pytest.importorskip("mcp")
    from mcp.shared.inbound import encode_header_value

    r = rig()
    name = "lire_fichier_é"
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": {}}}
    res = r.post(body, headers={"mcp-method": "tools/call", "mcp-name": encode_header_value(name)})
    assert res.status_code == 200 and res.json()["result"]["content"][0]["text"] == f"ran {name}"
    assert len(r.upstream_requests()) == 1


@pytest.mark.parametrize("kind", ["host", "origin", "origin-null", "content-type", "gzip", "too-big", "too-big-chunked",
                                  "batch", "not-json", "duplicate-key"])
def test_refused_requests_never_reach_the_upstream(rig, kind):
    r = rig(extra=["--max-body", "2000"])
    body, headers, raw, status = CALL, [], None, 400
    if kind == "host":
        headers, status = [("host", f"rebind.example:{r.port}")], 421
    elif kind == "origin":
        headers, status = [("origin", "http://evil.example")], 403
    elif kind == "origin-null":
        headers, status = [("origin", "null")], 403
    elif kind == "content-type":
        res = httpx2.post(r.url, content=json.dumps(CALL), headers={"content-type": "text/plain"}, timeout=10)
        assert res.status_code == 415 and r.upstream_requests() == []
        return
    elif kind == "gzip":
        headers, status = [("content-encoding", "gzip")], 415
    elif kind == "too-big":
        body, status = {**CALL, "params": {"name": "read_file", "arguments": {"path": "x" * 3000}}}, 413
    elif kind == "too-big-chunked":  # no Content-Length to go by: counted while reading
        big = json.dumps({**CALL, "params": {"name": "read_file", "arguments": {"path": "x" * 3000}}}).encode()
        raw, status = (big[i:i + 500] for i in range(0, len(big), 500)), 413
    elif kind == "batch":
        raw = json.dumps([CALL]).encode()
    elif kind == "not-json":
        raw = b'{"jsonrpc": "2.0", "id": 5, "method": '
    elif kind == "duplicate-key":
        raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","name":"drop_database"}}'
    res = r.post(body, headers=headers, raw=raw)
    assert res.status_code == status, res.text
    assert r.upstream_requests() == []


def test_an_origin_of_the_gateway_itself_is_fine(rig):
    r = rig()
    assert r.post(CALL, headers={"origin": f"http://localhost:{r.port}"}).status_code == 200


def test_redirects_are_not_followed(rig):
    r = rig(mode="redirect")
    res = r.post(CALL)
    assert res.status_code == 502 and "redirect" in res.json()["error"]["message"]
    assert [q["path"] for q in r.upstream_requests()] == ["/redirect"]
    assert r.audit_entries()[-1]["error"] == "upstream redirect 307 not followed"


def test_rate_limits_hold_under_parallel_requests(rig):
    r = rig()
    results = []

    async def one(client, i):
        body = {**CALL, "id": i}
        res = await client.post(r.url, json=body, headers={"accept": "application/json, text/event-stream"})
        results.append(res.json()["result"]["isError"])

    async def burst():
        async with httpx2.AsyncClient(timeout=10) as client, anyio.create_task_group() as tg:
            for i in range(20):
                tg.start_soon(one, client, i)

    anyio.run(burst)
    assert results.count(False) == 5 and results.count(True) == 15
    assert len(r.upstream_requests()) == 5
    assert verify(r.audit).ok


def test_unreachable_upstream_is_a_502_and_logged(rig, tmp_path):
    r = rig()
    r.procs[0].terminate()
    r.procs[0].wait(timeout=5)
    res = r.post(CALL)
    assert res.status_code == 502 and res.json()["id"] == 1
    assert r.audit_entries()[-1]["error"].startswith("upstream unreachable")


@pytest.mark.parametrize("args, why", [
    (["--listen", "0.0.0.0:8808"], "loopback only"),
    (["--upstream", "http://example.com/mcp"], "plain http"),
    (["--upstream", "https://user:pw@example.com/mcp"], "user or password"),
    (["--upstream-header", "Authorization=AG_TEST_UNSET_VAR"], "is not set"),
])
def test_serve_refuses_unsafe_setups(tmp_path, args, why):
    (tmp_path / "guard.yaml").write_text(POLICY)
    cmd = [sys.executable, "-m", "agent_guard", "serve", "-p", str(tmp_path / "guard.yaml"),
           "--upstream", "http://127.0.0.1:9/mcp", *args]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=20, env={k: v for k, v in os.environ.items()
                                                                              if k != "AG_TEST_UNSET_VAR"})
    assert p.returncode == 2 and why in p.stderr


# ---- the same policy features as the stdio proxy ----------------------------------------------------------------

ASK_POLICY = f"""
default: deny
ask: {{via: command, command: [{json.dumps(sys.executable)}, -c, "import sys, json; d = json.load(sys.stdin); sys.exit(0 if d['arguments']['text'] == 'yes' else 1)"]}}
rules:
  - {{name: confirm, tool: echo, decision: ask, reason: echo needs a yes}}
"""


def test_ask_runs_the_approver_and_only_an_approved_call_reaches_the_server(rig):
    r = rig(policy=ASK_POLICY)
    call = {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "echo", "arguments": {}}}
    yes = r.post({**call, "id": 1, "params": {"name": "echo", "arguments": {"text": "yes"}}})
    no = r.post({**call, "id": 2, "params": {"name": "echo", "arguments": {"text": "no"}}})
    assert yes.json()["result"]["content"][0]["text"] == "ran echo"
    assert no.json()["result"]["isError"] is True and "not approved" in no.json()["result"]["content"][0]["text"]
    assert [json.loads(q["body"])["params"]["arguments"]["text"] for q in r.upstream_requests()] == ["yes"]
    assert [e["approved"] for e in r.audit_entries() if e["event"] == "approval"] == [True, False]


PROMPT_ASK_POLICY = f"""
default: deny
guard_prompts: true
ask: {{via: command, command: [{json.dumps(sys.executable)}, -c, "import sys, json; d = json.load(sys.stdin); sys.exit(0 if d['arguments']['arguments']['ok'] == 'yes' else 1)"]}}
rules:
  - {{name: confirm-prompt, tool: prompts/get, decision: ask, reason: prompts need a yes}}
"""


def test_ask_on_a_prompt_sends_only_the_approved_one(rig):
    r = rig(policy=PROMPT_ASK_POLICY)
    get = {"jsonrpc": "2.0", "method": "prompts/get"}
    yes = r.post({**get, "id": 1, "params": {"name": "plan", "arguments": {"ok": "yes"}}})
    no = r.post({**get, "id": 2, "params": {"name": "plan", "arguments": {"ok": "no"}}})
    assert yes.json() == {"jsonrpc": "2.0", "id": 1, "result": {}}
    assert no.json()["error"]["code"] == -32001 and "not approved" in no.json()["error"]["message"]
    assert [json.loads(q["body"])["params"]["arguments"]["ok"] for q in r.upstream_requests()] == ["yes"]
    assert [e["approved"] for e in r.audit_entries() if e["event"] == "approval"] == [True, False]


RESOURCE_POLICY = """
default: deny
guard_resources: true
rules:
  - {name: no-secrets, tool: resources/read, args: {path: {under: /srv/secrets}}, decision: deny, reason: secrets stay put}
  - {name: docs, tool: resources/read, args: {scheme: file}, decision: allow}
"""


@pytest.mark.parametrize("modern", [False, True])
def test_resources_read_is_judged_over_http(rig, modern):
    from agent_guard.params import encode

    r = rig(policy=RESOURCE_POLICY)

    def read(uri, i):
        p = {"uri": uri}
        headers = {}
        if modern:
            p["_meta"] = META
            headers = {"mcp-protocol-version": "2026-07-28", "mcp-method": "resources/read", "mcp-name": encode(uri)}
        return r.post({"jsonrpc": "2.0", "id": i, "method": "resources/read", "params": p}, headers=headers)

    ok = read("file:///srv/docs/a.md", 1)
    sneaky = read("file:///srv/docs/%2e%2e/secrets/key.pem", 2)
    other = read("https://example.com/x", 3)
    assert ok.status_code == 200 and "error" not in ok.json()
    assert sneaky.json()["error"]["code"] == -32001 and "secrets stay put" in sneaky.json()["error"]["message"]
    assert other.json()["error"]["code"] == -32001
    assert [json.loads(q["body"])["params"]["uri"] for q in r.upstream_requests()] == ["file:///srv/docs/a.md"]


PROMPT_POLICY = """
default: allow
guard_prompts: true
rules:
  - {name: no-env, tool: prompts/get, args: {name: leak_env}, decision: deny, reason: no environment in prompts}
"""


@pytest.mark.parametrize("answers", ["sse", "json"])
@pytest.mark.parametrize("mode", ["legacy", "auto"])
def test_sdk_prompts_are_judged_over_http(rig, mode, answers):
    pytest.importorskip("mcp")
    from mcp.client.client import Client
    from mcp.shared.exceptions import MCPError

    r = rig(upstream="sdk", mode=answers, policy=PROMPT_POLICY)
    seen = {}

    async def session():
        async with Client(r.url, mode=mode) as c:
            seen["review"] = await c.get_prompt("review", {"code": "x = 1"})
            try:
                await c.get_prompt("leak_env")
            except MCPError as e:
                seen["leak"] = e

    anyio.run(session)
    assert seen["review"].messages[0].content.text == "review this: x = 1"
    assert seen["leak"].error.code == -32001 and "no environment in prompts" in seen["leak"].error.message
    events = [(e["event"], e.get("tool"), e.get("decision", e.get("ok"))) for e in r.audit_entries()]
    assert events == [("call", "prompts/get", "allow"), ("result", "prompts/get", True),
                      ("call", "prompts/get", "deny")]
    assert verify(r.audit).ok


def test_a_modern_prompts_get_is_sent_once_with_no_mcp_param_headers(rig):
    # Mcp-Param headers belong to tools/call: a prompt named like a tool must not cause a tools/list lookup or carry
    # that tool's headers, and a client's own copies are dropped as always.
    r = rig(policy=PROMPT_POLICY)
    headers = {"mcp-protocol-version": "2026-07-28", "mcp-method": "prompts/get", "mcp-name": "forecast",
               "mcp-param-region": "eu"}
    body = {"jsonrpc": "2.0", "id": 7, "method": "prompts/get",
            "params": {"name": "forecast", "arguments": {"region": "us"}, "_meta": META}}
    assert r.post(body, headers=headers).status_code == 200
    denied = {**body, "id": 8, "params": {**body["params"], "name": "leak_env"}}
    reply = r.post(denied, headers={**headers, "mcp-name": "leak_env"})
    assert reply.json()["error"]["code"] == -32001
    sent = r.upstream_requests()
    assert [json.loads(q["body"])["method"] for q in sent] == ["prompts/get"]  # no lookup, not the denied one
    assert not [k for k, _ in sent[0]["headers"] if k.lower().startswith("mcp-param-")]


# ---- many long-lived streams --------------------------------------------------------------------------------------

def test_open_server_streams_never_starve_calls_and_close_with_their_clients(rig):
    """Every 2025 session keeps a GET stream open for server messages. 120 of them (more than an HTTP client's
    usual pool of 100) must not hold up a call, and must be closed upstream when their clients go."""
    r = rig(mode="hold")
    gateway = r.procs[1].pid
    fds = lambda: len(os.listdir(f"/proc/{gateway}/fd"))  # noqa: E731
    assert r.post(CALL).status_code == 200
    baseline = fds()
    clients = []
    for _ in range(120):
        s = socket.create_connection(("127.0.0.1", r.port))
        s.sendall(f"GET /mcp HTTP/1.1\r\nHost: 127.0.0.1:{r.port}\r\nAccept: text/event-stream\r\n\r\n".encode())
        clients.append(s)
    for s in clients:  # each stream is open end to end
        s.settimeout(10)
        assert s.recv(15) == b"HTTP/1.1 200 OK"
    t0 = time.perf_counter()
    assert r.post({**CALL, "id": 2}).status_code == 200
    assert time.perf_counter() - t0 < 2
    for s in clients:
        s.close()
    for _ in range(100):
        if fds() <= baseline + 2:
            break
        time.sleep(0.1)
    assert fds() <= baseline + 2
