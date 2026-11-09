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
  - {name: files, tool: [read_file, delete_file, "lire_*"], decision: allow}
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
    assert seen["tools"] == ["delete_file", "read_file"]  # drop_database is hidden
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
    assert headers["mcp-session-id"] == "session-secret-4" and headers["mcp-param-region"] == "eu"
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
    assert [t["name"] for t in json.loads(data.split("data: ", 1)[1])["result"]["tools"]] == ["read_file"]


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
