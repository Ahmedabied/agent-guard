"""The HTTP gateway: agent-guard in front of a Streamable HTTP MCP server.

    agent-guard serve -p guard.yaml --upstream https://mcp.example.com/mcp

The client connects to http://127.0.0.1:8808/mcp instead of the server. Every POST is judged by the same Judge as
the stdio proxy before anything reaches the upstream, and a denied call is answered here. It speaks both wires the
MCP SDK speaks: the 2025 one (initialize, Mcp-Session-Id, answers as SSE or JSON, a GET stream, DELETE) and
2026-07-28 (one self-contained POST per request, with the Mcp-Method and Mcp-Name routing headers).

What it refuses, and why:
- Anything not on loopback. It has no client authentication of its own, so on a network anyone could use the
  upstream through it. Host and Origin are checked too (DNS rebinding), as the MCP transport spec requires.
- A body it cannot judge: not application/json, compressed, over the size cap, not strict JSON, or a batch.
- Routing headers that disagree with the body (Mcp-Method, Mcp-Name, MCP-Protocol-Version) or appear twice. A
  server that routes on the header while the guard judges the body would run a call nobody judged.
- Redirects from the upstream (not followed), and plain http to anything but loopback.
The upstream request is built here from the judged message: the body is re-serialised from the parse the policy
saw, and only known MCP headers are copied. The client's Authorization is never forwarded; give the upstream its
own credentials with --upstream-header NAME=ENVVAR (the value is read from the environment, never logged).
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import os
import re
import sys
import time
from typing import Any, AsyncIterator
from urllib.parse import urlsplit

import anyio
import httpx2
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse
from starlette.routing import Route

from .judge import Judge, _line, parse_strict, recover_id

PATH = "/mcp"
MAX_BODY = 4 * 1024 * 1024  # the MCP SDK's own default request cap
MAX_ANSWER = 64 * 1024 * 1024  # one JSON answer or one SSE event from the upstream
NAME_PARAM = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}
ROUTING = ("mcp-method", "mcp-name", "mcp-protocol-version")
VERSION_META = "io.modelcontextprotocol/protocolVersion"
HEADER_MISMATCH = -32020  # the MCP SDK's code for a routing header that disagrees with the body

# Request headers copied to the upstream. Everything else (Cookie, Authorization, Forwarded, hop-by-hop) stays here.
COPY_REQUEST = ("accept", "mcp-session-id", "mcp-protocol-version", "mcp-method", "mcp-name", "last-event-id")
COPY_RESPONSE = ("content-type", "mcp-session-id", "cache-control")


class GatewayError(ValueError):
    pass


def is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def check_upstream(url: str) -> str:
    u = urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise GatewayError(f"--upstream must be an http(s) URL, got {url!r}")
    if u.username or u.password:
        raise GatewayError("--upstream must not carry a user or password; use --upstream-header NAME=ENVVAR")
    if u.scheme == "http" and not is_loopback(u.hostname):
        raise GatewayError(f"plain http is only allowed to loopback; use https for {u.hostname}")
    return url


def decode_header_value(value: str) -> str | None:
    """The MCP header value codec: printable ASCII as is, anything else as =?base64?...?= (None if malformed)."""
    m = re.fullmatch(r"=\?base64\?(.*)\?=", value)
    if m is None:
        return value
    try:
        raw = base64.b64decode(m.group(1), validate=True)
        if base64.b64encode(raw).decode("ascii") != m.group(1):
            return None
        return raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None


def _error(msg_id: Any, code: int, message: str, status: int) -> Response:
    body = {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": f"agent-guard: {message}"}}
    return Response(_line(body), status_code=status, media_type="application/json")


def _plain(status: int, text: str) -> Response:
    return Response(f"agent-guard: {text}\n", status_code=status, media_type="text/plain")


class Watch:
    """What one POST is waiting for in the upstream's answer: the result of an allowed call (to log it) and a
    tools/list result (to hide denied tools)."""

    def __init__(self, judge: Judge, call: tuple | None, list_id: str | None):
        self.judge = judge
        self.call = call  # (key, id, name, t0) of an allowed call
        self.list_id = list_id
        self.logged = False

    def inspect(self, item: Any) -> bool:
        """Look at one message from the upstream. True if it was changed (and must be re-serialised)."""
        if not isinstance(item, dict) or "method" in item or "id" not in item:
            return False
        key = json.dumps(item["id"], sort_keys=True)
        if self.call and key == self.call[0] and not self.logged:
            self.logged = True
            self.judge.result(self.call[1], self.call[2], self.call[3], item)
        if self.list_id is not None and key == self.list_id:
            return self.judge.filter_tools(item)
        return False

    def unanswered(self, why: str) -> None:
        if self.call and not self.logged:
            self.logged = True
            self.judge.log({"event": "result", "id": self.call[1], "tool": self.call[2], "ok": False,
                            "us": (time.perf_counter_ns() - self.call[3]) // 1000, "error": why})


class Gateway:
    def __init__(
        self,
        judge: Judge,
        upstream: str,
        port: int,
        upstream_headers: dict[str, str] | None = None,
        max_body: int = MAX_BODY,
        allow_origins: list[str] | None = None,
        connect_timeout: float = 10,
    ):
        self.judge = judge
        self.upstream = check_upstream(upstream)
        self.port = port
        self.upstream_headers = {k.lower(): v for k, v in (upstream_headers or {}).items()}
        self.max_body = max_body
        names = ("127.0.0.1", "localhost", "[::1]")
        self.hosts = {f"{n}:{port}" for n in names}
        self.origins = {f"http://{n}:{port}" for n in names} | set(allow_origins or [])
        self.client = httpx2.AsyncClient(
            follow_redirects=False,
            timeout=httpx2.Timeout(connect=connect_timeout, read=None, write=30, pool=connect_timeout),
        )
        self.app = Starlette(routes=[Route(PATH, self.handle, methods=["GET", "POST", "DELETE"])])

    # ---- checks ---------------------------------------------------------------------------

    def _refuse_origin(self, request: Request) -> Response | None:
        hosts = request.headers.getlist("host")
        if len(hosts) != 1 or hosts[0].lower() not in self.hosts:
            return _plain(421, "Host must be this gateway's loopback address")
        origins = request.headers.getlist("origin")
        if len(origins) > 1 or (origins and origins[0] not in self.origins):
            return _plain(403, "Origin not allowed")
        return None

    def _routing_mismatch(self, request: Request, msg: dict) -> str:
        """Why the routing headers disagree with the body, or '' when they agree (or are absent)."""
        for name in ROUTING:
            if len(request.headers.getlist(name)) > 1:
                return f"{name} given more than once"
        method = request.headers.get("mcp-method")
        if method is not None and method != msg.get("method"):
            return "Mcp-Method does not match the body's method"
        name = request.headers.get("mcp-name")
        if name is not None:
            key = NAME_PARAM.get(msg.get("method"))
            params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
            if key is None or decode_header_value(name) != params.get(key):
                return "Mcp-Name does not match the body"
        version = request.headers.get("mcp-protocol-version")
        meta = (msg.get("params") or {}).get("_meta") if isinstance(msg.get("params"), dict) else None
        body_version = meta.get(VERSION_META) if isinstance(meta, dict) else None
        if version is not None and body_version is not None and version != body_version:
            return "MCP-Protocol-Version does not match the body's version"
        return ""

    def _headers(self, request: Request, post: bool) -> dict[str, str]:
        out = {k: v for k, v in request.headers.items() if k in COPY_REQUEST or k.startswith("mcp-param-")}
        out.update(self.upstream_headers)
        if post:
            out["content-type"] = "application/json"
        return out

    # ---- requests -------------------------------------------------------------------------

    async def handle(self, request: Request) -> Response:
        refused = self._refuse_origin(request)
        if refused is not None:
            return refused
        if request.method == "POST":
            return await self._post(request)
        return await self._forward(request, request.method, None, Watch(self.judge, None, None), None)

    async def _read_body(self, request: Request) -> bytes | Response:
        ctype = request.headers.get("content-type", "")
        if ctype.split(";")[0].strip().lower() != "application/json":
            return _plain(415, "Content-Type must be application/json")
        if request.headers.get("content-encoding", "identity").lower() != "identity":
            return _plain(415, "compressed bodies are not judged; send it uncompressed")
        declared = request.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_body:
            return _plain(413, f"body over {self.max_body} bytes")
        body = bytearray()
        async for chunk in request.stream():
            body += chunk
            if len(body) > self.max_body:
                return _plain(413, f"body over {self.max_body} bytes")
        return bytes(body)

    async def _post(self, request: Request) -> Response:
        raw = await self._read_body(request)
        if isinstance(raw, Response):
            return raw
        try:
            msg = parse_strict(raw)
        except (ValueError, RecursionError) as e:  # never forward what we could not judge
            why = "nested too deep to judge" if isinstance(e, RecursionError) else f"{e}"
            msg_id = recover_id(raw)
            self.judge.log({"event": "rejected", "id": msg_id, "reason": f"unparseable client message: {why}"[:300]})
            return _error(msg_id, -32700, f"parse error: {why}"[:300], 400)
        if not isinstance(msg, dict):
            self.judge.log({"event": "rejected", "id": None, "reason": "not a single JSON-RPC message"})
            return _error(None, -32600, "send one JSON-RPC message per POST (batches are not accepted)", 400)
        mismatch = self._routing_mismatch(request, msg)
        if mismatch:
            self.judge.log({"event": "rejected", "id": msg.get("id"), "reason": mismatch})
            return _error(msg.get("id"), HEADER_MISMATCH, mismatch, 400)
        call = None
        if self.judge.judged(msg):
            verdict = self.judge.call(msg)
            if verdict.action == "ask":
                verdict = await anyio.to_thread.run_sync(self.judge.ask, msg, verdict)
            if verdict.action != "allow":
                if verdict.reply is None:
                    return Response(status_code=202)
                return Response(_line(verdict.reply), status_code=200, media_type="application/json")
            if "id" in msg:
                call = (json.dumps(msg["id"], sort_keys=True), msg["id"], verdict.name, time.perf_counter_ns())
        list_id = None
        if msg.get("method") == "tools/list" and "id" in msg and self.judge.policy.hide_denied_tools:
            list_id = json.dumps(msg["id"], sort_keys=True)
        # The upstream gets exactly what the policy judged, re-serialised from the parse.
        return await self._forward(request, "POST", _line(msg)[:-1], Watch(self.judge, call, list_id), msg.get("id"))

    async def _forward(self, request: Request, method: str, body: bytes | None, watch: Watch, msg_id: Any) -> Response:
        req = self.client.build_request(method, self.upstream, headers=self._headers(request, body is not None),
                                        content=body)
        try:
            upstream = await self.client.send(req, stream=True)
        except httpx2.HTTPError as e:
            watch.unanswered(f"upstream unreachable: {type(e).__name__}")
            return _error(msg_id, -32603, f"upstream unreachable ({type(e).__name__})", 502)
        if 300 <= upstream.status_code < 400:
            await upstream.aclose()
            watch.unanswered(f"upstream redirect {upstream.status_code} not followed")
            return _error(msg_id, -32603, f"upstream answered a redirect ({upstream.status_code}); not followed", 502)
        headers = {k: v for k, v in upstream.headers.items() if k.lower() in COPY_RESPONSE}
        ctype = upstream.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype == "text/event-stream":
            return StreamingResponse(self._events(upstream, watch), status_code=upstream.status_code,
                                     headers=headers)
        try:
            data = bytearray()
            async for chunk in upstream.aiter_bytes():
                data += chunk
                if len(data) > MAX_ANSWER:
                    watch.unanswered("upstream answer too large")
                    return _error(msg_id, -32603, "upstream answer too large", 502)
        except httpx2.HTTPError as e:
            watch.unanswered(f"upstream failed mid-answer: {type(e).__name__}")
            return _error(msg_id, -32603, f"upstream failed mid-answer ({type(e).__name__})", 502)
        finally:
            await upstream.aclose()
        out = bytes(data)
        if ctype == "application/json" and out:
            try:
                item = json.loads(out)
            except ValueError:
                item = None
            if watch.inspect(item):
                out = _line(item)[:-1]
        if not watch.logged:
            watch.unanswered(f"upstream HTTP {upstream.status_code} without an answer")
        headers.pop("content-length", None)
        return Response(out, status_code=upstream.status_code, headers=headers)

    async def _events(self, upstream: httpx2.Response, watch: Watch) -> AsyncIterator[bytes]:
        """Pass an SSE stream through one event at a time, inspecting each data payload."""
        buf = bytearray()
        lines: list[str] = []
        size = 0
        try:
            async for chunk in upstream.aiter_bytes():
                buf += chunk
                while (nl := buf.find(b"\n")) >= 0:
                    line = bytes(buf[:nl]).rstrip(b"\r").decode("utf-8", errors="replace")
                    del buf[:nl + 1]
                    if line:
                        lines.append(line)
                        size += len(line)
                    elif lines:
                        yield self._event(lines, watch)
                        lines, size = [], 0
                if size + len(buf) > MAX_ANSWER:
                    watch.unanswered("upstream event too large")
                    return
            if lines:  # a last event without its blank line
                yield self._event(lines, watch)
        except httpx2.HTTPError as e:
            watch.unanswered(f"upstream stream failed: {type(e).__name__}")
        finally:
            await upstream.aclose()
            watch.unanswered("upstream stream ended without an answer")

    def _event(self, lines: list[str], watch: Watch) -> bytes:
        data = [ln[5:][1:] if ln[5:6] == " " else ln[5:] for ln in lines if ln.startswith("data:")]
        if data:
            try:
                item = json.loads("\n".join(data))
            except ValueError:
                item = None
            if watch.inspect(item):
                payload = _line(item)[:-1].decode("utf-8")
                lines = [ln for ln in lines if not ln.startswith("data:")] + [f"data: {payload}"]
        return ("\n".join(lines) + "\n\n").encode("utf-8")


def parse_listen(text: str) -> tuple[str, int]:
    host, sep, port = text.rpartition(":")
    if not sep or not port.isdigit():
        raise GatewayError(f"--listen takes HOST:PORT, got {text!r}")
    if not is_loopback(host):
        raise GatewayError("the gateway listens on loopback only (it has no client authentication of its own)")
    return host.strip("[]"), int(port)


def upstream_headers_from_env(items: list[str]) -> dict[str, str]:
    out = {}
    for it in items or []:
        name, sep, env = it.partition("=")
        if not sep or not name or not env:
            raise GatewayError(f"--upstream-header takes NAME=ENVVAR, got {it!r}")
        if env not in os.environ:
            raise GatewayError(f"--upstream-header {name}: environment variable {env} is not set")
        out[name.strip()] = os.environ[env]
    return out


def serve(gateway: Gateway, host: str, quiet: bool = False) -> int:
    import uvicorn

    if not quiet:
        print(f"agent-guard: serving http://{host}:{gateway.port}{PATH} -> {gateway.upstream}", file=sys.stderr,
              flush=True)
    uvicorn.run(gateway.app, host=host, port=gateway.port, log_level="warning", server_header=False,
                date_header=False)
    return 0
