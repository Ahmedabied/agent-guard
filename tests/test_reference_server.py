"""The official MCP reference server (@modelcontextprotocol/server-everything) behind agent-guard, on stdio and over
HTTP, with the Python SDK client in both modes: tools, a denied tool hidden and refused, prompts judged by name and
by argument.

Needs node and `npm install --prefix tests/ts` (CI does both); skipped otherwise.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

DIST = Path(__file__).parent / "ts" / "node_modules" / "@modelcontextprotocol" / "server-everything" / "dist" / "index.js"
if not shutil.which("node") or not DIST.exists():
    if os.environ.get("AG_REQUIRE_TS"):  # CI sets it, so a broken install fails instead of skipping
        raise RuntimeError("AG_REQUIRE_TS is set but node or the reference server is missing")
    pytest.skip("needs node and npm install --prefix tests/ts", allow_module_level=True)
pytest.importorskip("mcp")
anyio = pytest.importorskip("anyio")

from mcp.client.client import Client  # noqa: E402
from mcp.client.stdio import StdioServerParameters  # noqa: E402
from mcp.shared.exceptions import MCPError  # noqa: E402

from agent_guard.audit import verify  # noqa: E402
from test_gateway import free_port, wait_port  # noqa: E402

POLICY = """
default: allow
hide_denied_tools: true
guard_prompts: true
rules:
  - {name: no-env, tool: get-env, decision: deny, reason: the environment holds keys}
  - {name: no-texas, tool: prompts/get, args: {arguments.state: {glob: "T*"}}, decision: deny, reason: not that state}
  - {name: no-resource-prompt, tool: prompts/get, args: {name: resource-prompt}, decision: deny, reason: not that one}
"""


async def _session(target, mode):
    seen = {}
    async with Client(target, mode=mode) as c:
        seen["tools"] = {t.name for t in (await c.list_tools()).tools}
        seen["echo"] = await c.call_tool("echo", {"message": "hi"})
        seen["env"] = await c.call_tool("get-env", {})
        seen["prompts"] = {p.name for p in (await c.list_prompts()).prompts}
        seen["weather"] = await c.get_prompt("args-prompt", {"city": "Leeds", "state": "Yorkshire"})
        for key, name, args in (("texas", "args-prompt", {"city": "Austin", "state": "Texas"}),
                                ("resource", "resource-prompt", {"resourceType": "Text", "resourceId": "1"})):
            try:
                await c.get_prompt(name, args)
            except MCPError as e:
                seen[key] = e.error
    return seen


def _check(seen, log):
    assert "echo" in seen["tools"] and "get-env" not in seen["tools"]  # hidden: no arguments get it past the rules
    assert not seen["echo"].is_error and seen["echo"].content[0].text == "Echo: hi"
    assert seen["env"].is_error and "the environment holds keys" in seen["env"].content[0].text
    assert {"args-prompt", "resource-prompt"} <= seen["prompts"]  # prompts/list is not filtered (see Limits)
    assert seen["weather"].messages[0].content.text == "What's weather in Leeds, Yorkshire?"
    assert seen["texas"].code == -32001 and "(rule: no-texas)" in seen["texas"].message
    assert seen["resource"].code == -32001 and "(rule: no-resource-prompt)" in seen["resource"].message
    assert verify(log).ok


@pytest.mark.parametrize("mode", ["legacy", "auto"])
def test_reference_server_on_stdio(tmp_path, mode):
    (tmp_path / "guard.yaml").write_text(POLICY)
    log = tmp_path / "audit.jsonl"
    params = StdioServerParameters(command=sys.executable, args=[
        "-m", "agent_guard", "run", "-q", "-p", str(tmp_path / "guard.yaml"), "--log", str(log), "--",
        "node", str(DIST), "stdio"])
    _check(anyio.run(_session, params, mode), log)


@pytest.mark.parametrize("mode", ["legacy", "auto"])
def test_reference_server_over_http(tmp_path, mode):
    (tmp_path / "guard.yaml").write_text(POLICY)
    log = tmp_path / "audit.jsonl"
    up, gw = free_port(), free_port()
    procs = []
    try:
        procs.append(subprocess.Popen(["node", str(DIST), "streamableHttp"], env={**os.environ, "PORT": str(up)},
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        wait_port(up, procs[-1])
        procs.append(subprocess.Popen([sys.executable, "-m", "agent_guard", "serve", "-q", "-p",
                                       str(tmp_path / "guard.yaml"), "--upstream", f"http://127.0.0.1:{up}/mcp",
                                       "--listen", f"127.0.0.1:{gw}", "--log", str(log)],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.PIPE))
        wait_port(gw, procs[-1])
        seen = anyio.run(_session, f"http://127.0.0.1:{gw}/mcp", mode)
    finally:
        for p in procs:
            p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
    _check(seen, log)
