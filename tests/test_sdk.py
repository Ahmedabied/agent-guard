"""The official MCP Python SDK on both sides, agent-guard in the middle.

Runs for both handshakes: "legacy" (initialize, 2025 protocol versions) and "auto", which
negotiates the 2026-07-28 protocol (server/discover, per-request version, resultType required).
"""

import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp")
anyio = pytest.importorskip("anyio")

from mcp.client.client import Client  # noqa: E402
from mcp.client.stdio import StdioServerParameters  # noqa: E402

SERVER = str(Path(__file__).parent / "sdk_server.py")
POLICY = """
default: deny
hide_denied_tools: true
rules:
  - {name: no-etc, tool: delete_file, args: {path: {under: /etc}}, decision: deny, reason: nothing under /etc}
  - {name: files, tool: [read_file, delete_file], decision: allow}
"""


@pytest.mark.parametrize("mode", ["legacy", "auto"])
def test_sdk_client_through_guard(tmp_path, mode):
    policy = tmp_path / "guard.yaml"
    policy.write_text(POLICY)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "agent_guard", "run", "-q", "-p", str(policy), "--log", str(tmp_path / "audit.jsonl"), "--",
              sys.executable, SERVER],
    )
    seen = {}

    async def session():
        async with Client(params, mode=mode) as c:
            seen["tools"] = sorted(t.name for t in (await c.list_tools()).tools)
            seen["read"] = await c.call_tool("read_file", {"path": "/srv/a.txt"})
            seen["delete"] = await c.call_tool("delete_file", {"path": "/etc/passwd"})
            seen["drop"] = await c.call_tool("drop_database", {"name": "prod"})

    anyio.run(session)
    assert seen["tools"] == ["delete_file", "read_file"]  # drop_database is hidden
    assert not seen["read"].is_error and seen["read"].content[0].text == "contents of /srv/a.txt"
    assert seen["delete"].is_error and "nothing under /etc" in seen["delete"].content[0].text
    assert seen["drop"].is_error and "default is deny" in seen["drop"].content[0].text
