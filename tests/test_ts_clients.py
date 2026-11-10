"""The official MCP TypeScript SDK clients through the gateway: v1 (@modelcontextprotocol/sdk) and v2
(@modelcontextprotocol/client) in both handshakes, against a server answering with SSE and with JSON.

Needs node and `npm install --prefix tests/ts` (CI does both); skipped otherwise.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

TS = Path(__file__).parent / "ts"
if not shutil.which("node") or not (TS / "node_modules" / "@modelcontextprotocol" / "client").exists():
    if os.environ.get("AG_REQUIRE_TS"):  # CI sets it, so a broken install fails instead of skipping
        raise RuntimeError("AG_REQUIRE_TS is set but node or tests/ts/node_modules is missing")
    pytest.skip("needs node and npm install --prefix tests/ts", allow_module_level=True)
pytest.importorskip("mcp")

from test_gateway import Rig  # noqa: E402


@pytest.mark.parametrize("answers", ["sse", "json"])
@pytest.mark.parametrize("client, mode, protocol", [("v1", "legacy", None), ("v2", "legacy", "2025-11-25"),
                                                     ("v2", "auto", "2026-07-28")])
def test_typescript_client_through_gateway(tmp_path, client, mode, protocol, answers):
    r = Rig(tmp_path, upstream="sdk", mode=answers)
    try:
        p = subprocess.run(["node", str(TS / "probe.mjs"), client, r.url, mode], capture_output=True, text=True,
                           timeout=60, cwd=TS)
        assert p.returncode == 0, p.stderr[-2000:]
        seen = json.loads(p.stdout.strip().splitlines()[-1])
    finally:
        r.close()
    assert seen["protocol"] == protocol
    assert seen["tools"] == ["delete_file", "forecast", "read_file"]  # drop_database is hidden
    assert seen["read"] == [False, "contents of /srv/a.txt"]
    assert seen["delete"][0] and "nothing under /etc" in seen["delete"][1]
    assert seen["drop"][0] and "default is deny" in seen["drop"][1]
    # On 2026-07-28 the server refuses a call whose Mcp-Param headers are missing or wrong: these are the gateway's.
    assert seen["forecast"] == [False, "sunny in eu-west é for 3 days"]
