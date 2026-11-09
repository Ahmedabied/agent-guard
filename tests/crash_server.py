"""A server that dies on the first tool call, to test what the proxy does with a pending call."""

import json
import os
import sys

for raw in sys.stdin.buffer:
    msg = json.loads(raw)
    if msg.get("method") == "tools/call":
        os._exit(3)
    if "id" in msg:
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {}}) + "\n")
        sys.stdout.flush()
