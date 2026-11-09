#!/usr/bin/env python3
"""A tiny MCP file server for the demo and the tests: list, read, write and delete files.

Stdlib only, newline-delimited JSON-RPC on stdin and stdout. It never touches anything outside
the folder it is given. Inside that folder it does whatever it is asked, including deleting your
notes, which is the point: agent-guard decides which of those calls get through.

    python examples/files_server.py /tmp/agent-guard-demo
"""

import json
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()


def _schema(**props):
    return {"type": "object", "properties": {k: {"type": "string"} for k in props}, "required": list(props)}


TOOLS = [
    {"name": "list_files", "description": "List the files in a folder", "inputSchema": _schema(path=1)},
    {"name": "read_file", "description": "Read a text file", "inputSchema": _schema(path=1)},
    {"name": "write_file", "description": "Write a text file", "inputSchema": _schema(path=1, content=1)},
    {"name": "delete_file", "description": "Delete a file", "inputSchema": _schema(path=1)},
    {"name": "echo", "description": "Return the text it is given", "inputSchema": _schema(text=1)},
]


def _inside(path: str) -> Path:
    p = Path(path)
    p = (p if p.is_absolute() else ROOT / p).resolve()
    if p != ROOT and ROOT not in p.parents:
        raise ValueError(f"{path} is outside {ROOT}")
    return p


def call(name, args):
    if name == "echo":
        return str(args.get("text", ""))
    p = _inside(str(args.get("path", "")))
    if name == "list_files":
        return "\n".join(sorted(str(c.relative_to(ROOT)) for c in p.iterdir()))
    if name == "read_file":
        return p.read_text(encoding="utf-8")
    if name == "write_file":
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(str(args.get("content", "")), encoding="utf-8")
        return f"wrote {p.relative_to(ROOT)}"
    if name == "delete_file":
        p.unlink()
        return f"deleted {p.relative_to(ROOT)}"
    raise KeyError(f"unknown tool {name}")


def handle(msg):
    method, params, mid = msg.get("method"), msg.get("params") or {}, msg.get("id")
    if "id" not in msg:
        return None  # notifications need no answer
    if method == "initialize":
        result = {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                  "capabilities": {"tools": {}}, "serverInfo": {"name": "files-demo", "version": "0.1.0"}}
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        try:
            result = {"content": [{"type": "text", "text": call(params.get("name"), params.get("arguments") or {})}],
                      "isError": False}
        except Exception as e:
            result = {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True}
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def main():
    out = sys.stdout.buffer
    for raw in sys.stdin.buffer:
        if not raw.strip():
            continue
        try:
            msg = json.loads(raw)
        except ValueError:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        else:
            items = msg if isinstance(msg, list) else [msg]
            replies = [r for r in (handle(m) for m in items if isinstance(m, dict)) if r]
            if not replies:
                continue
            reply = replies if isinstance(msg, list) else replies[0]
        out.write(json.dumps(reply).encode() + b"\n")
        out.flush()


if __name__ == "__main__":
    main()
