"""agent-guard in front of a remote MCP server, start to finish.

A pretend issue tracker runs as a Streamable HTTP server, agent-guard serve listens on localhost in front of it,
and an agent built on the official MCP Python SDK connects to the gateway as if it were the server.

    pip install -e '.[http,sdk]'
    python examples/http_demo.py
"""

import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import anyio
from mcp.client.client import Client

HERE = Path(__file__).resolve().parent


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start(cmd, port):
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(200):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.1).close()
            return p
        except OSError:
            if p.poll() is not None:
                sys.exit(f"{cmd[1]} exited with code {p.returncode}")
            time.sleep(0.05)
    sys.exit(f"nothing listening on {port}")


async def agent(url):
    async with Client(url, mode="auto") as c:
        print(f"  connected to {url}, protocol {c.protocol_version}")
        print(f"  tools: {', '.join(sorted(t.name for t in (await c.list_tools()).tools))}  (delete_repo is hidden)")
        for name, args in [("list_issues", {"repo": "sandbox/demo"}), ("close_issue", {"repo": "prod/api", "number": 12}),
                           ("close_issue", {"repo": "sandbox/demo", "number": 15}), ("delete_repo", {"repo": "prod/api"})]:
            r = await c.call_tool(name, args)
            shown = ", ".join(f"{k}={v!r}" for k, v in args.items())
            print(f"  {'BLOCKED' if r.is_error else 'ok':7} {name}({shown})")
            print(f"          -> {r.content[0].text}")


def main():
    up, gw = free_port(), free_port()
    with tempfile.TemporaryDirectory() as tmp:
        log = Path(tmp) / "audit.jsonl"
        procs = [start([sys.executable, str(HERE / "tracker_server.py"), str(up)], up)]
        try:
            print("1. The tracker server, and agent-guard serve in front of it")
            print(f"  $ agent-guard serve -p examples/http-guard.yaml --upstream http://127.0.0.1:{up}/mcp "
                  f"--listen 127.0.0.1:{gw}")
            procs.append(start([sys.executable, "-m", "agent_guard", "serve", "-q", "-p", str(HERE / "http-guard.yaml"),
                                "--upstream", f"http://127.0.0.1:{up}/mcp", "--listen", f"127.0.0.1:{gw}",
                                "--log", str(log)], gw))
            print("\n2. An agent session through the gateway")
            anyio.run(agent, f"http://127.0.0.1:{gw}/mcp")
        finally:
            for p in procs:
                p.terminate()
                p.wait()
        print("\n3. The audit log")
        for args in (["log", str(log)], ["verify", str(log)]):
            r = subprocess.run([sys.executable, "-m", "agent_guard", *args], capture_output=True, text=True)
            print(f"  $ agent-guard {args[0]} audit.jsonl")
            for line in r.stdout.rstrip().splitlines():
                print(f"  {line}")
            if r.returncode:
                sys.exit(f"agent-guard {args[0]} failed")


if __name__ == "__main__":
    main()
