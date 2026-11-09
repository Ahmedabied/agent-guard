"""Added latency of the HTTP gateway: sequential tools/call round trips to the SDK demo server over Streamable
HTTP (2026-07-28, JSON answers), straight and through agent-guard serve.

python bench/bench_http.py [--calls 2000]
"""

import argparse
import json
import os
import platform
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx2

ROOT = Path(__file__).resolve().parent.parent
POLICY = "default: deny\nrules:\n  - {name: reads, tool: read_file, decision: allow}\n"
V = "2026-07-28"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait(port, proc):
    for _ in range(200):
        if proc.poll() is not None:
            sys.exit(f"exited {proc.returncode}")
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.1).close()
            return
        except OSError:
            time.sleep(0.05)
    sys.exit(f"nothing on {port}")


def run(url, calls):
    meta = {"io.modelcontextprotocol/protocolVersion": V, "io.modelcontextprotocol/clientInfo": {"name": "bench",
            "version": "1"}, "io.modelcontextprotocol/clientCapabilities": {}}
    headers = {"accept": "application/json, text/event-stream", "content-type": "application/json",
               "mcp-protocol-version": V, "mcp-method": "tools/call", "mcp-name": "read_file"}
    times = []
    with httpx2.Client(timeout=10) as c:
        for i in range(calls + 50):
            body = {"jsonrpc": "2.0", "id": i, "method": "tools/call",
                    "params": {"name": "read_file", "arguments": {"path": f"/srv/{i}"}, "_meta": meta}}
            t0 = time.perf_counter_ns()
            r = c.post(url, content=json.dumps(body), headers=headers)
            dt = time.perf_counter_ns() - t0
            assert r.status_code == 200 and r.json()["result"]["isError"] is False, r.text
            if i >= 50:  # warm-up
                times.append(dt / 1000)
    return times


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--calls", type=int, default=2000)
    a = ap.parse_args()
    procs = []
    with tempfile.TemporaryDirectory() as tmp:
        try:
            up, gw = free_port(), free_port()
            procs.append(subprocess.Popen([sys.executable, str(ROOT / "tests" / "sdk_http_server.py"), str(up), "json"],
                                          stderr=subprocess.DEVNULL))
            wait(up, procs[-1])
            Path(tmp, "guard.yaml").write_text(POLICY)
            procs.append(subprocess.Popen([sys.executable, "-m", "agent_guard", "serve", "-q", "-p",
                                           str(Path(tmp, "guard.yaml")), "--log", str(Path(tmp, "audit.jsonl")),
                                           "--upstream", f"http://127.0.0.1:{up}/mcp", "--listen", f"127.0.0.1:{gw}"]))
            wait(gw, procs[-1])
            direct = run(f"http://127.0.0.1:{up}/mcp", a.calls)
            guarded = run(f"http://127.0.0.1:{gw}/mcp", a.calls)
        finally:
            for p in procs:
                p.terminate()
                p.wait()
    print(f"{a.calls} sequential tools/call over Streamable HTTP per run, python {platform.python_version()}, "
          f"audit fsync off, {os.cpu_count()} cpus")
    print(f"{'':10}{'median':>10}{'p99':>12}")
    q = lambda xs, p: sorted(xs)[int(len(xs) * p) - 1]  # noqa: E731
    for name, xs in (("direct", direct), ("guarded", guarded)):
        print(f"{name:10}{statistics.median(xs):>8.0f}us{q(xs, 0.99):>10.0f}us")
    print(f"{'added':10}{statistics.median(guarded) - statistics.median(direct):>8.0f}us")


if __name__ == "__main__":
    main()
