"""How much time does agent-guard add to one tool call?

Runs the same sequence of tools/call requests against the demo file server twice: once
directly, once through `agent-guard run` with the example policy and a real audit log. Each call
is timed from writing the request to reading the answer. Also times the policy check alone.

    python bench/bench.py --calls 2000
"""

import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER = [sys.executable, str(ROOT / "examples" / "files_server.py")]
POLICY = ROOT / "examples" / "guard.yaml"


def session(cmd, calls, warmup=50):
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def rpc(i, method, params):
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params}).encode() + b"\n")
        p.stdin.flush()
        return json.loads(p.stdout.readline())

    rpc(0, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "bench", "version": "0"}})
    times = []
    for i in range(1, warmup + calls + 1):
        t0 = time.perf_counter_ns()
        r = rpc(i, "tools/call", {"name": "echo", "arguments": {"text": f"hello {i}"}})
        dt = time.perf_counter_ns() - t0
        assert r["result"]["isError"] is False, r
        if i > warmup:
            times.append(dt / 1000)
    p.stdin.close()
    p.wait(timeout=10)
    return times


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))]


def policy_only(n):
    sys.path.insert(0, str(ROOT / "src"))
    from agent_guard.policy import Policy

    pol = Policy.from_file(POLICY)
    args = {"path": "/tmp/agent-guard-demo/scratch/x.txt"}
    t0 = time.perf_counter_ns()
    for _ in range(n):
        pol.evaluate("delete_file", args, charge=False)
    return (time.perf_counter_ns() - t0) / n / 1000


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--calls", type=int, default=2000)
    ap.add_argument("--fsync", action="store_true", help="fsync the audit log after every entry")
    a = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        demo = Path(tmp) / "root"
        demo.mkdir()
        policy = POLICY
        if a.fsync:
            policy = Path(tmp) / "guard.yaml"
            policy.write_text(POLICY.read_text().replace("max_value_chars: 2000", "max_value_chars: 2000\n  fsync: true"))
        log = Path(tmp) / "audit.jsonl"
        direct = session(SERVER + [str(demo)], a.calls)
        guarded = session([sys.executable, "-m", "agent_guard", "run", "-q", "-p", str(policy), "--log", str(log), "--"]
                          + SERVER + [str(demo)], a.calls)
        entries = sum(1 for _ in open(log))
    p50d, p50g = statistics.median(direct), statistics.median(guarded)
    p99d, p99g = pct(direct, 0.99), pct(guarded, 0.99)
    print(f"{a.calls} sequential tools/call round trips per run, python {sys.version.split()[0]}, "
          f"audit fsync {'on' if a.fsync else 'off'}, {os.cpu_count()} cpus")
    print(f"{'':10}{'median':>12}{'p99':>12}")
    print(f"{'direct':10}{p50d:>10.0f}us{p99d:>10.0f}us")
    print(f"{'guarded':10}{p50g:>10.0f}us{p99g:>10.0f}us")
    print(f"{'added':10}{p50g - p50d:>10.0f}us{p99g - p99d:>10.0f}us")
    print(f"policy check alone: {policy_only(100_000):.1f}us per call (example policy, 4 rules)")
    print(f"audit entries written: {entries} (a call and a result per tool call)")


if __name__ == "__main__":
    main()
