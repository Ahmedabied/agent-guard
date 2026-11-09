"""A scripted agent session through agent-guard, start to finish.

1. The agent reads, writes and deletes files through the guard. Some calls are blocked.
2. One delete the policy allowed turns out to be a mistake (an incident).
3. `agent-guard learn` turns that incident into a rule and a regression test.
4. The same call is now blocked, and `agent-guard test` keeps it that way.

    python examples/demo.py

Works in a temporary copy of the example policy; your files are not touched.
"""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEMO = Path("/tmp/agent-guard-demo")


def guard(*args):
    r = subprocess.run([sys.executable, "-m", "agent_guard", *args], capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr).rstrip()


class Agent:
    def __init__(self, policy, log):
        self.p = subprocess.Popen(
            [sys.executable, "-m", "agent_guard", "run", "-q", "-p", str(policy), "--log", str(log), "--",
             sys.executable, str(HERE / "files_server.py"), str(DEMO)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        )
        self.n = 0
        self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                "clientInfo": {"name": "demo-agent", "version": "0"}})

    def rpc(self, method, params):
        self.n += 1
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params}).encode() + b"\n")
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())

    def call(self, tool, **args):
        r = self.rpc("tools/call", {"name": tool, "arguments": args})["result"]
        shown = ", ".join(f"{k}={v!r}" for k, v in args.items() if k != "content")
        status = "BLOCKED" if r["isError"] else "ok     "
        print(f"  {status} {tool}({shown})\n          -> {r['content'][0]['text'].strip()}")

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=10)


def main():
    shutil.rmtree(DEMO, ignore_errors=True)
    (DEMO / "notes").mkdir(parents=True)
    (DEMO / "scratch").mkdir()
    (DEMO / "notes" / "plan.md").write_text("ship v1 on friday\n")
    for name in ["old.log", "report-final.pdf", "report-final-v2.pdf"]:
        (DEMO / "scratch" / name).write_text("x\n")

    with tempfile.TemporaryDirectory() as tmp:
        policy, tests, log = Path(tmp) / "guard.yaml", Path(tmp) / "guard-tests.yaml", Path(tmp) / "audit.jsonl"
        shutil.copy(HERE / "guard.yaml", policy)
        shutil.copy(HERE / "guard-tests.yaml", tests)

        print("1. An agent session through the guard")
        a = Agent(policy, log)
        a.call("read_file", path=f"{DEMO}/notes/plan.md")
        a.call("delete_file", path=f"{DEMO}/notes/plan.md")
        a.call("delete_file", path=f"{DEMO}/scratch/../notes/plan.md")
        a.call("write_file", path=f"{DEMO}/scratch/todo.txt", content="tidy up")
        a.call("delete_file", path=f"{DEMO}/scratch/old.log")
        a.call("delete_file", path=f"{DEMO}/scratch/report-final.pdf")
        a.close()

        print("\n2. The audit log")
        print(guard("log", str(log), "-n", "12")[1])
        print("  " + guard("verify", str(log))[1])

        print("\n3. Deleting report-final.pdf was a mistake. Turn it into a rule:")
        seq = max(e["seq"] for e in map(json.loads, log.read_text().splitlines())
                  if e.get("event") == "call" and "report-final" in json.dumps(e.get("args")))
        code, out = guard("learn", "-p", str(policy), "--tests", str(tests), "--from-log", str(log), "--seq", str(seq),
                          "--name", "keep-final-reports", "--reason", "final reports are kept",
                          "--match", "path=*final*")
        print("  $ agent-guard learn --seq", seq, "--name keep-final-reports --match 'path=*final*' ...")
        print("  " + out.replace("\n", "\n  "))

        print("\n4. Same mistake, next session:")
        a = Agent(policy, log)
        a.call("delete_file", path=f"{DEMO}/scratch/report-final-v2.pdf")
        a.close()
        code, out = guard("test", "-p", str(policy), str(tests))
        print("  $ agent-guard test\n  " + out.splitlines()[-1])
        print("  " + guard("verify", str(log))[1])


if __name__ == "__main__":
    main()
