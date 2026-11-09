import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from agent_guard.audit import AuditError, read_entries, verify
from agent_guard.policy import Policy
from agent_guard.proxy import Proxy, parse_strict

HERE = Path(__file__).parent
FILES_SERVER = str(HERE.parent / "examples" / "files_server.py")
CRASH_SERVER = str(HERE / "crash_server.py")

POLICY = """
default: deny
hide_denied_tools: true
ask: {via: command, command: [PY, -c, "import sys, json; d = json.load(sys.stdin); sys.exit(0 if d['arguments']['text'] == 'yes' else 1)"]}
rules:
  - name: notes-read-only
    tool: [write_file, delete_file]
    args: {path: {under: ROOT/notes}}
    decision: deny
    reason: notes are read-only
  - name: scratch-deletes-only
    tool: delete_file
    args: {path: {not_under: ROOT/scratch}}
    decision: deny
    reason: deletes only in scratch
  - {name: echo-asks, tool: echo, args: {text: {glob: "y*"}}, decision: ask}
  - {name: work, tool: [list_files, read_file, write_file, delete_file, echo], decision: allow}
"""


class Session:
    def __init__(self, tmp_path, policy=POLICY, server=FILES_SERVER):
        self.root = tmp_path / "root"
        (self.root / "notes").mkdir(parents=True)
        (self.root / "scratch").mkdir()
        (self.root / "notes" / "plan.md").write_text("keep me")
        (self.root / "scratch" / "old.txt").write_text("tmp")
        self.policy = tmp_path / "guard.yaml"
        self.policy.write_text(policy.replace("ROOT", str(self.root)).replace("PY", json.dumps(sys.executable)))
        self.log = tmp_path / "audit.jsonl"
        self.p = subprocess.Popen(
            [sys.executable, "-m", "agent_guard", "run", "-p", str(self.policy), "--log", str(self.log), "-q", "--",
             sys.executable, server, str(self.root)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.lines: queue.Queue = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()
        self.next_id = 100

    def _read(self):
        for line in self.p.stdout:
            self.lines.put(json.loads(line))
        self.lines.put(None)

    def send(self, obj):
        data = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.p.stdin.write(data + b"\n")
        self.p.stdin.flush()

    def recv(self, timeout=10):
        msg = self.lines.get(timeout=timeout)
        assert msg is not None, "proxy closed its output"
        return msg

    def request(self, method, params=None):
        self.next_id += 1
        msg = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)
        return self.recv()

    def call(self, name, **args):
        return self.request("tools/call", {"name": name, "arguments": args})

    def path(self, rel):
        return str(self.root / rel)

    def close(self):
        self.p.stdin.close()
        code = self.p.wait(timeout=10)
        self.p.stdout.close()
        self.p.stderr.close()
        return code


@pytest.fixture
def s(tmp_path):
    sess = Session(tmp_path)
    init = sess.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                       "clientInfo": {"name": "test", "version": "0"}})
    assert init["result"]["serverInfo"]["name"] == "files-demo"
    sess.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    yield sess
    if sess.p.poll() is None:
        sess.close()


def _text(resp):
    return resp["result"]["content"][0]["text"]


def test_allowed_call_reaches_server(s):
    r = s.call("read_file", path=s.path("notes/plan.md"))
    assert r["result"]["isError"] is False and _text(r) == "keep me"


def test_denied_call_never_reaches_server(s):
    r = s.call("delete_file", path=s.path("notes/plan.md"))
    assert r["result"]["isError"] is True
    assert "notes are read-only" in _text(r) and "notes-read-only" in _text(r)
    assert (s.root / "notes" / "plan.md").exists()


def test_traversal_is_judged_on_the_normalised_path(s):
    r = s.call("delete_file", path=s.path("scratch/../notes/plan.md"))
    assert r["result"]["isError"] is True
    assert (s.root / "notes" / "plan.md").exists()
    r = s.call("delete_file", path=s.path("scratch/old.txt"))
    assert r["result"]["isError"] is False
    assert not (s.root / "scratch" / "old.txt").exists()


def test_always_denied_tools_are_hidden(tmp_path):
    # echo has an ask rule, so it can pass and stays listed; drop it from the policy entirely.
    policy = POLICY.replace("  - {name: echo-asks, tool: echo, args: {text: {glob: \"y*\"}}, decision: ask}\n", "")
    policy = policy.replace("delete_file, echo], decision: allow}", "delete_file], decision: allow}")
    assert "echo" not in policy
    sess = Session(tmp_path, policy)
    try:
        tools = [t["name"] for t in sess.request("tools/list")["result"]["tools"]]
        assert "echo" not in tools and "delete_file" in tools
    finally:
        sess.close()


def test_duplicate_keys_are_refused(s):
    # A first-key-wins parser would run delete_file; Python would judge read_file. Refuse both.
    raw = ('{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"delete_file","name":"read_file",'
           f'"arguments":{{"path":"{s.path("notes/plan.md")}"}}}}}}').encode()
    s.send(raw)
    r = s.recv()
    assert r["error"]["code"] == -32700 and "duplicate" in r["error"]["message"]
    assert (s.root / "notes" / "plan.md").exists()


def test_unparseable_line_is_answered_not_forwarded(s):
    s.send(b'{"jsonrpc":"2.0","id":8,"method":"tools/call",')
    assert s.recv()["error"]["code"] == -32700
    s.send(b'{"jsonrpc":"2.0","id":9,"method":"ping","params":{"x":NaN}}')
    assert s.recv()["error"]["code"] == -32700


def test_malformed_call(s):
    r = s.request("tools/call", {"name": "read_file", "arguments": ["not", "an", "object"]})
    assert r["error"]["code"] == -32602
    r = s.request("tools/call", {"arguments": {}})
    assert r["error"]["code"] == -32602


def test_ask_goes_to_the_approver(s):
    assert _text(s.call("echo", text="yes")) == "yes"  # approver exits 0
    r = s.call("echo", text="yikes")  # approver exits 1
    assert r["result"]["isError"] is True and "not approved" in _text(r)
    assert _text(s.call("echo", text="hello")) == "hello"  # no ask rule matched


def test_other_methods_pass_through(s):
    assert s.request("ping")["result"] == {}
    assert s.request("resources/list")["error"]["code"] == -32601  # the server's own answer


def test_batch_with_mixed_decisions(s):
    s.send([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "delete_file", "arguments": {"path": s.path("notes/plan.md")}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "echo", "arguments": {"text": "hi"}}},
    ])
    got = [s.recv(), s.recv()]
    flat = []
    for g in got:
        flat += g if isinstance(g, list) else [g]
    by_id = {m["id"]: m for m in flat}
    assert by_id[1]["result"]["isError"] is True
    assert _text(by_id[2]) == "hi"
    assert (s.root / "notes" / "plan.md").exists()


def test_audit_log_has_calls_and_results(s):
    s.call("read_file", path=s.path("notes/plan.md"))
    s.call("delete_file", path=s.path("notes/plan.md"))
    s.close()
    assert verify(s.log).ok
    entries = list(read_entries(s.log))
    calls = [e for e in entries if e["event"] == "call"]
    assert [c["decision"] for c in calls] == ["allow", "deny"]
    results = [e for e in entries if e["event"] == "result"]
    assert len(results) == 1 and results[0]["ok"] is True and results[0]["us"] > 0


def test_server_exit_fails_pending_calls(tmp_path):
    sess = Session(tmp_path, "default: allow\nrules: []\n", server=CRASH_SERVER)
    r = sess.call("anything")
    assert r["error"]["code"] == -32603 and "exited" in r["error"]["message"]
    assert sess.p.wait(timeout=10) == 3  # the server's exit code comes through


def test_no_audit_means_no_call(tmp_path):
    class BrokenAudit:
        def append(self, record):
            raise AuditError("disk full")

    policy = Policy.from_yaml("default: allow\nrules: []\n")
    cin_r, cin_w = os.pipe()
    cout_r, cout_w = os.pipe()
    proxy = Proxy(policy, [sys.executable, FILES_SERVER, str(tmp_path)], audit=BrokenAudit(),
                  client_in=os.fdopen(cin_r, "rb"), client_out=os.fdopen(cout_w, "wb"), quiet=True)
    t = threading.Thread(target=proxy.run, daemon=True)
    t.start()
    with os.fdopen(cin_w, "wb") as w, os.fdopen(cout_r, "rb") as r:
        w.write(b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"x"}}}\n')
        w.flush()
        resp = json.loads(r.readline())
        assert resp["result"]["isError"] is True and "audit log could not be written" in _text(resp)
    t.join(timeout=10)


def test_parse_strict():
    assert parse_strict(b'{"a": [1, 2]}\n') == {"a": [1, 2]}
    for bad in [b'{"a":1,"a":2}', b'{"a":Infinity}', b'\xff\xfe{}', b'{"a":']:
        with pytest.raises(ValueError):
            parse_strict(bad)


def test_blocked_result_matches_the_protocol_version(s):
    meta = {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
    new = s.request("tools/call", {"name": "delete_file", "arguments": {"path": s.path("notes/plan.md")}, "_meta": meta})
    old = s.call("delete_file", path=s.path("notes/plan.md"))
    assert new["result"]["resultType"] == "complete" and new["result"]["isError"] is True
    assert "resultType" not in old["result"]  # 2025 peers may reject unknown keys


def test_relative_path_cannot_slip_past_a_deny_rule(s):
    # the demo server resolves relative paths against its root, like the official filesystem server
    r = s.call("write_file", path="notes/plan.md", content="PWNED")
    assert r["result"]["isError"] is True
    assert (s.root / "notes" / "plan.md").read_text() == "keep me"


DEEP = b"[" * 5000 + b"0" + b"]" * 5000  # written by hand: json.dumps itself recurses too deep on some Pythons


@pytest.mark.parametrize("args", [b'{"text": "\\ud800"}', b'{"text": ' + DEEP + b"}"], ids=["lone-surrogate", "deep-nesting"])
def test_a_message_the_guard_cannot_judge_is_denied_and_the_guard_keeps_serving(s, args):
    s.send(b'{"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "echo", "arguments": ' + args + b"}}")
    r = s.recv()
    # Denied either way: as a parse error (id null) where the JSON parser gives up first, as on Python 3.10,
    # or as an error for id 7 where the parser copes and the judging fails.
    assert ("error" in r and r["id"] in (7, None)) or (r["id"] == 7 and r["result"]["isError"] is True)
    ok = s.call("echo", text="still here")
    assert ok["result"]["isError"] is False
    assert s.close() in (0, 70)


RESOURCE_POLICY = POLICY.replace("hide_denied_tools: true\n", "hide_denied_tools: true\nguard_resources: true\n") + \
    '  - {name: read-notes, tool: "resources/read", args: {scheme: file, path: {under: ROOT/notes}}, decision: allow}\n'


def _open(tmp_path, policy):
    sess = Session(tmp_path, policy=policy)
    sess.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                "clientInfo": {"name": "test", "version": "0"}})
    return sess


def test_resource_reads_go_through_the_policy_when_guarded(tmp_path):
    s = _open(tmp_path, RESOURCE_POLICY)
    try:
        ok = s.request("resources/read", {"uri": "file://" + s.path("notes/plan.md")})
        assert ok["result"]["contents"][0]["text"] == "keep me"
        for uri in ("file://" + s.path("scratch/old.txt"),                 # no rule allows it: default deny
                    "file://" + s.path("notes") + "/../scratch/old.txt",    # .. is normalised before under:
                    "file://" + s.path("notes") + "/%2e%2e/scratch/old.txt",  # and so is an encoded one
                    "notes://x" + s.path("notes/plan.md")):                  # the rule asks for file://
            r = s.request("resources/read", {"uri": uri})
            assert r["error"]["code"] == -32001, (uri, r)
            assert "agent-guard blocked reading" in r["error"]["message"]
        remote = s.request("resources/read", {"uri": "file://elsewhere" + s.path("notes/plan.md")})
        assert remote["error"]["code"] == -32602 and "another host (elsewhere)" in remote["error"]["message"]
        bad = s.request("resources/read", {})
        assert bad["error"]["code"] == -32602 and "needs a string uri" in bad["error"]["message"]
    finally:
        s.close()
    events = [json.loads(line) for line in s.log.read_text().splitlines()]
    reads = [e for e in events if e.get("tool") == "resources/read" and e["event"] == "call"]
    assert [e["decision"] for e in reads] == ["allow", "deny", "deny", "deny", "deny", "deny", "deny"]


def test_resource_reads_pass_through_unless_guard_resources_is_set(tmp_path):
    s = _open(tmp_path, POLICY)
    try:
        r = s.request("resources/read", {"uri": "file://" + s.path("scratch/old.txt")})
        assert r["result"]["contents"][0]["text"] == "tmp"  # the documented gap: off by default
    finally:
        s.close()


DENY_POLICY = """
default: allow
guard_resources: true
rules:
  - {name: no-scratch, tool: "resources/read", args: {path: {under: ROOT/scratch}}, decision: deny}
"""


def test_a_deny_rule_on_path_cannot_be_dodged_by_host_or_scheme(tmp_path):
    # Servers read the path and ignore the rest, so the rule must see the same path whatever wraps it.
    s = _open(tmp_path, DENY_POLICY)
    try:
        assert s.request("resources/read", {"uri": "file://" + s.path("notes/plan.md")})["result"]
        for uri in ("file://elsewhere" + s.path("scratch/old.txt"),     # refused outright: another host
                    "file://localhost:22" + s.path("scratch/old.txt"),   # or a port
                    "notes://x" + s.path("scratch/old.txt"),             # another scheme: its path cannot be placed
                    "notes:///public/readme",                            # so path deny rules catch every one of them
                    "FILE://" + s.path("scratch/old.txt"),
                    s.path("scratch/old.txt"),                           # no scheme: refused
                    "file://[::1" + s.path("scratch/old.txt")):          # does not parse: refused
            r = s.request("resources/read", {"uri": uri})
            assert "error" in r and "agent-guard" in r["error"]["message"], (uri, r)
    finally:
        s.close()


def test_a_path_allow_rule_without_a_scheme_only_allows_local_files(tmp_path):
    policy = "default: deny\nguard_resources: true\nrules:\n" \
             '  - {name: notes, tool: "resources/read", args: {path: {under: ROOT/notes}}, decision: allow}\n'
    s = _open(tmp_path, policy)
    try:
        assert s.request("resources/read", {"uri": "file://" + s.path("notes/plan.md")})["result"]
        for uri in ("notes://" + s.path("notes/plan.md"), "https://example.com" + s.path("notes/plan.md")):
            assert s.request("resources/read", {"uri": uri})["error"]["code"] == -32001, uri
    finally:
        s.close()


def test_deny_rules_see_every_reading_of_a_uri(tmp_path):
    policy = "default: allow\nguard_resources: true\nrules:\n" \
             '  - {name: no-secret, tool: "resources/read", args: {path: {glob: "*secret*"}}, decision: deny}\n' \
             '  - {name: no-evil, tool: "resources/read", args: {host: evil.example}, decision: deny}\n' \
             '  - {name: no-bad-host, tool: "resources/read", args: {host: {equals: bad.example}}, decision: deny}\n' \
             '  - {name: no-key, tool: "resources/read", args: {path: {equals: /keys/main}}, decision: deny}\n'
    s = _open(tmp_path, policy)
    try:
        for uri in ("notes://x/%73ecret/a",            # percent-encoded in the path
                    "notes://%73ecret/a",              # or in the host part a server may read as a folder
                    "file:///data/%73ecret",
                    "https://EVIL.example/a",          # host compared as written and normalised
                    "https://someone@evil.example:443/a",
                    "https://BAD.example/a",            # equals sees each reading on its own
                    "notes://x/keys/%6dain"):
            r = s.request("resources/read", {"uri": uri})
            assert r.get("error", {}).get("code") == -32001, (uri, r)
    finally:
        s.close()


def test_a_rate_rule_counts_a_read_whichever_reading_it_matched(tmp_path):
    # "EVIL.example" only matches the rule in its lowercased reading; the read must still count against it.
    policy = "default: allow\nguard_resources: true\nrules:\n" \
             '  - {name: few, tool: "resources/read", args: {host: evil.example}, rate: 2/minute, decision: deny}\n'
    s = _open(tmp_path, policy)
    try:
        got = [s.request("resources/read", {"uri": f"https://EVIL.example/{i}"}) for i in range(3)]
        assert [r.get("error", {}).get("code") for r in got] == [-32002, -32002, -32001]  # forwarded twice, then refused
    finally:
        s.close()
