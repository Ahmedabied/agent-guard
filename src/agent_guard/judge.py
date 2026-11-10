"""The judge: everything that decides a client message, shared by every transport.

The stdio proxy (proxy.py) and the HTTP gateway (http.py) only move bytes. Both hand each client message to one
Judge, so there is one copy of the rules about what reaches a server: a second copy that drifted would be a bypass.
The policy and the audit log lock themselves, so one Judge can serve many threads.
"""

from __future__ import annotations

import json
import os
import select
import subprocess
import threading
import time
from dataclasses import dataclass, replace
from typing import Any, Callable
from urllib.parse import unquote, urlsplit

from . import tracing
from .audit import AuditLog, Scrubber
from .policy import Decision, Policy

Approver = Callable[[str, Any, Decision], "tuple[bool, str]"]

VERSION_META = "io.modelcontextprotocol/protocolVersion"
RESULT_TYPE_SINCE = "2026-07-28"  # from this version on, every result must carry resultType


def _wants_result_type(params: Any) -> bool:
    # 2026-07-28 sessions have no initialize; each request names its version in _meta.
    meta = params.get("_meta") if isinstance(params, dict) else None
    version = meta.get(VERSION_META) if isinstance(meta, dict) else None
    return isinstance(version, str) and version >= RESULT_TYPE_SINCE


def _key(msg_id: Any) -> str:
    return json.dumps(msg_id, sort_keys=True)


RESOURCE_READ = "resources/read"
PROMPT_GET = "prompts/get"
# Rules on these names judge those requests, so a tools/call naming one is refused: it would be judged by rules
# written for something else.
RESERVED = (RESOURCE_READ, PROMPT_GET)


def resource_readings(uri: str) -> tuple[list[dict] | None, str]:
    """What a rule sees for resources/read: arguments uri, scheme, host and path, once for every reading a server
    might take. The read is judged once per reading: denied if any reading is denied, allowed only if all are.

    A local file:// uri has one reading: the decoded path, so `under:` sees through `..` and `%2e%2e`. Any other
    scheme: path is the decoded path, the decoded host and path together (some servers read the host as a folder),
    and the raw uri, which cannot be placed in a folder, so an `under:` deny rule always catches another scheme and
    an `under:` allow rule never passes one (allow those by `scheme` or `uri`); host is as written and lowercased
    without user or port. Refused before any rule (None, and why): a uri that does not parse or has no scheme, and a
    file:// uri naming another host, port or user."""
    try:
        u = urlsplit(uri)
        hostname = u.hostname or ""
    except ValueError:
        return None, "resources/read needs a uri that parses"
    scheme = u.scheme.lower()
    if not scheme:
        return None, "resources/read needs an absolute uri, with a scheme"
    if scheme == "file":
        if u.netloc.lower() not in ("", "localhost"):
            return None, f"a file:// uri naming another host ({u.netloc}) is refused"
        return [{"uri": uri, "scheme": scheme, "host": "", "path": unquote(u.path)}], ""
    paths = dict.fromkeys((unquote(u.path), unquote(u.netloc + u.path), uri))
    hosts = dict.fromkeys((u.netloc, hostname))
    return [{"uri": uri, "scheme": scheme, "host": h, "path": p} for p in paths for h in hosts], ""


def _line(obj: Any) -> bytes:
    try:
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
    except UnicodeEncodeError:  # lone surrogates: escape everything instead
        return json.dumps(obj, separators=(",", ":")).encode("ascii") + b"\n"


def _no_duplicate_keys(pairs: list) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate key {k!r}")
        out[k] = v
    return out


def _no_constants(name: str) -> Any:
    raise ValueError(f"{name} is not valid JSON")


_STRICT = json.JSONDecoder(object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constants)


def parse_strict(raw: bytes) -> Any:
    """Parse one client message the strict way. Duplicate keys, NaN and bad UTF-8 are refused,
    because two parsers that disagree on them would let the server run a call the policy never
    saw (for example {"name": "read_file", "name": "delete_file"})."""
    return _STRICT.decode(raw.decode("utf-8"))


def recover_id(raw: bytes) -> Any:
    """The top-level id of a message parse_strict refused, or None when it cannot be told for sure.

    A message nested deeper than this Python's JSON parser can follow (about 1,000 levels on 3.10, about 100,000 on
    3.12 and later) or one with a duplicate key is refused, but the client is still waiting for an answer to its
    id. This reads the text flat, one character at a time with no recursion, and returns the id only when the
    top level is an object with exactly one "id" key holding a string or an integer."""
    text = raw.decode("utf-8", errors="replace")
    n = len(text)

    def skip_space(k: int) -> int:
        while k < n and text[k] in " \t\r\n":
            k += 1
        return k

    def string_end(k: int) -> int:  # k is on the opening quote; returns the index after the closing one, or -1
        k += 1
        while k < n and text[k] != '"':
            k += 2 if text[k] == "\\" else 1
        return k + 1 if k < n else -1

    i = skip_space(0)
    if i >= n or text[i] != "{":
        return None
    depth, found, expect_key = 0, [], False
    while i < n:
        c = text[i]
        if c == '"':
            j = string_end(i)
            if j < 0:
                return None
            if depth == 1 and expect_key:
                try:
                    key = json.loads(text[i:j])
                except ValueError:
                    return None
                if key == "id":
                    k = skip_space(j)
                    if k >= n or text[k] != ":":
                        return None
                    k = skip_space(k + 1)
                    if k < n and text[k] == '"':
                        end = string_end(k)
                        if end < 0:
                            return None
                    else:
                        end = k
                        while end < n and text[end] in "-+.eE0123456789":
                            end += 1
                    try:
                        value = json.loads(text[k:end])
                    except ValueError:
                        return None
                    if isinstance(value, bool) or not isinstance(value, (str, int)):
                        return None
                    after = skip_space(end)
                    if after >= n or text[after] not in ",}":
                        return None
                    found.append(value)
                    j = end
            expect_key = False
            i = j
            continue
        if c in "{[":
            depth += 1
            expect_key = c == "{" and depth == 1
        elif c in "}]":
            depth -= 1
            if depth == 0:
                break
        elif c == "," and depth == 1:
            expect_key = True
        i += 1
    return found[0] if len(found) == 1 else None


class DenyApprover:
    def __call__(self, tool: str, args: Any, decision: Decision) -> tuple[bool, str]:
        return False, "nobody to ask (ask.via is deny)"


class TtyApprover:
    """Asks on the terminal the proxy was started from. MCP clients usually start servers
    without a terminal; then every ask is denied, which is the safe answer."""

    def __init__(self, timeout: float = 60, max_chars: int = 4000):
        self.timeout = timeout
        self.max_chars = max_chars
        self._lock = threading.Lock()

    def __call__(self, tool: str, args: Any, decision: Decision) -> tuple[bool, str]:
        with self._lock:
            try:
                fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
            except OSError:
                return False, "no terminal to ask on"
            with os.fdopen(fd, "r+b", buffering=0) as tty:
                # ASCII only: control and bidi characters cannot disguise what is being approved.
                shown = json.dumps(args, ensure_ascii=True, indent=2, sort_keys=True)
                name = json.dumps(tool, ensure_ascii=True)
                if len(shown) > self.max_chars:
                    tty.write(f"\nagent-guard: denied {name}: arguments too long to show ({len(shown)} chars)\n".encode())
                    return False, f"arguments too long to show for approval ({len(shown)} chars)"
                tty.write(f"\nagent-guard: {name} with arguments\n{shown}\n  rule {decision.rule}: "
                          f"{decision.reason}\n  allow this call? [y/N] ".encode("ascii", "backslashreplace"))
                ready, _, _ = select.select([tty], [], [], self.timeout)
                if not ready:
                    tty.write(b"\n  no answer, denied\n")
                    return False, f"no answer on the terminal in {self.timeout:g}s"
                answer = tty.readline().strip().lower()
                if answer in (b"y", b"yes"):
                    return True, "approved on the terminal"
                return False, "refused on the terminal"


class CommandApprover:
    """Runs a command with the call as JSON on stdin. Exit code 0 approves."""

    def __init__(self, command: list[str], timeout: float = 60):
        self.command = command
        self.timeout = timeout

    def __call__(self, tool: str, args: Any, decision: Decision) -> tuple[bool, str]:
        payload = json.dumps({"tool": tool, "arguments": args, "rule": decision.rule, "reason": decision.reason})
        try:
            r = subprocess.run(self.command, input=payload.encode(), capture_output=True, timeout=self.timeout)
        except (OSError, subprocess.TimeoutExpired) as e:
            return False, f"approver command failed: {e.__class__.__name__}"
        return (r.returncode == 0), f"approver command exit {r.returncode}"


def make_approver(cfg: dict) -> Approver:
    via = cfg.get("via", "tty")
    timeout = float(cfg.get("timeout", 60))
    if via == "deny":
        return DenyApprover()
    if via == "command":
        cmd = cfg.get("command")
        if isinstance(cmd, str):
            cmd = [cmd]
        if not cmd or not all(isinstance(c, str) for c in cmd):
            raise ValueError("ask.command must be a command line (a list of strings)")
        return CommandApprover(cmd, timeout)
    if via == "tty":
        return TtyApprover(timeout)
    raise ValueError(f"ask.via must be tty, command or deny, got {via!r}")




@dataclass
class Verdict:
    """What to do with one judged message. action is allow (forward it), deny or ask (then call Judge.ask).
    reply is the message to send back instead, when the client is waiting for one (the request had an id)."""

    action: str
    name: Any = None
    args: Any = None
    decision: Decision | None = None
    reply: dict | None = None


class Judge:
    def __init__(
        self,
        policy: Policy,
        audit: AuditLog | None = None,
        scrub: Scrubber | None = None,
        approver: Approver | None = None,
        say: Callable[[str], None] | None = None,
    ):
        self.policy = policy
        self.audit = audit
        self.scrub = scrub or Scrubber()
        self.approver = approver or make_approver(policy.ask)
        self.say = say or (lambda text: None)
        self._stats_lock = threading.Lock()
        self.stats = {"allowed": 0, "denied": 0, "asked": 0}

    def _count(self, key: str) -> None:
        with self._stats_lock:
            self.stats[key] += 1

    def log(self, record: dict) -> bool:
        if self.audit is None:
            return True
        try:
            self.audit.append(record)
            return True
        except Exception as e:  # noqa: BLE001  any failure to log means the call is denied
            self.say(f"audit log write failed: {type(e).__name__}: {e}"[:300])
            return False

    def judged(self, msg: Any) -> bool:
        if not isinstance(msg, dict):
            return False
        m = msg.get("method")
        return m == "tools/call" or (m == RESOURCE_READ and self.policy.guard_resources) \
            or (m == PROMPT_GET and self.policy.guard_prompts)

    def call(self, msg: dict) -> Verdict:
        """Judge one tools/call (or resources/read, prompts/get). allow means forward it now; ask means call ask()
        (it blocks)."""
        t0 = time.perf_counter_ns()
        w0 = time.time_ns() if tracing.enabled() else 0
        msg_id = msg.get("id")
        has_id = "id" in msg
        params = msg.get("params")
        if msg.get("method") == RESOURCE_READ:
            uri = params.get("uri") if isinstance(params, dict) else None
            name = RESOURCE_READ
            readings, bad = resource_readings(uri) if isinstance(uri, str) else (None, "resources/read needs a string uri")
            args = readings[0] if readings else None
        elif msg.get("method") == PROMPT_GET:
            readings = None
            prompt = params.get("name") if isinstance(params, dict) else None
            values = params.get("arguments") if isinstance(params, dict) else None
            name = PROMPT_GET
            # Nested, so a prompt argument called "name" cannot stand in for the prompt's name.
            args = {"name": prompt, "arguments": values} if values is not None else {"name": prompt}
            bad = "" if isinstance(prompt, str) and (values is None or isinstance(values, dict)) else \
                "prompts/get needs a string name and object arguments"
        else:
            readings = None
            name = params.get("name") if isinstance(params, dict) else None
            args = params.get("arguments") if isinstance(params, dict) else None
            bad = "" if isinstance(name, str) and (args is None or isinstance(args, dict)) else \
                "tools/call needs a string name and object arguments"
        if bad:
            self.log({"event": "call", "id": msg_id, "tool": name if isinstance(name, str) else None,
                      "decision": "deny", "rule": "malformed", "reason": bad})
            self._count("denied")
            reply = {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32602, "message": f"agent-guard: {bad}"}}
            tracing.decision(msg, name, "deny", "malformed", "malformed request", w0)  # bad can quote the uri
            return Verdict("deny", name, args, None, reply if has_id else None)
        if msg.get("method") == "tools/call" and name in RESERVED:
            decision = Decision("deny", "reserved", f"a tool named {name} would be judged by the rules for {name} "
                                                    "requests; agent-guard keeps that name for them")
        else:
            decision = self._decide(name, readings) if readings else self.policy.evaluate(name, args)
        eval_us = (time.perf_counter_ns() - t0) // 1000
        entry = {"event": "call", "id": msg_id, "tool": name, "args": self.scrub(args or {}),
                 "decision": decision.action, "rule": decision.rule, "reason": decision.reason, "eval_us": eval_us}
        if readings and len(readings) > 1:
            entry["readings"] = len(readings)
        logged = self.log(entry)
        if not logged:  # no audit trail, no tool call
            decision = Decision("deny", "audit-unavailable", "the audit log could not be written")
        tracing.decision(msg, name, decision.action, decision.rule, decision.reason, w0)
        if decision.action == "allow":
            self._count("allowed")
            return Verdict("allow", name, args, decision)
        if decision.action == "deny":
            self._count("denied")
            self.say(f"denied {name} (rule {decision.rule}): {decision.reason}")
            reply = self.blocked(msg, name, decision.rule, decision.reason) if has_id else None
            return Verdict("deny", name, args, decision, reply)
        self._count("asked")
        return Verdict("ask", name, args, decision)

    def _decide(self, name: str, readings: list[dict]) -> Decision:
        """One decision for several readings of the same request: any deny wins, then any ask; allow needs them all.
        Judged without charging rate rules, then an allow is charged once."""
        decisions = [self.policy.evaluate(name, r, charge=False) for r in readings]
        # Every rate rule any reading counted against, once each, so no reading can be used to skip a limit.
        charge = tuple({id(rule): rule for d in decisions for rule in d.charge}.values())
        for action in ("deny", "ask"):
            for d in decisions:
                if d.action == action:
                    return replace(d, charge=charge)
        allowed = replace(decisions[0], charge=charge)
        self.policy.charge(allowed)
        return allowed

    def ask(self, msg: dict, verdict: Verdict) -> Verdict:
        """Run the approver for an ask verdict (blocks until it answers) and return allow or deny."""
        name, args, decision = verdict.name, verdict.args, verdict.decision
        w0 = time.time_ns() if tracing.enabled() else 0
        try:
            ok, how = self.approver(name, args, decision)
        except Exception as e:  # an approver bug must not let a call through
            ok, how = False, f"approver error: {e.__class__.__name__}"
        msg_id = msg.get("id")
        if not self.log({"event": "approval", "id": msg_id, "tool": name, "approved": ok, "how": how}):
            ok, how = False, "the audit log could not be written"
        tracing.decision(msg, name, "allow" if ok else "deny", decision.rule, decision.reason, w0, approval=ok)
        if ok:
            self.policy.charge(decision)
            return Verdict("allow", name, args, decision)
        self.say(f"denied {name} after ask: {how}")
        reply = self.blocked(msg, name, decision.rule, f"needs approval and was not approved ({how})") \
            if "id" in msg else None
        return Verdict("deny", name, args, decision, reply)

    def blocked(self, msg: dict, name: str, rule: str, reason: str) -> dict:
        """The answer the client gets instead of the server's."""
        if msg.get("method") == RESOURCE_READ:  # no tool result to carry it: a JSON-RPC error, like a missing resource
            uri = (msg.get("params") or {}).get("uri")
            return {"jsonrpc": "2.0", "id": msg.get("id"), "error": {
                "code": -32001, "message": f"agent-guard blocked reading {uri}: {reason} (rule: {rule})"}}
        if msg.get("method") == PROMPT_GET:  # nor here: a prompt answer is messages, so an error, like a missing prompt
            prompt = (msg.get("params") or {}).get("name")
            return {"jsonrpc": "2.0", "id": msg.get("id"), "error": {
                "code": -32001, "message": f"agent-guard blocked the prompt {prompt}: {reason} (rule: {rule})"}}
        text = f"agent-guard blocked this call to {name}: {reason} (rule: {rule})"
        result: dict = {"content": [{"type": "text", "text": text}], "isError": True}
        if _wants_result_type(msg.get("params")):
            result["resultType"] = "complete"
        return {"jsonrpc": "2.0", "id": msg.get("id"), "result": result}

    def filter_tools(self, item: dict) -> bool:
        """Drop tools that can never pass from a tools/list result: the ones the policy always denies, and any named
        like a guarded request (every call to those is refused as reserved). True if any were dropped."""
        res = item.get("result")
        if not isinstance(res, dict) or not isinstance(res.get("tools"), list):
            return False
        before = res["tools"]
        res["tools"] = [t for t in before if not (isinstance(t, dict) and isinstance(t.get("name"), str)
                                                   and (t["name"] in RESERVED or self.policy.always_denied(t["name"])))]
        return len(res["tools"]) != len(before)

    def result(self, msg_id: Any, name: str, t0: int, item: dict) -> None:
        """Log the server's answer to an allowed call."""
        res = item.get("result")
        ok = "error" not in item and not (isinstance(res, dict) and res.get("isError") is True)
        us = (time.perf_counter_ns() - t0) // 1000
        self.log({"event": "result", "id": msg_id, "tool": name, "ok": ok, "us": us})
