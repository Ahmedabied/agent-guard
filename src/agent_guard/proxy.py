"""The proxy: an MCP stdio server that wraps another one.

The client (the agent's host app) talks to the proxy on stdin and stdout. The proxy starts the
real server as a child process and copies every message both ways untouched, except
"tools/call" requests (and "resources/read" with guard_resources: true), which go through the policy first. A denied call never reaches the
server: the client gets a normal tool result with isError set and the reason, so the agent can
read it and change course instead of crashing.

MCP over stdio is newline-delimited JSON-RPC, so this needs no MCP SDK and does not care which
protocol version the two ends agree on.
"""

from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import threading
import time
from typing import Any, Callable
from urllib.parse import unquote, urlsplit

from .audit import AuditError, AuditLog, Scrubber
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


def resource_args(uri: str) -> dict:
    """What a rule sees for resources/read: the uri, and for a local file:// uri its decoded path, so `under:` works
    on it (%2e%2e and .. included). A file:// uri naming another host gets no path, so a path rule cannot allow it."""
    args = {"uri": uri}
    u = urlsplit(uri)
    if u.scheme.lower() == "file" and u.netloc in ("", "localhost"):
        args["path"] = unquote(u.path)
    return args


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


class Proxy:
    def __init__(
        self,
        policy: Policy,
        command: list[str],
        audit: AuditLog | None = None,
        scrub: Scrubber | None = None,
        approver: Approver | None = None,
        client_in=None,
        client_out=None,
        quiet: bool = False,
    ):
        self.policy = policy
        self.command = command
        self.audit = audit
        self.scrub = scrub or Scrubber()
        self.approver = approver or make_approver(policy.ask)
        self.client_in = client_in or sys.stdin.buffer
        self.client_out = client_out or sys.stdout.buffer
        self.quiet = quiet
        self.proc: subprocess.Popen | None = None
        self._out_lock = threading.Lock()
        self._srv_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._pending: dict[str, tuple[Any, str, int]] = {}
        self._list_ids: set[str] = set()
        self._done = threading.Event()
        self.internal_errors = 0
        self.stats = {"allowed": 0, "denied": 0, "asked": 0}

    # ---- plumbing -------------------------------------------------------------------------

    def _to_client(self, data: bytes) -> None:
        with self._out_lock:
            try:
                self.client_out.write(data)
                self.client_out.flush()
            except (BrokenPipeError, ValueError, OSError):
                self._done.set()

    def _to_server(self, data: bytes) -> None:
        with self._srv_lock:
            try:
                self.proc.stdin.write(data if data.endswith(b"\n") else data + b"\n")
                self.proc.stdin.flush()
            except (BrokenPipeError, ValueError, OSError):
                self._done.set()

    def _say(self, text: str) -> None:
        if not self.quiet:
            print(f"agent-guard: {text}", file=sys.stderr, flush=True)

    def _log(self, record: dict) -> bool:
        if self.audit is None:
            return True
        try:
            self.audit.append(record)
            return True
        except Exception as e:  # noqa: BLE001  any failure to log means the call is denied
            self._say(f"audit log write failed: {type(e).__name__}: {e}"[:300])
            return False

    # ---- client to server -----------------------------------------------------------------

    def _pump_client(self) -> None:
        try:
            for raw in iter(self.client_in.readline, b""):
                if not raw.strip():
                    continue
                try:
                    msg = parse_strict(raw)
                except (ValueError, RecursionError) as e:  # never forward what we could not judge
                    self._log({"event": "rejected", "reason": f"unparseable client message: {e}"[:300]})
                    self._to_client(_line({"jsonrpc": "2.0", "id": None, "error": {
                        "code": -32700, "message": f"agent-guard: parse error: {e}"[:300]}}))
                    continue
                try:
                    if isinstance(msg, list):
                        self._batch(msg)
                    elif isinstance(msg, dict):
                        self._message(msg)
                    else:
                        self._to_server(_line(msg))
                except Exception as e:  # noqa: BLE001  one bad message must not take the guard down
                    self._internal_error(msg, e)
        finally:
            self._done.set()

    def _internal_error(self, msg: Any, err: Exception) -> None:
        """A message the guard failed to judge is denied, logged if possible, and answered, and
        the guard keeps serving. The exit code reports it afterwards."""
        self.internal_errors += 1
        reason = f"internal error while judging: {type(err).__name__}"
        self._say(f"{reason}: {err}"[:300])
        try:
            self._log({"event": "rejected", "reason": reason})
        except Exception:  # noqa: BLE001
            pass
        items = msg if isinstance(msg, list) else [msg]
        replies = [{"jsonrpc": "2.0", "id": m["id"], "error": {"code": -32603, "message": f"agent-guard: {reason}"}}
                   for m in items if isinstance(m, dict) and "id" in m and "method" in m]
        if replies:
            self._to_client(_line(replies if isinstance(msg, list) else replies[0]))

    def _judged(self, msg: Any) -> bool:
        if not isinstance(msg, dict):
            return False
        m = msg.get("method")
        return m == "tools/call" or (m == RESOURCE_READ and self.policy.guard_resources)

    def _message(self, msg: dict) -> None:
        # Everything forwarded is re-serialised from the parsed message, so the server receives
        # exactly what the policy judged, byte for byte.
        method = msg.get("method")
        if self._judged(msg):
            if self._call(msg):
                self._to_server(_line(msg))
        else:
            if method == "tools/list" and "id" in msg and self.policy.hide_denied_tools:
                with self._state_lock:
                    self._list_ids.add(_key(msg["id"]))
            self._to_server(_line(msg))

    def _batch(self, items: list) -> None:
        keep = []
        for item in items:
            if self._judged(item):
                if self._call(item):
                    keep.append(item)
            else:
                if isinstance(item, dict) and item.get("method") == "tools/list" and "id" in item \
                        and self.policy.hide_denied_tools:
                    with self._state_lock:
                        self._list_ids.add(_key(item["id"]))
                keep.append(item)
        if keep:
            self._to_server(_line(keep))

    def _call(self, msg: dict) -> bool:
        """Judge one tools/call (or resources/read). True means forward it now."""
        t0 = time.perf_counter_ns()
        msg_id = msg.get("id")
        has_id = "id" in msg
        params = msg.get("params")
        if msg.get("method") == RESOURCE_READ:
            uri = params.get("uri") if isinstance(params, dict) else None
            name, args = RESOURCE_READ, (resource_args(uri) if isinstance(uri, str) else None)
            bad = "resources/read needs a string uri" if args is None else ""
        else:
            name = params.get("name") if isinstance(params, dict) else None
            args = params.get("arguments") if isinstance(params, dict) else None
            bad = "" if isinstance(name, str) and (args is None or isinstance(args, dict)) else \
                "tools/call needs a string name and object arguments"
        if bad:
            self._log({"event": "call", "id": msg_id, "tool": name if isinstance(name, str) else None,
                       "decision": "deny", "rule": "malformed", "reason": bad})
            self.stats["denied"] += 1
            if has_id:
                self._to_client(_line({"jsonrpc": "2.0", "id": msg_id, "error": {
                    "code": -32602, "message": f"agent-guard: {bad}"}}))
            return False
        decision = self.policy.evaluate(name, args)
        eval_us = (time.perf_counter_ns() - t0) // 1000
        logged = self._log({"event": "call", "id": msg_id, "tool": name, "args": self.scrub(args or {}),
                            "decision": decision.action, "rule": decision.rule, "reason": decision.reason,
                            "eval_us": eval_us})
        if not logged:  # no audit trail, no tool call
            decision = Decision("deny", "audit-unavailable", "the audit log could not be written")
        if decision.action == "allow":
            self.stats["allowed"] += 1
            self._track(msg_id, has_id, name)
            return True
        if decision.action == "deny":
            self.stats["denied"] += 1
            self._say(f"denied {name} (rule {decision.rule}): {decision.reason}")
            if has_id:
                self._blocked(msg, name, decision.rule, decision.reason)
            return False
        self.stats["asked"] += 1
        threading.Thread(target=self._ask, args=(msg, name, args, decision), daemon=True).start()
        return False

    def _track(self, msg_id: Any, has_id: bool, name: str) -> None:
        if has_id:
            with self._state_lock:
                self._pending[_key(msg_id)] = (msg_id, name, time.perf_counter_ns())

    def _blocked(self, msg: dict, name: str, rule: str, reason: str) -> None:
        if msg.get("method") == RESOURCE_READ:  # no tool result to carry it: a JSON-RPC error, like a missing resource
            uri = (msg.get("params") or {}).get("uri")
            self._to_client(_line({"jsonrpc": "2.0", "id": msg.get("id"), "error": {
                "code": -32001, "message": f"agent-guard blocked reading {uri}: {reason} (rule: {rule})"}}))
            return
        text = f"agent-guard blocked this call to {name}: {reason} (rule: {rule})"
        result: dict = {"content": [{"type": "text", "text": text}], "isError": True}
        if _wants_result_type(msg.get("params")):
            result["resultType"] = "complete"
        self._to_client(_line({"jsonrpc": "2.0", "id": msg.get("id"), "result": result}))

    def _ask(self, msg: dict, name: str, args: Any, decision: Decision) -> None:
        try:
            ok, how = self.approver(name, args, decision)
        except Exception as e:  # an approver bug must not let a call through
            ok, how = False, f"approver error: {e.__class__.__name__}"
        msg_id = msg.get("id")
        if not self._log({"event": "approval", "id": msg_id, "tool": name, "approved": ok, "how": how}):
            ok, how = False, "the audit log could not be written"
        if ok:
            self.policy.charge(decision)
            self._track(msg_id, "id" in msg, name)
            self._to_server(_line(msg))
        else:
            self._say(f"denied {name} after ask: {how}")
            if "id" in msg:
                self._blocked(msg, name, decision.rule, f"needs approval and was not approved ({how})")

    # ---- server to client -----------------------------------------------------------------

    def _pump_server(self) -> None:
        try:
            for raw in iter(self.proc.stdout.readline, b""):
                done: list = []
                if self._pending or self._list_ids:
                    raw, done = self._inspect(raw)
                self._to_client(raw)
                for (msg_id, name, t0), item in done:  # logged after forwarding: off the hot path
                    res = item.get("result")
                    ok = "error" not in item and not (isinstance(res, dict) and res.get("isError") is True)
                    us = (time.perf_counter_ns() - t0) // 1000
                    self._log({"event": "result", "id": msg_id, "tool": name, "ok": ok, "us": us})
        finally:
            self._fail_pending()
            self._done.set()

    def _inspect(self, raw: bytes) -> tuple[bytes, list]:
        try:
            msg = json.loads(raw)
        except ValueError:
            return raw, []
        items = msg if isinstance(msg, list) else [msg]
        changed = False
        done = []
        for item in items:
            if not isinstance(item, dict) or "method" in item or "id" not in item:
                continue
            k = _key(item["id"])
            with self._state_lock:
                entry = self._pending.pop(k, None)
                is_list = k in self._list_ids
                self._list_ids.discard(k)
            if entry is not None:
                done.append((entry, item))
            elif is_list:
                changed |= self._filter_tools(item)
        if changed:
            raw = _line(msg)
        return raw, done

    def _filter_tools(self, item: dict) -> bool:
        res = item.get("result")
        if not isinstance(res, dict) or not isinstance(res.get("tools"), list):
            return False
        before = res["tools"]
        res["tools"] = [t for t in before if not (isinstance(t, dict) and isinstance(t.get("name"), str)
                                                   and self.policy.always_denied(t["name"]))]
        return len(res["tools"]) != len(before)

    def _fail_pending(self) -> None:
        with self._state_lock:
            pending = list(self._pending.values())
            self._pending.clear()
        for msg_id, name, _ in pending:
            self._log({"event": "result", "id": msg_id, "tool": name, "ok": False, "us": 0, "error": "server exited"})
            self._to_client(_line({"jsonrpc": "2.0", "id": msg_id, "error": {
                "code": -32603, "message": "agent-guard: the tool server exited before answering"}}))

    # ---- lifecycle ------------------------------------------------------------------------

    def run(self) -> int:
        self.proc = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
        threads = [threading.Thread(target=self._pump_server, daemon=True),
                   threading.Thread(target=self._pump_client, daemon=True)]
        for t in threads:
            t.start()
        self._done.wait()
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            code = self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:
                code = self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                code = self.proc.wait()
        threads[0].join(timeout=2)
        if self.internal_errors and not (code and code > 0):
            return 70  # EX_SOFTWARE: the guard denied messages it failed to judge; see stderr
        return code if code and code > 0 else 0
