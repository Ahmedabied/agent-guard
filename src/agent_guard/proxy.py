"""The proxy: an MCP stdio server that wraps another one.

The client (the agent's host app) talks to the proxy on stdin and stdout. The proxy starts the
real server as a child process and copies every message both ways untouched, except
"tools/call" requests (and "resources/read" with guard_resources: true, "prompts/get" with guard_prompts: true),
which go through the policy first. A denied call never reaches the server: the client gets a normal tool result
with isError set and the reason, so the agent can read it and change course instead of crashing (a denied read or
prompt gets a JSON-RPC error, since it has no tool result to carry the reason).

MCP over stdio is newline-delimited JSON-RPC, so this needs no MCP SDK and does not care which
protocol version the two ends agree on. The decisions themselves live in judge.py.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from typing import Any

from .audit import AuditLog, Scrubber
from .judge import (  # noqa: F401  re-exported: older imports name them from here
    RESOURCE_READ,
    Approver,
    CommandApprover,
    DenyApprover,
    Judge,
    TtyApprover,
    Verdict,
    _key,
    _line,
    make_approver,
    parse_strict,
    recover_id,
    resource_readings,
)
from .policy import Policy


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
        self.quiet = quiet
        self.judge = Judge(policy, audit, scrub, approver, say=self._say)
        self.client_in = client_in or sys.stdin.buffer
        self.client_out = client_out or sys.stdout.buffer
        self.proc: subprocess.Popen | None = None
        self._out_lock = threading.Lock()
        self._srv_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._pending: dict[str, tuple[Any, str, int]] = {}
        self._list_ids: set[str] = set()
        self._done = threading.Event()
        self.internal_errors = 0

    @property
    def stats(self) -> dict:
        return self.judge.stats

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

    # ---- client to server -----------------------------------------------------------------

    def _pump_client(self) -> None:
        try:
            for raw in iter(self.client_in.readline, b""):
                if not raw.strip():
                    continue
                try:
                    msg = parse_strict(raw)
                except (ValueError, RecursionError) as e:  # never forward what we could not judge
                    # The client gets its own id back when it can be read for sure, so it is not left waiting
                    # for an answer that never comes (JSON-RPC uses null only when the id cannot be told).
                    why = "nested too deep to judge" if isinstance(e, RecursionError) else f"{e}"
                    msg_id = recover_id(raw)
                    self.judge.log({"event": "rejected", "id": msg_id, "reason": f"unparseable client message: {why}"[:300]})
                    self._to_client(_line({"jsonrpc": "2.0", "id": msg_id, "error": {
                        "code": -32700, "message": f"agent-guard: parse error: {why}"[:300]}}))
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
            self.judge.log({"event": "rejected", "reason": reason})
        except Exception:  # noqa: BLE001
            pass
        items = msg if isinstance(msg, list) else [msg]
        replies = [{"jsonrpc": "2.0", "id": m["id"], "error": {"code": -32603, "message": f"agent-guard: {reason}"}}
                   for m in items if isinstance(m, dict) and "id" in m and "method" in m]
        if replies:
            self._to_client(_line(replies if isinstance(msg, list) else replies[0]))

    def _message(self, msg: dict) -> None:
        # Everything forwarded is re-serialised from the parsed message, so the server receives
        # exactly what the policy judged, byte for byte.
        method = msg.get("method")
        if self.judge.judged(msg):
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
            if self.judge.judged(item):
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
        """Judge one tools/call (or resources/read, prompts/get). True means forward it now."""
        verdict = self.judge.call(msg)
        if verdict.action == "allow":
            self._track(msg.get("id"), "id" in msg, verdict.name)
            return True
        if verdict.action == "ask":
            threading.Thread(target=self._ask, args=(msg, verdict), daemon=True).start()
        elif verdict.reply is not None:
            self._to_client(_line(verdict.reply))
        return False

    def _track(self, msg_id: Any, has_id: bool, name: str) -> None:
        if has_id:
            with self._state_lock:
                self._pending[_key(msg_id)] = (msg_id, name, time.perf_counter_ns())

    def _ask(self, msg: dict, verdict: Verdict) -> None:
        verdict = self.judge.ask(msg, verdict)
        if verdict.action == "allow":
            self._track(msg.get("id"), "id" in msg, verdict.name)
            self._to_server(_line(msg))
        elif verdict.reply is not None:
            self._to_client(_line(verdict.reply))

    # ---- server to client -----------------------------------------------------------------

    def _pump_server(self) -> None:
        try:
            for raw in iter(self.proc.stdout.readline, b""):
                done: list = []
                if self._pending or self._list_ids:
                    raw, done = self._inspect(raw)
                self._to_client(raw)
                for (msg_id, name, t0), item in done:  # logged after forwarding: off the hot path
                    self.judge.result(msg_id, name, t0, item)
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
                changed |= self.judge.filter_tools(item)
        if changed:
            raw = _line(msg)
        return raw, done

    def _fail_pending(self) -> None:
        with self._state_lock:
            pending = list(self._pending.values())
            self._pending.clear()
        for msg_id, name, _ in pending:
            self.judge.log({"event": "result", "id": msg_id, "tool": name, "ok": False, "us": 0, "error": "server exited"})
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
