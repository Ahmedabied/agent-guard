"""Command line: agent-guard run | serve | check | verify | learn | test | log"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .audit import AuditLog, Scrubber, read_entries, verify
from .learn import Incident, LearnError, decide, incident_from_log, learn, load_cases, run_cases
from .policy import Policy, PolicyError


def _default_log() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return Path(base) / "agent-guard" / "audit.jsonl"


def _audit_path(policy: Policy, policy_path: Path, flag: str | None) -> Path:
    if flag:
        return Path(flag).expanduser()
    configured = policy.audit.get("path")
    if configured:
        p = Path(str(configured)).expanduser()
        return p if p.is_absolute() else policy_path.parent / p
    return _default_log()


def cmd_run(a) -> int:
    from .proxy import Proxy, make_approver

    if not a.command:
        print("agent-guard run: give the server command after --, e.g. agent-guard run -p guard.yaml -- npx server", file=sys.stderr)
        return 2
    policy_path = Path(a.policy)
    policy = Policy.from_file(policy_path)
    log_path = _audit_path(policy, policy_path, a.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    scrub = Scrubber(policy.audit.get("redact"), int(policy.audit.get("max_value_chars", 2000)))
    from . import tracing

    tracing.setup()
    with AuditLog(log_path, fsync=bool(policy.audit.get("fsync", False))) as audit:
        proxy = Proxy(policy, a.command, audit=audit, scrub=scrub, approver=make_approver(policy.ask), quiet=a.quiet)
        code = proxy.run()
    tracing.shutdown()  # os._exit below skips atexit, so the last spans are sent here
    # The client reader thread may still be blocked on stdin, holding its buffer lock. A normal
    # interpreter exit would abort on that lock, so flush what matters and leave directly.
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    finally:
        os._exit(code)


def cmd_serve(a) -> int:
    try:
        from .gateway import Gateway, GatewayError, parse_listen, serve, upstream_headers_from_env
    except ImportError as e:
        print(f"agent-guard serve needs the http extra ({e.name} is missing): pip install -e '.[http]' in a clone, "
              "or pip install 'agent-guard[http] @ git+https://github.com/Ahmedabied/agent-guard'", file=sys.stderr)
        return 2
    from . import tracing
    from .judge import Judge, make_approver

    try:
        host, port = parse_listen(a.listen)
        headers = upstream_headers_from_env(a.upstream_header)
        policy_path = Path(a.policy)
        policy = Policy.from_file(policy_path)
        log_path = _audit_path(policy, policy_path, a.log)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        scrub = Scrubber(policy.audit.get("redact"), int(policy.audit.get("max_value_chars", 2000)))
        with AuditLog(log_path, fsync=bool(policy.audit.get("fsync", False))) as audit:
            def say(text: str) -> None:
                if not a.quiet:
                    print(f"agent-guard: {text}", file=sys.stderr, flush=True)

            judge = Judge(policy, audit, scrub, make_approver(policy.ask), say=say)
            gateway = Gateway(judge, a.upstream, port, headers, max_body=a.max_body, allow_origins=a.allow_origin)
            if tracing.setup():
                gateway.on_shutdown.append(tracing.shutdown)  # sends the last spans before the process ends
            return serve(gateway, host, quiet=a.quiet)
    except GatewayError as e:
        print(f"agent-guard serve: {e}", file=sys.stderr)
        return 2


def cmd_check(a) -> int:
    policy = Policy.from_file(a.policy)
    try:
        args = json.loads(a.args) if a.args else {}
    except ValueError as e:
        print(f"agent-guard check: arguments are not JSON: {e}", file=sys.stderr)
        return 2
    d = decide(policy, a.tool, args)  # guards included: a prompt with guard_prompts off passes
    print(f"{d.action}  rule={d.rule}  reason={d.reason}")
    return {"allow": 0, "deny": 1, "ask": 3}[d.action]


def cmd_verify(a) -> int:
    r = verify(a.log, a.expect_head)
    if r.ok:
        print(f"ok: {r.entries} entries, chain intact, head {r.head}")
        return 0
    print(f"BROKEN at line {r.line}: {r.error} ({r.entries} entries before it are intact)")
    return 1


def _parse_match(items: list[str]) -> dict[str, str]:
    out = {}
    for it in items or []:
        if "=" not in it:
            raise LearnError(f"--match takes key=glob, got {it!r}")
        k, v = it.split("=", 1)
        out[k] = v
    return out


def cmd_learn(a) -> int:
    if a.seq is not None:
        policy_path = Path(a.policy)
        log = a.from_log or _audit_path(Policy.from_file(policy_path), policy_path, None)
        incident = incident_from_log(log, a.seq)
    elif a.tool:
        try:
            args = json.loads(a.args) if a.args else {}
        except ValueError as e:
            raise LearnError(f"--args is not JSON: {e}") from None
        if not isinstance(args, dict):
            raise LearnError("--args must be a JSON object")
        incident = Incident(a.tool, args, "a reported incident")
    else:
        raise LearnError("give an incident: --seq N (from the audit log) or --tool NAME --args JSON")
    rule = learn(a.policy, a.tests, incident, a.name, a.reason, _parse_match(a.match))
    print(f"added rule {rule['name']!r} at the top of {a.policy}:")
    print(json.dumps(rule, indent=2, ensure_ascii=False))
    print(f"added a regression case to {a.tests}; run 'agent-guard test -p {a.policy} {a.tests}' in CI")
    if not a.match:
        print("note: the rule matches these exact values. Use --match key=glob to cover the whole family.")
    return 0


def cmd_test(a) -> int:
    files = a.tests or ["guard-tests.yaml"]
    cases = []
    for f in files:
        if not Path(f).exists():
            print(f"agent-guard test: {f} not found", file=sys.stderr)
            return 2
        cases += load_cases(f)
    failures = run_cases(a.policy, cases)
    failed = {id(c) for c, _, _ in failures}
    for c in cases:
        if id(c) not in failed:
            print(f"pass  {c.name}  ({c.tool} -> {c.expect})")
    for c, got, rule in failures:
        print(f"FAIL  {c.name}  ({c.tool}): expected {c.expect}, got {got} from rule {rule}")
    print(f"{len(cases) - len(failures)}/{len(cases)} cases pass")
    return 1 if failures else 0


def cmd_log(a) -> int:
    entries = list(read_entries(a.log))
    if a.denied:
        entries = [e for e in entries if e.get("decision") == "deny" or e.get("approved") is False]
    for e in entries[-a.last:]:
        if e.get("event") == "call":
            args = json.dumps(e.get("args", {}), ensure_ascii=False)
            if len(args) > 100:
                args = args[:100] + "..."
            print(f"{e['seq']:>6}  {e['ts']}  {e.get('decision', '?'):5}  {e.get('tool')}  {args}  [{e.get('rule')}]")
        elif e.get("event") == "result":
            print(f"{e['seq']:>6}  {e['ts']}  {'ok' if e.get('ok') else 'error':5}  {e.get('tool')}  {e.get('us', 0) / 1000:.1f} ms")
        else:
            print(f"{e['seq']:>6}  {e['ts']}  {e.get('event')}  {e.get('tool')}  approved={e.get('approved')}  {e.get('how', '')}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agent-guard", description="Guardrails as code for MCP tool calls.")
    p.add_argument("--version", action="version", version=f"agent-guard {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="wrap an MCP stdio server: agent-guard run -p guard.yaml -- <server command>")
    r.add_argument("-p", "--policy", default="guard.yaml")
    r.add_argument("--log", help="audit log path (default: policy audit.path, else ~/.local/state/agent-guard/audit.jsonl)")
    r.add_argument("-q", "--quiet", action="store_true", help="no stderr line per denied call")
    r.add_argument("command", nargs=argparse.REMAINDER)
    r.set_defaults(fn=cmd_run)

    s = sub.add_parser("serve", help="guard a Streamable HTTP MCP server: agent-guard serve -p guard.yaml --upstream URL")
    s.add_argument("-p", "--policy", default="guard.yaml")
    s.add_argument("--upstream", required=True, help="the MCP server's URL, e.g. https://mcp.example.com/mcp")
    s.add_argument("--listen", default="127.0.0.1:8808", help="loopback HOST:PORT (default 127.0.0.1:8808)")
    s.add_argument("--upstream-header", action="append", metavar="NAME=ENVVAR",
                   help="send header NAME to the upstream with the value of environment variable ENVVAR")
    s.add_argument("--allow-origin", action="append", metavar="ORIGIN",
                   help="a browser origin allowed besides the gateway's own (default: none)")
    s.add_argument("--max-body", type=int, default=4 * 1024 * 1024, help="largest request body in bytes (4 MiB)")
    s.add_argument("--log", help="audit log path (default: policy audit.path, else ~/.local/state/agent-guard/audit.jsonl)")
    s.add_argument("-q", "--quiet", action="store_true", help="no stderr line per denied call")
    s.set_defaults(fn=cmd_serve)

    c = sub.add_parser("check", help="what would the policy decide for one call? exit 0 allow, 1 deny, 3 ask")
    c.add_argument("-p", "--policy", default="guard.yaml")
    c.add_argument("tool")
    c.add_argument("args", nargs="?", help="arguments as a JSON object")
    c.set_defaults(fn=cmd_check)

    v = sub.add_parser("verify", help="check that the audit log's hash chain is intact")
    v.add_argument("log")
    v.add_argument("--expect-head", help="the head hash you saved earlier; catches lines cut from the end")
    v.set_defaults(fn=cmd_verify)

    l = sub.add_parser("learn", help="turn an incident into a deny rule plus a regression test")
    l.add_argument("-p", "--policy", default="guard.yaml")
    l.add_argument("--tests", default="guard-tests.yaml")
    l.add_argument("--from-log", help="audit log to read --seq from (default: the policy's audit.path)")
    l.add_argument("--seq", type=int, help="the audit log entry of the incident")
    l.add_argument("--tool", help="or describe the incident: the tool name")
    l.add_argument("--args", help="and its arguments as a JSON object")
    l.add_argument("--name", required=True, help="name for the new rule, e.g. no-drop-prod")
    l.add_argument("--reason", required=True, help="shown to the agent when the rule blocks a call")
    l.add_argument("--match", action="append", metavar="KEY=GLOB", help="generalise: match this argument by glob")
    l.set_defaults(fn=cmd_learn)

    t = sub.add_parser("test", help="replay regression cases against the policy (use in CI)")
    t.add_argument("-p", "--policy", default="guard.yaml")
    t.add_argument("tests", nargs="*")
    t.set_defaults(fn=cmd_test)

    g = sub.add_parser("log", help="show recent audit entries with their seq numbers")
    g.add_argument("log", nargs="?", default=str(_default_log()))
    g.add_argument("-n", "--last", type=int, default=20)
    g.add_argument("--denied", action="store_true")
    g.set_defaults(fn=cmd_log)
    return p


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)
    if getattr(a, "command", None) and a.command[:1] == ["--"]:
        a.command = a.command[1:]
    try:
        return a.fn(a)
    except (PolicyError, LearnError, ValueError, OSError) as e:
        print(f"agent-guard: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
