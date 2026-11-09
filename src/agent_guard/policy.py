"""Policy: rules in a YAML file that decide allow, deny or ask for each tool call.

Rules are checked top to bottom and the first match wins, like a firewall. A rule with a
rate only matches once its limit is used up, so it can sit above a broad allow rule.
"""

from __future__ import annotations

import fnmatch
import json
import posixpath
import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ACTIONS = ("allow", "deny", "ask")
OPERATORS = ("glob", "regex", "not_glob", "not_regex", "equals", "contains", "under", "not_under")
RULE_KEYS = {"name", "tool", "args", "rate", "decision", "reason"}
TOP_KEYS = {"version", "default", "default_reason", "hide_denied_tools", "ask", "audit", "rules"}
_UNITS = {
    "s": 1, "sec": 1, "second": 1, "seconds": 1,
    "m": 60, "min": 60, "minute": 60, "minutes": 60,
    "h": 3600, "hour": 3600, "hours": 3600,
}


class PolicyError(ValueError):
    """The policy file is invalid. The message says where and why."""


@dataclass(frozen=True)
class Decision:
    action: str
    rule: str
    reason: str
    # Rate rules to charge if this call is forwarded. Kept out of equality and repr.
    charge: tuple = field(default=(), compare=False, repr=False)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else [value]


def _glob_rx(patterns: list[str], where: str) -> re.Pattern:
    for p in patterns:
        if not isinstance(p, str):
            raise PolicyError(f"{where}: glob patterns must be strings, got {p!r}")
    return re.compile("|".join(f"(?:{fnmatch.translate(p)})" for p in patterns))


def _regex_rx(patterns: list[str], where: str) -> re.Pattern:
    for p in patterns:
        if not isinstance(p, str):
            raise PolicyError(f"{where}: regex patterns must be strings, got {p!r}")
        try:
            re.compile(p)
        except re.error as e:
            raise PolicyError(f"{where}: bad regex {p!r}: {e}") from None
    return re.compile("|".join(f"(?:{p})" for p in patterns))


def _norm_path(p: str) -> str:
    # Lexical only: collapses "..", "." and repeated slashes. It does not follow symlinks,
    # because the guard may not share a filesystem with the tool server.
    out = posixpath.normpath(p)
    if out.startswith("//"):  # POSIX keeps a leading "//"; treat it as "/"
        out = "/" + out.lstrip("/")
    return out


def _is_under(value: str, bases: list[str]) -> bool:
    p = _norm_path(value)
    for b in bases:
        if p == b or p.startswith(b.rstrip("/") + "/"):
            return True
    return False


def _same(a: Any, b: Any) -> bool:
    # True == 1 in Python; a policy that says equals: 1 should not match true.
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    return a == b


class Condition:
    """One argument test, built from a policy spec. All operators in a spec must hold."""

    __slots__ = ("checks", "negative_only")

    def __init__(self, spec: Any, where: str):
        if isinstance(spec, str) or (isinstance(spec, list) and spec and all(isinstance(s, str) for s in spec)):
            spec = {"glob": spec}
        elif not isinstance(spec, dict):
            spec = {"equals": spec}
        if not spec:
            raise PolicyError(f"{where}: empty condition")
        self.checks: list[tuple[str, Any]] = []
        for op, val in spec.items():
            if op not in OPERATORS:
                raise PolicyError(f"{where}: unknown operator {op!r}, use one of {', '.join(OPERATORS)}")
            if op in ("glob", "not_glob"):
                self.checks.append((op, _glob_rx(_as_list(val), where)))
            elif op in ("regex", "not_regex"):
                self.checks.append((op, _regex_rx(_as_list(val), where)))
            elif op in ("under", "not_under"):
                bases = _as_list(val)
                if not all(isinstance(b, str) and b.startswith("/") for b in bases):
                    raise PolicyError(f"{where}: {op} needs absolute paths, got {val!r}")
                self.checks.append((op, [_norm_path(b) for b in bases]))
            else:
                self.checks.append((op, val))
        self.negative_only = all(op.startswith("not_") for op, _ in self.checks)

    def test(self, value: Any, present: bool = True, strict: bool = False) -> bool:
        """Does the value pass every operator?

        strict=True is used by allow rules: when the value is a list or mapping, every string
        inside it must pass. strict=False is used by deny and ask rules: one is enough. Either
        way a wrongly typed value cannot slip past a rule.
        """
        if not present:
            # A missing argument cannot match a pattern. Deny rules built only from "not_*"
            # still apply (fail closed); allow rules never match on a missing argument.
            return self.negative_only and not strict
        for op, arg in self.checks:
            if op == "equals":
                ok = _same(value, arg)
            elif op == "contains":
                if isinstance(value, str):
                    ok = isinstance(arg, str) and arg in value
                elif isinstance(value, list):
                    ok = any(_same(v, arg) for v in value)
                else:
                    ok = False
            elif isinstance(value, (dict, list)):
                if strict:  # allow rules: every value inside must pass
                    leaves = list(_leaves(value))
                    ok = bool(leaves) and all(_check(op, arg, v) for v in leaves)
                elif op.startswith("not_"):  # deny and ask: one value outside is enough
                    leaves = list(_leaves(value))
                    ok = not leaves or any(_check(op, arg, v) for v in leaves)  # empty: fail closed
                else:  # deny and ask: a value, a key or the whole JSON text matching is enough
                    ok = any(_check(op, arg, v) for v in _leaves(value, keys=True)) or _check(
                        op, arg, canonical(value)
                    )
            else:
                ok = _check(op, arg, value)
            if not ok:
                return False
        return True


def _check(op: str, arg: Any, value: Any) -> bool:
    if op == "under":
        return isinstance(value, str) and _is_under(value, arg)
    if op == "not_under":
        return not (isinstance(value, str) and _is_under(value, arg))
    text = value if isinstance(value, str) else canonical(value)
    if op == "glob":
        return arg.match(text) is not None
    if op == "not_glob":
        return arg.match(text) is None
    if op == "regex":
        return arg.search(text) is not None
    return arg.search(text) is None  # not_regex


_MISSING = object()


def _lookup(args: Any, key: str) -> list:
    """Every value the key could mean. A plain key reads one argument. A dotted key
    ("opts.force", "files.0") could mean a nested path or a literal key with dots in it, so
    both readings come back. The nested reading is always in the list (as _MISSING when it is
    absent), so an allow rule cannot be satisfied by a literal key alone."""
    if not isinstance(args, dict):
        return [_MISSING]
    if "." not in key:
        return [args.get(key, _MISSING)]
    found = [args[key]] if key in args else []
    cur: Any = args
    for part in key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            cur = _MISSING
            break
    found.append(cur)
    return found


def _leaves(value: Any, keys: bool = False):
    if isinstance(value, dict):
        for k, v in value.items():
            if keys:
                yield k
            yield from _leaves(v, keys)
    elif isinstance(value, list):
        for v in value:
            yield from _leaves(v, keys)
    else:
        yield value


def parse_rate(text: Any, where: str) -> tuple[int, float]:
    """'10/minute', '5/10s', '100/hour' -> (limit, window seconds)."""
    m = re.fullmatch(r"\s*(\d+)\s*/\s*(\d*)\s*([a-z]+)\s*", str(text))
    if not m or m.group(3) not in _UNITS or int(m.group(1)) < 1:
        raise PolicyError(f"{where}: rate must look like '10/minute' or '5/10s', got {text!r}")
    window = (int(m.group(2)) if m.group(2) else 1) * _UNITS[m.group(3)]
    return int(m.group(1)), float(window)


class Rule:
    __slots__ = ("name", "action", "reason", "tool_rx", "conditions", "rate", "hits")

    def __init__(self, spec: Any, index: int):
        where = f"rules[{index}]"
        if not isinstance(spec, dict):
            raise PolicyError(f"{where}: a rule is a mapping, got {type(spec).__name__}")
        unknown = set(spec) - RULE_KEYS
        if unknown:
            raise PolicyError(f"{where}: unknown key(s) {sorted(unknown)}, allowed: {sorted(RULE_KEYS)}")
        self.name = str(spec.get("name") or f"rule-{index + 1}")
        where = f"rule {self.name!r}"
        self.action = spec.get("decision")
        if self.action not in ACTIONS:
            raise PolicyError(f"{where}: decision must be one of {ACTIONS}, got {self.action!r}")
        self.reason = str(spec.get("reason") or f"matched rule {self.name}")
        tool = spec.get("tool")
        self.tool_rx = None if tool in (None, "*") else _glob_rx(_as_list(tool), f"{where} tool")
        args = spec.get("args") or {}
        if not isinstance(args, dict):
            raise PolicyError(f"{where}: args must be a mapping of argument name to condition")
        self.conditions: list[tuple[str, Condition]] = []
        for key, cond_spec in args.items():
            cond = Condition(cond_spec, f"{where} args.{key}")
            if key == "*" and any(op.startswith("not_") for op, _ in cond.checks):
                raise PolicyError(f"{where} args.*: '*' takes positive operators only; write an allow rule instead")
            self.conditions.append((str(key), cond))
        self.rate = parse_rate(spec["rate"], where) if spec.get("rate") is not None else None
        self.hits: deque = deque()

    @property
    def unconditional(self) -> bool:
        return not self.conditions and self.rate is None

    def matches_tool(self, tool: str) -> bool:
        return self.tool_rx is None or self.tool_rx.match(tool) is not None

    def matches(self, tool: str, args: Any) -> bool:
        if self.tool_rx is not None and self.tool_rx.match(tool) is None:
            return False
        strict = self.action == "allow"
        for key, cond in self.conditions:
            if key == "*":
                leaves = list(_leaves(args, keys=not strict))  # '*' takes positive operators only
                quantifier = all if strict else any
                if not (leaves and quantifier(cond.test(v, True, strict) for v in leaves)):
                    return False
            else:
                found = _lookup(args, key)
                if strict:  # allow: every reading must exist and pass
                    ok = all(v is not _MISSING and cond.test(v, True, True) for v in found)
                else:  # deny and ask: any reading is enough; nothing present is tested as missing
                    present = [v for v in found if v is not _MISSING]
                    ok = any(cond.test(v, True, False) for v in present) if present else cond.test(None, False)
                if not ok:
                    return False
        return True


class Policy:
    def __init__(self, data: Any, source: str = "<policy>"):
        if not isinstance(data, dict):
            raise PolicyError(f"{source}: the policy must be a mapping with a 'rules' list")
        unknown = set(data) - TOP_KEYS
        if unknown:
            raise PolicyError(f"{source}: unknown top-level key(s) {sorted(unknown)}, allowed: {sorted(TOP_KEYS)}")
        if data.get("version", 1) != 1:
            raise PolicyError(f"{source}: only version 1 is supported")
        self.source = source
        self.default = data.get("default", "deny")
        if self.default not in ACTIONS:
            raise PolicyError(f"{source}: default must be one of {ACTIONS}, got {self.default!r}")
        self.default_reason = str(data.get("default_reason") or f"no rule matched, default is {self.default}")
        self.hide_denied_tools = bool(data.get("hide_denied_tools", False))
        self.ask = data.get("ask") or {}
        self.audit = data.get("audit") or {}
        if not isinstance(self.ask, dict) or not isinstance(self.audit, dict):
            raise PolicyError(f"{source}: 'ask' and 'audit' must be mappings")
        rules = data.get("rules") or []
        if not isinstance(rules, list):
            raise PolicyError(f"{source}: 'rules' must be a list")
        self.rules = [Rule(r, i) for i, r in enumerate(rules)]
        seen: set[str] = set()
        for r in self.rules:
            if r.name in seen:
                raise PolicyError(f"{source}: two rules are named {r.name!r}; names must be unique")
            seen.add(r.name)
        self._lock = threading.Lock()

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        path = Path(path)
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            raise PolicyError(f"{path}: not valid YAML: {e}") from None
        return cls(data, str(path))

    @classmethod
    def from_yaml(cls, text: str, source: str = "<policy>") -> "Policy":
        return cls(yaml.safe_load(text), source)

    def evaluate(self, tool: str, args: Any = None, now: float | None = None, charge: bool = True) -> Decision:
        """Decide one call. With charge=True an allowed call counts against its rate rules."""
        args = {} if args is None else args
        with self._lock:
            t = time.monotonic() if now is None else now
            pending = []
            decision = None
            for rule in self.rules:
                if not rule.matches(tool, args):
                    continue
                if rule.rate is not None:
                    limit, window = rule.rate
                    hits = rule.hits
                    while hits and hits[0] <= t - window:
                        hits.popleft()
                    if len(hits) < limit:
                        pending.append(rule)
                        continue
                decision = Decision(rule.action, rule.name, rule.reason, tuple(pending))
                break
            if decision is None:
                decision = Decision(self.default, "default", self.default_reason, tuple(pending))
            if charge and decision.action == "allow":
                for rule in pending:
                    rule.hits.append(t)
            return decision

    def charge(self, decision: Decision, now: float | None = None) -> None:
        """Count a call that was approved later (after an ask) against its rate rules."""
        with self._lock:
            t = time.monotonic() if now is None else now
            for rule in decision.charge:
                rule.hits.append(t)

    def always_denied(self, tool: str) -> bool:
        """True when no arguments could ever get this tool past the rules."""
        for rule in self.rules:
            if not rule.matches_tool(tool):
                continue
            if rule.unconditional:
                return rule.action == "deny"
            if rule.action != "deny":
                return False
        return self.default == "deny"
