"""Turn an incident into a rule and a regression test, so the same mistake is blocked next time.

The rule goes to the top of the policy's rules list (first match wins, so it beats any broader
allow). The text of the policy file is edited in place, so comments and layout survive. The
regression case goes into a tests file that `agent-guard test` replays in CI: if a later edit to
the policy would let the incident through again, the build fails.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from .audit import read_entries
from .policy import Policy, PolicyError, load_yaml


class LearnError(ValueError):
    pass


@dataclass
class Incident:
    tool: str
    args: dict
    source: str


@dataclass
class Case:
    name: str
    tool: str
    args: dict = field(default_factory=dict)
    expect: str = "deny"
    note: str = ""


def incident_from_log(log: str | Path, seq: int) -> Incident:
    entries = {e.get("seq"): e for e in read_entries(log)}
    e = entries.get(seq)
    if e is None:
        raise LearnError(f"{log}: no entry with seq {seq}")
    if e.get("event") in ("result", "approval"):  # point at the call it belongs to
        calls = [c for c in entries.values() if c.get("event") == "call" and c.get("id") == e.get("id")
                 and c.get("seq", 0) < seq]
        if not calls:
            raise LearnError(f"{log}: entry {seq} is a {e.get('event')} with no call before it")
        e = calls[-1]
    if e.get("event") != "call" or not isinstance(e.get("tool"), str):
        raise LearnError(f"{log}: entry {seq} is not a tool call")
    return Incident(e["tool"], e.get("args") or {}, f"audit log {Path(log).name} seq {seq}")


def _usable(value: Any) -> bool:
    # Values the audit log redacted or shortened are not the real values; never match on them.
    return not (isinstance(value, str) and (value.startswith("[redacted") or re.match(r"^\[\d+ chars, sha256 ", value)))


def build_rule(incident: Incident, name: str, reason: str, match: dict[str, str] | None = None,
               decision: str = "deny") -> dict:
    rule: dict[str, Any] = {"name": name, "tool": incident.tool}
    if match:
        rule["args"] = dict(match)
    else:
        exact = {k: {"equals": v} for k, v in incident.args.items()
                 if isinstance(v, (str, int, float, bool)) and _usable(v)}
        if exact:
            rule["args"] = exact
    rule["decision"] = decision
    rule["reason"] = reason
    return rule


def _rule_block(rule: dict, indent: str, comment: str) -> str:
    body = yaml.safe_dump(rule, sort_keys=False, default_flow_style=False, allow_unicode=True, width=1000)
    lines = body.rstrip("\n").split("\n")
    out = [f"{indent}# {comment}", f"{indent}- {lines[0]}"]
    out += [f"{indent}  {ln}" for ln in lines[1:]]
    return "\n".join(out) + "\n"


def _rules_node(policy_text: str) -> yaml.Node | None:
    root = yaml.compose(policy_text, Loader=yaml.SafeLoader)
    if isinstance(root, yaml.MappingNode):
        for k, v in root.value:
            if isinstance(k, yaml.ScalarNode) and k.value == "rules":
                return v
    return None


def insert_rule(policy_text: str, rule: dict, comment: str) -> str:
    """Put the rule first in the rules list, keeping the rest of the file as written.

    The edit is made on the text, so comments survive; it is then checked on the parsed result, and
    refused unless the new policy is exactly the old one with the rule added in front."""
    before = load_yaml(policy_text)
    node = _rules_node(policy_text)
    if isinstance(node, yaml.SequenceNode) and node.flow_style and node.value:
        raise LearnError("the rules list is written inline (rules: [...]); write it as a block list, one '- ' per "
                         "rule, so learn can add to it without rewriting your file")
    new_text = _insert_text(policy_text, rule, comment)
    after = load_yaml(new_text)
    before = before if isinstance(before, dict) else {}

    def rest(d: dict) -> dict:
        return {k: v for k, v in d.items() if k != "rules"}

    expected = [yaml.safe_load(yaml.safe_dump(rule))] + list(before.get("rules") or [])
    if not isinstance(after, dict) or after.get("rules") != expected or rest(after) != rest(before):
        raise LearnError("could not add the rule without changing the rest of the policy; add it by hand, first "
                         "in the rules list:\n" + _rule_block(rule, "  ", comment))
    return new_text


def _insert_text(policy_text: str, rule: dict, comment: str) -> str:
    lines = policy_text.splitlines(keepends=True)
    for i, ln in enumerate(lines):
        m = re.match(r"^rules:\s*(\[\s*\])?\s*(#.*)?$", ln.rstrip("\n"))
        if not m:
            continue
        indent = ""
        for nxt in lines[i + 1:]:
            if not nxt.strip() or nxt.lstrip().startswith("#"):
                continue
            mm = re.match(r"^(\s*)- ", nxt)
            indent = mm.group(1) if mm else ""
            break
        head = "rules:\n" if m.group(1) else ln if ln.endswith("\n") else ln + "\n"
        return "".join(lines[:i]) + head + _rule_block(rule, indent, comment) + "".join(lines[i + 1:])
    sep = "" if policy_text.endswith("\n") or not policy_text else "\n"
    return policy_text + sep + "rules:\n" + _rule_block(rule, "", comment)


def load_cases(path: str | Path) -> list[Case]:
    path = Path(path)
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(data, list):
        raise LearnError(f"{path}: a tests file is a YAML list of cases")
    cases = []
    for i, c in enumerate(data):
        if not isinstance(c, dict) or not isinstance(c.get("tool"), str):
            raise LearnError(f"{path}: case {i + 1} needs at least a 'tool'")
        if c.get("expect", "deny") not in ("allow", "deny", "ask"):
            raise LearnError(f"{path}: case {i + 1}: expect must be allow, deny or ask")
        cases.append(Case(str(c.get("name") or f"case-{i + 1}"), c["tool"], c.get("args") or {},
                          c.get("expect", "deny"), str(c.get("note") or "")))
    return cases


def append_case(path: str | Path, case: Case) -> None:
    path = Path(path)
    item = {"name": case.name, "tool": case.tool, "args": case.args, "expect": case.expect}
    if case.note:
        item["note"] = case.note
    text = yaml.safe_dump([item], sort_keys=False, allow_unicode=True, width=1000)
    old = path.read_text(encoding="utf-8") if path.exists() else ""
    if old and not old.endswith("\n"):
        old += "\n"
    path.write_text(old + text, encoding="utf-8")


def run_cases(policy_path: str | Path, cases: list[Case]) -> list[tuple[Case, str, str]]:
    """Replay each case on a fresh policy. Returns the failures as (case, got, rule)."""
    failures = []
    for case in cases:
        policy = Policy.from_file(policy_path)  # fresh state: rate limits never leak between cases
        d = policy.evaluate(case.tool, case.args, charge=False)
        if d.action != case.expect:
            failures.append((case, d.action, d.rule))
    return failures


def learn(policy_path: str | Path, tests_path: str | Path, incident: Incident, name: str, reason: str,
          match: dict[str, str] | None = None) -> dict:
    policy_path = Path(policy_path)
    text = policy_path.read_text(encoding="utf-8")
    policy = Policy.from_yaml(text, str(policy_path))
    if any(r.name == name for r in policy.rules):
        raise LearnError(f"{policy_path}: a rule named {name!r} already exists")
    rule = build_rule(incident, name, reason, match)
    new_text = insert_rule(text, rule, f"learned {date.today().isoformat()} from {incident.source}")
    try:
        new_policy = Policy.from_yaml(new_text, str(policy_path))
    except PolicyError as e:
        raise LearnError(f"the new rule would break the policy: {e}") from None
    d = new_policy.evaluate(incident.tool, incident.args, charge=False)
    if d.action != "deny" or d.rule != name:
        raise LearnError(f"the new rule does not match the incident (got {d.action} from {d.rule}); check --match")
    policy_path.write_text(new_text, encoding="utf-8")
    append_case(tests_path, Case(name, incident.tool, incident.args, "deny", f"learned from {incident.source}"))
    return rule
