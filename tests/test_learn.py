import subprocess
import sys

import pytest

from agent_guard.audit import AuditLog
from agent_guard.learn import Incident, LearnError, incident_from_log, insert_rule, learn, load_cases, run_cases
from agent_guard.policy import Policy

POLICY = """\
# my agent's policy
version: 1
default: deny

rules:
  # reads are fine
  - name: reads
    tool: read_file
    decision: allow

  - name: deletes
    tool: delete_file
    decision: allow
"""


def cli(*args, cwd=None):
    return subprocess.run([sys.executable, "-m", "agent_guard", *args], capture_output=True, text=True, cwd=cwd)


def test_insert_rule_goes_first_and_keeps_comments():
    rule = {"name": "no-prod", "tool": "delete_file", "args": {"path": "*prod*"}, "decision": "deny", "reason": "r"}
    out = insert_rule(POLICY, rule, "learned today")
    assert "# my agent's policy" in out and "# reads are fine" in out
    p = Policy.from_yaml(out)
    assert [r.name for r in p.rules] == ["no-prod", "reads", "deletes"]
    assert p.evaluate("delete_file", {"path": "/srv/prod.db"}).action == "deny"


@pytest.mark.parametrize("text", ["default: deny\nrules: []\n", "default: deny\n", "default: deny"])
def test_insert_rule_without_a_rules_block(text):
    rule = {"name": "x", "tool": "t", "decision": "deny", "reason": "r"}
    assert [r.name for r in Policy.from_yaml(insert_rule(text, rule, "c")).rules] == ["x"]


def test_learn_full_loop(tmp_path):
    policy, tests, log = tmp_path / "guard.yaml", tmp_path / "guard-tests.yaml", tmp_path / "audit.jsonl"
    policy.write_text(POLICY)
    with AuditLog(log) as a:
        a.append({"event": "call", "id": 1, "tool": "read_file", "args": {"path": "/srv/a"}, "decision": "allow"})
        a.append({"event": "call", "id": 2, "tool": "delete_file", "args": {"path": "/srv/prod.db"}, "decision": "allow"})
        a.append({"event": "result", "id": 2, "tool": "delete_file", "ok": True, "us": 900})

    # Point at the result line; learn walks back to the call it belongs to.
    incident = incident_from_log(log, 3)
    assert incident.tool == "delete_file" and incident.args == {"path": "/srv/prod.db"}
    rule = learn(policy, tests, incident, "no-prod-deletes", "never delete production files", {"path": "*prod*"})
    assert rule["args"] == {"path": "*prod*"}

    p = Policy.from_file(policy)
    assert p.evaluate("delete_file", {"path": "/srv/prod.db"}).rule == "no-prod-deletes"
    assert p.evaluate("delete_file", {"path": "/srv/prod-2.db"}).action == "deny"  # the whole family
    assert p.evaluate("delete_file", {"path": "/srv/tmp.txt"}).action == "allow"

    cases = load_cases(tests)
    assert len(cases) == 1 and cases[0].expect == "deny"
    assert run_cases(policy, cases) == []

    # Someone later removes the rule: the regression test catches it.
    policy.write_text(POLICY)
    failures = run_cases(policy, cases)
    assert len(failures) == 1 and failures[0][1] == "allow"


def test_learn_exact_values_by_default_and_skips_redacted(tmp_path):
    policy, tests = tmp_path / "guard.yaml", tmp_path / "t.yaml"
    policy.write_text(POLICY)
    inc = Incident("delete_file", {"path": "/srv/prod.db", "token": "[redacted]", "force": True}, "test")
    rule = learn(policy, tests, inc, "exact", "r")
    assert rule["args"] == {"path": {"equals": "/srv/prod.db"}, "force": {"equals": True}}


def test_learn_refuses_a_rule_that_misses_the_incident(tmp_path):
    policy = tmp_path / "guard.yaml"
    policy.write_text(POLICY)
    inc = Incident("delete_file", {"path": "/srv/prod.db"}, "test")
    with pytest.raises(LearnError, match="does not match the incident"):
        learn(policy, tmp_path / "t.yaml", inc, "typo", "r", {"path": "*staging*"})
    assert policy.read_text() == POLICY  # nothing written


def test_learn_refuses_duplicate_name(tmp_path):
    policy = tmp_path / "guard.yaml"
    policy.write_text(POLICY)
    with pytest.raises(LearnError, match="already exists"):
        learn(policy, tmp_path / "t.yaml", Incident("delete_file", {}, "x"), "reads", "r")


def test_cli_check_learn_test(tmp_path):
    policy, tests = tmp_path / "guard.yaml", tmp_path / "guard-tests.yaml"
    policy.write_text(POLICY)
    r = cli("check", "-p", str(policy), "delete_file", '{"path": "/srv/prod.db"}')
    assert r.returncode == 0 and r.stdout.startswith("allow")
    r = cli("learn", "-p", str(policy), "--tests", str(tests), "--tool", "delete_file",
            "--args", '{"path": "/srv/prod.db"}', "--name", "no-prod", "--reason", "not prod", "--match", "path=*prod*")
    assert r.returncode == 0, r.stderr
    r = cli("check", "-p", str(policy), "delete_file", '{"path": "/srv/prod.db"}')
    assert r.returncode == 1 and "no-prod" in r.stdout
    r = cli("test", "-p", str(policy), str(tests))
    assert r.returncode == 0 and "1/1 cases pass" in r.stdout
    policy.write_text(POLICY)
    r = cli("test", "-p", str(policy), str(tests))
    assert r.returncode == 1 and "FAIL  no-prod" in r.stdout


def test_cli_verify_and_log(tmp_path):
    log = tmp_path / "audit.jsonl"
    with AuditLog(log) as a:
        a.append({"event": "call", "id": 1, "tool": "rm", "args": {"p": "x"}, "decision": "deny", "rule": "r"})
    r = cli("verify", str(log))
    assert r.returncode == 0 and "1 entries" in r.stdout
    r = cli("log", str(log), "--denied")
    assert "rm" in r.stdout and "deny" in r.stdout
    log.write_text(log.read_text().replace('"rm"', '"ls"'))
    r = cli("verify", str(log))
    assert r.returncode == 1 and "BROKEN at line 1" in r.stdout


def test_cli_bad_policy_is_a_clear_error(tmp_path):
    policy = tmp_path / "guard.yaml"
    policy.write_text("rules: [{name: a, decison: deny}]")
    r = cli("check", "-p", str(policy), "x")
    assert r.returncode == 2 and "unknown key" in r.stderr
