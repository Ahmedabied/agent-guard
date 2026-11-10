import subprocess
import sys

import pytest

from agent_guard.audit import AuditLog
from agent_guard.learn import Incident, LearnError, incident_from_log, insert_rule, learn, load_cases, run_cases
from agent_guard import learn as learn_mod
from agent_guard.policy import Policy, PolicyError

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


def test_learn_from_a_prompt_line(tmp_path):
    # A prompts/get line (guard_prompts: true) learns a rule on the prompt's name; its arguments, an object, are
    # left out of the exact match, and the regression case replays the whole request.
    policy, tests, log = tmp_path / "guard.yaml", tmp_path / "t.yaml", tmp_path / "audit.jsonl"
    policy.write_text(POLICY.replace("default: deny\n", "default: deny\nguard_prompts: true\n") +
                      "  - {name: prompts, tool: prompts/get, decision: allow}\n")
    with AuditLog(log) as a:
        a.append({"event": "call", "id": 1, "tool": "prompts/get", "decision": "allow",
                  "args": {"name": "dump_env", "arguments": {"scope": "all"}}})
    rule = learn(policy, tests, incident_from_log(log, 1), "no-env-prompt", "prompts never show the environment")
    assert rule["tool"] == "prompts/get" and rule["args"] == {"name": {"equals": "dump_env"}}
    p = Policy.from_file(policy)
    assert p.evaluate("prompts/get", {"name": "dump_env"}).rule == "no-env-prompt"
    assert p.evaluate("prompts/get", {"name": "review", "arguments": {"name": "dump_env"}}).action == "allow"
    assert run_cases(policy, load_cases(tests)) == []


@pytest.mark.parametrize("flag, tool, args", [
    ("guard_prompts", "prompts/get", {"name": "dump_env"}),
    ("guard_resources", "resources/read", {"uri": "file:///srv/a", "scheme": "file", "host": "", "path": "/srv/a"}),
])
def test_turning_a_guard_off_fails_the_cases_that_need_it(tmp_path, flag, tool, args):
    # With the guard off those requests pass without any rule, so a case that expects deny must fail: otherwise
    # switching the guard off would loosen the policy while agent-guard test stays green.
    policy, tests = tmp_path / "guard.yaml", tmp_path / "t.yaml"
    policy.write_text(POLICY.replace("default: deny\n", f"default: deny\n{flag}: true\n"))
    learn(policy, tests, Incident(tool, args, "test"), "no-this", "never")
    cases = load_cases(tests)
    assert run_cases(policy, cases) == []
    learned = policy.read_text()
    policy.write_text(learned.replace(f"{flag}: true\n", ""))  # the learned rule is still there: it would never run
    with pytest.raises(PolicyError, match=f"{flag} is off"):
        run_cases(policy, cases)
    policy.write_text(POLICY)  # rule gone too: the case itself catches it
    failures = run_cases(policy, cases)
    assert [(f[1], f[2]) for f in failures] == [("allow", "unguarded")]


def test_check_says_a_prompt_passes_when_its_guard_is_off(tmp_path):
    policy = tmp_path / "guard.yaml"
    policy.write_text(POLICY)
    off = cli("check", "-p", str(policy), "prompts/get", '{"name": "dump_env"}')
    assert off.returncode == 0 and "rule=unguarded" in off.stdout
    policy.write_text(POLICY.replace("default: deny\n", "default: deny\nguard_prompts: true\n"))
    on = cli("check", "-p", str(policy), "prompts/get", '{"name": "dump_env"}')
    assert on.returncode == 1 and "rule=default" in on.stdout


@pytest.mark.parametrize("tool, flag", [("prompts/get", "guard_prompts"), ("resources/read", "guard_resources"),
                                        ("[read_file, prompts/get]", "guard_prompts")])
def test_a_rule_its_guard_would_never_run_stops_the_policy_loading(tool, flag):
    with pytest.raises(PolicyError, match=f"rule 'r' is for .*{flag} is off"):
        Policy.from_yaml(f"default: allow\nrules:\n  - {{name: r, tool: {tool}, decision: deny}}\n")
    assert Policy.from_yaml(f"default: allow\n{flag}: true\nrules:\n  - {{name: r, tool: {tool}, decision: deny}}\n")
    assert Policy.from_yaml("default: allow\nrules:\n  - {name: r, tool: \"*\", decision: deny}\n")  # a pattern is fine


def test_learn_refuses_a_rule_its_guard_would_never_run(tmp_path):
    policy, tests = tmp_path / "guard.yaml", tmp_path / "t.yaml"
    policy.write_text(POLICY)  # guard_prompts is off
    with pytest.raises(LearnError, match="guard_prompts"):
        learn(policy, tests, Incident("prompts/get", {"name": "dump_env"}, "test"), "no-env", "never")
    assert policy.read_text() == POLICY and not tests.exists()


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


def test_learn_refuses_an_inline_rules_list_instead_of_dropping_it(tmp_path):
    # Appending a second `rules:` would make YAML keep only the new one: every old rule gone.
    policy = tmp_path / "guard.yaml"
    text = "default: deny\nrules: [{name: work, tool: read_file, decision: allow}]\n"
    policy.write_text(text)
    with pytest.raises(LearnError, match="written inline"):
        learn(policy, tmp_path / "t.yaml", Incident("delete_file", {"path": "/x"}, "test"), "no-del", "r")
    assert policy.read_text() == text
    assert not (tmp_path / "t.yaml").exists()


def test_learn_refuses_a_policy_with_a_key_written_twice(tmp_path):
    policy = tmp_path / "guard.yaml"
    policy.write_text("default: deny\nrules:\n  - name: a\n    tool: t\n    decision: allow\nrules: []\n")
    with pytest.raises(PolicyError, match="'rules' is written twice"):
        learn(policy, tmp_path / "t.yaml", Incident("t", {}, "test"), "x", "r")


def test_insert_rule_is_checked_on_the_parsed_result(monkeypatch):
    # Whatever the text edit does, the result must be the old policy with one rule in front.
    monkeypatch.setattr(learn_mod, "_insert_text", lambda text, rule, comment: "default: deny\nrules: []\n")
    with pytest.raises(LearnError, match="add it by hand"):
        insert_rule(POLICY, {"name": "x", "tool": "t", "decision": "deny", "reason": "r"}, "c")
