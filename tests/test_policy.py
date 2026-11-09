import pytest

from agent_guard.policy import Policy, PolicyError, parse_rate

BASE = """
default: deny
rules:
  - name: no-delete-outside-sandbox
    tool: delete_file
    args:
      path: {not_under: /sandbox}
    decision: deny
    reason: deletes only inside /sandbox
  - name: deletes-ask
    tool: delete_file
    decision: ask
  - name: reads
    tool: [read_file, list_*]
    decision: allow
  - name: shell-no-rm-rf
    tool: run_shell
    args:
      "*": {regex: 'rm\\s+-\\w*(r\\w*f|f\\w*r)'}
    decision: deny
  - name: shell
    tool: run_shell
    decision: allow
"""


def test_first_match_wins_and_default():
    p = Policy.from_yaml(BASE)
    assert p.evaluate("read_file", {"path": "/etc/passwd"}).action == "allow"
    assert p.evaluate("list_dir").action == "allow"
    d = p.evaluate("write_file", {"path": "/x"})
    assert (d.action, d.rule) == ("deny", "default")


def test_path_under_is_normalised():
    p = Policy.from_yaml(BASE)
    assert p.evaluate("delete_file", {"path": "/sandbox/a.txt"}).action == "ask"
    for sneaky in ["/sandbox/../etc/passwd", "/sandboxed/x", "//etc/passwd", "relative/path", "/sandbox/./../x"]:
        d = p.evaluate("delete_file", {"path": sneaky})
        assert d.action == "deny", sneaky
        assert d.reason == "deletes only inside /sandbox"


def test_missing_argument_fails_closed_for_not_rules():
    p = Policy.from_yaml(BASE)
    assert p.evaluate("delete_file", {}).action == "deny"


def test_star_matches_any_value_anywhere():
    p = Policy.from_yaml(BASE)
    assert p.evaluate("run_shell", {"cmd": "ls -la"}).action == "allow"
    assert p.evaluate("run_shell", {"cmd": "rm -rf /"}).rule == "shell-no-rm-rf"
    assert p.evaluate("run_shell", {"steps": [{"cmd": "echo hi"}, {"cmd": "rm -fr ~"}]}).action == "deny"


def test_rate_rule_only_matches_after_limit():
    p = Policy.from_yaml("""
default: deny
rules:
  - name: write-burst
    tool: write_file
    rate: 3/10s
    decision: deny
    reason: too many writes
  - name: writes
    tool: write_file
    decision: allow
""")
    t = 1000.0
    assert [p.evaluate("write_file", now=t + i).action for i in range(4)] == ["allow"] * 3 + ["deny"]
    # Denied calls do not use up the limit; once the window passes, writes flow again.
    assert p.evaluate("write_file", now=t + 10.5).action == "allow"


def test_rate_not_charged_without_forwarding():
    p = Policy.from_yaml("""
rules:
  - {name: burst, tool: t, rate: 1/minute, decision: deny}
  - {name: ok, tool: t, decision: ask}
""")
    d = p.evaluate("t", now=0)
    assert d.action == "ask"
    assert p.evaluate("t", now=1).action == "ask"  # the ask was never approved, nothing charged
    p.charge(d, now=2)
    assert p.evaluate("t", now=3).rule == "burst"


def test_operators():
    p = Policy.from_yaml("""
default: allow
rules:
  - {name: eq, tool: a, args: {n: 1}, decision: deny}
  - {name: contains, tool: b, args: {tags: {contains: prod}}, decision: deny}
  - {name: dotted, tool: c, args: {opts.force: true}, decision: deny}
  - {name: glob, tool: d, args: {url: "https://*.internal/*"}, decision: deny}
  - {name: notglob, tool: e, args: {host: {not_glob: ["*.example.com", "example.com"]}}, decision: deny}
""")
    assert p.evaluate("a", {"n": 1}).action == "deny"
    assert p.evaluate("a", {"n": True}).action == "allow"  # bool is not 1
    assert p.evaluate("b", {"tags": ["dev", "prod"]}).action == "deny"
    assert p.evaluate("b", {"tags": "production-db"}).action == "deny"
    assert p.evaluate("b", {"tags": ["dev"]}).action == "allow"
    assert p.evaluate("c", {"opts": {"force": True}}).action == "deny"
    assert p.evaluate("c", {"opts": {"force": False}}).action == "allow"
    assert p.evaluate("d", {"url": "https://db.internal/drop"}).action == "deny"
    assert p.evaluate("e", {"host": "api.example.com"}).action == "allow"
    assert p.evaluate("e", {"host": "evil.test"}).action == "deny"


def test_always_denied():
    p = Policy.from_yaml("""
default: deny
rules:
  - {name: a, tool: drop_*, decision: deny}
  - {name: b, tool: read, args: {path: {under: /data}}, decision: allow}
  - {name: c, tool: "*", args: {x: 1}, decision: deny}
  - {name: d, tool: write, decision: ask}
""")
    assert p.always_denied("drop_table")
    assert not p.always_denied("read")  # some arguments are allowed
    assert not p.always_denied("write")
    assert p.always_denied("anything_else")


@pytest.mark.parametrize(
    "text, msg",
    [
        ("rules: [{name: a, decison: deny}]", "unknown key"),
        ("rules: [{name: a, decision: maybe}]", "decision must be"),
        ("rules: [{name: a, decision: deny}, {name: a, decision: allow}]", "unique"),
        ("rules: [{name: a, decision: deny, args: {p: {regex: '('}}}]", "bad regex"),
        ("rules: [{name: a, decision: deny, args: {p: {startswith: x}}}]", "unknown operator"),
        ("rules: [{name: a, decision: deny, args: {p: {under: tmp}}}]", "absolute"),
        ("rules: [{name: a, decision: deny, args: {'*': {not_regex: x}}}]", "positive"),
        ("rules: [{name: a, decision: deny, rate: lots}]", "rate must"),
        ("default: maybe", "default must"),
        ("rulez: []", "unknown top-level"),
        ("- a\n- b", "must be a mapping"),
    ],
)
def test_bad_policies_fail_loudly(text, msg):
    with pytest.raises(PolicyError, match=msg):
        Policy.from_yaml(text)


def test_parse_rate():
    assert parse_rate("10/minute", "x") == (10, 60.0)
    assert parse_rate("5/10s", "x") == (5, 10.0)
    assert parse_rate("100 / hour", "x") == (100, 3600.0)


def test_dotted_key_cannot_be_shadowed_by_literal_key():
    p = Policy.from_yaml("""
default: allow
rules:
  - {name: no-force, tool: push, args: {opts.force: true}, decision: deny}
""")
    assert p.evaluate("push", {"opts.force": False, "opts": {"force": True}}).action == "deny"
    assert p.evaluate("push", {"opts.force": True, "opts": {"force": False}}).action == "deny"
    assert p.evaluate("push", {"opts": {"force": False}}).action == "allow"


def test_lists_and_maps_are_checked_per_value():
    p = Policy.from_yaml("""
default: deny
rules:
  - {name: no-etc, tool: read, args: {path: {under: /etc}}, decision: deny}
  - {name: data-only, tool: read, args: {path: {under: /data}}, decision: allow}
  - {name: shell-ls, tool: sh, args: {"*": {regex: "^ls( |$)"}}, decision: allow}
""")
    # Deny rules fire when any value inside matches.
    assert p.evaluate("read", {"path": ["/data/a", "/etc/shadow"]}).rule == "no-etc"
    assert p.evaluate("read", {"path": {"p": "/etc/shadow"}}).rule == "no-etc"
    # Allow rules need every value inside to match.
    assert p.evaluate("read", {"path": ["/data/a", "/data/b"]}).action == "allow"
    assert p.evaluate("read", {"path": ["/data/a", "/tmp/b"]}).action == "deny"
    assert p.evaluate("read", {"path": []}).action == "deny"
    assert p.evaluate("read", {"path": {"/etc/shadow": 1}}).rule == "no-etc"  # keys count for deny rules
    assert p.evaluate("sh", {"cmd": "ls -la"}).action == "allow"
    assert p.evaluate("sh", {"cmd": "rm -rf /", "note": "ls"}).action == "deny"
    assert p.evaluate("sh", {}).action == "deny"


def test_allow_rule_does_not_match_missing_argument():
    p = Policy.from_yaml("""
default: deny
rules:
  - {name: not-secret, tool: read, args: {path: {not_glob: "*.key"}}, decision: allow}
""")
    assert p.evaluate("read", {"path": "a.txt"}).action == "allow"
    assert p.evaluate("read", {}).action == "deny"


def test_deny_not_rule_fails_closed_on_empty_container():
    p = Policy.from_yaml("""
default: allow
rules:
  - {name: sandbox, tool: rm, args: {path: {not_under: /sandbox}}, decision: deny}
""")
    assert p.evaluate("rm", {"path": []}).action == "deny"
    assert p.evaluate("rm", {"path": ["/sandbox/a"]}).action == "allow"
    assert p.evaluate("rm", {"path": ["/sandbox/a", "/etc"]}).action == "deny"


def test_allow_rule_needs_the_nested_reading():
    p = Policy.from_yaml("""
default: deny
rules:
  - {name: safe-mode, tool: run, args: {opts.mode: safe}, decision: allow}
""")
    assert p.evaluate("run", {"opts": {"mode": "safe"}}).action == "allow"
    assert p.evaluate("run", {"opts.mode": "safe"}).action == "deny"  # server would read opts.mode as missing
    assert p.evaluate("run", {"opts.mode": "safe", "opts": {"mode": "x"}}).action == "deny"
