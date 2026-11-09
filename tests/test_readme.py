"""The policy shown in the README must load and do what the README says."""

import re
from pathlib import Path

from agent_guard.policy import Policy

README = (Path(__file__).parent.parent / "README.md").read_text()


def test_readme_policy_example():
    block = re.search(r"## The policy\n\n```yaml\n(.*?)```", README, re.S).group(1)
    p = Policy.from_yaml(block)
    assert p.evaluate("delete_file", {"path": "/data/notes/a.md"}).rule == "notes-are-read-only"
    assert p.evaluate("delete_file", {"path": "/data/x/../notes/a.md"}).rule == "notes-are-read-only"
    assert p.evaluate("run_shell", {"cmd": "rm -rf /"}).rule == "no-rm-rf"
    assert p.evaluate("run_shell", {"cmd": "ls"}).action == "allow"
    assert p.evaluate("drop_table", {}).action == "deny"
    assert p.always_denied("drop_table") and not p.always_denied("read_file")
