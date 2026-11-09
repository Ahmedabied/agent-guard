import json
import threading

import pytest

from agent_guard.audit import GENESIS, AuditError, AuditLog, Scrubber, read_entries, verify


def _write(path, n):
    with AuditLog(path) as log:
        for i in range(n):
            log.append({"event": "call", "tool": "t", "args": {"i": i}})
        return log.head


def test_chain_verifies(tmp_path):
    p = tmp_path / "audit.jsonl"
    head = _write(p, 5)
    r = verify(p)
    assert r.ok and r.entries == 5 and r.head == head
    entries = list(read_entries(p))
    assert entries[0]["prev"] == GENESIS
    assert [e["seq"] for e in entries] == [1, 2, 3, 4, 5]


def test_reopen_continues_chain(tmp_path):
    p = tmp_path / "audit.jsonl"
    _write(p, 3)
    _write(p, 2)
    r = verify(p)
    assert r.ok and r.entries == 5


def _lines(p):
    return p.read_bytes().splitlines(keepends=True)


def test_edit_is_detected(tmp_path):
    p = tmp_path / "audit.jsonl"
    _write(p, 4)
    lines = _lines(p)
    e = json.loads(lines[1])
    e["decision"] = "allow"  # someone rewrites history
    lines[1] = (json.dumps(e) + "\n").encode()
    p.write_bytes(b"".join(lines))
    r = verify(p)
    assert not r.ok and r.line == 2 and "edited" in r.error


def test_delete_and_reorder_are_detected(tmp_path):
    p = tmp_path / "audit.jsonl"
    _write(p, 4)
    lines = _lines(p)
    p.write_bytes(lines[0] + lines[2] + lines[3])
    assert verify(p).line == 2
    p.write_bytes(lines[1] + lines[0] + lines[2])
    assert not verify(p).ok


def test_truncation_needs_expected_head(tmp_path):
    p = tmp_path / "audit.jsonl"
    head = _write(p, 4)
    p.write_bytes(b"".join(_lines(p)[:3]))
    assert verify(p).ok  # a shorter chain is still a valid chain
    r = verify(p, expect_head=head)
    assert not r.ok and "head" in r.error


def test_incomplete_last_line_refuses_to_append(tmp_path):
    p = tmp_path / "audit.jsonl"
    _write(p, 2)
    with open(p, "ab") as f:
        f.write(b'{"seq": 3, "half')
    assert verify(p).error == "incomplete last line"
    with pytest.raises(AuditError, match="incomplete"):
        _write(p, 1)


def test_threads_keep_one_chain(tmp_path):
    p = tmp_path / "audit.jsonl"
    with AuditLog(p) as log:
        def work():
            for i in range(200):
                log.append({"event": "call", "i": i})
        ts = [threading.Thread(target=work) for _ in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
    r = verify(p)
    assert r.ok and r.entries == 800


def test_two_writers_on_one_file(tmp_path):
    p = tmp_path / "audit.jsonl"
    a, b = AuditLog(p), AuditLog(p)
    for i in range(10):
        (a if i % 2 else b).append({"i": i})
    a.close()
    b.close()
    assert verify(p).entries == 10 and verify(p).ok


def test_scrubber():
    s = Scrubber(max_value_chars=50)
    out = s({"path": "/x", "api_key": "abc", "headers": {"Authorization": "Bearer x"}, "body": "y" * 100, "n": 3})
    assert out["path"] == "/x" and out["n"] == 3
    assert out["api_key"] == "[redacted]"
    assert out["headers"]["Authorization"] == "[redacted]"
    assert out["body"].startswith("[100 chars, sha256 ")
