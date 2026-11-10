"""The flows around a call: a client that gives up, a server that asks the client something mid-call, progress.
Proxies tend to break here, not on plain call and answer."""

import json
import sys
import time

import pytest

httpx2 = pytest.importorskip("httpx2")
anyio = pytest.importorskip("anyio")

from test_gateway import CALL, POLICY, Rig  # noqa: E402


def notes(r, timeout=5.0):
    """What the fake server logged about slow calls (cancelled or finished), once it has decided."""
    end = time.time() + timeout
    while time.time() < end:
        got = [q["body"] for q in r.upstream_requests() if q["method"] == "NOTE"]
        if got:
            return got
        time.sleep(0.1)
    return []


@pytest.mark.parametrize("mode", ["slow", "slowsse"])
def test_a_client_that_gives_up_cancels_the_call_upstream(tmp_path, mode):
    """2026-07-28 cancels a request by closing its stream, so the gateway must close its own upstream request: before
    the server has sent anything (slow), and in the middle of an SSE answer (slowsse)."""
    r = Rig(tmp_path, mode=mode)
    try:
        with pytest.raises(httpx2.TimeoutException):
            with httpx2.Client(timeout=httpx2.Timeout(0.6)) as c:
                with c.stream("POST", r.url, json=CALL, headers={"accept": "application/json, text/event-stream"}) as res:
                    for _ in res.iter_bytes():
                        pass
        assert notes(r) == ["cancelled"]
        assert r.audit_entries()[-1].get("error", "").startswith("client left")
    finally:
        r.close()


ASK_SLOW = f"""
default: deny
ask: {{via: command, command: [{json.dumps(sys.executable)}, -c, "import time; time.sleep(1.5)"]}}
rules:
  - {{name: confirm, tool: read_file, decision: ask}}
"""


def test_a_call_approved_after_its_client_left_is_not_sent(tmp_path):
    r = Rig(tmp_path, policy=ASK_SLOW)
    try:
        with pytest.raises(httpx2.TimeoutException):
            httpx2.post(r.url, json=CALL, headers={"accept": "application/json"}, timeout=0.5)
        time.sleep(2.5)  # the approver says yes at 1.5 s
        assert [e["approved"] for e in r.audit_entries() if e["event"] == "approval"] == [True]
        assert r.upstream_requests() == []
        assert r.audit_entries()[-1].get("error") == "client left before the approval; not sent"
    finally:
        r.close()


FLOW_POLICY = POLICY.replace('"lire_*", forecast]', '"lire_*", forecast, slow, confirm_delete]')


@pytest.mark.parametrize("mode", ["legacy", "auto"])
def test_progress_arrives_while_the_tool_runs(tmp_path, mode):
    pytest.importorskip("mcp")
    from mcp.client.client import Client

    r = Rig(tmp_path, upstream="sdk", mode="sse", policy=FLOW_POLICY)
    seen = []

    async def session():
        async with Client(r.url, mode=mode) as c:
            t0 = time.perf_counter()

            async def progress(p, total, message):
                seen.append(time.perf_counter() - t0)

            res = await c.call_tool("slow", {"seconds": 1.2, "steps": 3}, progress_callback=progress)
            seen.append(("done", time.perf_counter() - t0, res.content[0].text))

    try:
        anyio.run(session)
    finally:
        r.close()
    done = seen[-1]
    assert done[2] == "slow done" and len(seen) == 4
    assert seen[0] < done[1] - 0.6  # the first progress came long before the answer: nothing is buffered


@pytest.mark.parametrize("mode", ["legacy", "auto"])
def test_the_server_can_ask_the_client_mid_call(tmp_path, mode):
    """Elicitation. 2025: the server's question rides the call's stream and the answer is a new POST. 2026-07-28: the
    call ends 'input_required' and the client sends it again with the answer, so the guard judges it twice."""
    pytest.importorskip("mcp")
    from mcp.client.client import Client
    from mcp_types import ElicitResult

    r = Rig(tmp_path, upstream="sdk", mode="sse", policy=FLOW_POLICY)
    asked = []

    async def answer(context, params):
        asked.append(params.message)
        return ElicitResult(action="accept", content={"sure": True})

    async def session():
        async with Client(r.url, mode=mode, elicitation_callback=answer) as c:
            return await c.call_tool("confirm_delete", {"path": "/srv/old.log"})

    try:
        res = anyio.run(session)
    finally:
        r.close()
    assert asked == ["Really delete /srv/old.log?"]
    assert res.content[0].text == "deleted /srv/old.log"
    calls = [e for e in r.audit_entries() if e["event"] == "call"]
    assert [c["tool"] for c in calls] == ["confirm_delete"] * (1 if mode == "legacy" else 2)
