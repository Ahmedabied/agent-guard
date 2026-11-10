"""Read the demo's traces back from Jaeger and check where the guard's spans landed.

    OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 python examples/http_demo.py
    python examples/jaeger_check.py [http://localhost:16686]

Each agent step is one trace. An allowed call must hold the agent's step, the guard's decision and the tracker's
own span; a blocked one the step and the guard's decision, and nothing from the tracker.
"""

import json
import sys
import time
import urllib.request

JAEGER = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:16686").rstrip("/")


def get(path):
    with urllib.request.urlopen(JAEGER + path, timeout=10) as r:
        return json.load(r)


def spans_of(payload):
    out = []
    for rs in payload.get("result", {}).get("resourceSpans", []):
        attrs = {a["key"]: a["value"] for a in rs.get("resource", {}).get("attributes", [])}
        service = attrs.get("service.name", {}).get("stringValue")
        for ss in rs.get("scopeSpans", []):
            for s in ss.get("spans", []):
                a = {x["key"]: next(iter(x["value"].values())) for x in s.get("attributes", [])}
                out.append((service, s["name"], a, s["traceId"]))
    return out


def main():
    now = time.time()
    window = (f"query.start_time_min={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now - 900))}"
              f"&query.start_time_max={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now + 60))}")
    steps = [s for s in spans_of(get(f"/api/v3/traces?query.service_name=demo-agent&{window}"))
             if s[1].startswith("agent step")]
    if not steps:
        sys.exit("no demo-agent traces in Jaeger: run the demo with OTEL_EXPORTER_OTLP_ENDPOINT set first")
    failures = 0
    for _, name, attrs, trace_id in sorted(steps, key=lambda s: s[2].get("demo.step", "")):
        spans = spans_of(get(f"/api/v3/traces/{trace_id}"))
        guard = [a for svc, n, a, _ in spans if svc == "agent-guard"]
        tracker = [n for svc, n, _, _ in spans if svc == "tracker"]
        decision = guard[0].get("agent_guard.decision") if guard else None
        ok = bool(guard) and ((decision == "allow" and any(n.startswith("tools/call") for n in tracker))
                              or (decision == "deny" and not tracker))
        failures += not ok
        print(f"  {'ok' if ok else 'FAIL':4} {attrs.get('demo.step')}: guard {decision}, "
              f"tracker spans {tracker or 'none'}  (trace {trace_id})")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
