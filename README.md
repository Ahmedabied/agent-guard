# agent-guard

AI agents call tools that change real things, and the only check between a bad idea and `delete_file` is the
model's own judgement. agent-guard puts rules you can read, review and test in front of those tools, and keeps a
tamper-evident record of every call.

It is a small proxy for [MCP](https://modelcontextprotocol.io) tool servers. Your client starts agent-guard
instead of the server; agent-guard starts the server and sits on the pipe between them.

```
agent (MCP client)  <--stdio-->  agent-guard  <--stdio-->  MCP server (files, shell, database, ...)
                                     |
                         guard.yaml      audit.jsonl
                         (rules)         (hash-chained)
```

- **Rules as code.** A YAML file says allow, deny or ask for each call, by tool name, argument patterns and rate.
  First match wins, like a firewall. Anything not listed is denied.
- **Blocked calls fail softly.** The agent gets a normal tool error with the reason, so it can change course.
  The server never sees the call.
- **Audit log you can check.** Every decision and result is one JSON line, hash-chained to the line before it.
  `agent-guard verify` finds the first edited, removed or reordered line.
- **A mistake happens once.** `agent-guard learn` turns an incident from the log into a new rule plus a
  regression test. `agent-guard test` replays those tests in CI, so nobody can quietly loosen the policy later.
- **Tools that can never pass are hidden** from `tools/list`, so the agent does not waste turns on them.

Stdlib Python plus PyYAML. No MCP SDK needed at runtime: MCP over stdio is newline-delimited JSON-RPC, and
agent-guard only steps in on `tools/call`, so it works with any protocol version the two ends agree on.

## Try it in under a minute

```sh
git clone https://github.com/Ahmedabied/agent-guard && cd agent-guard
python3 -m venv .venv && . .venv/bin/activate && pip install -e .
python examples/demo.py
```

The demo runs a scripted agent against a tiny file server ([examples/files_server.py](examples/files_server.py))
through the example policy ([examples/guard.yaml](examples/guard.yaml)). Real output, trimmed:

```
1. An agent session through the guard
  ok      read_file(path='/tmp/agent-guard-demo/notes/plan.md')
  BLOCKED delete_file(path='/tmp/agent-guard-demo/notes/plan.md')
          -> agent-guard blocked this call to delete_file: notes are read-only for agents (rule: notes-are-read-only)
  BLOCKED delete_file(path='/tmp/agent-guard-demo/scratch/../notes/plan.md')
          -> agent-guard blocked this call to delete_file: notes are read-only for agents (rule: notes-are-read-only)
  ok      delete_file(path='/tmp/agent-guard-demo/scratch/report-final.pdf')

3. Deleting report-final.pdf was a mistake. Turn it into a rule:
  $ agent-guard learn --seq 9 --name keep-final-reports --match 'path=*final*' ...
  added rule 'keep-final-reports' at the top of guard.yaml

4. Same mistake, next session:
  BLOCKED delete_file(path='/tmp/agent-guard-demo/scratch/report-final-v2.pdf')
          -> agent-guard blocked this call to delete_file: final reports are kept (rule: keep-final-reports)
  $ agent-guard test
  8/8 cases pass
  ok: 11 entries, chain intact, head c7a5c6bd0548...
```

Note the second block: `scratch/../notes/plan.md` is judged as the path it really points to.

## Put it in front of a real server

Wherever your MCP client config names a stdio server, put `agent-guard run -p <policy> --` in front of it:

```json
{
  "mcpServers": {
    "files": {
      "command": "agent-guard",
      "args": ["run", "-p", "/path/to/guard.yaml", "--",
               "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path/to/project"]
    }
  }
}
```

Checked with the official filesystem server (`@modelcontextprotocol/server-filesystem`) driven by the official
MCP Python SDK client: tools the policy never allows disappear from the list, a write into a read-only folder
comes back as a tool error, and a write elsewhere goes through.

## The policy

```yaml
version: 1
default: deny              # what happens when no rule matches
hide_denied_tools: true    # drop tools that can never pass from tools/list
ask: {via: tty, timeout: 60}
audit: {path: audit.jsonl}

rules:
  - name: notes-are-read-only
    tool: [write_file, delete_file]          # glob, or a list of globs
    args:
      path: {under: /data/notes}             # normalised, so ../ tricks do not work
    decision: deny
    reason: notes are read-only for agents   # the agent sees this

  - name: write-burst
    tool: write_file
    rate: 20/minute                          # matches only once the limit is used up
    decision: deny

  - name: no-rm-rf
    tool: run_shell
    args:
      "*": {regex: 'rm\s+-\w*(r\w*f|f\w*r)'} # "*" means any value anywhere in the arguments
    decision: deny

  - name: file-work
    tool: [read_file, write_file, delete_file, run_shell]
    decision: allow
```

| Operator | Meaning |
|---|---|
| `"text*"` (a plain string) or `glob:` | glob match, `*` matches any characters including `/` |
| `regex:` | Python regex, searched anywhere in the value |
| `under:` | the path, after normalising `.`, `..` and `//`, is inside one of these folders |
| `equals:` | exact value; `true` does not equal `1` |
| `contains:` | substring of a string, or item of a list |
| `not_glob:` `not_regex:` `not_under:` | the opposite |

Arguments are named by key, or by a dotted path into nested objects (`options.force`, `files.0`). The matching
rules are written to fail closed:

- An argument that is missing makes a `not_*` deny rule match, and never satisfies an allow rule.
- A list or object where a string was expected is checked value by value: one bad value is enough for a deny
  rule, every value must pass for an allow rule.
- A dotted key is checked both as a nested path and as a literal key with dots in it.
- Duplicate JSON keys, `NaN` and invalid UTF-8 are refused before any rule runs, and the server receives the
  message exactly as it was judged. Two JSON parsers that disagree on `{"name": "read_file", "name": "delete_file"}`
  would otherwise let one call through as another.
- Typos in the policy (`decison: deny`, an unknown operator, a bad regex) stop it from loading, with the rule name.

`ask` sends the call to a person: `via: tty` asks on the terminal agent-guard was started from, `via: command`
runs a command with the call as JSON on stdin (exit 0 approves), `via: deny` refuses. With nobody to ask, the
answer is no.

## The audit log

One JSON object per line. `prev` is the hash of the line before, `hash` is sha256 of the line's own canonical
JSON. Arguments are logged with secrets removed: keys like `password`, `token` or `api_key` (in any casing), and
values that look like keys (Bearer tokens, PEM private keys, common token formats). Long values are shortened to
a length and a hash.

```sh
agent-guard log audit.jsonl --denied     # recent entries with their seq numbers
agent-guard verify audit.jsonl           # ok: 11 entries, chain intact, head c7a5c6bd...
agent-guard verify audit.jsonl --expect-head c7a5c6bd...   # also catches lines cut from the end
```

If the log cannot be written (disk full), calls are denied. No record, no tool call.

## From incident to rule

```sh
agent-guard log audit.jsonl                                # find the call that went wrong
agent-guard learn -p guard.yaml --seq 9 --name keep-final-reports \
    --reason "final reports are kept" --match 'path=*final*'
agent-guard test -p guard.yaml guard-tests.yaml            # add this to CI
```

`learn` puts the rule at the top of the policy (first match wins, so it beats any broader allow), keeps your
comments and layout, refuses to write a rule that would not have caught the incident, and appends a regression
case to `guard-tests.yaml`. Without `--match` it matches the exact values from the incident.

`agent-guard check -p guard.yaml delete_file '{"path": "/data/notes/a.md"}'` shows the decision for one call
without running anything (exit code 0 allow, 1 deny, 3 ask).

## How fast

`python bench/bench.py --calls 3000` times sequential `tools/call` round trips against the demo server, once
directly and once through agent-guard with the example policy and a real audit log:

| | median | p99 |
|---|---|---|
| added per tool call, audit fsync off (default) | 89 to 126 us | about 210 us |
| policy check alone | 3.6 us | |
| added per tool call, audit fsync on (ext4) | 714 us | 15 ms |

Five runs on an Intel i5-14400F, Python 3.12, with the machine busy (load 3.4). Most of the added time is the two
extra pipe hops and thread wake-ups, not the checks: the policy is 3.6 us and the audit write about 12 us.
Every call is written to the log before it is forwarded. With fsync off, a crash of agent-guard itself can lose
at most the result line of a call in flight; a power cut can lose the last entries. Turn on
`audit: {fsync: true}` if that matters more than 0.7 ms per call.

## Limits

- **Stdio servers only.** Streamable HTTP is not proxied yet.
- **Only `tools/call` is judged.** Resources, prompts and sampling requests pass through untouched.
- **Patterns, not a sandbox.** A rule on a shell command string is a speed bump: a determined agent can phrase
  `rm` in ways a regex will not catch. `under` is lexical and does not follow symlinks, because the guard may not
  share a filesystem with the server. Pair agent-guard with server-side limits (allowed folders, read-only users,
  containers) and use it for policy, approval and the record.
- **Rate limits live in memory**, per agent-guard process. Restarting resets them.
- **The audit chain proves order and content, not existence.** Deleting the whole file, or cutting lines from
  the end, is only caught if you keep the head hash somewhere else.
- **Old-style JSON-RPC batches** (2025-03-26) are split: denied calls in a batch are answered one by one.
- File locking for several writers on one log is Unix only.

## Development

```sh
pip install -e '.[test,sdk]'
pytest -q                      # 67 tests
```

The tests start real processes on real pipes. One suite drives agent-guard with the official MCP Python SDK on
both sides, in both handshakes: `initialize` (2025 protocol versions) and `server/discover` (2026-07-28, where
every result must carry `resultType`). CI runs the tests, the example policy's regression cases and a short
benchmark on Python 3.10, 3.12 and 3.13.

Built with AI pair programming.

## Licence

MIT
