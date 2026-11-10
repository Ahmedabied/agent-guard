// One session with an official MCP TypeScript SDK client: node probe.mjs v1|v2 URL legacy|auto
// Prints what it saw as one JSON line, for tests/test_ts_clients.py.
const [which, url, mode] = process.argv.slice(2);
const mod = which === "v2"
  ? await import("@modelcontextprotocol/client")
  : { ...(await import("@modelcontextprotocol/sdk/client/index.js")),
      ...(await import("@modelcontextprotocol/sdk/client/streamableHttp.js")) };
const { Client, StreamableHTTPClientTransport } = mod;
const options = mode === "auto" ? { versionNegotiation: { mode: "auto" } } : undefined;
const client = new Client({ name: "agent-guard-ts-test", version: "1.0.0" }, options);
await client.connect(new StreamableHTTPClientTransport(new URL(url)));
const call = async (name, args) => {
  const r = await client.callTool({ name, arguments: args });
  return [Boolean(r.isError), r.content?.[0]?.text ?? ""];
};
const prompt = async (name, args) => {  // a blocked prompt is a JSON-RPC error made by the guard, not a result
  try {
    const r = await client.getPrompt({ name, arguments: args });
    return ["ok", r.messages?.[0]?.content?.text ?? ""];
  } catch (e) {
    return ["error", e.code ?? null, String(e.message ?? e)];
  }
};
const seen = {
  protocol: client.getNegotiatedProtocolVersion?.() ?? null,
  tools: (await client.listTools()).tools.map((t) => t.name).sort(),
  read: await call("read_file", { path: "/srv/a.txt" }),
  delete: await call("delete_file", { path: "/etc/passwd" }),
  drop: await call("drop_database", { name: "prod" }),
  forecast: await call("forecast", { region: "eu-west é", days: 3 }),
  review: await prompt("review", { code: "x = 1" }),
  leak: await prompt("leak_env", {}),
};
await client.close();
console.log(JSON.stringify(seen));
