# agent-guard

Guardrails as code for AI agents. A small proxy that sits between an agent and its MCP tool servers: rules in a
YAML file allow or deny each tool call, and every call lands in an append-only, hash-chained audit log.

Work in progress. First version is being built now.
