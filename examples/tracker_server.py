"""A pretend issue tracker as a remote MCP server (Streamable HTTP), for examples/http_demo.py.

    python examples/tracker_server.py PORT

Built with the official MCP Python SDK. Nothing is stored: each tool says what it would have done.
"""

import sys

from mcp.server.mcpserver import MCPServer

server = MCPServer("tracker")


@server.tool()
def list_issues(repo: str) -> str:
    """Open issues in a repository."""
    return f"{repo}: #12 login page slow, #15 typo in footer"


@server.tool()
def close_issue(repo: str, number: int) -> str:
    """Close an issue."""
    return f"closed {repo}#{number}"


@server.tool()
def delete_repo(repo: str) -> str:
    """Delete a repository and everything in it."""
    return f"deleted {repo}"


if __name__ == "__main__":
    import os

    if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):  # the SDK server traces every request once a backend is set
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor

        provider = TracerProvider(resource=Resource.create({"service.name": "tracker"}))
        provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(provider)
    server.run(transport="streamable-http", host="127.0.0.1", port=int(sys.argv[1]))
