"""The SDK demo server over Streamable HTTP: python sdk_http_server.py PORT [json]. json answers every POST with
JSON instead of an SSE stream."""

import sys
from typing import Annotated

import anyio
from mcp.server.mcpserver import Context, Elicit, MCPServer, Resolve
from pydantic import BaseModel, Field

server = MCPServer("sdk-demo")


@server.tool()
def read_file(path: str) -> str:
    """Pretend to read a file."""
    return f"contents of {path}"


@server.tool()
def delete_file(path: str) -> str:
    """Pretend to delete a file."""
    return f"deleted {path}"


@server.tool()
def drop_database(name: str) -> str:
    """Never reachable through the demo policy."""
    return f"dropped {name}"


@server.tool()
def forecast(region: Annotated[str, Field(json_schema_extra={"x-mcp-header": "Region"})],
             days: Annotated[int, Field(json_schema_extra={"x-mcp-header": "Days"})] = 1) -> str:
    """Region and days are mirrored into Mcp-Param headers on 2026-07-28, and the server checks them."""
    return f"sunny in {region} for {days} days"


@server.tool()
async def slow(seconds: float, steps: int, ctx: Context) -> str:
    """Works for a while and reports progress along the way."""
    for i in range(steps):
        await ctx.report_progress(i + 1, steps)
        await anyio.sleep(seconds / steps)
    return "slow done"


class Sure(BaseModel):
    sure: bool


def ask_sure(path: str) -> Elicit[Sure]:
    return Elicit(f"Really delete {path}?", Sure)


@server.tool()
async def confirm_delete(path: str, answer: Annotated[Sure, Resolve(ask_sure)]) -> str:
    """Asks the client before it pretends to delete: mid-call on 2025, as input_required on 2026-07-28."""
    return f"deleted {path}" if answer.sure else f"kept {path}"


if __name__ == "__main__":
    import os

    if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):  # the SDK server makes a span per request once this is set
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor

        provider = TracerProvider(resource=Resource.create({"service.name": "sdk-demo-server"}))
        provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(provider)
    server.run(transport="streamable-http", host="127.0.0.1", port=int(sys.argv[1]),
               json_response=sys.argv[2:3] == ["json"])
