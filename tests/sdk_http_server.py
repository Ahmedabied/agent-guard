"""The SDK demo server over Streamable HTTP: python sdk_http_server.py PORT [json]. json answers every POST with
JSON instead of an SSE stream."""

import sys

from mcp.server.mcpserver import MCPServer

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


if __name__ == "__main__":
    server.run(transport="streamable-http", host="127.0.0.1", port=int(sys.argv[1]),
               json_response=sys.argv[2:3] == ["json"])
