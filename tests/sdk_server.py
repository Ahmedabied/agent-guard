"""A server built with the official MCP Python SDK, to prove the proxy works with real SDK peers."""

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
    server.run()
