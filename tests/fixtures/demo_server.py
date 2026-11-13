"""Small MCP server used by the tests and the demo.

Read-only tools carry the readOnlyHint annotation, tools that change state do
not. Run with `python demo_server.py` (stdio) or
`python demo_server.py http <port>` (streamable HTTP on 127.0.0.1).
DEMO_ADD_DESCRIPTION replaces the description of `add`, so a restart can come
back with a changed definition.
DEMO_EXTRA_TOOLS=<n> adds n read-only tools, echo_000 and on, for tests about
how many tools a view can hold.
"""

import os
import sys
import time
from pathlib import Path

from mcp import types
from mcp.types import ToolAnnotations

try:  # MCP Python SDK 2.x
    from mcp.server.mcpserver import Context, MCPServer as Server
except ImportError:  # 1.x
    from mcp.server.fastmcp import Context, FastMCP as Server

server = Server("omega-demo")
READ = ToolAnnotations(read_only_hint=True) if "read_only_hint" in ToolAnnotations.model_fields \
    else ToolAnnotations(readOnlyHint=True)
NOTES: dict[str, str] = {}


@server.tool(annotations=READ, description=os.environ.get("DEMO_ADD_DESCRIPTION"))
def add(a: int, b: int) -> str:
    """Add two integers."""
    return str(a + b)


@server.tool(annotations=READ)
def list_notes() -> str:
    """List the titles of the saved notes."""
    return "\n".join(sorted(NOTES)) or "(no notes)"


@server.tool(annotations=READ)
def get_note(title: str) -> str:
    """Return the text of one note."""
    return NOTES.get(title, f"(no note named '{title}')")


@server.tool(annotations=READ)
def whoami() -> str:
    """Return the demo token the server was started with."""
    return os.environ.get("DEMO_TOKEN", "(none)")


@server.tool(annotations=READ)
def slow(seconds: float) -> str:
    """Sleep, then answer."""
    time.sleep(seconds)
    return "done"


@server.tool(annotations=READ)
def big() -> str:
    """Return a very long text."""
    return "x" * 20000


@server.tool(annotations=READ)
def crash() -> str:
    """Kill the server process."""
    os._exit(3)


@server.tool()
def create_note(title: str, text: str) -> str:
    """Save a note. Changes state."""
    NOTES[title] = text
    return f"saved '{title}'"


@server.tool()
def delete_notes() -> str:
    """Delete every note. Changes state."""
    NOTES.clear()
    return "deleted"


@server.tool(annotations=READ)
def fail() -> str:
    """Always raise an error."""
    raise ValueError("this tool always fails")


@server.tool()
async def redefine(tool: str, description: str, ctx: Context, read_only: bool = False) -> str:
    """Give one of this server's tools a new description and read-only hint, then tell the client
    that the tool list changed. Changes state."""
    if hasattr(server, "remove_tool"):
        server.remove_tool(tool)
    else:  # FastMCP before remove_tool
        server._tool_manager._tools.pop(tool)
    server.add_tool(globals()[tool], name=tool, description=description, annotations=READ if read_only else None)
    notice = types.ToolListChangedNotification(method="notifications/tools/list_changed")
    if hasattr(types.ServerNotification, "model_fields"):  # 1.x wraps notifications in a RootModel
        notice = types.ServerNotification(notice)
    await ctx.session.send_notification(notice, related_request_id=ctx.request_id)  # on this call's stream
    return f"redefined '{tool}'"


def _echo(text: str = "") -> str:
    """Return the text it is given."""
    return text


for _index in range(int(os.environ.get("DEMO_EXTRA_TOOLS", "0"))):
    server.add_tool(_echo, name=f"echo_{_index:03}", description=f"Echo the text (copy {_index}).", annotations=READ)


def _http_app():
    """Streamable HTTP app; with DEMO_REQUIRE_TOKEN set, every request must
    carry `Authorization: Bearer <that token>` or it gets a 401. DEMO_TOKEN_FILE
    names a file holding that token instead, read at every request, so a test
    can make the server refuse a token it took before."""
    app = server.streamable_http_app()
    fixed, token_file = os.environ.get("DEMO_REQUIRE_TOKEN"), os.environ.get("DEMO_TOKEN_FILE")
    if not (fixed or token_file):
        return app

    async def guarded(scope, receive, send):
        if scope["type"] == "http":
            expected = Path(token_file).read_text().strip() if token_file else fixed
            headers = dict(scope.get("headers") or [])
            if headers.get(b"authorization", b"").decode() != f"Bearer {expected}":
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"text/plain")]})
                await send({"type": "http.response.body", "body": b"unauthorized"})
                return
        await app(scope, receive, send)

    return guarded


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "http":
        import uvicorn

        uvicorn.run(_http_app(), host="127.0.0.1", port=int(sys.argv[2]), log_level="warning")
    else:
        server.run()
