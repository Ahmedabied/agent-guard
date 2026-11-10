"""A tiny Streamable HTTP MCP server that records every request it gets, for the gateway tests.

python fake_upstream.py PORT LOG. The path picks the answer: /json answers with JSON, /sse with an SSE stream that
sends a notification before the result, /redirect answers 307 to /json, /hold keeps a GET stream open and silent,
/slow and /slowsse take 3 s over a tool call and log whether the caller stayed.
"""

import json
import sys

import anyio
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse
from starlette.routing import Route

PORT, LOG = int(sys.argv[1]), sys.argv[2]


async def handle(request: Request) -> Response:
    body = await request.body()
    with open(LOG, "a") as f:
        f.write(json.dumps({"method": request.method, "path": request.url.path, "headers": request.headers.items(),
                            "body": body.decode("utf-8", "replace")}) + "\n")
    mode = request.path_params["mode"]
    if mode == "redirect":
        return Response(status_code=307, headers={"location": f"http://127.0.0.1:{PORT}/json"})
    if request.method == "GET" and mode == "hold":  # a server-message stream that stays open and says nothing
        async def quiet():
            yield b": open\n\n"
            await anyio.sleep_forever()

        return StreamingResponse(quiet(), media_type="text/event-stream")
    if request.method != "POST":
        return Response(status_code=405)
    msg = json.loads(body)
    if "id" not in msg:
        return Response(status_code=202)
    if mode in ("slow", "slowsse") and msg.get("method") == "tools/call":
        return await slow(request, msg, mode)
    if msg.get("method") == "tools/call":
        result = {"content": [{"type": "text", "text": f"ran {msg['params']['name']}"}], "isError": False}
    elif msg.get("method") == "tools/list":
        result = {"tools": [{"name": n, "inputSchema": {"type": "object"}} for n in ("read_file", "drop_database")]}
        result["tools"].append({"name": "forecast", "inputSchema": {"type": "object", "properties": {
            "region": {"type": "string", "x-mcp-header": "Region"}}}})
    else:
        result = {}
    answer = json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result})
    if mode == "sse":
        note = json.dumps({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": "hi"}})
        text = f": ping\n\nevent: message\ndata: {note}\n\nevent: message\nid: 7\ndata: {answer}\n\n"
        return Response(text, media_type="text/event-stream")
    return Response(answer, media_type="application/json")


def note(event: str, msg: dict) -> None:
    with open(LOG, "a") as f:
        f.write(json.dumps({"method": "NOTE", "path": "", "headers": [], "body": event, "id": msg.get("id")}) + "\n")


async def slow(request: Request, msg: dict, mode: str) -> Response:
    """A call that works for 3 s and notices if the caller goes away: /slow before answering anything (no headers
    yet), /slowsse after sending a first progress event."""
    async def work():
        try:
            for _ in range(30):
                if await request.is_disconnected():
                    note("cancelled", msg)
                    return False
                await anyio.sleep(0.1)
        except anyio.get_cancelled_exc_class():  # Starlette cancels a stream whose reader went away
            note("cancelled", msg)
            raise
        note("finished", msg)
        return True

    done = {"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [{"type": "text", "text": "slow done"}]}}
    if mode == "slow":
        await work()
        return Response(json.dumps(done), media_type="application/json")

    async def stream():
        progress = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": 1, "progress": 1}}
        yield f"event: message\ndata: {json.dumps(progress)}\n\n".encode()
        if await work():
            yield f"event: message\ndata: {json.dumps(done)}\n\n".encode()

    return StreamingResponse(stream(), media_type="text/event-stream")


app = Starlette(routes=[Route("/{mode}", handle, methods=["GET", "POST", "DELETE"])])
uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
