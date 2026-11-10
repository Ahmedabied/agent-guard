"""A stand-in OpenTelemetry collector: python fake_collector.py PORT OUT. Each OTLP/HTTP trace export it receives
is appended to OUT as one base64 line (protobuf ExportTraceServiceRequest)."""

import base64
import sys

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

PORT, OUT = int(sys.argv[1]), sys.argv[2]


async def traces(request: Request) -> Response:
    body = await request.body()
    with open(OUT, "a") as f:
        f.write(base64.b64encode(body).decode() + "\n")
    return Response(b"", media_type="application/x-protobuf")


app = Starlette(routes=[Route("/v1/traces", traces, methods=["POST"])])
uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
