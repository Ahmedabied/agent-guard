"""Mcp-Param-* headers (MCP 2026-07-28): tool arguments mirrored into HTTP headers so a load balancer can route on
them without reading the body.

A tool's input schema marks a property with "x-mcp-header": "Region", and a client calling it sends
`Mcp-Param-Region: <the argument's value>`. The gateway never forwards the client's copies: it rebuilds them from
the arguments the policy judged, with the same rules the official SDK uses, so whatever routes on a header sees the
value that was judged.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any

PREFIX = "mcp-param-"
_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")  # RFC 9110 field-name characters
_SAFE = re.compile(r"^[\x20-\x7E]*$")
_SENTINEL = re.compile(r"^=\?base64\?(.*)\?=$")
_TYPES = {"string", "integer", "boolean"}
# JSON Schema keywords whose values are schemas. Only `properties` keeps a path an annotation may sit on; the rest
# lead off it. Data keywords (default, examples, const, enum) and $ref are not entered.
_ONE = {"items", "contains", "unevaluatedItems", "additionalProperties", "propertyNames", "unevaluatedProperties",
        "not", "if", "then", "else", "contentSchema"}
_LIST = {"allOf", "anyOf", "oneOf", "prefixItems"}
_MAP = {"patternProperties", "dependentSchemas", "$defs", "definitions"}


def encode(value: str) -> str:
    """Printable ASCII without edge spaces as is; anything else as =?base64?...?= (the MCP header codec)."""
    if _SAFE.fullmatch(value) and value == value.strip() and not _SENTINEL.fullmatch(value):
        return value
    return f"=?base64?{base64.b64encode(value.encode('utf-8')).decode('ascii')}?="


def decode(value: str) -> str | None:
    """The inverse of encode; None for a malformed sentinel, so a corrupt header never matches by accident."""
    m = _SENTINEL.fullmatch(value)
    if m is None:
        return value
    try:
        raw = base64.b64decode(m.group(1), validate=True)
        if base64.b64encode(raw).decode("ascii") != m.group(1):
            return None
        return raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None


def _positions(schema: Any):
    """(path, node) for every schema position. path is the chain of `properties` keys, or None off that chain."""
    stack: list[tuple[tuple[str, ...] | None, Any]] = [((), schema)]
    while stack:
        path, node = stack.pop()
        if not isinstance(node, dict):
            continue
        yield path, node
        for kw, val in node.items():
            if kw == "properties" and isinstance(val, dict):
                stack.extend(((*path, k) if path is not None else None, sub) for k, sub in val.items())
            elif kw in _ONE:
                stack.append((None, val))
            elif kw in _LIST and isinstance(val, list):
                stack.extend((None, sub) for sub in val)
            elif kw in _MAP and isinstance(val, dict):
                stack.extend((None, sub) for sub in val.values())


def header_map(schema: Any) -> dict[tuple[str, ...], str]:
    """Property path -> header token for every x-mcp-header in a tool's input schema.

    A schema with any invalid annotation (off a plain `properties` chain, not a token, not on a string, integer or
    boolean property, or a token used twice) maps to nothing: the spec has clients drop such a tool, and servers
    check nothing for it."""
    out: dict[tuple[str, ...], str] = {}
    seen: set[str] = set()
    for path, node in _positions(schema):
        if "x-mcp-header" not in node:
            continue
        token = node["x-mcp-header"]
        if not path or not isinstance(token, str) or not _TOKEN.fullmatch(token) or node.get("type") not in _TYPES \
                or token.lower() in seen:
            return {}
        seen.add(token.lower())
        out[path] = token
    return out


def _render(value: Any) -> str | None:
    if isinstance(value, bool):
        return "true" if value else "false"
    if not isinstance(value, (str, int, float)):
        return None
    try:
        return str(value)
    except ValueError:  # an int past Python's digit limit
        return None


def headers_for(hmap: dict[tuple[str, ...], str], arguments: Any) -> dict[str, str]:
    """The Mcp-Param-* headers a call with these arguments carries: one per annotated argument that is present."""
    out = {}
    for path, token in hmap.items():
        node = arguments
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
        rendered = _render(node) if node is not None else None
        if rendered is not None:
            out[f"Mcp-Param-{token}"] = encode(rendered)
    return out
