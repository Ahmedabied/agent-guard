"""Mcp-Param header rules, checked against the official SDK's own functions where it is installed."""

import pytest

from agent_guard.params import decode, encode, header_map, headers_for

SCHEMA = {"type": "object", "properties": {
    "region": {"type": "string", "x-mcp-header": "Region"},
    "days": {"type": "integer", "x-mcp-header": "Days"},
    "flag": {"type": "boolean", "x-mcp-header": "Flag"},
    "where": {"type": "object", "properties": {"zone": {"type": "string", "x-mcp-header": "Zone"}}},
    "plain": {"type": "string"},
}}
ARGS = [{"region": "eu", "days": 3, "flag": True, "where": {"zone": "z é"}}, {"region": " edge "}, {"days": 2 ** 70},
        {"region": "=?base64?abc?="}, {"flag": False, "days": None}, {"where": "not an object"}, {}]
INVALID = [
    {"properties": {"a": {"type": "number", "x-mcp-header": "A"}}},
    {"properties": {"a": {"type": "string", "x-mcp-header": "bad header"}}},
    {"properties": {"a": {"type": "string", "x-mcp-header": "A"}, "b": {"type": "string", "x-mcp-header": "a"}}},
    {"anyOf": [{"properties": {"a": {"type": "string", "x-mcp-header": "A"}}}]},
    {"x-mcp-header": "Root", "type": "string"},
]


def test_header_map_and_values():
    hmap = header_map(SCHEMA)
    assert hmap == {("region",): "Region", ("days",): "Days", ("flag",): "Flag", ("where", "zone"): "Zone"}
    h = headers_for(hmap, ARGS[0])
    assert h == {"Mcp-Param-Region": "eu", "Mcp-Param-Days": "3", "Mcp-Param-Flag": "true",
                 "Mcp-Param-Zone": encode("z é")}
    assert decode(h["Mcp-Param-Zone"]) == "z é" and decode("=?base64?not base64?=") is None


@pytest.mark.parametrize("schema", INVALID)
def test_an_invalid_annotation_means_no_headers(schema):
    assert header_map(schema) == {}


@pytest.mark.parametrize("args", ARGS)
def test_same_headers_as_the_sdk(args):
    inbound = pytest.importorskip("mcp.shared.inbound")
    assert headers_for(header_map(SCHEMA), args) == inbound.mcp_param_headers(inbound.x_mcp_header_map(SCHEMA), args)
    hdrs = headers_for(header_map(SCHEMA), args)
    assert inbound.validate_mcp_param_headers(SCHEMA, args, hdrs) is None  # the SDK server would accept them


@pytest.mark.parametrize("schema", INVALID)
def test_invalid_schemas_agree_with_the_sdk(schema):
    inbound = pytest.importorskip("mcp.shared.inbound")
    assert inbound.find_invalid_x_mcp_header(schema) is not None


@pytest.mark.parametrize("value", ["eu", " edge", "é", "=?base64?eA==?=", "a\\nb", ""])
def test_encode_matches_the_sdk(value):
    inbound = pytest.importorskip("mcp.shared.inbound")
    assert encode(value) == inbound.encode_header_value(value)
    assert decode(encode(value)) == value == inbound.decode_header_value(encode(value))
