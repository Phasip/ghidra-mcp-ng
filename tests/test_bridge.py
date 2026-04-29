"""
test_bridge.py — unit tests for bridge.py.

Tests the pure-logic helpers and the MCP JSON-RPC main loop without a live
Ghidra server.  HTTP calls are replaced by lightweight stubs so that every
test is fast and fully offline.
"""

from __future__ import annotations

import io
import json
import sys
import urllib.error
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Module under test
# ---------------------------------------------------------------------------
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
import bridge  # noqa: E402


# ---------------------------------------------------------------------------
# Minimal OpenAPI spec used across tests
# ---------------------------------------------------------------------------

_MINIMAL_SPEC: dict = {
    "paths": {
        "/check_connection": {
            "get": {
                "operationId": "check_connection",
                "summary": "Check server connectivity",
                "parameters": [],
            }
        },
        "/search_functions": {
            "get": {
                "operationId": "search_functions",
                "summary": "Search functions by name",
                "parameters": [
                    {
                        "name": "program",
                        "in": "query",
                        "required": True,
                        "description": "Program name",
                        "schema": {"type": "string"},
                    },
                    {
                        "name": "query",
                        "in": "query",
                        "required": False,
                        "description": "Name filter",
                        "schema": {"type": "string", "default": ""},
                    },
                    {
                        "name": "limit",
                        "in": "query",
                        "required": False,
                        "schema": {"type": "integer", "default": 100},
                    },
                ],
            }
        },
        "/rename_function": {
            "post": {
                "operationId": "rename_function",
                "summary": "Rename a function",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/RenameFunctionRequest"
                            }
                        }
                    },
                },
            }
        },
    },
    "components": {
        "schemas": {
            "RenameFunctionRequest": {
                "type": "object",
                "properties": {
                    "program": {
                        "type": "string",
                        "description": "Program name",
                    },
                    "name_or_address": {
                        "type": "string",
                        "description": "Function name or hex address",
                    },
                    "new_name": {
                        "type": "string",
                        "description": "New function name",
                    },
                },
                "required": ["program", "name_or_address", "new_name"],
            }
        }
    },
}


# ---------------------------------------------------------------------------
# _resolve_ref / _resolve
# ---------------------------------------------------------------------------

class TestResolveRef:
    def test_resolves_simple_ref(self):
        spec = {"components": {"schemas": {"Foo": {"type": "object"}}}}
        result = bridge._resolve_ref(spec, "#/components/schemas/Foo")
        assert result == {"type": "object"}

    def test_resolves_nested_ref(self):
        spec = {"a": {"b": {"c": {"value": 42}}}}
        result = bridge._resolve_ref(spec, "#/a/b/c")
        assert result == {"value": 42}

    def test_missing_key_raises(self):
        with pytest.raises((KeyError, TypeError)):
            bridge._resolve_ref({}, "#/components/schemas/Missing")


class TestResolve:
    def test_ref_is_resolved(self):
        spec = {"components": {"schemas": {"Bar": {"type": "string"}}}}
        schema = {"$ref": "#/components/schemas/Bar"}
        assert bridge._resolve(spec, schema) == {"type": "string"}

    def test_plain_schema_returned_unchanged(self):
        spec: dict = {}
        schema = {"type": "integer", "description": "a number"}
        assert bridge._resolve(spec, schema) is schema


# ---------------------------------------------------------------------------
# _input_schema
# ---------------------------------------------------------------------------

class TestInputSchema:
    def test_get_builds_schema_from_parameters(self):
        op = _MINIMAL_SPEC["paths"]["/search_functions"]["get"]
        schema = bridge._input_schema(_MINIMAL_SPEC, op, "get")
        assert schema["type"] == "object"
        assert "program" in schema["properties"]
        assert "query" in schema["properties"]
        assert "limit" in schema["properties"]

    def test_get_marks_required_params(self):
        op = _MINIMAL_SPEC["paths"]["/search_functions"]["get"]
        schema = bridge._input_schema(_MINIMAL_SPEC, op, "get")
        assert "program" in schema["required"]
        assert "query" not in schema.get("required", [])

    def test_get_carries_description_and_default(self):
        op = _MINIMAL_SPEC["paths"]["/search_functions"]["get"]
        schema = bridge._input_schema(_MINIMAL_SPEC, op, "get")
        assert schema["properties"]["query"]["description"] == "Name filter"
        assert schema["properties"]["query"]["default"] == ""
        assert schema["properties"]["limit"]["default"] == 100

    def test_get_skips_non_query_params(self):
        op = {
            "parameters": [
                {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
                {"name": "q", "in": "query", "required": False, "schema": {"type": "string"}},
            ]
        }
        schema = bridge._input_schema(_MINIMAL_SPEC, op, "get")
        assert "id" not in schema["properties"]
        assert "q" in schema["properties"]

    def test_post_resolves_ref_and_builds_schema(self):
        op = _MINIMAL_SPEC["paths"]["/rename_function"]["post"]
        schema = bridge._input_schema(_MINIMAL_SPEC, op, "post")
        assert "program" in schema["properties"]
        assert "name_or_address" in schema["properties"]
        assert "new_name" in schema["properties"]
        assert set(schema["required"]) == {"program", "name_or_address", "new_name"}

    def test_post_carries_field_description(self):
        op = _MINIMAL_SPEC["paths"]["/rename_function"]["post"]
        schema = bridge._input_schema(_MINIMAL_SPEC, op, "post")
        assert schema["properties"]["program"]["description"] == "Program name"

    def test_empty_post_body_returns_empty_schema(self):
        op: dict = {}
        schema = bridge._input_schema(_MINIMAL_SPEC, op, "post")
        assert schema == {"type": "object", "properties": {}}


# ---------------------------------------------------------------------------
# _openapi_to_mcp_tools
# ---------------------------------------------------------------------------

class TestOpenApiToMcpTools:
    def test_produces_one_tool_per_operation(self):
        tools = bridge._openapi_to_mcp_tools(_MINIMAL_SPEC)
        names = [t["name"] for t in tools]
        assert "check_connection" in names
        assert "search_functions" in names
        assert "rename_function" in names

    def test_tools_are_sorted_by_name(self):
        tools = bridge._openapi_to_mcp_tools(_MINIMAL_SPEC)
        names = [t["name"] for t in tools]
        assert names == sorted(names)

    def test_tool_has_required_mcp_fields(self):
        tools = bridge._openapi_to_mcp_tools(_MINIMAL_SPEC)
        tool = next(t for t in tools if t["name"] == "check_connection")
        assert tool["description"] == "Check server connectivity"
        assert "inputSchema" in tool
        assert tool["inputSchema"]["type"] == "object"

    def test_operation_without_operationId_is_skipped(self):
        spec = {
            "paths": {
                "/no-id": {"get": {"summary": "No id here"}},
                "/with-id": {"get": {"operationId": "has_id", "summary": "Has id"}},
            }
        }
        tools = bridge._openapi_to_mcp_tools(spec)
        assert len(tools) == 1
        assert tools[0]["name"] == "has_id"

    def test_non_get_post_methods_are_skipped(self):
        spec = {
            "paths": {
                "/res": {
                    "delete": {"operationId": "del_res", "summary": "Delete"},
                    "put": {"operationId": "put_res", "summary": "Put"},
                    "get": {"operationId": "get_res", "summary": "Get"},
                }
            }
        }
        tools = bridge._openapi_to_mcp_tools(spec)
        assert len(tools) == 1
        assert tools[0]["name"] == "get_res"

    def test_empty_spec_returns_empty_list(self):
        assert bridge._openapi_to_mcp_tools({}) == []
        assert bridge._openapi_to_mcp_tools({"paths": {}}) == []


# ---------------------------------------------------------------------------
# _dispatch
# ---------------------------------------------------------------------------

class TestDispatch:
    def test_get_operation_called_without_args(self):
        with patch.object(bridge, "_get", return_value={"status": "ok"}) as mock_get:
            result = bridge._dispatch(_MINIMAL_SPEC, "http://host", "check_connection", {})
        mock_get.assert_called_once_with("http://host/check_connection")
        assert result == {"status": "ok"}

    def test_get_operation_appends_query_string(self):
        with patch.object(bridge, "_get", return_value=[]) as mock_get:
            bridge._dispatch(
                _MINIMAL_SPEC, "http://host", "search_functions",
                {"program": "test.exe", "query": "main"},
            )
        url = mock_get.call_args[0][0]
        assert "program=test.exe" in url
        assert "query=main" in url

    def test_post_operation_calls_post_with_body(self):
        with patch.object(bridge, "_post", return_value={"success": True}) as mock_post:
            result = bridge._dispatch(
                _MINIMAL_SPEC, "http://host", "rename_function",
                {"program": "p", "name_or_address": "f", "new_name": "g"},
            )
        mock_post.assert_called_once_with(
            "http://host/rename_function",
            {"program": "p", "name_or_address": "f", "new_name": "g"},
        )
        assert result == {"success": True}

    def test_unknown_tool_raises_value_error(self):
        with pytest.raises(ValueError, match="Unknown tool"):
            bridge._dispatch(_MINIMAL_SPEC, "http://host", "nonexistent_tool", {})


# ---------------------------------------------------------------------------
# Main loop (JSON-RPC)
# ---------------------------------------------------------------------------

def _run_main_with_inputs(*messages: dict, get_mock: Any = None, post_mock: Any = None) -> list[dict]:
    """
    Run bridge.main() with stdin replaced by the given JSON-RPC messages.
    Returns the list of JSON objects written to stdout.

    ``get_mock`` / ``post_mock``: optional mock objects for bridge._get / bridge._post.
    When omitted, ``_get`` defaults to returning ``_MINIMAL_SPEC`` for every call.
    """
    stdin_lines = "\n".join(json.dumps(m) for m in messages) + "\n"
    captured: list[str] = []

    def fake_print(s: str, **_: Any) -> None:
        captured.append(s)

    if get_mock is None:
        get_mock = MagicMock(return_value=_MINIMAL_SPEC)

    patches: list[Any] = [
        patch("sys.stdin", io.StringIO(stdin_lines)),
        patch("sys.argv", ["bridge.py", "--url", "http://testhost"]),
        patch.object(bridge, "_get", get_mock),
        patch("builtins.print", side_effect=fake_print),
    ]
    if post_mock is not None:
        patches.append(patch.object(bridge, "_post", post_mock))

    with patches[0], patches[1], patches[2], patches[3]:
        if post_mock is not None:
            with patches[4]:
                bridge.main()
        else:
            bridge.main()

    return [json.loads(line) for line in captured]


class TestMainLoopInitialize:
    def test_initialize_returns_protocol_version(self):
        responses = _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        )
        assert len(responses) == 1
        r = responses[0]
        assert r["id"] == 1
        assert r["result"]["protocolVersion"] == bridge.PROTOCOL_VERSION

    def test_initialize_returns_server_info(self):
        responses = _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        )
        info = responses[0]["result"]["serverInfo"]
        assert info["name"] == bridge.SERVER_NAME
        assert info["version"] == bridge.SERVER_VERSION

    def test_initialize_advertises_tools_capability(self):
        responses = _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        )
        assert "tools" in responses[0]["result"]["capabilities"]


class TestMainLoopToolsList:
    def test_tools_list_returns_all_tools(self):
        responses = _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        )
        tools = responses[0]["result"]["tools"]
        names = [t["name"] for t in tools]
        assert "check_connection" in names
        assert "rename_function" in names

    def test_tools_list_error_on_connection_refused(self):
        err = urllib.error.URLError("Connection refused")
        with (
            patch("sys.stdin", io.StringIO(
                json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}) + "\n"
            )),
            patch("sys.argv", ["bridge.py"]),
            patch.object(bridge, "_get", side_effect=err),
            patch("builtins.print") as mock_print,
        ):
            bridge.main()
        output = json.loads(mock_print.call_args[0][0])
        assert "error" in output
        assert output["error"]["code"] == -32603


class TestMainLoopToolsCall:
    def test_tools_call_dispatches_and_returns_result(self):
        # Spec is fetched first, then the actual GET call returns the response
        get_mock = MagicMock(side_effect=[_MINIMAL_SPEC, {"status": "ok"}])
        responses = _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "check_connection", "arguments": {}}},
            get_mock=get_mock,
        )
        r = responses[0]
        assert r["id"] == 4
        content = r["result"]["content"][0]
        assert content["type"] == "text"
        assert "ok" in content["text"]

    def test_tools_call_missing_name_returns_error(self):
        responses = _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {}}
        )
        assert "error" in responses[0]
        assert responses[0]["error"]["code"] == -32600

    def test_tools_call_unknown_tool_returns_is_error_result(self):
        responses = _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
             "params": {"name": "no_such_tool", "arguments": {}}}
        )
        r = responses[0]
        assert r["result"]["isError"] is True
        assert "Unknown tool" in r["result"]["content"][0]["text"]

    def test_tools_call_http_400_returns_is_error_with_hint(self):
        http_err = urllib.error.HTTPError(
            url="http://testhost/rename_function",
            code=400,
            msg="Bad Request",
            hdrs=MagicMock(),
            fp=io.BytesIO(b"Required parameter 'program' is missing"),
        )
        responses = _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
             "params": {"name": "rename_function",
                        "arguments": {"program": "p", "name_or_address": "f", "new_name": "g"}}},
            post_mock=MagicMock(side_effect=http_err),
        )
        r = responses[0]
        assert r["result"]["isError"] is True
        text = r["result"]["content"][0]["text"]
        assert "400" in text
        assert "bad parameters" in text

    def test_tools_call_http_500_returns_is_error_with_hint(self):
        http_err = urllib.error.HTTPError(
            url="http://testhost/check_connection",
            code=500,
            msg="Internal Server Error",
            hdrs=MagicMock(),
            fp=io.BytesIO(b"NullPointerException"),
        )
        get_mock = MagicMock(side_effect=[_MINIMAL_SPEC, http_err])
        responses = _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 8, "method": "tools/call",
             "params": {"name": "check_connection", "arguments": {}}},
            get_mock=get_mock,
        )
        r = responses[0]
        assert r["result"]["isError"] is True
        assert "500" in r["result"]["content"][0]["text"]
        assert "server error" in r["result"]["content"][0]["text"]

    def test_tools_call_connection_error_returns_is_error(self):
        url_err = urllib.error.URLError("Connection refused")
        get_mock = MagicMock(side_effect=[_MINIMAL_SPEC, url_err])
        responses = _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
             "params": {"name": "check_connection", "arguments": {}}},
            get_mock=get_mock,
        )
        r = responses[0]
        assert r["result"]["isError"] is True
        assert "Cannot reach" in r["result"]["content"][0]["text"]


class TestMainLoopMiscMethods:
    def test_ping_returns_empty_result(self):
        responses = _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 10, "method": "ping"}
        )
        assert responses[0]["result"] == {}
        assert responses[0]["id"] == 10

    def test_unknown_method_returns_method_not_found(self):
        responses = _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 11, "method": "unsupported/method"}
        )
        assert responses[0]["error"]["code"] == -32601
        assert "unsupported/method" in responses[0]["error"]["message"]

    def test_missing_method_field_returns_invalid_request(self):
        responses = _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 12}
        )
        assert responses[0]["error"]["code"] == -32600

    def test_malformed_json_returns_parse_error(self):
        stdin_data = "{ this is not json }\n"
        captured: list[str] = []

        def fake_print(s: str, **_: Any) -> None:
            captured.append(s)

        with (
            patch("sys.stdin", io.StringIO(stdin_data)),
            patch("sys.argv", ["bridge.py"]),
            patch("builtins.print", side_effect=fake_print),
        ):
            bridge.main()

        r = json.loads(captured[0])
        assert r["error"]["code"] == -32700
        assert r["id"] is None

    def test_notification_without_id_produces_no_response(self):
        """Messages without an 'id' are notifications — must not be replied to."""
        responses = _run_main_with_inputs(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}  # no id
        )
        assert responses == []

    def test_blank_lines_in_stdin_are_ignored(self):
        stdin_data = "\n   \n" + json.dumps(
            {"jsonrpc": "2.0", "id": 13, "method": "ping"}
        ) + "\n\n"
        captured: list[str] = []

        def fake_print(s: str, **_: Any) -> None:
            captured.append(s)

        with (
            patch("sys.stdin", io.StringIO(stdin_data)),
            patch("sys.argv", ["bridge.py"]),
            patch("builtins.print", side_effect=fake_print),
        ):
            bridge.main()

        assert len(captured) == 1
        assert json.loads(captured[0])["result"] == {}
