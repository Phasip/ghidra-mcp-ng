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
        "/list_scripts": {
            "get": {
                "operationId": "list_scripts",
                "tags": ["Scripting"],
                "summary": "List available Ghidra scripts",
                "parameters": [],
            }
        },
        "/search_functions": {
            "get": {
                "operationId": "search_functions",
                "tags": ["Functions"],
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
                "tags": ["Annotation"],
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
        assert schema == {"type": "object", "properties": {}, "additionalProperties": False}

    def test_schema_refuses_undeclared_arguments(self):
        # the server rejects them, so the schema says so and a strict client never sends one
        op = _MINIMAL_SPEC["paths"]["/search_functions"]["get"]
        assert bridge._input_schema(_MINIMAL_SPEC, op, "get")["additionalProperties"] is False


# ---------------------------------------------------------------------------
# _openapi_to_mcp_tools
# ---------------------------------------------------------------------------

_META = {"list_tools", "describe_tool", "call_tool"}


class TestOpenApiToMcpTools:
    def test_lists_hot_core_operations(self):
        tools = bridge._openapi_to_mcp_tools(_MINIMAL_SPEC)
        names = [t["name"] for t in tools]
        assert "search_functions" in names
        assert "rename_function" in names

    def test_omits_operations_outside_the_hot_core(self):
        tools = bridge._openapi_to_mcp_tools(_MINIMAL_SPEC)
        assert "list_scripts" not in [t["name"] for t in tools]

    def test_always_offers_the_discovery_tools(self):
        tools = bridge._openapi_to_mcp_tools(_MINIMAL_SPEC)
        assert _META.issubset({t["name"] for t in tools})

    def test_discovery_tools_come_last(self):
        names = [t["name"] for t in bridge._openapi_to_mcp_tools(_MINIMAL_SPEC)]
        assert names[-3:] == ["list_tools", "describe_tool", "call_tool"]

    def test_hot_core_is_sorted_by_name(self):
        names = [t["name"] for t in bridge._openapi_to_mcp_tools(_MINIMAL_SPEC)
                 if t["name"] not in _META]
        assert names == sorted(names)

    def test_tool_has_required_mcp_fields(self):
        tools = bridge._openapi_to_mcp_tools(_MINIMAL_SPEC)
        tool = next(t for t in tools if t["name"] == "search_functions")
        assert tool["description"] == "Search functions by name"
        assert tool["inputSchema"]["type"] == "object"

    def test_list_tools_advertises_the_categories(self):
        tools = bridge._openapi_to_mcp_tools(_MINIMAL_SPEC)
        desc = next(t for t in tools if t["name"] == "list_tools")["description"]
        assert "Annotation" in desc and "Functions" in desc and "Scripting" in desc

    def test_operation_without_operationId_is_skipped(self):
        spec = {
            "paths": {
                "/no-id": {"get": {"summary": "No id here"}},
                "/with-id": {"get": {"operationId": "has_id", "summary": "Has id"}},
            }
        }
        assert "has_id" in bridge._index(spec)
        assert len(bridge._index(spec)) == 1

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
        assert list(bridge._index(spec)) == ["get_res"]

    def test_empty_spec_still_offers_discovery_tools(self):
        for spec in ({}, {"paths": {}}):
            assert {t["name"] for t in bridge._openapi_to_mcp_tools(spec)} == _META


# ---------------------------------------------------------------------------
# Discovery tools
# ---------------------------------------------------------------------------

class TestDiscoveryTools:
    def _call(self, name, arguments):
        return bridge._dispatch(_MINIMAL_SPEC, "http://host", name, arguments)

    def test_list_tools_groups_every_operation_by_category(self):
        result = self._call("list_tools", {})
        assert result["categories"] == {
            "Annotation": ["rename_function"],
            "Functions": ["search_functions"],
            "Scripting": ["list_scripts"],
        }

    def test_list_tools_by_category_carries_summaries(self):
        result = self._call("list_tools", {"category": "Scripting"})
        assert result["tools"] == [
            {"name": "list_scripts", "summary": "List available Ghidra scripts"}
        ]

    def test_untagged_operation_falls_back_to_other(self):
        spec = {"paths": {"/x": {"get": {"operationId": "x_tool", "summary": "X"}}}}
        result = bridge._dispatch(spec, "http://host", "list_tools", {})
        assert result["categories"] == {bridge.UNCATEGORIZED: ["x_tool"]}

    def test_unknown_category_is_rejected_with_the_valid_ones(self):
        with pytest.raises(ValueError, match="Unknown category"):
            self._call("list_tools", {"category": "Nonsense"})

    def test_describe_tool_returns_the_full_schema(self):
        result = self._call("describe_tool", {"tool_name": "search_functions"})
        assert result["category"] == "Functions"
        assert result["description"] == "Search functions by name"
        assert "program" in result["inputSchema"]["properties"]
        assert result["inputSchema"]["required"] == ["program"]

    def test_describe_tool_reaches_operations_outside_the_hot_core(self):
        assert self._call("describe_tool", {"tool_name": "list_scripts"})["name"] \
            == "list_scripts"

    def test_describe_tool_requires_a_tool_name(self):
        with pytest.raises(ValueError, match="Required parameter 'tool_name' is missing"):
            self._call("describe_tool", {})

    def test_describe_tool_shows_the_shape_it_wanted(self):
        # A guessed key is the whole failure here, so the fix has to be in the message.
        with pytest.raises(ValueError) as e:
            self._call("describe_tool", {})
        assert '{"tool_name": "get_struct_layout"}' in str(e.value)
        assert "you passed nothing" in str(e.value)

    def test_describe_tool_rejects_a_guessed_key_by_listing_the_real_ones(self):
        # The reported failure: 'tool_name' guessed as 'name'. Same wording as the server's own
        # unknown-field filter, so one rule covers the whole surface — and the field vocabulary
        # is small enough to state, so it is stated rather than guessed at.
        with pytest.raises(ValueError) as e:
            self._call("describe_tool", {"name": "get_struct_layout"})
        assert "Unknown field 'name' for tool 'describe_tool'" in str(e.value)
        assert "Valid fields: tool_name." in str(e.value)
        assert "Did you mean" not in str(e.value)

    def test_describe_tool_suggests_the_nearest_name(self):
        with pytest.raises(ValueError, match="Did you mean 'search_functions'"):
            self._call("describe_tool", {"tool_name": "search_function"})

    def test_call_tool_runs_an_operation_outside_the_hot_core(self):
        with patch.object(bridge, "_get", return_value={"status": "ok"}) as mock_get:
            result = self._call("call_tool", {"tool_name": "list_scripts"})
        mock_get.assert_called_once_with("http://host/list_scripts")
        assert result == {"status": "ok"}

    def test_call_tool_forwards_arguments(self):
        with patch.object(bridge, "_post", return_value={"new_name": "g"}) as mock_post:
            self._call("call_tool", {
                "tool_name": "rename_function",
                "arguments": {"program": "p", "name_or_address": "f", "new_name": "g"},
            })
        assert mock_post.call_args[0][1]["new_name"] == "g"

    def test_call_tool_requires_a_tool_name(self):
        with pytest.raises(ValueError, match="Required parameter 'tool_name' is missing"):
            self._call("call_tool", {})

    def test_call_tool_shows_the_shape_it_wanted(self):
        with pytest.raises(ValueError) as e:
            self._call("call_tool", {})
        assert '"tool_name": "get_struct_layout"' in str(e.value)
        assert '"arguments"' in str(e.value)

    def test_call_tool_rejects_flattened_arguments(self):
        # Flattening the target tool's arguments is the other way this call goes wrong; running
        # the tool with no arguments at all would report a missing 'program' and hide the cause.
        with pytest.raises(ValueError) as e:
            self._call("call_tool", {"tool_name": "list_scripts", "program": "p"})
        assert "Unknown field 'program' for tool 'call_tool'" in str(e.value)
        assert "under 'arguments'" in str(e.value)

    def test_list_tools_rejects_an_undeclared_argument(self):
        with pytest.raises(ValueError, match="Unknown field 'name' for tool 'list_tools'"):
            self._call("list_tools", {"name": "Functions"})

    def test_call_tool_refuses_to_nest_a_discovery_tool(self):
        with pytest.raises(ValueError, match="it is a discovery tool"):
            self._call("call_tool", {"tool_name": "list_tools"})


# ---------------------------------------------------------------------------
# _dispatch
# ---------------------------------------------------------------------------

class TestDispatch:
    def test_get_operation_called_without_args(self):
        with patch.object(bridge, "_get", return_value={"status": "ok"}) as mock_get:
            result = bridge._dispatch(_MINIMAL_SPEC, "http://host", "list_scripts", {})
        mock_get.assert_called_once_with("http://host/list_scripts")
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
        with patch.object(bridge, "_post", return_value={"new_name": "g"}) as mock_post:
            result = bridge._dispatch(
                _MINIMAL_SPEC, "http://host", "rename_function",
                {"program": "p", "name_or_address": "f", "new_name": "g"},
            )
        mock_post.assert_called_once_with(
            "http://host/rename_function",
            {"program": "p", "name_or_address": "f", "new_name": "g"},
        )
        assert result == {"new_name": "g"}

    def test_unknown_tool_raises_value_error(self):
        with pytest.raises(ValueError, match="Unknown tool"):
            bridge._dispatch(_MINIMAL_SPEC, "http://host", "nonexistent_tool", {})

    def test_unknown_tool_suggests_the_nearest_name(self):
        with pytest.raises(ValueError, match="Did you mean 'rename_function'"):
            bridge._dispatch(_MINIMAL_SPEC, "http://host", "rename_funtcion", {})

    def test_list_valued_arg_becomes_repeated_query_params(self):
        spec = {
            "paths": {
                "/get_xrefs_to": {
                    "get": {
                        "operationId": "get_xrefs_to",
                        "tags": ["Cross-references"],
                        "summary": "Xrefs to",
                        "parameters": [],
                    }
                }
            }
        }
        with patch.object(bridge, "_get", return_value=[]) as mock_get:
            bridge._dispatch(spec, "http://host", "get_xrefs_to",
                             {"ref_types": ["CALL", "READ"]})
        assert "ref_types=CALL&ref_types=READ" in mock_get.call_args[0][0]


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


def _get_failing_on_tool_call(error: BaseException) -> Any:
    """A _get that serves /health and /openapi.json, then fails the tool call itself.

    A plain side_effect list would spend its failure on the schema fetch instead, which is a
    different code path with a different error message.
    """
    def _get(url: str, timeout: int = 0) -> Any:
        if url.endswith("/health"):
            return {"started_at": "2026-08-30T07:00:00Z"}
        if url.endswith("/openapi.json"):
            return _MINIMAL_SPEC
        raise error
    return MagicMock(side_effect=_get)

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

    def test_initialize_echoes_a_version_the_bridge_speaks(self):
        for version in bridge.SUPPORTED_PROTOCOL_VERSIONS:
            responses = _run_main_with_inputs(
                {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                 "params": {"protocolVersion": version}}
            )
            assert responses[0]["result"]["protocolVersion"] == version

    def test_initialize_answers_an_unknown_version_with_the_newest_one(self):
        responses = _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2099-01-01"}}
        )
        assert responses[0]["result"]["protocolVersion"] == bridge.PROTOCOL_VERSION

    def test_initialize_carries_the_orientation_a_host_needs(self):
        responses = _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        )
        instructions = responses[0]["result"]["instructions"]
        assert "list_project_files" in instructions
        assert "name_or_address" in instructions


class TestSpecCache:
    """The cached schema must follow the server process it was generated from."""

    def _urls(self, spec_by_call):
        """A _get stub answering /health and /openapi.json from a scripted sequence."""
        calls: list[str] = []

        def fake_get(url: str):
            calls.append(url)
            if url.endswith("/health"):
                return {"status": "ok", "started_at": spec_by_call.pop(0)}
            return _MINIMAL_SPEC

        return fake_get, calls

    def test_spec_is_fetched_once_while_the_server_stays_up(self):
        fake_get, calls = self._urls(["2026-08-30T07:00:00Z"] * 4)
        _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            get_mock=MagicMock(side_effect=fake_get),
        )
        assert [c for c in calls if c.endswith("/openapi.json")] == \
            ["http://testhost/openapi.json"]

    def test_a_restarted_server_gets_its_schema_refetched(self):
        # The schema is generated from the running code, so a rebuild-and-restart under a
        # long-lived bridge is exactly when a cached copy starts describing tools that no
        # longer exist — or fields the live server now rejects.
        fake_get, calls = self._urls(["2026-08-30T07:00:00Z", "2026-08-30T09:30:00Z"])
        _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            get_mock=MagicMock(side_effect=fake_get),
        )
        assert len([c for c in calls if c.endswith("/openapi.json")]) == 2

    def test_an_unreachable_health_endpoint_keeps_the_cached_schema(self):
        def fake_get(url: str):
            if url.endswith("/health"):
                raise urllib.error.URLError("Connection refused")
            return _MINIMAL_SPEC

        responses = _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            get_mock=MagicMock(side_effect=fake_get),
        )
        assert responses[0]["result"]["tools"]


class TestMainLoopToolsList:
    def test_tools_list_returns_hot_core_and_discovery_tools(self):
        responses = _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        )
        tools = responses[0]["result"]["tools"]
        names = [t["name"] for t in tools]
        assert "rename_function" in names
        assert _META.issubset(set(names))
        # list_scripts is reachable only through the discovery tools
        assert "list_scripts" not in names

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
        # The server is asked for its identity and its spec before the call itself goes out.
        get_mock = MagicMock(side_effect=lambda url: (
            {"started_at": "2026-08-30T07:00:00Z"} if url.endswith("/health")
            else _MINIMAL_SPEC if url.endswith("/openapi.json")
            else {"status": "ok"}
        ))
        responses = _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "list_scripts", "arguments": {}}},
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

    def test_tools_call_http_error_surfaces_the_servers_own_message(self):
        # The server already diagnosed this; the bridge must not bury it under a status line
        # and a guess about what might be wrong.
        body = json.dumps({
            "ok": False,
            "error": "Unknown query parameter 'address_or_name' for endpoint "
                     "'POST /tool/rename_function'. Valid fields: program, name_or_address, new_name.",
        }).encode()
        http_err = urllib.error.HTTPError(
            url="http://testhost/rename_function",
            code=400,
            msg="Bad Request",
            hdrs=MagicMock(),
            fp=io.BytesIO(body),
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
        assert text.startswith("Unknown query parameter 'address_or_name'")
        assert "400" not in text
        assert '"ok"' not in text

    def test_tools_call_http_error_without_a_json_body_keeps_the_status(self):
        http_err = urllib.error.HTTPError(
            url="http://testhost/list_scripts",
            code=502,
            msg="Bad Gateway",
            hdrs=MagicMock(),
            fp=io.BytesIO(b"<html>proxy exploded</html>"),
        )
        responses = _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 8, "method": "tools/call",
             "params": {"name": "list_scripts", "arguments": {}}},
            get_mock=_get_failing_on_tool_call(http_err),
        )
        r = responses[0]
        assert r["result"]["isError"] is True
        assert "502" in r["result"]["content"][0]["text"]

    def test_tools_call_connection_error_returns_is_error(self):
        responses = _run_main_with_inputs(
            {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
             "params": {"name": "list_scripts", "arguments": {}}},
            get_mock=_get_failing_on_tool_call(urllib.error.URLError("Connection refused")),
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


# ---------------------------------------------------------------------------
# Nested request schemas
# ---------------------------------------------------------------------------

class TestNestedSchema:
    _SPEC = {
        "paths": {
            "/set_function_prototype": {
                "post": {
                    "operationId": "set_function_prototype",
                    "tags": ["Annotation"],
                    "summary": "Set a prototype",
                    "requestBody": {"content": {"application/json": {
                        "schema": {"$ref": "#/components/schemas/PrototypeRequest"}}}},
                }
            }
        },
        "components": {"schemas": {
            "PrototypeRequest": {
                "type": "object",
                "properties": {
                    "parameters": {
                        "type": "array",
                        "description": "Ordered parameter list.",
                        "items": {"$ref": "#/components/schemas/PrototypeParameter"},
                    },
                },
            },
            "PrototypeParameter": {
                "type": "object",
                "description": "Ordered parameter list.",
                "properties": {
                    "name": {"type": "string", "description": "Parameter name"},
                    "type_name": {"type": "string", "description": "Data type"},
                },
                "required": ["name", "type_name"],
            },
        }},
    }

    def _parameters(self) -> dict:
        op = self._SPEC["paths"]["/set_function_prototype"]["post"]
        return bridge._input_schema(self._SPEC, op, "post")["properties"]["parameters"]

    def test_an_items_record_keeps_its_fields(self):
        items = self._parameters()["items"]
        assert set(items["properties"]) == {"name", "type_name"}
        assert items["properties"]["name"]["description"] == "Parameter name"

    def test_an_items_record_keeps_its_required_fields(self):
        assert self._parameters()["items"]["required"] == ["name", "type_name"]

    def test_the_item_does_not_repeat_the_arrays_description(self):
        # swagger folds the field's @Schema(description) into the component it references
        assert "description" not in self._parameters()["items"]

    def test_an_untyped_object_stays_untyped(self):
        # batch_tool_call's 'calls' really is free-form; nothing to recurse into
        entry = bridge._prop_schema({}, {"type": "array", "items": {"type": "object"}})
        assert entry["items"] == {"type": "object"}


# ---------------------------------------------------------------------------
# Result rendering
# ---------------------------------------------------------------------------

class TestRenderResult:
    def test_the_ok_envelope_is_dropped(self):
        assert bridge._render_result({"ok": True, "result": {"count": 2}}) == '{"count":2}'

    def test_json_is_compact(self):
        rendered = bridge._render_result({"ok": True, "result": {"a": 1, "b": [1, 2]}})
        assert rendered == '{"a":1,"b":[1,2]}'

    def test_multi_line_text_is_printed_as_text(self):
        rendered = bridge._render_result({"ok": True, "result": {
            "name": "main", "decompiled": "int main(void)\n{\n  return 0;\n}\n"}})
        assert rendered == '{"name":"main"}\n\ndecompiled:\nint main(void)\n{\n  return 0;\n}'
        assert "\\n" not in rendered

    def test_a_single_line_string_stays_in_the_json(self):
        rendered = bridge._render_result({"ok": True, "result": {"output": "done"}})
        assert rendered == '{"output":"done"}'

    def test_an_unenveloped_payload_is_left_alone(self):
        assert bridge._render_result([1, 2]) == "[1,2]"

    def test_a_failed_batch_item_keeps_its_own_ok_flag(self):
        rendered = bridge._render_result(
            {"ok": True, "result": {"results": [{"ok": False, "error": "nope"}]}})
        assert rendered == '{"results":[{"ok":false,"error":"nope"}]}'


# ---------------------------------------------------------------------------
# Error text
# ---------------------------------------------------------------------------

class TestErrorText:
    def test_the_servers_message_is_used_verbatim(self):
        body = json.dumps({"ok": False, "error": "Unknown data type 'uint32'. Did you mean 'uint'?"})
        assert bridge._error_text(400, body, "Bad Request") == \
            "Unknown data type 'uint32'. Did you mean 'uint'?"

    def test_a_non_json_body_falls_back_to_the_status(self):
        assert bridge._error_text(502, "<html>", "Bad Gateway") == "HTTP 502: <html>"

    def test_an_empty_body_falls_back_to_the_reason(self):
        assert bridge._error_text(503, "", "Service Unavailable") == "HTTP 503: Service Unavailable"
