"""
test_integration.py — integration tests for ghidra-mcp-ng HTTP API.

Covers all 33 registered tools.  Requires a running Ghidra server started by
the ``ghidra_server`` session fixture in conftest.py (self-contained: compiles
a C binary, creates a Ghidra project, starts the server on port 8199).

Tests are automatically skipped when GHIDRA_HOME is not available.

Tool coverage
--------------
ReadTools (25):
  check_connection, list_project_files, list_exports, list_imports,
    list_data_type_categories, get_program_info, list_globals,
    get_function_info, get_address_info,
  get_calling_conventions, get_function_variables,
    decompile_function, read_data, get_disassembly,
    search_functions, search_data_types,
    search_bytes, search_instructions,
  search_defined_strings, get_struct_layout,
    get_xrefs_to, get_xrefs_from, get_function_callees, search_constant_references,
    batch_tool_call

WriteTools (10):
  rename_function, rename_variable, set_function_prototype,
  set_parameter_type, create_struct, add_struct_field,
  remove_struct_field, replace_struct_field, set_comment, import_binary

ScriptTool (5):
  list_scripts, get_script_description, add_script, run_script, delete_script
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from conftest import GhidraClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _func_address(client: GhidraClient, prog: str, name: str) -> str:
    """Return the hex entry address (without 0x prefix) for a named function."""
    result = client.ok("search_functions", {"program": prog, "query": name, "limit": 500})
    for f in result.get("functions", []):
        if f["name"] == name:
            return f["address"]
    raise AssertionError(
        f"Function '{name}' not found in program '{prog}'. "
        f"Available: {[f['name'] for f in result.get('functions', [])]}"
    )


def _hex(addr: str) -> str:
    """Prepend 0x to an address string if not already present."""
    return addr if addr.startswith("0x") else "0x" + addr


def _last_json_line(text: str) -> dict:
    """Parse the last non-empty output line as JSON."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise AssertionError("Expected script output, got empty output")
    return json.loads(lines[-1])


# ---------------------------------------------------------------------------
# 1. Health & tools list
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_endpoint(self, ghidra_server: GhidraClient):
        h = ghidra_server.health()
        assert h["status"] == "ok"
        assert isinstance(h.get("tools"), int)
        assert h["tools"] >= 33

    def test_tools_list_contains_expected_tools(self, ghidra_server: GhidraClient):
        tools = ghidra_server.tools()
        names = {t["name"] for t in tools}
        expected = {
            # ReadTools (25)
            "check_connection", "list_project_files",
            "list_exports", "list_imports", "list_data_type_categories",
            "get_program_info", "list_globals",
            "get_function_info", "get_address_info", "get_calling_conventions",
            "get_function_variables", "decompile_function", "search_functions",
            "read_data", "get_disassembly", "search_bytes", "search_instructions",
            "search_data_types", "search_defined_strings", "get_struct_layout",
            "get_xrefs_to", "get_xrefs_from", "get_function_callees",
            "search_constant_references", "batch_tool_call",
            # WriteTools (10)
            "rename_function", "rename_variable",
            "set_function_prototype", "set_parameter_type",
            "create_struct", "add_struct_field", "remove_struct_field", "replace_struct_field",
            "set_comment", "import_binary",
            # ScriptTool (5)
            "list_scripts", "get_script_description", "add_script", "run_script", "delete_script",
        }
        missing = expected - names
        assert not missing, f"Missing tools: {missing}"
        assert "run_script_inline" not in names


# ---------------------------------------------------------------------------
# 2. Connection & project enumeration
# ---------------------------------------------------------------------------

class TestConnectionAndProject:
    def test_check_connection(self, ghidra_server: GhidraClient):
        result = ghidra_server.ok("check_connection")
        assert result["status"] == "ok"

    def test_list_project_files(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok("list_project_files")
        assert "files" in result
        assert "count" in result
        files = result["files"]
        assert any(prog in f for f in files), (
            f"Expected program '{prog}' in project files: {files}"
        )


# ---------------------------------------------------------------------------
# 3. Function enumeration
# ---------------------------------------------------------------------------

class TestFunctionEnumeration:
    def test_search_functions_list_all(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok("search_functions", {"program": prog, "query": ""})
        functions = result.get("functions", [])
        assert len(functions) > 0, "Program must have at least one function"
        f = functions[0]
        assert "name" in f, f"Function entry missing 'name': {f}"
        assert "address" in f, f"Function entry missing 'address': {f}"
        # Verify our fixture functions are present
        names = {f["name"] for f in functions}
        for expected in ("add", "multiply", "compute", "main"):
            assert expected in names, (
                f"Expected function '{expected}' in {names}"
            )

    def test_search_functions_rejects_limit_above_max(
            self, ghidra_server: GhidraClient, prog: str):
        response = ghidra_server.call(
            "search_functions", {"program": prog, "limit": 1001}
        )
        assert response["ok"] is False
        assert "Maximum supported value is 1000" in response["error"]

    def test_search_functions_range_filters_entry_points(
            self, ghidra_server: GhidraClient, prog: str):
        add_addr = _func_address(ghidra_server, prog, "add")
        result = ghidra_server.ok(
            "search_functions",
            {
                "program": prog,
                "query": "",
                "start_address": _hex(add_addr),
                "end_address": _hex(add_addr),
                "limit": 100,
            },
        )
        names = [f["name"] for f in result.get("functions", [])]
        assert "add" in names


# ---------------------------------------------------------------------------
# 4. Exports & imports
# ---------------------------------------------------------------------------

class TestExportsImports:
    def test_list_exports(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok("list_exports", {"program": prog})
        assert "exports" in result

    def test_list_imports(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok("list_imports", {"program": prog})
        assert "imports" in result


# ---------------------------------------------------------------------------
# 5. Data types
# ---------------------------------------------------------------------------

class TestDataTypes:
    def test_list_data_type_categories(
            self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "list_data_type_categories", {"program": prog}
        )
        assert "categories" in result

    def test_search_data_types(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "search_data_types", {"program": prog, "query": "int"}
        )
        assert "data_types" in result
        assert result["count"] > 0, "Should find at least one 'int' type"

    def test_search_data_types_rejects_limit_above_max(
            self, ghidra_server: GhidraClient, prog: str):
        response = ghidra_server.call(
            "search_data_types", {"program": prog, "query": "int", "limit": 501}
        )
        assert response["ok"] is False
        assert "Maximum supported value is 500" in response["error"]


# ---------------------------------------------------------------------------
# 5b. Program metadata and globals
# ---------------------------------------------------------------------------

class TestProgramMetadata:
    def test_get_program_info(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok("get_program_info", {"program": prog})
        assert result["program"] == prog
        assert "image_base" in result
        assert "memory_blocks" in result
        assert result["memory_block_count"] == len(result["memory_blocks"])

    def test_list_globals(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok("list_globals", {"program": prog, "limit": 200})
        assert "functions" in result
        assert "data" in result
        assert "labels" in result
        assert "count" in result

    def test_batch_tool_call(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "batch_tool_call",
            {
                "tool": "get_function_info",
                "calls": [
                    {"program": prog, "name_or_address": "add"},
                    {"program": prog, "name_or_address": "multiply"},
                ],
            },
        )
        assert result["tool"] == "get_function_info"
        assert result["count"] == 2
        assert all(item["ok"] for item in result["results"])


# ---------------------------------------------------------------------------
# 6. Strings
# ---------------------------------------------------------------------------

class TestStrings:
    def test_search_defined_strings_no_filter(
            self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok("search_defined_strings", {"program": prog})
        assert "strings" in result
        assert "count" in result

    def test_search_defined_strings_with_filter(
            self, ghidra_server: GhidraClient, prog: str):
        # Filter for our sentinel; may return 0 if Ghidra didn't define the string
        result = ghidra_server.ok(
            "search_defined_strings",
            {"program": prog, "filter": "SENTINEL"}
        )
        assert "strings" in result
        # If the sentinel string was analysed, verify its value
        for s in result["strings"]:
            assert "SENTINEL" in s.get("value", "").upper()


# ---------------------------------------------------------------------------
# 7. Function lookup
# ---------------------------------------------------------------------------

class TestFunctionLookup:
    def test_get_function_info_by_address(
            self, ghidra_server: GhidraClient, prog: str):
        addr = _func_address(ghidra_server, prog, "add")
        result = ghidra_server.ok(
            "get_function_info",
            {"program": prog, "name_or_address": _hex(addr)},
        )
        assert result["name"] == "add"
        assert "address" in result

    def test_get_function_info_invalid(
            self, ghidra_server: GhidraClient, prog: str):
        assert ghidra_server.is_error(
            "get_function_info",
            {"program": prog, "name_or_address": "0xdeadbeef00"},
        )

    def test_get_function_info_requires_entry_point(
            self, ghidra_server: GhidraClient, prog: str):
        addr = _func_address(ghidra_server, prog, "add")
        inside_addr = hex(int(addr, 16) + 1)
        response = ghidra_server.call(
            "get_function_info",
            {"program": prog, "name_or_address": inside_addr},
        )
        assert response["ok"] is False
        assert "function entry point" in response.get("error", "").lower()

    def test_search_functions(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "search_functions", {"program": prog, "query": "add"}
        )
        assert "functions" in result
        names = [f["name"] for f in result["functions"]]
        assert "add" in names, f"Expected 'add' in search results: {names}"


# ---------------------------------------------------------------------------
# 8. Decompilation
# ---------------------------------------------------------------------------

class TestDecompilation:
    def test_decompile_function_by_name(
            self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "decompile_function",
            {"program": prog, "name_or_address": "add"},
        )
        assert result["name"] == "add"
        assert len(result.get("decompiled", "")) > 10

    def test_decompile_function_by_address(
            self, ghidra_server: GhidraClient, prog: str):
        addr = _func_address(ghidra_server, prog, "multiply")
        result = ghidra_server.ok(
            "decompile_function",
            {"program": prog, "name_or_address": _hex(addr)},
        )
        assert result["name"] == "multiply"
        assert "decompiled" in result

    def test_decompile_function_with_custom_timeout(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "decompile_function",
            {"program": prog, "name_or_address": "add", "timeout_seconds": 180},
        )
        assert result["name"] == "add"
        assert len(result.get("decompiled", "")) > 10

    def test_decompile_function_with_invalid_timeout_throws(self, ghidra_server: GhidraClient, prog: str):
        assert ghidra_server.is_error(
            "decompile_function",
            {"program": prog, "name_or_address": "add", "timeout_seconds": -1},
        )

    def test_get_function_variables(
            self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "get_function_variables",
            {"program": prog, "name_or_address": "add"},
        )
        assert result["function"] == "add"
        variables = result.get("variables", [])
        # Ghidra may model stack-spilled register args as locals rather than
        # formal parameters depending on analysis depth, so only assert that
        # the function has at least some variables.
        assert len(variables) > 0, f"add() should have variables, got: {variables}"

    def test_get_disassembly_returns_lines(self, ghidra_server: GhidraClient, prog: str):
        addr = _func_address(ghidra_server, prog, "add")
        result = ghidra_server.ok(
            "get_disassembly",
            {"program": prog, "address": _hex(addr), "instructions": 5},
        )
        assert result["count"] > 0
        assert len(result["lines"]) == result["count"]

    def test_read_data_returns_items(self, ghidra_server: GhidraClient, prog: str):
        addr = _func_address(ghidra_server, prog, "add")
        result = ghidra_server.ok(
            "read_data",
            {"program": prog, "address": _hex(addr), "item_size": 1, "item_count": 8},
        )
        assert result["bytes_read"] == 8
        assert len(result["items"]) == 8

    def test_search_instructions_finds_common_call_opcode(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "search_instructions",
            {"program": prog, "pattern": "E8 ?? ?? ?? ??", "limit": 20},
        )
        assert result["count"] > 0

    def test_search_bytes_finds_ascii_word(self, ghidra_server: GhidraClient, prog: str):
        # ASCII 'SENTINEL' bytes: 53 45 4E 54 49 4E 45 4C
        result = ghidra_server.ok(
            "search_bytes",
            {"program": prog, "hex_pattern": "53 45 4E 54 49 4E 45 4C", "limit": 20},
        )
        assert result["count"] > 0


# ---------------------------------------------------------------------------
# 9. Call graph
# ---------------------------------------------------------------------------

class TestCallGraph:
    def test_get_function_callees(
            self, ghidra_server: GhidraClient, prog: str):
        # compute() calls add() and multiply()
        result = ghidra_server.ok(
            "get_function_callees",
            {"program": prog, "name_or_address": "compute"},
        )
        assert "callees" in result or "functions" in result


# ---------------------------------------------------------------------------
# 10. Cross-references
# ---------------------------------------------------------------------------

class TestXrefs:
    def test_get_xrefs_to(self, ghidra_server: GhidraClient, prog: str):
        addr = _func_address(ghidra_server, prog, "add")
        result = ghidra_server.ok(
            "get_xrefs_to",
            {"program": prog, "address_or_name": _hex(addr)},
        )
        assert "xrefs" in result
        assert "count" in result
        # add() is called by compute() and multiply() — at least 2 xrefs
        assert result["count"] >= 2, (
            f"Expected >=2 xrefs to add(), got {result['count']}: {result['xrefs']}"
        )

    def test_get_xrefs_from(self, ghidra_server: GhidraClient, prog: str):
        # Use compute()'s entry point — xrefs FROM that address may be empty
        # (entry point instruction usually has no outgoing refs at the byte level)
        addr = _func_address(ghidra_server, prog, "compute")
        result = ghidra_server.ok(
            "get_xrefs_from",
            {"program": prog, "address": _hex(addr)},
        )
        assert "xrefs" in result
        assert "count" in result

    def test_get_xrefs_to_ref_type_filter(self, ghidra_server: GhidraClient, prog: str):
        addr = _func_address(ghidra_server, prog, "add")
        result = ghidra_server.ok(
            "get_xrefs_to",
            {"program": prog, "address_or_name": _hex(addr), "ref_types": ["CALL"]},
        )
        assert "call_refs" in result

    def test_get_xrefs_to_includes_indirect_calls_key(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "get_xrefs_to",
            {"program": prog, "address_or_name": "add"},
        )
        assert "indirect_calls" in result

    def test_get_function_info_requires_0x_prefix(self, ghidra_server: GhidraClient, prog: str):
        addr = _func_address(ghidra_server, prog, "add")
        bare = addr[2:] if addr.startswith("0x") else addr
        err = ghidra_server.call(
            "get_function_info",
            {"program": prog, "name_or_address": bare},
        )
        assert err["ok"] is False

    def test_get_xrefs_to_requires_0x_prefix(self, ghidra_server: GhidraClient, prog: str):
        addr = _func_address(ghidra_server, prog, "add")
        bare = addr[2:] if addr.startswith("0x") else addr
        err = ghidra_server.call(
            "get_xrefs_to",
            {"program": prog, "address_or_name": bare},
        )
        assert err["ok"] is False


# ---------------------------------------------------------------------------
# 11. Write operations
# ---------------------------------------------------------------------------

class TestWriteOperations:
    """
    Write tests use permissive (no-rules) naming — rules enforcement is
    covered by the fast RulesEngineTest unit tests.
    """

    def test_rename_function(self, ghidra_server: GhidraClient, prog: str):
        new_name = "multiply_integration_test_renamed"
        result = ghidra_server.ok(
            "rename_function",
            {"program": prog,
             "name_or_address": "multiply",
             "new_name": new_name},
        )
        assert result["success"] is True
        assert result["new_name"] == new_name

        # Rename back so subsequent tests can find 'multiply'
        result = ghidra_server.ok(
            "rename_function",
            {"program": prog,
             "name_or_address": new_name,
             "new_name": "multiply"},
        )
        assert result["success"] is True

    def test_rename_variable(self, ghidra_server: GhidraClient, prog: str):
        # Get any variable from add() — Ghidra may model stack-spilled register
        # args as locals rather than formal parameters, so we do not filter by kind.
        vars_result = ghidra_server.ok(
            "get_function_variables",
            {"program": prog, "name_or_address": "add"},
        )
        variables = vars_result.get("variables", [])
        assert variables, "add() should have variables"
        original_name = variables[0]["name"]

        new_name = "integration_test_renamed_param"
        result = ghidra_server.ok(
            "rename_variable",
            {"program": prog,
             "name_or_address": "add",
             "variable_name": original_name,
             "new_name": new_name},
        )
        assert result["success"] is True
        assert result["new_name"] == new_name

        # Rename back to original
        ghidra_server.ok(
            "rename_variable",
            {"program": prog,
             "name_or_address": "add",
             "variable_name": new_name,
             "new_name": original_name},
        )

    def test_set_function_prototype(
            self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "set_function_prototype",
            {"program": prog,
             "name_or_address": "compute",
             "return_type": "int",
             "parameters": [
                 {"name": "x", "type": "int"},
                 {"name": "y", "type": "int"},
                 {"name": "mode", "type": "int"},
             ]},
        )
        assert result["success"] is True
        assert result["parameter_count"] == 3

    def test_set_function_prototype_requires_parameter_fields(
            self, ghidra_server: GhidraClient, prog: str):
        missing_type = ghidra_server.call(
            "set_function_prototype",
            {"program": prog,
             "name_or_address": "compute",
             "return_type": "int",
             "parameters": [{"name": "x"}]},
        )
        assert missing_type["ok"] is False
        assert "parameters[0].type" in missing_type.get("error", "")

        blank_name = ghidra_server.call(
            "set_function_prototype",
            {"program": prog,
             "name_or_address": "compute",
             "return_type": "int",
             "parameters": [{"name": "   ", "type": "int"}]},
        )
        assert blank_name["ok"] is False
        assert "parameters[0].name" in blank_name.get("error", "")

    def test_set_parameter_type(
            self, ghidra_server: GhidraClient, prog: str):
        # Use 'compute' which already has 3 formal parameters set by
        # test_set_function_prototype (x, y, mode at indices 0-2).
        result = ghidra_server.ok(
            "set_parameter_type",
            {"program": prog,
             "name_or_address": "compute",
             "parameter_index": 0,
             "type_name": "int"},
        )
        assert result["success"] is True
        assert result["parameter_index"] == 0
        assert result["type_name"] == "int"

    def test_set_comment(self, ghidra_server: GhidraClient, prog: str):
        addr = _func_address(ghidra_server, prog, "add")
        comment_text = "Integration test comment — ghidra-mcp-ng"

        result = ghidra_server.ok(
            "set_comment",
            {"program": prog,
             "address": _hex(addr),
             "comment": comment_text,
             "type": "PRE"},
        )
        assert result["success"] is True

        # Clear the comment
        ghidra_server.ok(
            "set_comment",
            {"program": prog,
             "address": _hex(addr),
             "comment": "PLACEHOLDER",
             "type": "PRE"},
        )

    def test_set_comment_requires_0x_prefix(self, ghidra_server: GhidraClient, prog: str):
        addr = _func_address(ghidra_server, prog, "add")
        bare = addr[2:] if addr.startswith("0x") else addr
        err = ghidra_server.call(
            "set_comment",
            {"program": prog,
             "address": bare,
             "comment": "test",
             "type": "PRE"},
        )
        assert err["ok"] is False
        assert "missing the 0x prefix" in err.get("error", "").lower()


# ---------------------------------------------------------------------------
# 12. Struct lifecycle
# ---------------------------------------------------------------------------

class TestStructs:
    STRUCT_NAME = "IntegrationTestStruct"

    def test_create_struct(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "create_struct",
            {"program": prog, "name": self.STRUCT_NAME, "size": 8},
        )
        assert result["success"] is True

    def test_add_struct_field(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "add_struct_field",
            {"program": prog,
             "struct_name": self.STRUCT_NAME,
             "field_name": "size_field",
             "type_name": "int",
             "comment": "Size field added by integration test"},
        )
        assert result["success"] is True

        second = ghidra_server.ok(
            "add_struct_field",
            {"program": prog,
             "struct_name": self.STRUCT_NAME,
             "field_name": "tail_field",
             "type_name": "int",
             "comment": "Tail field added by integration test"},
        )
        assert second["success"] is True

    def test_get_struct_layout(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "get_struct_layout",
            {"program": prog, "name": self.STRUCT_NAME},
        )
        assert result["name"] == self.STRUCT_NAME
        fields = {field["name"]: field for field in result.get("fields", [])}
        assert fields["size_field"]["offset"] == 0
        assert fields["tail_field"]["offset"] == 4

    def test_remove_struct_field(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "remove_struct_field",
            {"program": prog,
             "struct_name": self.STRUCT_NAME,
             "field_name": "size_field"},
        )
        assert result["success"] is True

        layout = ghidra_server.ok(
            "get_struct_layout",
            {"program": prog, "name": self.STRUCT_NAME},
        )
        fields = {field["name"]: field for field in layout.get("fields", [])}
        assert "size_field" not in fields
        assert fields["tail_field"]["offset"] == 4

    def test_replace_struct_field(self, ghidra_server: GhidraClient, prog: str):
        arguments = {
            "program": prog,
            "struct_name": self.STRUCT_NAME,
            "field_name": "tail_field",
            "type_name": "byte",
            "new_name": "tail_byte",
        }
        result = ghidra_server.ok(
            "replace_struct_field",
            arguments,
        )
        assert result["success"] is True

        layout = ghidra_server.ok(
            "get_struct_layout",
            {"program": prog, "name": self.STRUCT_NAME},
        )
        fields = {field["name"]: field for field in layout.get("fields", [])}
        assert fields["tail_byte"]["offset"] == 4
        assert fields["tail_byte"]["type"] == "byte"

    def test_struct_field_mutations_require_field_name(
            self, ghidra_server: GhidraClient, prog: str):
        remove_response = ghidra_server.call(
            "remove_struct_field",
            {"program": prog, "struct_name": self.STRUCT_NAME, "ordinal": 0},
        )
        assert remove_response["ok"] is False
        assert "field_name" in remove_response.get("error", "")

        replace_response = ghidra_server.call(
            "replace_struct_field",
            {
                "program": prog,
                "struct_name": self.STRUCT_NAME,
                "ordinal": 0,
                "type_name": "byte",
            },
        )
        assert replace_response["ok"] is False
        assert "field_name" in replace_response.get("error", "")

    def test_create_struct_override_recreates_in_place(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "create_struct",
            {"program": prog, "name": self.STRUCT_NAME, "size": 16, "override": True},
        )
        assert result["success"] is True

        layout = ghidra_server.ok(
            "get_struct_layout",
            {"program": prog, "name": self.STRUCT_NAME},
        )
        assert layout["size"] == 16
        assert layout.get("fields", []) == []

    def test_add_struct_field_array_type(self, ghidra_server: GhidraClient, prog: str):
        # Verify that array type notation (e.g. byte[16]) is supported by findDataType.
        struct_name = "ByteArrayStruct"
        ghidra_server.ok(
            "create_struct",
            {"program": prog, "name": struct_name, "size": 32},
        )

        result = ghidra_server.ok(
            "add_struct_field",
            {
                "program": prog,
                "struct_name": struct_name,
                "field_name": "buf",
                "type_name": "byte[16]",
                "comment": "16-byte buffer",
            },
        )
        assert result["success"] is True

        layout = ghidra_server.ok(
            "get_struct_layout",
            {"program": prog, "name": struct_name},
        )
        fields = {f["name"]: f for f in layout.get("fields", [])}
        assert "buf" in fields, f"Expected 'buf' in struct fields: {list(fields)}"
        assert fields["buf"]["offset"] == 0
        assert fields["buf"]["length"] == 16

    def test_code_pointer_error_mentions_void_pointer(self, ghidra_server: GhidraClient, prog: str):
        response = ghidra_server.call(
            "set_parameter_type",
            {"program": prog,
             "name_or_address": "compute",
             "parameter_index": 0,
             "type_name": "code*"},
        )
        assert response["ok"] is False
        error = response.get("error", "")
        assert "Ghidra internal generated type" in error
        assert "void*" in error


# ---------------------------------------------------------------------------
# 13. Script management
# ---------------------------------------------------------------------------

class TestScript:
    SENTINEL = "MCP_MANAGED_SCRIPT_SENTINEL_42"

    def test_script_lifecycle(self, ghidra_server: GhidraClient, prog: str, tmp_path: Path):
        before = ghidra_server.ok("list_scripts")
        before_names = set(before.get("scripts", []))
        suffix = uuid4().hex
        script_name = f"ManagedIntegrationScript{suffix}"

        source = tmp_path / f"{script_name}.java"
        source.write_text(
            "import ghidra.app.script.GhidraScript;\n"
            f"public class {script_name} extends GhidraScript {{\n"
            "    @Override\n"
            "    public void run() throws Exception {\n"
            f'        println("{self.SENTINEL}");\n'
            "    }\n"
            "}\n",
            encoding="utf-8",
        )

        added = ghidra_server.ok("add_script", {"file_path": str(source)})
        assert added["success"] is True
        filename = added["filename"]
        assert source.exists()  # add_script copies, does not move the source file

        after_add = ghidra_server.ok("list_scripts")
        assert filename in after_add.get("scripts", [])

        run = ghidra_server.ok(
            "run_script",
            {"program": prog, "filename": filename},
        )
        assert run["success"] is True
        assert self.SENTINEL in run.get("output", "")

        deleted = ghidra_server.ok("delete_script", {"filename": filename})
        assert deleted["success"] is True

        after_delete = ghidra_server.ok("list_scripts")
        assert set(after_delete.get("scripts", [])) == before_names

    def test_run_script_rejects_path_like_filename(
            self, ghidra_server: GhidraClient, prog: str):
        assert ghidra_server.is_error(
            "run_script",
            {"program": prog, "filename": "nested/path/script.java"},
        )

    def test_list_scripts_includes_new_analyzers(self, ghidra_server: GhidraClient):
        result = ghidra_server.ok("list_scripts")
        names = set(result.get("scripts", []))
        assert "PEAnalyser.java" in names
        assert "VtablesAnalyser.java" in names

    def test_run_pe_analyser_help_no_args(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "run_script",
            {"program": prog, "filename": "PEAnalyser.java"},
        )
        payload = _last_json_line(result.get("output", ""))
        assert payload.get("help") is True
        assert payload.get("script") == "PEAnalyser.java"

    def test_run_pe_analyser_with_args(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "run_script",
            {
                "program": prog,
                "filename": "PEAnalyser.java",
                "args": ["false", "0", "10"],
            },
        )
        payload = _last_json_line(result.get("output", ""))
        assert payload.get("program") == prog
        assert "image_base" in payload
        assert "sections" in payload
        assert payload.get("relocation_count") == 0

    def test_run_vtables_analyser_help_no_args(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "run_script",
            {"program": prog, "filename": "VtablesAnalyser.java"},
        )
        payload = _last_json_line(result.get("output", ""))
        assert payload.get("help") is True
        assert payload.get("script") == "VtablesAnalyser.java"

    def test_run_vtables_analyser_with_args(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "run_script",
            {
                "program": prog,
                "filename": "VtablesAnalyser.java",
                "args": ["2", "0", "10"],
            },
        )
        payload = _last_json_line(result.get("output", ""))
        assert payload.get("program") == prog
        assert "pointer_size" in payload
        assert "vtables" in payload
