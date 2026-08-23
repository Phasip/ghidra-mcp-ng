"""
test_integration.py — integration tests for ghidra-mcp-ng HTTP API.

Covers every registered tool.  Requires a running Ghidra server started by
the ``ghidra_server`` session fixture in conftest.py (self-contained: compiles
a C binary, creates a Ghidra project, starts the server on port 8199).

Tests are automatically skipped when GHIDRA_HOME is not available.

``TestHealth.test_tools_list_contains_expected_tools`` holds the authoritative
list of tools that must exist; the served ``/schema`` is what it checks against.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from uuid import uuid4

import pytest

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


_TEMP_NAME_RE = re.compile(r"\b[a-z]{1,4}Var\d+\b")


def _find_decompiler_temporary(client: GhidraClient, prog: str) -> tuple[str | None, str | None]:
    """
    Return (function_name, temporary_name) for the first decompiler temporary in the program,
    or (None, None). A temporary is a name the decompiler shows that the program database does
    not hold as a parameter or local — which is what makes naming one a different code path.
    """
    functions = client.ok(
        "search_functions", {"program": prog, "query": "", "limit": 500}
    )["functions"]
    for fn in functions:
        # Externals and thunks have nothing to decompile; skip them rather than fail the search.
        resp = client.call(
            "decompile_function", {"program": prog, "name_or_address": fn["name"]},
        )
        if not resp.get("ok"):
            continue
        decompiled = resp["result"]["decompiled"]
        committed = {
            v["name"] for v in client.ok(
                "get_function_variables", {"program": prog, "name_or_address": fn["name"]},
            )["variables"]
            if v.get("kind") != "temporary"
        }
        for token in _TEMP_NAME_RE.findall(decompiled):
            if token not in committed:
                return fn["name"], token
    return None, None


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
        # The count is reflection-derived server-side; check it against the served schema
        # rather than a literal, so adding a tool cannot leave this quietly wrong.
        assert h["tools"] == len(ghidra_server.tools())

    def test_tools_list_contains_expected_tools(self, ghidra_server: GhidraClient):
        tools = ghidra_server.tools()
        names = {t["name"] for t in tools}
        expected = {
            # ReadTools
            "check_connection", "list_project_files",
            "list_exports", "list_imports", "list_data_type_categories",
            "get_program_info", "list_globals",
            "get_function_info", "get_address_info", "get_calling_conventions",
            "get_function_variables", "decompile_function", "search_functions",
            "read_data", "get_disassembly", "search_bytes", "search_instructions",
            "search_data_types", "search_defined_strings", "get_struct_layout",
            "get_xrefs_to", "get_xrefs_from", "get_function_callees",
            "search_constant_references", "batch_tool_call",
            # WriteTools
            "rename_function", "set_variable", "rename_global", "create_label",
            "set_function_prototype", "set_parameter_type",
            "create_struct", "add_struct_field", "remove_struct_field", "replace_struct_field",
            "set_comment", "analyze_program", "import_binary",
            # ScriptTool
            "list_scripts", "get_script_description", "add_script", "run_script", "delete_script",
        }
        missing = expected - names
        assert not missing, f"Missing tools: {missing}"
        assert "run_script_inline" not in names

    def test_every_tool_carries_exactly_one_category_tag(self, ghidra_server: GhidraClient):
        # The tag is what bridge.py groups by for list_tools and what TOOLS.md sections
        # on. An untagged tool still works but is only findable in an "Other" bucket,
        # so catch it here rather than letting it quietly land there.
        spec = ghidra_server.schema()
        untagged = []
        multi = []
        for path, methods in spec["paths"].items():
            for method, op in methods.items():
                if "operationId" not in op:
                    continue
                tags = op.get("tags") or []
                if not tags:
                    untagged.append(op["operationId"])
                elif len(tags) > 1:
                    multi.append(op["operationId"])
        assert not untagged, f"Tools missing a `tags` category: {sorted(untagged)}"
        assert not multi, f"Tools with more than one tag: {sorted(multi)}"


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
        assert result["failed"] == 0
        assert all(item["ok"] for item in result["results"])


# ---------------------------------------------------------------------------
# 6. Strings
# ---------------------------------------------------------------------------

class TestStrings:
    def test_search_defined_strings_no_query(
            self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok("search_defined_strings", {"program": prog})
        assert "strings" in result
        assert "count" in result

    def test_search_defined_strings_with_query(
            self, ghidra_server: GhidraClient, prog: str):
        # Match our sentinel; may return 0 if Ghidra didn't define the string
        result = ghidra_server.ok(
            "search_defined_strings",
            {"program": prog, "query": "SENTINEL"}
        )
        assert "strings" in result
        # If the sentinel string was analysed, verify its value
        for s in result["strings"]:
            assert "SENTINEL" in s.get("value", "").upper()

    def test_search_defined_strings_paging_terminates(
            self, ghidra_server: GhidraClient, prog: str):
        # 'truncated' is evaluated after the offset skip, so it means "a match past
        # this page was dropped" — paging by 'count' must reach an untruncated page.
        # Deduped on address, not value: a binary legitimately holds the same string
        # value at several addresses (section names appear in more than one table).
        seen: list[str] = []
        offset = 0
        pages = 0
        for _ in range(40):
            page = ghidra_server.ok(
                "search_defined_strings",
                {"program": prog, "offset": offset, "limit": 50},
            )
            seen.extend(s["address"] for s in page["strings"])
            pages += 1
            if not page["truncated"]:
                break
            offset += page["count"]
        else:
            pytest.fail("paging by offset never reached an untruncated page")
        assert pages > 1, "fixture has too few strings to exercise paging"
        assert len(seen) == len(set(seen)), "pages overlapped"

    def test_search_defined_strings_rejects_an_undeclared_param(
            self, ghidra_server: GhidraClient, prog: str):
        # The substring filter is 'query', as on every search tool. Any other spelling must
        # surface as a rejection, never as a silently ignored argument.
        resp = ghidra_server.call(
            "search_defined_strings",
            {"program": prog, "filter": "SENTINEL"},
        )
        assert resp["ok"] is False
        assert "filter" in resp["error"]


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
        # The error should diagnose the specific mistake: the address is inside a known
        # function but is not its entry point, and it should name that function.
        err = response.get("error", "").lower()
        assert "entry point" in err
        assert "add" in err

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
            {"program": prog, "address": _hex(addr), "limit": 5},
        )
        assert result["count"] > 0
        assert len(result["lines"]) == result["count"]

    def test_get_disassembly_accepts_function_name(self, ghidra_server: GhidraClient, prog: str):
        # A name resolves to its symbol address — no separate lookup needed.
        result = ghidra_server.ok(
            "get_disassembly",
            {"program": prog, "address": "add", "limit": 5},
        )
        assert result["count"] > 0
        assert len(result["lines"]) == result["count"]

    def test_get_disassembly_reports_truncation(self, ghidra_server: GhidraClient, prog: str):
        addr = _func_address(ghidra_server, prog, "add")
        # A single-instruction window into a larger function must flag more remain.
        result = ghidra_server.ok(
            "get_disassembly",
            {"program": prog, "address": _hex(addr), "limit": 1},
        )
        assert result["truncated"] is True
        assert result["next_address"] is not None

    def test_get_disassembly_rejects_an_undeclared_param(
            self, ghidra_server: GhidraClient, prog: str):
        # The window size is 'limit', as on every list tool.
        addr = _func_address(ghidra_server, prog, "add")
        resp = ghidra_server.call(
            "get_disassembly",
            {"program": prog, "address": _hex(addr), "instructions": 5},
        )
        assert resp["ok"] is False
        assert "instructions" in resp["error"]

    def test_get_disassembly_rejects_limit_over_max(
            self, ghidra_server: GhidraClient, prog: str):
        addr = _func_address(ghidra_server, prog, "add")
        resp = ghidra_server.call(
            "get_disassembly",
            {"program": prog, "address": _hex(addr), "limit": 2001},
        )
        assert resp["ok"] is False
        assert "2000" in resp["error"]

    def test_unknown_query_param_is_rejected(self, ghidra_server: GhidraClient, prog: str):
        addr = _func_address(ghidra_server, prog, "add")
        # 'count' is not a real parameter (it is 'item_count') — the server must reject
        # it with a clear error instead of silently falling back to defaults.
        resp = ghidra_server.call(
            "read_data",
            {"program": prog, "address": _hex(addr), "count": 112},
        )
        assert resp["ok"] is False
        assert "count" in resp["error"]
        assert "item_count" in resp["error"]

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
            {"program": prog, "name_or_address": _hex(addr)},
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
            {"program": prog, "name_or_address": _hex(addr), "ref_types": ["CALL"]},
        )
        assert "call_refs" in result

    def test_get_xrefs_to_limit_truncates(self, ghidra_server: GhidraClient, prog: str):
        # add() is called from at least two sites, so a limit of 1 must drop one and say so.
        addr = _func_address(ghidra_server, prog, "add")
        result = ghidra_server.ok(
            "get_xrefs_to",
            {"program": prog, "name_or_address": _hex(addr), "limit": 1},
        )
        assert result["count"] == 1
        assert len(result["xrefs"]) == 1
        assert result["truncated"] is True

    def test_get_xrefs_to_untruncated_when_limit_not_reached(
            self, ghidra_server: GhidraClient, prog: str):
        addr = _func_address(ghidra_server, prog, "add")
        result = ghidra_server.ok(
            "get_xrefs_to",
            {"program": prog, "name_or_address": _hex(addr), "limit": 5000},
        )
        assert result["truncated"] is False

    def test_get_xrefs_to_rejects_limit_over_max(self, ghidra_server: GhidraClient, prog: str):
        addr = _func_address(ghidra_server, prog, "add")
        resp = ghidra_server.call(
            "get_xrefs_to",
            {"program": prog, "name_or_address": _hex(addr), "limit": 5001},
        )
        assert resp["ok"] is False
        assert "5000" in resp["error"]

    def test_get_xrefs_from_reports_truncated(self, ghidra_server: GhidraClient, prog: str):
        addr = _func_address(ghidra_server, prog, "compute")
        result = ghidra_server.ok(
            "get_xrefs_from",
            {"program": prog, "address": _hex(addr)},
        )
        assert result["truncated"] is False

    def test_get_xrefs_to_includes_indirect_calls_key(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "get_xrefs_to",
            {"program": prog, "name_or_address": "add"},
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
            {"program": prog, "name_or_address": bare},
        )
        assert err["ok"] is False


# ---------------------------------------------------------------------------
# 10b. Pagination — 'truncated' means the same thing in every paged tool
# ---------------------------------------------------------------------------

# (tool, its documented max limit, tool-specific arguments). Each of these returns
# a 'count' bounded by 'limit' plus a 'truncated' flag, and the flag must mean
# "a matching item was dropped" — never "the page happened to fill exactly".
_PAGED_TOOLS = [
    ("search_functions", 1000, {"query": "add"}),
    ("search_data_types", 500, {"query": "int"}),
    ("search_defined_strings", 1000, {}),
    ("search_bytes", 2000, {"hex_pattern": "53 45 4E 54 49 4E 45 4C"}),
    ("search_instructions", 2000, {"pattern": "E8 ?? ?? ?? ??"}),
    ("search_constant_references", 2000, {"value": "-2401053088876216593"}),
    ("list_globals", 5000, {}),
    ("get_xrefs_to", 5000, {"name_or_address": "add"}),
]


@pytest.mark.parametrize(
    "tool,max_limit,args", _PAGED_TOOLS, ids=[t[0] for t in _PAGED_TOOLS]
)
class TestPaginationTruncation:
    def _total(self, ghidra_server: GhidraClient, prog: str, tool, max_limit, args):
        full = ghidra_server.ok(tool, {"program": prog, "limit": max_limit, **args})
        assert full["truncated"] is False, f"{tool}: fixture exceeds the tool's own max limit"
        assert full["count"] > 0, f"{tool}: fixture yields no matches for {args}"
        return full["count"]

    def test_exact_page_is_not_truncated(
            self, ghidra_server: GhidraClient, prog: str, tool, max_limit, args):
        # A page that fills exactly is a complete result: it must not ask the agent to
        # page again for a second copy of what it already has.
        total = self._total(ghidra_server, prog, tool, max_limit, args)
        exact = ghidra_server.ok(tool, {"program": prog, "limit": total, **args})
        assert exact["count"] == total
        assert exact["truncated"] is False

    def test_short_page_is_truncated(
            self, ghidra_server: GhidraClient, prog: str, tool, max_limit, args):
        total = self._total(ghidra_server, prog, tool, max_limit, args)
        short = ghidra_server.ok(tool, {"program": prog, "limit": total - 1, **args})
        assert short["count"] == total - 1
        assert short["truncated"] is True


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

    def test_set_variable_renames(self, ghidra_server: GhidraClient, prog: str):
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
            "set_variable",
            {"program": prog,
             "name_or_address": "add",
             "variable_name": original_name,
             "new_name": new_name},
        )
        assert result["success"] is True
        assert result["name"] == new_name

        # Rename back to original
        ghidra_server.ok(
            "set_variable",
            {"program": prog,
             "name_or_address": "add",
             "variable_name": new_name,
             "new_name": original_name},
        )

    def test_set_variable_retypes(self, ghidra_server: GhidraClient, prog: str):
        variables = ghidra_server.ok(
            "get_function_variables",
            {"program": prog, "name_or_address": "add"},
        )["variables"]
        assert variables, "add() should have variables"
        target = variables[0]
        original_type = target["type"]

        result = ghidra_server.ok(
            "set_variable",
            {"program": prog,
             "name_or_address": "add",
             "variable_name": target["name"],
             "type_name": "uint"},
        )
        assert result["success"] is True
        assert result["name"] == target["name"]
        assert result["type_name"] == "uint"

        current = {
            v["name"]: v["type"] for v in ghidra_server.ok(
                "get_function_variables",
                {"program": prog, "name_or_address": "add"},
            )["variables"]
        }
        assert current[target["name"]] == "uint"

        ghidra_server.ok(
            "set_variable",
            {"program": prog, "name_or_address": "add",
             "variable_name": target["name"], "type_name": original_type},
        )

    def test_set_variable_requires_a_change(
            self, ghidra_server: GhidraClient, prog: str):
        variables = ghidra_server.ok(
            "get_function_variables",
            {"program": prog, "name_or_address": "add"},
        )["variables"]
        resp = ghidra_server.call(
            "set_variable",
            {"program": prog, "name_or_address": "add",
             "variable_name": variables[0]["name"]},
        )
        assert resp["ok"] is False
        error = resp.get("error", "")
        assert "new_name" in error and "type_name" in error

    def test_set_variable_unknown_type_reports_it(
            self, ghidra_server: GhidraClient, prog: str):
        variables = ghidra_server.ok(
            "get_function_variables",
            {"program": prog, "name_or_address": "add"},
        )["variables"]
        resp = ghidra_server.call(
            "set_variable",
            {"program": prog, "name_or_address": "add",
             "variable_name": variables[0]["name"],
             "type_name": "NoSuchTypeXyz"},
        )
        assert resp["ok"] is False
        assert "NoSuchTypeXyz" in resp.get("error", "")

    def test_set_variable_nonexistent_reports_not_found(
            self, ghidra_server: GhidraClient, prog: str):
        resp = ghidra_server.call(
            "set_variable",
            {"program": prog,
             "name_or_address": "add",
             "variable_name": "definitely_not_a_real_variable_xyz",
             "new_name": "whatever"},
        )
        assert resp["ok"] is False
        error = resp.get("error", "")
        # A name that exists nowhere must be reported as not found — not misattributed
        # to a decompiler temporary.
        assert "not found" in error.lower()
        assert "decompiler temporary" not in error

    def test_set_variable_names_a_decompiler_temporary(
            self, ghidra_server: GhidraClient, prog: str):
        # A decompiler temporary is a register or intermediate value the program database does
        # not hold; naming one has to go through the decompiler's own view of the function.
        found_func, found_temp = _find_decompiler_temporary(ghidra_server, prog)
        if found_temp is None:
            pytest.skip("No decompiler temporary present in the fixture binary")

        resp = ghidra_server.call(
            "set_variable",
            {"program": prog,
             "name_or_address": found_func,
             "variable_name": found_temp,
             "new_name": "named_temp"},
        )
        if not resp["ok"]:
            # Some values genuinely cannot be pinned to storage. That must be reported as a
            # failure that names the value and points somewhere useful — never as a success.
            error = resp["error"]
            assert found_temp in error
            assert "set_comment" in error
            return

        assert resp["result"]["kind"] == "temporary"
        assert resp["result"]["name"] == "named_temp"
        names = {
            v["name"] for v in ghidra_server.ok(
                "get_function_variables",
                {"program": prog, "name_or_address": found_func},
            )["variables"]
        }
        assert "named_temp" in names, "a reported rename must survive the next decompile"

    def test_set_variable_retype_of_a_temporary_needs_a_name(
            self, ghidra_server: GhidraClient, prog: str):
        found_func, found_temp = _find_decompiler_temporary(ghidra_server, prog)
        if found_temp is None:
            pytest.skip("No decompiler temporary present in the fixture binary")

        resp = ghidra_server.call(
            "set_variable",
            {"program": prog,
             "name_or_address": found_func,
             "variable_name": found_temp,
             "type_name": "uint"},
        )
        assert resp["ok"] is False
        error = resp.get("error", "")
        assert "new_name" in error
        assert found_temp in error

    def test_set_function_prototype(
            self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "set_function_prototype",
            {"program": prog,
             "name_or_address": "compute",
             "return_type": "int",
             "parameters": [
                 {"name": "x", "type_name": "int"},
                 {"name": "y", "type_name": "int"},
                 {"name": "mode", "type_name": "int"},
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
        assert "parameters[0].type_name" in missing_type.get("error", "")

        blank_name = ghidra_server.call(
            "set_function_prototype",
            {"program": prog,
             "name_or_address": "compute",
             "return_type": "int",
             "parameters": [{"name": "   ", "type_name": "int"}]},
        )
        assert blank_name["ok"] is False
        assert "parameters[0].name" in blank_name.get("error", "")

    def test_set_function_prototype_rejects_an_undeclared_parameter_key(
            self, ghidra_server: GhidraClient, prog: str):
        # A key inside parameters[] is checked like any other input: rejecting it is right,
        # but the error must name the field that was meant, not just report one missing.
        resp = ghidra_server.call(
            "set_function_prototype",
            {"program": prog,
             "name_or_address": "compute",
             "return_type": "int",
             "parameters": [{"name": "x", "type": "int"}]},
        )
        assert resp["ok"] is False
        error = resp.get("error", "")
        assert "'type'" in error
        assert "type_name" in error

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
# 11b. Batched writes
# ---------------------------------------------------------------------------

class TestBatchedWrites:
    """
    batch_tool_call is the single batching idiom for reads and writes alike —
    renaming N locals must not cost N round-trips (improvement_plan §4.1).
    """

    def _variable_names(self, ghidra_server: GhidraClient, prog: str) -> list:
        result = ghidra_server.ok(
            "get_function_variables",
            {"program": prog, "name_or_address": "add"},
        )
        return [v["name"] for v in result.get("variables", [])]

    def test_batch_set_variable(self, ghidra_server: GhidraClient, prog: str):
        originals = self._variable_names(ghidra_server, prog)
        assert originals, "add() should have variables"
        renamed = [f"batch_renamed_{i}" for i in range(len(originals))]

        result = ghidra_server.ok(
            "batch_tool_call",
            {
                "tool": "set_variable",
                "calls": [
                    {"program": prog, "name_or_address": "add",
                     "variable_name": old, "new_name": new}
                    for old, new in zip(originals, renamed)
                ],
            },
        )
        assert result["tool"] == "set_variable"
        assert result["count"] == len(originals)
        assert result["failed"] == 0
        assert all(item["ok"] for item in result["results"])
        assert set(renamed) <= set(self._variable_names(ghidra_server, prog))

        # Rename back so later tests see the original names.
        restore = ghidra_server.ok(
            "batch_tool_call",
            {
                "tool": "set_variable",
                "calls": [
                    {"program": prog, "name_or_address": "add",
                     "variable_name": new, "new_name": old}
                    for old, new in zip(originals, renamed)
                ],
            },
        )
        assert restore["failed"] == 0

    def test_batch_partial_failure_still_applies_the_rest(
            self, ghidra_server: GhidraClient, prog: str):
        original = self._variable_names(ghidra_server, prog)[0]
        result = ghidra_server.ok(
            "batch_tool_call",
            {
                "tool": "set_variable",
                "calls": [
                    {"program": prog, "name_or_address": "add",
                     "variable_name": "no_such_variable_xyz", "new_name": "never_applied"},
                    {"program": prog, "name_or_address": "add",
                     "variable_name": original, "new_name": "batch_partial_ok"},
                ],
            },
        )
        assert result["failed"] == 1
        assert result["results"][0]["ok"] is False
        assert result["results"][0]["error"]
        assert result["results"][1]["ok"] is True
        assert "batch_partial_ok" in self._variable_names(ghidra_server, prog)

        ghidra_server.ok(
            "set_variable",
            {"program": prog, "name_or_address": "add",
             "variable_name": "batch_partial_ok", "new_name": original},
        )

    def test_batch_set_comment(self, ghidra_server: GhidraClient, prog: str):
        addr = _func_address(ghidra_server, prog, "add")
        result = ghidra_server.ok(
            "batch_tool_call",
            {
                "tool": "set_comment",
                "calls": [
                    {"program": prog, "address": _hex(addr),
                     "comment": "batch comment", "type": "PRE"},
                    {"program": prog, "address": _hex(addr),
                     "comment": "batch eol", "type": "EOL"},
                ],
            },
        )
        assert result["failed"] == 0
        assert result["count"] == 2

    def test_batch_rejects_analyze_program(
            self, ghidra_server: GhidraClient, prog: str):
        err = ghidra_server.call(
            "batch_tool_call",
            {"tool": "analyze_program", "calls": [{"program": prog}]},
        )
        assert err["ok"] is False
        assert "not batchable" in err.get("error", "")

    def test_batch_rejects_non_allowlisted_tool(
            self, ghidra_server: GhidraClient, prog: str):
        err = ghidra_server.call(
            "batch_tool_call",
            {"tool": "list_scripts", "calls": [{}]},
        )
        assert err["ok"] is False
        assert "not allowlisted" in err.get("error", "")
        # The message must name the alternatives so the agent can self-correct.
        assert "set_variable" in err.get("error", "")


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

    def test_unknown_data_type_suggests_close_match(self, ghidra_server: GhidraClient, prog: str):
        # A near-miss type name (typo of 'uint') should get a targeted suggestion rather than
        # a dump of every built-in type.
        response = ghidra_server.call(
            "set_parameter_type",
            {"program": prog,
             "name_or_address": "compute",
             "parameter_index": 0,
             "type_name": "uintt"},
        )
        assert response["ok"] is False
        error = response.get("error", "")
        assert "not found" in error.lower()
        assert "Did you mean" in error
        assert "uint" in error
        # A suggestion, not a catalogue: the message must stay short enough to read.
        assert len(error) < 400


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

    def _managed_script(self, tmp_path: Path, sentinel: str):
        """Write a script that prints `sentinel`, and return (source path, class name)."""
        script_name = f"EditedIntegrationScript{uuid4().hex}"
        source = tmp_path / f"{script_name}.java"
        source.write_text(
            "import ghidra.app.script.GhidraScript;\n"
            f"public class {script_name} extends GhidraScript {{\n"
            "    @Override\n"
            "    public void run() throws Exception {\n"
            f'        println("{sentinel}");\n'
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        return source, script_name

    def test_run_script_picks_up_an_edited_source(
            self, ghidra_server: GhidraClient, prog: str, tmp_path: Path):
        # The failure this guards: add_script copies, so without reconciling the source an
        # edited script runs its stale snapshot and still reports success — a response
        # indistinguishable from a correct run.
        first, script_name = self._managed_script(tmp_path, "MCP_EDIT_BEFORE")
        added = ghidra_server.ok("add_script", {"file_path": str(first)})
        filename = added["filename"]
        assert added["source_path"] == str(first)
        try:
            run = ghidra_server.ok("run_script", {"program": prog, "filename": filename})
            assert "MCP_EDIT_BEFORE" in run["output"]
            assert run["source_state"] == "current"
            assert run["source_path"] == str(first)

            first.write_text(
                first.read_text(encoding="utf-8").replace("MCP_EDIT_BEFORE", "MCP_EDIT_AFTER"),
                encoding="utf-8",
            )

            # No second add_script: the edit alone must change what runs.
            rerun = ghidra_server.ok("run_script", {"program": prog, "filename": filename})
            assert rerun["source_state"] == "refreshed"
            assert "MCP_EDIT_AFTER" in rerun["output"]
            assert "MCP_EDIT_BEFORE" not in rerun["output"]

            # Once re-copied, the next run has nothing left to refresh.
            again = ghidra_server.ok("run_script", {"program": prog, "filename": filename})
            assert again["source_state"] == "current"
            assert "MCP_EDIT_AFTER" in again["output"]
        finally:
            ghidra_server.call("delete_script", {"filename": filename})

    def test_run_script_reports_a_deleted_source(
            self, ghidra_server: GhidraClient, prog: str, tmp_path: Path):
        # A registered source that has gone away is not an error — the last registered copy
        # is still the best available — but the response must not claim it is current.
        source, _ = self._managed_script(tmp_path, "MCP_SOURCE_GONE")
        filename = ghidra_server.ok("add_script", {"file_path": str(source)})["filename"]
        try:
            source.unlink()
            run = ghidra_server.ok("run_script", {"program": prog, "filename": filename})
            assert run["success"] is True
            assert run["source_state"] == "source_missing"
            assert run["source_path"] == str(source)
            assert "MCP_SOURCE_GONE" in run["output"]
        finally:
            ghidra_server.call("delete_script", {"filename": filename})

    def test_run_script_reports_no_source_for_a_bundled_script(
            self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "run_script", {"program": prog, "filename": "PEAnalyser.java"}
        )
        assert result["source_state"] == "no_registered_source"
        # Nulls are omitted API-wide, so there is simply no source_path key.
        assert "source_path" not in result

    def test_add_script_rejects_a_bundled_script_name(
            self, ghidra_server: GhidraClient, tmp_path: Path):
        # A colliding name would copy fine and then never be what run_script runs, since
        # the extension's own directory takes priority.
        clash = tmp_path / "PEAnalyser.java"
        clash.write_text("// not the real one\n", encoding="utf-8")
        resp = ghidra_server.call("add_script", {"file_path": str(clash)})
        assert resp["ok"] is False
        assert "PEAnalyser.java" in resp["error"]
        assert "bundled" in resp["error"]

    def test_delete_script_removes_the_source_registration(
            self, ghidra_server: GhidraClient, prog: str, tmp_path: Path):
        # Re-adding after a delete must start from a clean registration, not inherit the
        # sidecar the previous copy left behind.
        source, _ = self._managed_script(tmp_path, "MCP_REREGISTER")
        filename = ghidra_server.ok("add_script", {"file_path": str(source)})["filename"]
        ghidra_server.ok("delete_script", {"filename": filename})

        moved = tmp_path / "moved" / source.name
        moved.parent.mkdir()
        moved.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        readded = ghidra_server.ok("add_script", {"file_path": str(moved)})
        try:
            assert readded["source_path"] == str(moved)
            run = ghidra_server.ok("run_script", {"program": prog, "filename": filename})
            assert run["source_path"] == str(moved)
            assert run["source_state"] == "current"
        finally:
            ghidra_server.call("delete_script", {"filename": filename})

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


# ---------------------------------------------------------------------------
# 15. Error reporting
# ---------------------------------------------------------------------------

class TestErrorReporting:
    """
    Failures must arrive as the failure they are: a tool name that does not exist is a 404
    naming the closest real tool, not an internal error. A genuine server fault returns
    getMessage() plus an error_id, and the full stack trace goes to a log file the caller can
    find — a trace that reaches only the launching terminal cannot be put in a bug report.
    """

    def test_unknown_tool_is_404_and_suggests_the_real_name(self, ghidra_server: GhidraClient):
        status, body = ghidra_server.raw("/tool/get_function_infoo")
        assert status == 404
        assert body["ok"] is False
        assert "get_function_infoo" in body["error"]
        assert "get_function_info'" in body["error"], "must suggest the closest real tool"
        assert "Internal error" not in body["error"]

    def test_unknown_path_names_the_real_surface(self, ghidra_server: GhidraClient):
        # /tools is a plausible guess at a dispatcher endpoint; this server has none.
        status, body = ghidra_server.raw("/tools")
        assert status == 404
        assert body["ok"] is False
        assert "/schema" in body["error"]
        assert "/tool/" in body["error"]

    def test_wrong_method_keeps_its_own_status(self, ghidra_server: GhidraClient):
        # rename_function is POST-only; a GET is a 405, not an internal error.
        status, body = ghidra_server.raw("/tool/rename_function", method="GET")
        assert status == 405
        assert body["ok"] is False
        assert "Internal error" not in body["error"]

    def test_health_reports_the_log_file(self, ghidra_server: GhidraClient):
        log_file = ghidra_server.health().get("log_file")
        assert log_file, "health must report where stack traces are written"
        assert Path(log_file).exists()

    def test_server_error_returns_an_error_id_recorded_in_the_log(
            self, ghidra_server: GhidraClient, prog: str, tmp_path: Path):
        script_name = f"ErrorIdProbe{uuid4().hex}"
        marker = "mcp-error-id-probe"
        source = tmp_path / f"{script_name}.java"
        source.write_text(
            "import ghidra.app.script.GhidraScript;\n"
            f"public class {script_name} extends GhidraScript {{\n"
            "    @Override\n"
            "    public void run() throws Exception {\n"
            f'        throw new RuntimeException("{marker}");\n'
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        filename = ghidra_server.ok("add_script", {"file_path": str(source)})["filename"]
        try:
            resp = ghidra_server.call("run_script", {"program": prog, "filename": filename})
            assert resp["ok"] is False
            assert marker in resp["error"]
            error_id = resp.get("error_id")
            assert error_id, f"an unexpected failure must carry an error_id: {resp}"

            log = Path(ghidra_server.health()["log_file"]).read_text(errors="replace")
            entry = log.split(f"[{error_id}]")
            assert len(entry) == 2, f"error_id {error_id} must appear exactly once in the log"
            assert marker in entry[1]
            assert "\tat " in entry[1], "the log entry must carry the full stack trace"

            # The program is still usable afterwards — the failed script's copy was evicted.
            assert ghidra_server.ok("get_program_info", {"program": prog})["program"] == prog
        finally:
            ghidra_server.call("delete_script", {"filename": filename})


class TestArgumentTypeStrictness:
    """
    A JSON value of the wrong type is rejected, never coerced. Gson's own accessors are
    lenient in ways that all read as a successful call — "5" parses as 5, 5.7 truncates to 5,
    [5] unwraps to 5, and "yes" reads as the boolean false — so an argument the agent got
    wrong would take effect as a different argument and come back ok=True.
    """

    def test_int_field_rejects_a_string(self, ghidra_server: GhidraClient, prog: str):
        resp = ghidra_server.call(
            "create_struct",
            {"program": prog, "name": f"StrictInt{uuid4().hex[:8]}", "size": "8"},
        )
        assert resp["ok"] is False
        assert "size" in resp["error"] and "integer" in resp["error"]

    def test_int_field_rejects_a_fraction_rather_than_truncating(
            self, ghidra_server: GhidraClient, prog: str):
        name = f"StrictFrac{uuid4().hex[:8]}"
        resp = ghidra_server.call(
            "create_struct", {"program": prog, "name": name, "size": 8.5})
        assert resp["ok"] is False
        assert "size" in resp["error"]
        # The rejection must be total: nothing was created under that name.
        assert ghidra_server.is_error("get_struct_layout", {"program": prog, "name": name})

    def test_int_field_rejects_a_single_element_array(
            self, ghidra_server: GhidraClient, prog: str):
        resp = ghidra_server.call(
            "create_struct",
            {"program": prog, "name": f"StrictArr{uuid4().hex[:8]}", "size": [8]},
        )
        assert resp["ok"] is False
        assert "size" in resp["error"]

    def test_bool_field_rejects_a_string(self, ghidra_server: GhidraClient, prog: str):
        resp = ghidra_server.call(
            "create_struct",
            {"program": prog, "name": f"StrictBool{uuid4().hex[:8]}",
             "size": 4, "override": "yes"},
        )
        assert resp["ok"] is False
        assert "override" in resp["error"] and "boolean" in resp["error"]

    def test_array_field_rejects_a_string_without_a_500(
            self, ghidra_server: GhidraClient, prog: str):
        resp = ghidra_server.call(
            "set_function_prototype",
            {"program": prog, "name_or_address": "main",
             "return_type": "int", "parameters": "int argc"},
        )
        assert resp["ok"] is False
        assert "parameters" in resp["error"] and "array" in resp["error"]
        assert "Internal error" not in resp["error"]
        assert "error_id" not in resp, "a bad argument is a 400, not a logged server fault"

    def test_batch_arguments_are_as_strict_as_a_standalone_call(
            self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok(
            "batch_tool_call",
            {"tool": "search_functions",
             "calls": [{"program": prog, "limit": "5"}]},
        )
        assert result["failed"] == 1
        assert "limit" in result["results"][0]["error"]
        assert "integer" in result["results"][0]["error"]


class TestUnknownFieldRejection:
    """
    A field the tool does not declare is refused, not dropped. Query parameters were already
    checked; a request body was not, and that is the more dangerous half — most body fields are
    optional, so a misspelled one takes effect as its default and the call still reports success.
    """

    def test_misspelled_optional_field_does_not_silently_default(
            self, ghidra_server: GhidraClient, prog: str):
        address = _hex(_func_address(ghidra_server, prog, "main"))
        resp = ghidra_server.call(
            "set_comment",
            {"program": prog, "address": address,
             "comment": "plate please", "comment_type": "PLATE"},
        )
        assert resp["ok"] is False
        assert "comment_type" in resp["error"]
        assert "set_comment" in resp["error"]
        assert "type" in resp["error"], "must name the field that was meant among the valid set"

        # And nothing was written under the default type.
        info = ghidra_server.ok("get_address_info", {"program": prog, "address": address})
        assert "plate please" not in json.dumps(info)

    def test_unknown_field_names_the_valid_set(self, ghidra_server: GhidraClient, prog: str):
        resp = ghidra_server.call(
            "rename_function",
            {"program": prog, "name_or_address": "main", "new_name": "main", "source": "USER"},
        )
        assert resp["ok"] is False
        for field in ("program", "name_or_address", "new_name"):
            assert field in resp["error"]

    def test_declared_optional_fields_are_still_accepted(
            self, ghidra_server: GhidraClient, prog: str):
        # The check must not reject what the schema actually declares.
        name = f"DeclaredOk{uuid4().hex[:8]}"
        result = ghidra_server.ok(
            "create_struct",
            {"program": prog, "name": name, "size": 4, "category": "/test", "override": False},
        )
        assert result["success"] is True

    def test_batch_items_are_checked_like_standalone_calls(
            self, ghidra_server: GhidraClient, prog: str):
        # A key that is not a substring of any valid one, so only a real check can catch it:
        # without it the item would simply run with defaults and report success.
        result = ghidra_server.ok(
            "batch_tool_call",
            {"tool": "get_function_info",
             "calls": [{"program": prog, "name_or_address": "main", "timeout_ms": 500}]},
        )
        assert result["failed"] == 1
        error = result["results"][0]["error"]
        assert "timeout_ms" in error and "name_or_address" in error


class TestRefTypeVocabulary:
    """
    An unrecognised ref_types value can match nothing, so accepting one would make the tool
    answer "no cross-references" — a statement about the program, from a typo in the request.
    """

    def test_unknown_ref_type_is_rejected_not_silently_empty(
            self, ghidra_server: GhidraClient, prog: str):
        resp = ghidra_server.call(
            "get_xrefs_to", {"program": prog, "name_or_address": "main", "ref_types": "CALLS"})
        assert resp["ok"] is False
        assert "CALLS" in resp["error"]
        assert "'CALL'" in resp["error"], "must suggest the real type"

    def test_one_bad_type_among_good_ones_is_rejected(
            self, ghidra_server: GhidraClient, prog: str):
        resp = ghidra_server.call(
            "get_xrefs_to",
            {"program": prog, "name_or_address": "main", "ref_types": "CALL,NONSENSE_TYPE"})
        assert resp["ok"] is False
        assert "NONSENSE_TYPE" in resp["error"]

    def test_categories_and_exact_names_both_work(self, ghidra_server: GhidraClient, prog: str):
        for value in ("CALL", "call", "DATA", "UNCONDITIONAL_CALL", "READ,WRITE"):
            resp = ghidra_server.call(
                "get_xrefs_to",
                {"program": prog, "name_or_address": "main", "ref_types": value})
            assert resp["ok"] is True, f"ref_types={value!r} must be accepted: {resp.get('error')}"


class TestAddressStrictness:
    """A malformed address is rejected outright — never trimmed, signed, or otherwise repaired."""

    @pytest.mark.parametrize("address", ["0x +1000", "0x+1000", "0x1000 ", "0x10 00"])
    def test_malformed_hex_is_not_repaired(
            self, ghidra_server: GhidraClient, prog: str, address: str):
        resp = ghidra_server.call("get_address_info", {"program": prog, "address": address})
        assert resp["ok"] is False
        assert "0x" in resp["error"]


class TestImportLeavesProgramWritable:
    """
    An imported program must be writable afterwards.

    Regression test. GhidraProject opens a transaction on every program it manages
    (initializeProgram -> startTransaction("Batch Processing")) and saveAs() ends that
    transaction only to open a fresh one in its finally block. importBinary used to return
    without closing the program, so that transaction stayed open forever — and an open
    transaction makes DomainObjectAdapterDB.save() throw "Unable to lock due to active
    transaction". The symptom was silent and expensive: the import reported success, later
    writes applied in memory and read back correctly, but every save failed, and restarting
    the server to clear the lock discarded the import along with all the edits.

    The fix is ghidraProject.close(imported) after saveAs, which ends the transaction and
    releases GhidraProject's consumer reference.
    """

    def test_write_after_import_saves(self, ghidra_server: GhidraClient, tmp_path_factory):
        # Import a second copy of the fixture binary under its own name.
        src = Path(ghidra_server.binary_path)
        staged = tmp_path_factory.mktemp("reimport") / "import_writable"
        shutil.copy(src, staged)

        imported = ghidra_server.ok("import_binary", {"file_path": str(staged)})
        assert imported["success"] is True
        program = "/" + imported["program"]

        # The write must SUCCEED, not merely apply in memory. Before the fix this returned
        # ok:false with "Unable to lock due to active transaction" while the rename was
        # nonetheless visible to search_functions — so assert on the write's own result.
        renamed = ghidra_server.ok(
            "rename_function",
            {"program": program, "name_or_address": "multiply", "new_name": "multiply_after_import"},
        )
        assert renamed["success"] is True

        # And it must be durable: a fresh read of the program still sees the new name.
        found = ghidra_server.ok(
            "search_functions", {"program": program, "query": "multiply_after_import"})
        names = [f["name"] for f in (found if isinstance(found, list) else found.get("functions", []))]
        assert "multiply_after_import" in names
