# Developer guide

## Project layout

```
src/main/java/com/ghidramcpng/
  GhidraMcpServer.java    entry point (GhidraLaunchable)
  mcp/
    McpServer.java        JSON-RPC 2.0 stdio loop
    HttpApiServer.java    HTTP REST server (GET /health, /tools; POST /call)
    ToolRegistry.java     tool table and dispatch
  program/
    ProgramManager.java   lazy program open, transactions, auto-save
  rules/
    RulesConfig.java      SnakeYAML bean for rules.yaml
    RulesEngine.java      pattern validation + exemptions
    NamingRuleViolation.java
  tools/
    ToolHelpers.java      shared lookups and decompiler utilities
    ReadTools.java        24 read-only tools
    WriteTools.java       9 write tools
    ScriptTool.java       list_scripts, add_script, run_script, delete_script

src/test/java/com/ghidramcpng/
  mcp/McpServerTest.java        JSON-RPC protocol tests (no live Ghidra)
  rules/RulesEngineTest.java    naming-rule pattern tests

tests/
  conftest.py             session fixture — compiles a C binary, installs the
                          extension, runs analyzeHeadless, starts the server
  test_integration.py     integration tests (require live Ghidra)
  test_bridge.py          MCP bridge unit tests
```

## Running the tests

```bash
# Java unit tests
GHIDRA_HOME=/path/to/ghidra gradle test

# Python integration tests
GHIDRA_HOME=/path/to/ghidra python3 -m pytest tests/
```

## Adding a tool

Every tool must have a corresponding integration test before it is merged.

### 1. Implement the tool

Tools are registered in the constructor or `registerAll()` of the appropriate class:

- Read-only → `ReadTools.java`
- Write (modifies the program) → `WriteTools.java`
- Scripting → `ScriptTool.java`

Use `ToolHelpers` for program/function lookup and decompiler access. Wrap write
operations in `ProgramManager.inTransaction()`.

**Minimal read tool:**

```java
registry.register(
    ToolHelpers.tool("my_tool",
        "One-line description shown to the agent.",
        ToolHelpers.schema()
            .req("program", "string", "Program name or path")
            .req("name",    "string", "Something to look up")
            .build()),
    args -> {
        Program prog = mgr.open(ToolHelpers.str(args, "program"));
        String name  = ToolHelpers.str(args, "name");
        // ... do work, build result map
        return result;
    }
);
```

**Minimal write tool:**

```java
registry.register(
    ToolHelpers.tool("rename_thing", "...", schema),
    args -> mgr.inTransaction(ToolHelpers.str(args, "program"), prog -> {
        rules.check(RulesEngine.Field.FUNCTION_NAME, newName);
        // ... modify prog
        return Map.of("renamed", true);
    })
);
```

### 2. Write the integration test

Add a test class or method to `tests/test_integration.py`. The `ghidra_server`
fixture provides a `GhidraClient` connected to a live server loaded with
`tests/fixture/test_target.c`. Use `client.ok(tool, args)` for calls that must
succeed and `client.is_error(tool, args)` for expected failures.

```python
class TestMyTool:
    def test_my_tool_basic(self, ghidra_server: GhidraClient, prog: str):
        result = ghidra_server.ok("my_tool", {"program": prog, "name": "add"})
        assert "expected_key" in result

    def test_my_tool_unknown_name(self, ghidra_server: GhidraClient, prog: str):
        assert ghidra_server.is_error("my_tool", {"program": prog, "name": "???"})
```

Test the error path: a missing or invalid argument must return `ok=false`, never
raise an unhandled exception on the server.

### 3. Update the README

Add a row to the appropriate table in the **Tools reference** section of `README.md`.

## Naming rules

Naming-rule patterns are validated in `RulesEngine`. To add a new field kind:

1. Add a constant to `RulesEngine.Field`.
2. Add the corresponding key to `RulesConfig.NamingRule` (SnakeYAML maps the
   YAML key to the field automatically).
3. Call `rules.check(Field.YOUR_FIELD, name)` before writing.
4. Add tests in `RulesEngineTest.java`.

## Code style

- Java: standard Ghidra style (4-space indent, K&R braces).
- Python: PEP 8, max line length 120.
- Comments explain *why*, not *what*. Keep them short.
