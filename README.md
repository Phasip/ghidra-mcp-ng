# ghidra-mcp-ng

A Ghidra extension that exposes reverse-engineering operations as an MCP (Model Context Protocol) server over JSON-RPC 2.0 on stdio. Designed to be driven by an AI agent (Claude, GPT-4, etc.) via any MCP-compatible client.

## Why this exists

- Existing Ghidra MCP servers had broad feature surfaces but many of those features were buggy and confused the LLM driving them.
- Existing servers required the Ghidra UI to be running, which made them awkward for unattended or long-form work.
- Existing servers felt geared toward short, AI-assisted tasks rather than letting an LLM drive a full reverse-engineering workflow on its own.

## Features

- Tools covering function analysis, decompilation, cross-references, data types, structs, comments, and managed scripting
- Configurable naming-convention enforcement and operation timeouts via `rules.yaml` — the server rejects names that do not follow your conventions and makes decompilation timeout behavior explicit
- Write operations run inside Ghidra transactions and are auto-saved
- HTTP REST API — one Ghidra instance can serve multiple AI agents simultaneously
- Minimal Python MCP bridge (`bridge.py`) — stdlib only, no extra dependencies
- Tool usage errors give clear guidance on what was wrong and how to use the tool.

---

## Requirements

- Ghidra
- Python
---

## Building and installing

```bash
python build_and_install.py /path/to/ghidra
```

This builds the extension with Gradle, removes any previous installation, and installs the built ZIP into the Ghidra user-extensions directory.

### Running tests

```bash
# Java unit tests
GHIDRA_HOME=/path/to/ghidra gradle test

# Python integration tests against a live Ghidra instance
GHIDRA_HOME=/path/to/ghidra python3 -m pytest tests/
```

---

## Starting the server

Use the provided `start.py` helper:

```bash
./start.py --ghidra <ghidra_path> --project <project_path> [--rules FILE] [--port PORT] [--install-ext ZIP_OR_DIR ...]
```

| Flag | Value |
|---|---|
| `--ghidra` | Path to Ghidra installation directory (required) |
| `--project` | Path to the Ghidra project directory — the folder containing `<name>.rep` (required) |
| `--rules` | Path to `rules.yaml` (optional — omit to disable all naming rules) |
| `--port` | HTTP port (optional, default `8192`) |
| `--install-ext` | Install an extension ZIP or directory into the user-extensions directory before launch. Repeatable. |

Examples:

```bash
# No naming rules
./start.py --ghidra /opt/ghidra --project ~/ghidra-projects/MyProject

# With naming rules
./start.py --ghidra /opt/ghidra --project ~/ghidra-projects/MyProject --rules ~/rules.yaml
```

The server logs to **stderr** and starts the HTTP API on `http://127.0.0.1:8192`.
Send SIGTERM or Ctrl-C to shut down cleanly.

---

## Connecting an MCP client

Run `bridge.py` as the MCP client's subprocess command. It speaks MCP JSON-RPC 2.0
over stdio and forwards everything to the Ghidra HTTP API.

Each agent gets its own `bridge.py` process — they all talk to the same Ghidra instance.

Example `mcp-config.json`:

```json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": ["/path/to/ghidra-mcp-ng/bridge.py", "--url", "http://127.0.0.1:8192"]
    }
  }
}
```

### HTTP API (direct access)

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/health` | — | `{"status":"ok","version":"...","tools":<n>}` |
| GET | `/tools` | — | JSON array of tool descriptors |
| POST | `/call` | `{"tool":"...","arguments":{...}}` | `{"ok":true,"result":{...}}` or `{"ok":false,"error":"..."}` |

---

## Server config (`rules.yaml`)

Write tools validate proposed names against `rules.yaml` before touching the program. The same file also controls server timeouts for long-running operations. A violation returns `{"isError":true}` with the configured message — no partial writes occur.

Timeout settings:

```yaml
timeouts:
  decompile_seconds: 60
```

`decompile_seconds` is the timeout, in seconds, applied to each fresh decompilation invoked by `decompile_function`.

Each rule entry:

```yaml
naming:
  function_name:
    pattern: "^[a-zA-Z_][a-zA-Z0-9_]*$"   # Java regex; name must fully match
    message: "Function names must be valid C identifiers"
```

Supported field keys: `function_name`, `variable_name`, `struct_field_name`, `struct_name`.

Struct workflow notes:

- `create_struct` accepts `override=true` to clear and resize an existing struct in place without replacing the underlying data type object.
- `add_struct_field`, `remove_struct_field`, and `replace_struct_field` preserve later field offsets for non-packed structs and reject edits that would force a relayout.
- If a type lookup fails for `code*`, the error explains that `code*` is a Ghidra-internal generated type and suggests `void*` or a concrete function definition instead.

Omit `--rules` to disable all naming rules and use the built-in default timeouts.

---

## Tools reference

See **[TOOLS.md](TOOLS.md)** for the full, up-to-date tool reference with parameters and descriptions.

`TOOLS.md` is auto-generated from the Java annotations.  Regenerate it any time with:

```bash
make tools-docs
```

### Addressing functions

All tools that accept `name_or_address` follow two strict rules:

1. If the value starts with `0x` — parsed as a hex address (entry point must exist there)
2. Otherwise — exact, case-sensitive function name lookup via the symbol table

The `0x` prefix is **required** for hex addresses. `0x00401000` is valid; `00401000` is not.

If the function cannot be found the error message explains exactly what to do:

```
Function not found: 'parse_header'. Names are case-sensitive.
To find the correct name use search_functions.
To address by location use a 0x-prefixed hex address, e.g. 0x00401000.
```

---

## Project layout

```
ghidra-mcp-ng/
├── build.gradle                # Gradle build — applies Ghidra's buildExtension.gradle
├── extension.properties        # Extension metadata (name, version)
├── rules.yaml                  # Default naming-rule configuration
├── build_and_install.py        # Build and install the extension (arg: ghidra path)
├── start.py                    # Server launcher (named flags: --ghidra, --project, --rules, --port, --install-ext)
├── bridge.py                   # Minimal Python MCP bridge (stdlib only)
├── src/
│   ├── main/java/com/ghidramcpng/
│   │   ├── GhidraMcpServer.java          # GhidraLaunchable entry point
│   │   ├── mcp/
│   │   │   ├── McpServer.java            # JSON-RPC 2.0 stdio loop
│   │   │   └── ToolRegistry.java         # Tool registration and dispatch
│   │   ├── program/
│   │   │   └── ProgramManager.java       # Lazy program open, transactions, save
│   │   ├── rules/
│   │   │   ├── RulesConfig.java          # SnakeYAML bean for rules.yaml
│   │   │   ├── RulesEngine.java          # Pattern validation + exemptions
│   │   │   └── NamingRuleViolation.java  # Thrown on rule violation
│   │   └── tools/
│   │       ├── ToolHelpers.java          # Shared lookup + decompiler utilities
│   │       ├── ReadTools.java            # Read-only HTTP tools
│   │       ├── WriteTools.java           # Program-modifying HTTP tools
│   │       └── ScriptTool.java           # Script management and execution tools
│   └── test/java/com/ghidramcpng/
│       ├── mcp/McpServerTest.java        # 13 JSON-RPC protocol tests
│       └── rules/RulesEngineTest.java    # 16 naming-rule tests
└── tests/
    ├── conftest.py                       # pytest fixtures (skipped without live project)
    └── test_integration.py               # 30 integration tests
```


# Security
No security, LLM and anyone who reaches the server can run anything through scripting 
