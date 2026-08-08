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

There is no dispatcher endpoint — each tool is its own route under `/tool/`, named by its
`operationId`. Read tools are `GET` with query parameters; write and script tools are `POST` with a
JSON body.

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/health` | — | `{"status":"ok","version":"...","tools":<n>,"log_file":"..."}` |
| GET | `/schema` | — | The OpenAPI 3 document describing every tool |
| GET | `/openapi.json` | — | Identical to `/schema` |
| GET | `/tool/<operationId>?...` | — | `{"ok":true,"result":{...}}` or `{"ok":false,"error":"..."}` |
| POST | `/tool/<operationId>` | the tool's arguments as a JSON object | same envelope |

`/schema` is the authoritative tool list — `bridge.py` reads it at startup and derives the MCP tool
definitions from it. `TOOLS.md` is generated from the same document.

```bash
curl 'http://127.0.0.1:8192/tool/search_functions?program=/prog.elf&query=init&limit=20'
curl -X POST http://127.0.0.1:8192/tool/rename_function \
     -H 'Content-Type: application/json' \
     -d '{"program":"/prog.elf","name_or_address":"FUN_00401000","new_name":"maybe_init"}'
```

Every response carries the same envelope: `{"ok":true,"result":{…}}` on success, or
`{"ok":false,"error":"…"}` with an HTTP 400 for a rejected argument and 500 for anything else. A 500
also carries an `error_id` that appears next to the full stack trace in `log_file`. An unknown tool
name is a 404 that names the closest real tool.

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

Supported field keys, and the tools they gate:

| Key | Applies to |
|---|---|
| `function_name` | `rename_function` |
| `variable_name` | `rename_variable`, `set_parameter_type`, `set_function_prototype` parameters |
| `struct_name` | `create_struct` |
| `struct_field_name` | `add_struct_field`, `replace_struct_field` |
| `label_name` | `create_label` |
| `global_name` | `rename_global` |

A key with no entry is unconstrained. An **unknown** key is rejected at startup rather than
ignored — a typo would otherwise leave a rule looking configured while enforcing nothing.

`label_name` and `global_name` are separate from `function_name` on purpose. The
`maybe_`/`likely_`/`guess_` prefixes mark a name as an *inference*, but data labels and globals are
often *recovered* — a CMSIS peripheral register, a symbol from a map file. `UART0->CTRL` is a
datasheet fact and reads better than `likely_UART0->maybe_CTRL_0x18`. The shipped `rules.yaml`
leaves both unset (unconstrained) and carries commented-out examples for projects that want them.

### Comment rules

An optional `comments:` section constrains `set_comment`, keyed by comment type (`PRE`, `POST`,
`EOL`, `PLATE`, `REPEATABLE`). It exists because a comment is one call that accepts arbitrary prose
and never fails, while naming is N calls that are each validated — left alone, an agent follows that
gradient and produces a well-documented function still full of `local_2c`. Nothing propagates,
because the next session's tools read names and types, not prose.

```yaml
comments:
  PLATE:
    max_length: 300              # tightens the global 4096-char cap
    require_named_function: true # reject inside a still-FUN_/SUB_-named function
    max_auto_named_variables: 4  # reject while the function has more than N auto-named vars
    message: "Record findings by renaming, not by describing."
```

Every key is optional and every constraint is off unless set, so omitting the section — or
`--rules` entirely — leaves `set_comment` unconstrained. `max_auto_named_variables` counts listing
variables only (`local_`, `param_`, `unaff_`, `in_`, `extraout_`); the decompiler's own `uVar7`/
`iVar3` never reach the listing and are not counted. Comments on data (no enclosing function) are
subject to `max_length` alone. Clearing a comment is always allowed.

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
