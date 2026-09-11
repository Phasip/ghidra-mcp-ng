# ghidra-mcp-ng

A Ghidra extension that exposes reverse-engineering operations as an MCP (Model Context Protocol) server over JSON-RPC 2.0 on stdio. Designed to be driven by an AI agent (Claude, GPT-4, etc.) via any MCP-compatible client.

## Why this exists

- Existing Ghidra MCP servers had broad feature surfaces but many of those features were buggy and confused the LLM driving them.
- Existing servers required the Ghidra UI to be running, which made them awkward for unattended or long-form work.
- Existing servers felt geared toward short, AI-assisted tasks rather than letting an LLM drive a full reverse-engineering workflow on its own.

## Features

- Tools covering function analysis, decompilation, cross-references, data types, structs, comments, and managed scripting
- `rules.yaml` — an optional server-side policy file that holds the agent to your conventions: it rejects names that do not match your patterns, constrains comments so prose cannot stand in for names and types, and sets decompilation timeouts. It ships as a working example you can edit, and the server runs without it
- `REVERSING.md` — the reversing methodology the naming conventions come from, written to be handed to the agent
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

Give the agent **[REVERSING.md](REVERSING.md)** alongside the tools. The tool schemas say what
each call does; that document says what to do with them — when to name rather than comment, what
the `maybe_`/`likely_`/`guess_` prefixes mean, why a finding that is not a name or a type is lost
at the end of the session. It is the reasoning half of the same surface `rules.yaml` enforces, and
an agent that has not read it discovers those conventions by having writes rejected. In Claude
Code, the natural home is a skill that points at it; any client with a system prompt or project
instructions works as well.

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

The envelope is for HTTP callers. `bridge.py` strips it before the result reaches an MCP client:
success is already carried by the absence of `isError`, and a failure is delivered as the server's
own message with nothing prefixed to it.

---

## Server config (`rules.yaml`)

`rules.yaml` is where you write down what a good annotation looks like on your projects, so the
server can hold the agent to it instead of you doing it in review. It is **optional** — pass it
with `--rules`, omit it and every rule below is simply off — and the copy in this repository is a
working example rather than a required config, meant to be edited or replaced.

It governs four things: the **names** write tools will accept, the **comments** `set_comment` will
accept, an opt-in **read budget** that caps how far reading may run ahead of what has been written
down, and **timeouts** for long-running operations. Rules are checked before the program is
touched: a violation returns `{"isError":true}` with the configured message and writes nothing.

The conventions the shipped file enforces — the `maybe_`/`likely_`/`guess_` prefixes and the
struct-field offset suffix — are not arbitrary. They come from the methodology in
**[REVERSING.md](REVERSING.md)**, which is written for the agent to read: give it that document
and the rules stop being obstacles it has to discover by failing.

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
| `variable_name` | `set_variable`, `set_parameter_type`, `set_function_prototype` parameters |
| `struct_name` | `create_struct` |
| `struct_field_name` | `add_struct_field`, `replace_struct_field` |
| `label_name` | `create_label` |
| `global_name` | `set_global` |

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

### Read budget

An optional `reads:` section caps how far reading may run ahead of the record. **It ships
disabled** (`max_without_write: 0`) and is the one rule worth leaving off until you have watched
an agent work on your own targets — unlike the others it can fire on a call chain that genuinely
had to be followed before anything was worth naming. Same gradient as above, one step earlier:
reading is one cheap call that always succeeds, writing is N validated calls that can fail, and
an agent that follows it decompiles thirty functions, understands the
binary perfectly in its own context, writes none of it down, and leaves the next session opening
the project to `FUN_00401000` again.

```yaml
reads:
  max_without_write: 0    # reads allowed between writes; 0 (the shipped value) disables the rule
  allow_ignore: true      # true = advisory (resets as it fires); false = forces a write
  message: "Persist what you already worked out before reading further."
```

`message` is the **entire** error the agent is shown — nothing is prepended or appended, so it
replaces the built-in diagnostic rather than decorating it. Say everything the agent needs,
including what to do next. Omit the key to fall back to the built-in text, which states the
limit, names `reads.max_without_write`, and lists the tools that clear it. The shipped
`rules.yaml` carries a complete message and a tuned example, both inert until you raise
`max_without_write` above zero.

Only `decompile_function` and `get_disassembly` are counted — those are where a function's
contents arrive and a finding is made. Searches, xrefs and listings are navigation, and charging
them would only teach the agent to navigate blind. A call that fails its own argument validation
is never charged, and the count is server-wide rather than per program.

The budget is cleared by a write that records a finding: `rename_function`, `set_variable`,
`set_global`, `create_label`, `set_function_prototype`, `set_parameter_type`, `create_struct`,
`add_struct_field`, `remove_struct_field`, `replace_struct_field`. Deliberately **not** by
`set_comment` — prose substituting for names and types is exactly what this rule exists to stop,
so a comment must not buy more reading — nor by `run_script`, whose effect on the program cannot
be inspected from here, so a read-only audit script would otherwise clear the budget for free.
`analyze_program` and `import_binary` are program lifecycle, not findings, and do not clear it.

`allow_ignore` decides what happens once the budget is spent:

| Value | Behaviour |
|---|---|
| `true` | Advisory. The budget resets as the error is raised, so repeating the call succeeds and the same error returns one budget later. The agent is nagged, never stuck. |
| `false` | Forcing. Every further read is refused until a qualifying write lands. |

Struct workflow notes:

- `create_struct` accepts `override=true` to clear and resize an existing struct in place without replacing the underlying data type object.
- `add_struct_field`, `remove_struct_field`, and `replace_struct_field` preserve later field offsets for non-packed structs and reject edits that would force a relayout.
- If a type lookup fails for `code*`, the error explains that `code*` is a Ghidra-internal generated type and points at the function-pointer declarator below, or `void*` if the signature is still unknown.

Callback types:

- Every `type_name` also accepts a C function-pointer declarator — `int (*)(void *dst, int nbytes)` — which creates the function-definition type and applies a pointer to it. An optional calling convention goes where C puts it: `int (__stdcall *)(int)`. `return_type_name` takes one too.
- Ghidra has no anonymous function definition, so applying a signature always creates one. An unnamed declarator names it after its own signature, in `/functions`: `int (*)(int a, int b)` becomes `func_int__int_int`, and the callback reaches the next parameter, struct field or vtable slot as `func_int__int_int *`. Writing the same signature anywhere else finds that same type, and two different signatures can never want the same name.
- To choose the name yourself, write it where C writes it — `int (*maybe_readCb)(void *dst, int nbytes)` — and the definition is called `maybe_readCb`. That name is refused, not redefined, if the program already has something else by it: every site already typed with the definition would change with it.
- This matters because an untyped function pointer leaves the decompiler inferring each indirect call's arity from the pushes at that call site, so one callback comes out with a different signature at every site. One applied type fixes them all.

Omit `--rules` to disable all naming rules and use the built-in default timeouts.

---

## Tools reference

See **[TOOLS.md](TOOLS.md)** for the full, up-to-date tool reference with parameters and descriptions.

`TOOLS.md` is auto-generated from the Java annotations.  Regenerate it any time with:

```bash
make tools-docs
```

### How the tool surface is exposed

The MCP client is not handed every tool at once. Listing a tool costs its full JSON schema in
every session whether or not it is ever called, so `bridge.py` lists only the tools a session
uses constantly — orientation, function lookup, decompilation, disassembly, xrefs, renaming,
comments, scripts — plus three discovery tools:

| Tool | Purpose |
|---|---|
| `list_tools` | Browse the rest, grouped by category (`Annotation`, `Code`, `Cross-references`, `Data types`, `Functions`, `Program`, `Scripting`, `Symbols and memory`) |
| `describe_tool` | Fetch one tool's full parameter schema on demand (`tool_name`) |
| `call_tool` | Run any tool by name, listed or not (`tool_name` + `arguments`) |

Everything remains reachable — an unlisted tool is one `call_tool` away, and the direct HTTP
API is unaffected. Categories come from the `tags` field on each tool's `@Operation`
annotation, which is also what groups `TOOLS.md`. To change what is listed up front, edit
`HOT_CORE` in `bridge.py`.

The schema those three answer from is the running server's own `/openapi.json`, cached per
server process: `/health` carries a `started_at` that changes on every start, and the bridge
re-fetches when it does. Without that, a rebuilt-and-restarted server keeps being described by
the schema of the one it replaced, and `describe_tool` advertises fields the live server rejects.

### What the bridge publishes

Everything an MCP client sees is derived from that document — no tool is defined in `bridge.py`.

- **Protocol version.** The bridge speaks `2025-06-18` back to `2024-11-05` and answers with the
  version the client asked for when it is one of those, otherwise with the newest it supports.
- **Tool annotations.** Each tool carries `readOnlyHint`, `destructiveHint`, `idempotentHint` and
  `openWorldHint`, so a host can auto-approve a lookup without auto-approving a script run. Most
  of it follows from the method — a GET reads and repeats harmlessly, a POST does neither — and
  `McpToolHints.java` names the tools that contradict the default. `TOOLS.md` prints the result
  under every tool.
- **Timeouts.** Also from `McpToolHints.java`: full auto-analysis, imports and script runs get 30
  minutes rather than the default two, and a call that does run out of time is reported as a
  timeout against a server that is still working, not as an unreachable server.
- **Results.** Structured results arrive as compact JSON; a multi-line string — decompiled C,
  script output — is printed as itself rather than as a JSON-escaped one-liner.

### Specialized analyses are scripts, not tools

The tool surface holds general primitives only — functions, addresses, symbols, types, memory.
Anything tied to one executable format, toolchain or analysis recipe ships as a `GhidraScript`
in `ghidra_scripts/` (PE parsing, vtable recovery, signature propagation, program and function
audits) and is reached with `list_scripts` → `get_script_description` → `run_script`. This
keeps narrow capabilities out of every session's context while leaving them one call away, and
`add_script` lets you add your own the same way.

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
├── ghidra_scripts/             # Bundled GhidraScripts, reached through run_script
├── scripts/
│   └── generate_tools_docs.py  # Renders TOOLS.md from the OpenAPI document
├── src/
│   ├── main/java/com/ghidramcpng/
│   │   ├── GhidraMcpServer.java          # GhidraLaunchable entry point
│   │   ├── GenerateSpec.java             # Emits build/openapi.json without a running server
│   │   ├── mcp/
│   │   │   ├── HttpApiServer.java        # Jersey bootstrap, providers, /health and /openapi.json
│   │   │   ├── ApiSupport.java           # Response envelope and shared error wording
│   │   │   ├── McpToolHints.java         # Per-tool behaviour hints published as "x-mcp"
│   │   │   └── ServerLog.java            # Stack traces behind the error_id in a 500
│   │   ├── program/
│   │   │   ├── ProgramManager.java       # Lazy program open, transactions, save
│   │   │   └── TemporaryNames.java       # Tracks decompiler temporaries across renames
│   │   ├── rules/
│   │   │   ├── RulesConfig.java          # SnakeYAML bean for rules.yaml
│   │   │   ├── RulesEngine.java          # Pattern validation + exemptions
│   │   │   └── NamingRuleViolation.java  # Thrown on rule violation
│   │   ├── model/                        # Shared DTO records
│   │   └── tools/
│   │       ├── ToolHelpers.java          # Shared lookup + decompiler utilities
│   │       ├── ReadTools.java            # Read-only HTTP tools
│   │       ├── WriteTools.java           # Program-modifying HTTP tools
│   │       └── ScriptTool.java           # Script management and execution tools
│   └── test/java/com/ghidramcpng/
│       ├── mcp/McpToolHintsTest.java     # Guards the behaviour-hint tables against drift
│       ├── rules/RulesEngineTest.java    # Naming-rule mechanics
│       └── tools/ToolResourceIntegrationTest.java   # Every route against a real program
├── REVERSING.md                          # Reversing methodology handed to the agent
└── tests/
    ├── conftest.py                       # pytest fixtures (live server per worker)
    ├── test_bridge.py                    # bridge.py, offline
    ├── test_integration.py               # Every tool against a live server
    └── test_schema_matches_implementation.py
```


# Security
No security, LLM and anyone who reaches the server can run anything through scripting 
