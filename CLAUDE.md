# CLAUDE.md — ghidra-mcp-ng

Guidance for AI agents working in this repo. Read this before adding or changing tools.

`ghidra-mcp-ng` is a Ghidra extension that exposes reverse-engineering operations as an
**annotation-driven JAX-RS HTTP API** (Jersey + JDK HTTP server). An AI agent drives it
through the thin stdlib MCP bridge (`bridge.py`), which translates MCP tool calls into
HTTP requests. The guiding principle for the whole codebase: **every error must be clear,
specific, and actionable so an LLM can self-correct without guessing.**

## Design principles (read first)

Three principles outrank almost everything else here. When a change trades one of them away
for convenience, don't make it — reconsider the design.

1. **Consistency.** The tool surface must feel like one API, not a pile of independently
   authored endpoints. The same concept uses the same parameter name everywhere
   (a function/symbol identifier is `name_or_address` — never `address_or_name` or a bare
   `address` when a name is also accepted); responses use the same shapes and the same
   snake_case keys; list/search tools share the same `limit`/`truncated`/`count` conventions;
   errors follow the same specific-and-actionable style. Before adding a parameter or a
   response field, find how the nearest existing tool spells the same idea and match it. An
   agent that learned one tool should be able to predict the next.
2. **A small, sharp tool set — not many functions.** This project exists because other Ghidra
   MCP servers had broad, buggy surfaces that confused the LLM driving them. Fewer tools that
   each work reliably beat many overlapping ones. **Default to extending an existing tool
   (an optional parameter, a richer response) rather than adding a new one.** Add a tool only
   when the capability is genuinely distinct and can't live as an option on something that
   already exists. Every new tool is one more thing the agent must learn, disambiguate, and
   possibly misuse — treat that as a real cost.
3. **Breaking changes are cheap; correctness is not.** The only consumer is an LLM agent that
   reads the current tool schema on every session and adapts immediately — there is no pinned
   client, no stored integration, no deprecation window to honor. So do not preserve backward
   compatibility for its own sake: when a parameter name, response shape, or behavior is wrong,
   change it outright rather than layering an alias or a compatibility shim on top. A cleaner,
   more consistent surface (principles 1–2) always beats a stable-but-crufty one. By the same
   token, **never silently accept or "fix" invalid input** — do not coerce a malformed address,
   guess at a misspelled name, or fall back to a default when a required value is wrong. Reject
   it with a clear, specific, actionable error (see coding standard 1) and let the agent
   correct itself. Guessing hides bugs and teaches the agent the wrong thing; a sharp error
   teaches it the right one.

## Project structure

```
src/main/java/com/ghidramcpng/
  GhidraMcpServer.java     Entry point (GhidraLaunchable); wires ProgramManager, RulesEngine, HttpApiServer.
  GenerateSpec.java        CLI that emits build/openapi.json from annotations (no server). Feeds TOOLS.md.
  mcp/
    HttpApiServer.java     Jersey bootstrap. Registers resources + providers:
                           GsonProvider (JSON, Address→0x-hex), ApiExceptionMapper (Throwable→JSON),
                           UnknownQueryParamFilter (rejects undeclared query params), MetaResource
                           (/health, /schema, /openapi.json).
    ApiSupport.java        JSON envelope helpers: ok(result) / error(status, msg) → {"ok":bool,...}.
  program/
    ProgramManager.java    Lazy open+cache (getOrOpen), auto-analysis, import, and withTransaction(...).
  rules/
    RulesEngine.java       validate(fieldType, name) + validateImport(...) from rules.yaml.
    RulesConfig.java       SnakeYAML bean.  NamingRuleViolation.java  (→ 400).
  tools/
    ReadTools.java         Read-only @GET/@POST tools + their response records + batch_tool_call.
    WriteTools.java        Write @POST tools + request/response records.
    ScriptTool.java        Managed scripting: list_scripts, get_script_description, add_script,
                           run_script, delete_script.
    ToolHelpers.java       Shared lookups + decompiler + param-validation helpers (see below).
  model/                   Shared DTO records: FunctionEntry, FunctionRef, XrefEntry, VariableEntry,
                           StructField, DataTypeEntry, ExportEntry, ImportEntry, StringEntry.

bridge.py                  stdlib-only MCP↔HTTP bridge (no deps).
start.py, build_and_install.py   Launch / build+install helpers.
rules.yaml                 Naming-convention + timeout config (optional at runtime).
TOOLS.md                   GENERATED tool reference — do not hand-edit; regenerate from the spec.
tests/                     Python: conftest.py (live-server fixture), test_integration.py (live),
                           test_bridge.py (offline). src/test/java: ToolResourceIntegrationTest,
                           RulesEngineTest.
```

The MCP tool count is derived by reflection (`ToolHelpers.countEndpoints`), so it stays in
sync automatically — never hardcode it. For the current tool list, see `TOOLS.md`.

## How a tool is defined

A tool is a public method on `ReadTools`/`WriteTools`/`ScriptTool` annotated with JAX-RS +
swagger annotations. The `operationId` IS the MCP tool name.

**GET (read) tools** take `@QueryParam` arguments:

```java
@GET
@Path("/get_function_info")
@Operation(operationId = "get_function_info", summary = "One-line description shown to the agent.")
@ApiResponse(responseCode = "200", description = "...",
        content = @Content(schema = @Schema(implementation = FunctionEntry.class)))
public FunctionEntry getFunctionInfo(
        @Parameter(description = "...", required = true) @QueryParam("program") String programName,
        @Parameter(description = "...", required = true) @QueryParam("name_or_address") String nameOrAddress) {
    Program program = openProgram(programName);
    return FunctionEntry.from(findFunction(program, requireText(nameOrAddress, "name_or_address")));
}
```

**POST (write) tools** take a `JsonObject request` body. You MUST attach an explicit
`@RequestBody(@Content(schema = @Schema(implementation = XxxRequest.class)))` and define a
matching request record with `@Schema` fields — otherwise the generated OpenAPI request
body is empty and the params are undiscoverable.

```java
@POST @Path("/rename_function")
@Operation(operationId = "rename_function", summary = "Rename a function.")
public RenameFunctionResponse renameFunction(
        @RequestBody(required = true,
                content = @Content(schema = @Schema(implementation = RenameFunctionRequest.class)))
        JsonObject request) {
    String programName = required(request, "program");
    String current     = required(request, "name_or_address");
    String newName      = requireMaxLength(required(request, "new_name"), "new_name", MAX_NAME_LENGTH);
    rules.validate("function_name", newName);                 // naming rules BEFORE writing
    Program program = openProgram(programName);
    runTransaction(program, "Rename function: " + current + " -> " + newName, () -> {
        Function f = findFunction(program, current);
        f.setName(newName, SourceType.USER_DEFINED);
    });
    return new RenameFunctionResponse(true, newName);
}
```

Request/response DTOs are **Java records** with **snake_case component names** (they become
JSON keys). Add `@Schema(description=...)` for docs. `Address` fields serialize to
`"0x..."` automatically via `GsonProvider`.

## Coding standards

1. **Error messages are the product.** Diagnose the *actual* failure and stop there — do
   not enumerate every possibility. Name the offending value, say why it failed, and point
   to the exact tool/next step. Prefer a "did you mean" suggestion over dumping a catalogue.
   Reference implementations of this standard:
   - `UnknownQueryParamFilter` — rejects unknown query params, suggests the closest valid one.
   - `ToolHelpers.findFunction` — a mid-function address names the containing function and its entry point.
   - `ToolHelpers.findDataType` — an unknown type suggests near matches, never lists all types.
   - `WriteTools.findVariable` — distinguishes a decompiler temporary from a truly missing name.
2. **Validate with the helpers**, don't hand-roll:
   - GET: `requireText`, `requirePositive`, `requireNonNegative`, `requireLimit(value,max,field)`.
   - POST body: `required`, `optional(...,default)`, `optionalInt`, `optionalBool`,
     `optionalArray`, `requireMaxLength(v,field,MAX_*)`.
   - Missing required arg → `IllegalArgumentException("Required parameter 'X' is missing")`.
3. **Exceptions map to HTTP status:** `IllegalArgumentException` and `NamingRuleViolation`
   → 400 (via `ApiExceptionMapper`); anything else → 500. In `openProgram`/`runTransaction`,
   rethrow `RuntimeException` as-is (preserves 400s) and wrap only checked exceptions, adding
   context. Do not swallow exceptions.
4. **Resolution helpers** (in `ToolHelpers`) — reuse, don't reinvent:
   - `findFunction(program, nameOrAddress)` — function by exact name or `0x` entry-point address.
   - `findSymbolAddress(program, nameOrAddress)` — any symbol type → address.
   - `toAddress(program, str)` — `0x`-prefixed hex only (prefix is required everywhere).
   - `findDataType(program, name)` — handles `type*` and `type[N]` notation.
5. **Transactions:** wrap every program mutation in `runTransaction(program, desc, () -> ...)`
   (→ `ProgramManager.withTransaction`). Do expensive read work (lookups, diagnostic
   decompiles) *before* opening the transaction, not inside it.
6. **Naming rules:** call `rules.validate("<field_kind>", name)` before writing any name
   (`function_name`, `variable_name`, `struct_name`, `struct_field_name`). Rules are enforced
   uniformly — there are no exemptions (e.g. `this`, struct type names all go through it).
7. **Batch:** to make a read tool batchable, add its operationId to `BATCH_ALLOWLIST` AND a
   case in `dispatchBatchTool` in `ReadTools`. Write/script tools are never batchable.
8. **Match the neighbours (consistency principle).** Reuse the established spelling of every
   shared concept — `program`, `name_or_address`, `limit`, `truncated`, `count`, `start_address`
   /`end_address`, `ref_types` — rather than inventing a synonym. New response records should
   mirror the field naming of the closest existing record. A divergent name is a bug even if it
   works.
9. **Prefer extending over adding (minimal-surface principle).** Before writing a new
   `@GET`/`@POST` method, check whether an optional parameter or a richer response on an
   existing tool covers the need. Only add a tool for a genuinely distinct capability.
10. Java: 4-space indent, K&R braces, records for DTOs. Python: PEP 8, max line 120. Comments
    explain *why*, not *what*, and stay short.

## Build / test / docs workflow

Requires `GHIDRA_HOME` pointing at a Ghidra install (in this environment:
`/home/develop/tools/ghidra`).

```bash
# compile
GHIDRA_HOME=$GHIDRA_HOME gradle compileJava --no-daemon -q
# build the extension zip → dist/ghidra_<ver>_<date>_ghidra-mcp-ng.zip
GHIDRA_HOME=$GHIDRA_HOME gradle buildExtension --no-daemon
# regenerate the tool spec + docs after changing any annotation/schema
make tools-docs        # = generateOpenApiSpec + scripts/generate_tools_docs.py → TOOLS.md
# tests
GHIDRA_HOME=$GHIDRA_HOME gradle test --no-daemon          # Java
GHIDRA_HOME=$GHIDRA_HOME python3 -m pytest tests/          # Python (needs gcc; live headless server)
```

**Two gotchas that will silently waste your time:**
- The pytest live-server fixture installs the **newest `dist/*.zip`** and does **not**
  rebuild. After any Java change you MUST run `gradle buildExtension` before `pytest`, or
  the integration tests run against stale code.
- After changing a tool's annotations, params, or response records, regenerate `TOOLS.md`
  (`make tools-docs`) — it is generated, not hand-maintained.

## Definition of done for a tool change

- If this adds a tool: you confirmed the capability can't reasonably be an option on an
  existing one (minimal-surface principle), and its parameter/response names match the
  existing conventions (consistency principle).
- The tool compiles and its OpenAPI schema is populated (POST tools need the `@RequestBody`
  + request record).
- Integration test(s) in `tests/test_integration.py` cover the happy path AND the error
  path. An invalid/missing argument must return `{"ok": false, "error": ...}` with a clear
  message — never an unhandled 500.
- `TOOLS.md` regenerated; full test suite green against a freshly built extension.
