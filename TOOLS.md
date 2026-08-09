# Tools reference

> Auto-generated from the Java annotations.  Run `make tools-docs` to regenerate.

## Infrastructure

### `check_connection`

Check if the Ghidra MCP server is running and responsive.

### `list_project_files`

List all program files in the Ghidra project.

## Functions

### `get_calling_conventions`

List all calling conventions available in a program's compiler spec. Use this to find valid values for the calling_convention field when calling set_function_prototype.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to get valid values. |

### `get_function_callees`

Get all functions called by the specified function.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to see available programs. |
| `name_or_address` | string | yes |  | Function name (case-sensitive) or 0x-prefixed hex entry-point address. |

### `get_function_info`

Get full details for a single function: signature, calling convention, size, and thunk status. Use search_functions to find the name or address first.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to get valid values. |
| `name_or_address` | string | yes |  | Function name (case-sensitive) or 0x-prefixed hex entry-point address. |

### `get_function_variables`

Get all parameters and local variables of a function.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to see available programs. |
| `name_or_address` | string | yes |  | Function name (case-sensitive) or 0x-prefixed hex entry-point address. |

### `search_functions`

Search for functions by name substring (case-insensitive). Returns name and address. Pass an empty string to list all functions. Optional start/end address filters limit results to function entry-points in a range. Use get_function_info for full details on any result.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to get valid values. |
| `query` | string |  |  | Substring to search for (case-insensitive). Pass an empty string to list all functions. |
| `limit` | integer (int32) |  | 100 | Maximum number of items to return (max 1000). 'count' is the size of this page; 'truncated' is true when further matches were dropped. |
| `start_address` | string |  |  | Optional start address (inclusive) for function entry-point filtering. |
| `end_address` | string |  |  | Optional end address (inclusive) for function entry-point filtering. |

## Decompilation

### `decompile_function`

Decompile a function to C pseudocode.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to see available programs. |
| `name_or_address` | string | yes |  | Function name (case-sensitive) or 0x-prefixed hex entry-point address. |
| `timeout_seconds` | integer (int32) |  | 0 | Optional override for decompile timeout in seconds. 0 means default. |

## Symbols

### `list_exports`

List all exported functions and symbols in a program. Returns all exports; no pagination.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to see available programs. |

### `list_imports`

List all imported external symbols in a program. Returns all imports; no pagination.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to see available programs. |

## Cross-references

### `get_xrefs_from`

List cross-references originating from an address with optional destination-range and ref-type filters.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to see available programs. |
| `address` | string | yes |  | Hex address with 0x prefix, e.g. 0x00401000. Use search_functions to find entry points. |
| `ref_types` | array of string |  |  | Optional reference type filter(s), e.g. CALL, COMPUTED_CALL, DATA, READ, WRITE. Can be repeated or comma-separated. |
| `start_address` | string |  |  | Optional lower bound (inclusive) for destination addresses. |
| `end_address` | string |  |  | Optional upper bound (inclusive) for destination addresses. |
| `limit` | integer (int32) |  | 500 | Maximum number of cross-references to return (max 5000). 'count' is the size of this page; 'truncated' is true when further matches were dropped. |

### `get_xrefs_to`

List cross-references to an address or symbol, with optional ref-type and source-address-range filtering. When the target resolves to a function entry point, indirect caller candidates are also returned.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to see available programs. |
| `name_or_address` | string | yes |  | Target: a function/symbol name (case-sensitive) — function, global, label, etc. — or a 0x-prefixed hex address (e.g. 0x00401000). |
| `ref_types` | array of string |  |  | Optional reference type filter(s), e.g. CALL, COMPUTED_CALL, DATA, READ, WRITE. Can be repeated or comma-separated. |
| `start_address` | string |  |  | Optional lower bound (inclusive) for xref source addresses. |
| `end_address` | string |  |  | Optional upper bound (inclusive) for xref source addresses. |
| `limit` | integer (int32) |  | 500 | Maximum number of cross-references to return (max 5000). 'count' is the size of this page; 'truncated' is true when further matches were dropped. Narrow with ref_types or start_address/end_address rather than raising this. |

## Data types

### `get_struct_layout`

Get the field layout of a structure data type.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to see available programs. |
| `name` | string | yes |  | Exact name of the structure data type. |

### `list_data_type_categories`

List all data type category paths in a program. Returns all categories; no pagination. Use search_data_types with a category path as the query to explore contents.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to see available programs. |

### `search_data_types`

Search for data types by name (case-insensitive). Pass an empty string to list all data types. Use list_data_type_categories to explore the category hierarchy. Note that the C99 fixed-width spellings (int8_t..int64_t, uint8_t..uint64_t, size_t, ssize_t, intptr_t, uintptr_t, ptrdiff_t) are accepted by every tool that takes a type name even when they are absent here — they resolve to a type of exactly that width.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to get valid values. |
| `query` | string |  |  | Substring filter applied to data type names (case-insensitive). Pass an empty string to list all data types. |
| `limit` | integer (int32) |  | 50 | Maximum number of items to return (max 500). 'count' is the size of this page; 'truncated' is true when further matches were dropped. |

## Strings

### `search_defined_strings`

Search for defined strings across the program listing.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to see available programs. |
| `query` | string |  |  | Optional substring match (case-insensitive) applied to string values. Pass an empty string or omit to list all defined strings. |
| `offset` | integer (int32) |  | 0 | 0-based item offset for pagination. O(n) cost — avoid large offsets on large programs. |
| `limit` | integer (int32) |  | 200 | Maximum number of items to return (max 1000). 'count' is the size of this page; 'truncated' is true when further matches were dropped — raise 'offset' by 'count' to page on. |

## Write operations

### `add_script`

Copy an existing script file into the Ghidra user script directory, making it available to run_script. This takes a snapshot: later edits to the source file are NOT picked up — call add_script again after every edit.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `file_path` | string | yes |  | Path to an existing script file to move into the Ghidra user script directory |

### `add_struct_field`

Add a field to an existing structure.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name |
| `struct_name` | string | yes |  | Struct name to modify |
| `field_name` | string | yes |  | Field name (max 256 chars) |
| `type_name` | string | yes |  | Field data type |
| `comment` | string |  |  | Optional field comment (max 4096 chars) |
| `offset` | integer (int32) |  |  | Byte offset at which to place the field within an existing struct gap. The offset must point to undefined (unnamed) bytes — it may not overlap any existing named field. The field must fit entirely within the struct: offset + field_size must be <= struct size. Use this to name a gap left by replace_struct_field shrinking a field, e.g. offset=18 places a 1-byte field at offset 0x12 without inflating the struct. Omit this parameter to append the field after the last defined component (may grow the struct). |

### `create_label`

Create a named label at the given address.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name |
| `address` | string | yes |  | 0x-prefixed hex address at which to create the label |
| `name` | string | yes |  | Label name (max 256 chars) |

### `create_struct`

Create a new structure data type in the program's Data Type Manager.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name |
| `name` | string | yes |  | Struct name (max 256 chars) |
| `size` | integer (int32) |  |  | Initial size in bytes |
| `category` | string |  |  | Category path to place the struct in |
| `override` | boolean |  |  | If true and the struct already exists, clear and resize it in place instead of replacing the data type object |

### `import_binary`

Import a binary file into the Ghidra project and run full auto-analysis. The returned program name can be used immediately with all other tools. The format is auto-detected; a headerless image (a raw flash dump or firmware blob) has nothing to detect, so pass language_id and base_address for those.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `file_path` | string | yes |  | Absolute path to the binary file to import, e.g. /home/user/target.exe. |
| `project_dir` | string |  |  | Project folder path where the binary will be saved, e.g. "hello/bin". Intermediate folders are created automatically. Omit or pass "/" to place the binary in the project root. Subject to import.min_directory_depth and import.require_child_path constraints in rules.yaml. |
| `language_id` | string |  |  | Ghidra language/processor id, e.g. "ARM:LE:32:Cortex" or "x86:LE:64:default". Omit for any file with a recognisable header (ELF, PE, Mach-O) — the loader detects it. Required for a headerless image, which carries nothing to detect from. |
| `base_address` | string |  |  | 0-prefixed hex load address, e.g. "0x08000000". Applied before auto-analysis, so recovered addresses and pointers are correct. Omit to load at the format's own base (0x0 for a headerless image). |

### `remove_struct_field`

Remove a field from a structure by field name without moving later fields.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name |
| `struct_name` | string | yes |  | Struct name |
| `field_name` | string | yes |  | Name of the field to remove (max 256 chars) |

### `rename_function`

Rename a function.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name |
| `name_or_address` | string | yes |  | Current name or hex address of the function |
| `new_name` | string | yes |  | New function name (max 256 chars) |

### `rename_global`

Rename a global symbol (data, label, or import) by name or hex address.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name |
| `name_or_address` | string | yes |  | Current name or 0x-prefixed hex address of the global symbol |
| `new_name` | string | yes |  | New symbol name (max 256 chars) |

### `rename_variable`

Rename a local variable or parameter in a function.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name |
| `name_or_address` | string | yes |  | Function containing the variable |
| `variable_name` | string | yes |  | Current variable or parameter name |
| `new_name` | string | yes |  | New variable name (max 256 chars) |

### `replace_struct_field`

Replace an existing structure field in place without moving later fields.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name |
| `struct_name` | string | yes |  | Struct name |
| `field_name` | string | yes |  | Field name to replace |
| `type_name` | string | yes |  | Replacement field data type |
| `new_name` | string |  |  | Optional replacement field name (max 256 chars) |
| `comment` | string |  |  | Optional replacement field comment (max 4096 chars) |

### `set_comment`

Set a comment on a code unit at the specified address.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name |
| `address` | string | yes |  | Hex address |
| `comment` | string | yes |  | Comment text (max 4096 chars) |
| `type` | string |  |  | Comment type: PRE, POST, EOL, PLATE, or REPEATABLE |

### `set_function_prototype`

Set a function's return type, calling convention, and parameter list.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name |
| `name_or_address` | string | yes |  | Function name or hex address |
| `return_type` | string | yes |  | Return type name |
| `parameters` | array of object {name, type_name} |  |  | Ordered parameter list; each entry is {name, type_name}. Replaces the function's existing parameters — omit or pass an empty array for a no-argument function. |
| `calling_convention` | string |  |  | Calling convention name (e.g. __cdecl, __stdcall, __fastcall, __thiscall). Use get_calling_conventions to see valid values for this program. |

### `set_parameter_type`

Set the data type and optionally the name of a specific function parameter by index.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name |
| `name_or_address` | string | yes |  | Function name or hex address |
| `parameter_index` | integer (int32) | yes |  | 0-based parameter index |
| `type_name` | string | yes |  | Data type to assign |
| `new_name` | string |  |  | Optional new parameter name (max 256 chars) |

## Scripting

### `delete_script`

Delete a script from the Ghidra user script directory.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `filename` | string | yes |  | Script filename returned by list_scripts |

### `run_script`

Run a Ghidra script against an open program. Searches the user script directory and all extension script directories. Omitting 'args' passes an empty argument list; by convention the bundled scripts treat that as a request for their built-in help and print their argument list instead of running. That is a script-authoring convention, not server behaviour — a script that genuinely takes no arguments should just run. Use get_script_description for a script's header documentation either way. Ghidra runs the script inside a transaction it opens around run(), so a script must NOT open its own outer transaction. An operation that manages its own transaction (Program.setLanguage is the usual one) must be wrapped in end(true) before and start() after, or it throws; returning from run() with an extra transaction still open is an error and the program is evicted and reopened.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name to bind as the current program |
| `filename` | string | yes |  | Script filename returned by list_scripts |
| `args` | array of string |  |  | Optional arguments passed to the script via getScriptArgs(). Omit to trigger the script's built-in help output. |

## Other

### `analyze_program`

Run Ghidra's full auto-analysis on an already-imported program and block until completion. Required once for any program imported outside MCP (e.g. via the Ghidra GUI): every other tool rejects a program that has never been analyzed. Also use it to re-run analysis after large structural edits. import_binary already analyzes on import — you do not need to call this after a successful import.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name as listed by list_project_files. |

### `batch_tool_call`

Run one allowlisted read or write tool many times with different arguments, returning ordered per-call results. Prefer this over one call per item when renaming or commenting several things in a function.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `tool` | string | yes |  | Allowlisted read or write tool operationId to execute. |
| `calls` | array of object | yes |  | List of argument objects, each exactly what the tool takes on its own. One tool call is executed per item, in order; a failed item does not stop the rest. Maximum 50. |

### `get_address_info`

Get detailed information about a specific address: the memory segment it belongs to, the function containing it (if any), and all cross-references pointing to it.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to get valid values. |
| `address` | string | yes |  | Address in 0x-prefixed hex, e.g. 0x00401000. |

### `get_disassembly`

Get disassembly lines starting at an address for a fixed number of instructions.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to get valid values. |
| `address` | string | yes |  | Start location: a 0x-prefixed hex address (e.g. 0x00401000) or a symbol/function name (case-sensitive). A name resolves to that symbol's address. |
| `limit` | integer (int32) |  | 20 | Maximum number of instructions to return (max 2000). If more instructions follow the returned window, the response 'truncated' flag is true and 'next_address' points to the first instruction not returned. |

### `get_program_info`

Get core program metadata including image base, executable format, language/compiler IDs, and memory blocks.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to get valid values. |

### `get_script_description`

Get metadata and description for a script — equivalent to clicking a script in Ghidra's Script Manager. The bundled scripts also print their argument list when run_script is called with no args.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `filename` | string | yes |  | Script filename (e.g. AuditFunction.java) |

### `list_globals`

List named global symbols grouped by functions, data, and labels, with optional section and address-range filters.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to get valid values. |
| `section` | string |  |  | Optional memory block/section name filter, e.g. .data or .bss. |
| `start_address` | string |  |  | Optional start address (inclusive) for symbol address filtering. |
| `end_address` | string |  |  | Optional end address (inclusive) for symbol address filtering. |
| `limit` | integer (int32) |  | 500 | Maximum number of symbols to return across all groups (max 5000). 'count' is the size of this page; 'truncated' is true when further matches were dropped. |

### `list_scripts`

List available Ghidra scripts. Use mcp_scripts_only=true to list only scripts bundled with this extension (in its ghidra_scripts/ directory, with guaranteed JSON output and built-in help). Without the filter, also includes user scripts added via add_script.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `mcp_scripts_only` | boolean |  | False | When true, return only extension-provided scripts. When false (default), return all scripts. |

### `read_data`

Read raw memory bytes from an address as fixed-size items.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to get valid values. |
| `address` | string | yes |  | Start address in 0x-prefixed hex, e.g. 0x00401000. |
| `item_size` | integer (int32) |  | 1 | Byte width of each item to read. Must be >= 1. |
| `item_count` | integer (int32) |  | 16 | Number of items to read. Must be >= 1. |

### `search_bytes`

Search initialized memory for a hex byte pattern. Supports wildcards with ?? and optional address-range filtering.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to get valid values. |
| `hex_pattern` | string | yes |  | Hex byte pattern, e.g. 'FF ?? 48' or '68 4E 58 50 20'. |
| `start_address` | string |  |  | Optional start address (inclusive) for the search range. |
| `end_address` | string |  |  | Optional end address (inclusive) for the search range. |
| `limit` | integer (int32) |  | 100 | Maximum number of hits to return (max 2000). |

### `search_constant_references`

Find all instructions that use a specific constant as an immediate operand. Useful for locating every usage of a magic number, error code, or flag value, e.g. passing 0x100D0 to find all mov/cmp/push instructions referencing that constant.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to see available programs. |
| `value` | string | yes |  | Constant to search for. Accepts decimal (e.g. 65744), 0x-prefixed hex (e.g. 0x100D0), or a negative value treated as its unsigned bit pattern (e.g. -1 matches 0xFFFFFFFFFFFFFFFF). |
| `limit` | integer (int32) |  | 200 | Maximum number of hits to return (max 2000). 'count' is the size of this page; 'truncated' is true when further matches were dropped. |

### `search_instructions`

Search decoded instructions for a byte-pattern prefix (supports ?? wildcards) with optional address-range filtering.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Name of the open program to analyze. Use list_project_files to get valid values. |
| `pattern` | string | yes |  | Instruction byte pattern, e.g. 'FF ?? 48'. |
| `start_address` | string |  |  | Optional start address (inclusive) for instruction filtering. |
| `end_address` | string |  |  | Optional end address (inclusive) for instruction filtering. |
| `limit` | integer (int32) |  | 100 | Maximum number of hits to return (max 2000). |

