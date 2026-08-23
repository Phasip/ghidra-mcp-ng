# Tools reference

> Auto-generated from the Java annotations.  Run `make tools-docs` to regenerate.

## Annotation

### `create_label`

Create a named label at the given address.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `address` | string | yes |  | 0x-prefixed hex address at which to create the label |
| `name` | string | yes |  | Label name (max 256 chars) |

### `rename_function`

Rename a function.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `name_or_address` | string | yes |  | Function name (case-sensitive) or 0x-prefixed hex entry point. |
| `new_name` | string | yes |  | New function name (max 256 chars) |

### `rename_global`

Rename a global symbol (data, label, or import) by name or hex address.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `name_or_address` | string | yes |  | Current name or 0x-prefixed hex address of the global symbol |
| `new_name` | string | yes |  | New symbol name (max 256 chars) |

### `set_comment`

Set a comment on a code unit at the specified address.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `address` | string | yes |  | 0x-prefixed hex address. |
| `comment` | string | yes |  | Comment text (max 4096 chars) |
| `type` | string |  |  | Comment type: PRE, POST, EOL, PLATE, or REPEATABLE |

### `set_function_prototype`

Set a function's return type, calling convention, and parameter list.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `name_or_address` | string | yes |  | Function name or hex address |
| `return_type` | string | yes |  | Return type name |
| `parameters` | array of object {name, type_name} |  |  | Ordered parameter list; each entry is {name, type_name}. Replaces the function's existing parameters — omit or pass an empty array for a no-argument function. |
| `calling_convention` | string |  |  | Calling convention name (e.g. __cdecl, __stdcall, __fastcall, __thiscall). Use get_calling_conventions to see valid values for this program. |

### `set_parameter_type`

Set the data type and optionally the name of a specific function parameter by index.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `name_or_address` | string | yes |  | Function name or hex address |
| `parameter_index` | integer (int32) | yes |  | 0-based parameter index |
| `type_name` | string | yes |  | Data type to assign |
| `new_name` | string |  |  | Optional new parameter name (max 256 chars) |

### `set_variable`

Rename and/or retype one parameter or local variable in a function.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `name_or_address` | string | yes |  | Function name (case-sensitive) or 0x-prefixed hex entry point. |
| `variable_name` | string | yes |  | Current variable or parameter name; see get_function_variables. |
| `new_name` | string |  |  | New variable name (max 256 chars); omit to keep the current one. |
| `type_name` | string |  |  | Data type to assign, e.g. int, char *, MyStruct *; omit to keep the current one. |

## Code

### `decompile_function`

Decompile a function to C pseudocode.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `name_or_address` | string | yes |  | Function name (case-sensitive) or 0x-prefixed hex entry point. |
| `timeout_seconds` | integer (int32) |  | 0 | Decompile timeout override in seconds; 0 uses the default. |

### `get_disassembly`

Disassemble a fixed number of instructions from an address.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `address` | string | yes |  | 0x-prefixed hex address, or a symbol name (case-sensitive) to start at its address. |
| `limit` | integer (int32) |  | 20 | Max instructions (max 2000); when more follow, 'truncated' is true and 'next_address' is the first not returned. |

### `search_constant_references`

Find all instructions that use a specific constant as an immediate operand. Useful for locating every usage of a magic number, error code, or flag value, e.g. passing 0x100D0 to find all mov/cmp/push instructions referencing that constant.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `value` | string | yes |  | Constant to search for. Accepts decimal (e.g. 65744), 0x-prefixed hex (e.g. 0x100D0), or a negative value treated as its unsigned bit pattern (e.g. -1 matches 0xFFFFFFFFFFFFFFFF). |
| `limit` | integer (int32) |  | 200 | Maximum number of hits to return (max 2000). 'truncated' is true when matches were dropped. |

### `search_instructions`

Search decoded instructions for a byte-pattern prefix (supports ?? wildcards) with optional address-range filtering.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `pattern` | string | yes |  | Instruction byte pattern, e.g. 'FF ?? 48'. |
| `start_address` | string |  |  | Optional start address (inclusive) for instruction filtering. |
| `end_address` | string |  |  | Optional end address (inclusive) for instruction filtering. |
| `limit` | integer (int32) |  | 100 | Maximum number of hits to return (max 2000). |

## Cross-references

### `get_xrefs_from`

List cross-references originating from an address with optional destination-range and ref-type filters.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `address` | string | yes |  | Hex address with 0x prefix, e.g. 0x00401000. Use search_functions to find entry points. |
| `ref_types` | array of string |  |  | Filter by category (CALL, COMPUTED_CALL, DATA, READ, WRITE, OTHER) or exact Ghidra type name (e.g. UNCONDITIONAL_CALL). Repeatable or comma-separated. |
| `start_address` | string |  |  | Optional lower bound (inclusive) for destination addresses. |
| `end_address` | string |  |  | Optional upper bound (inclusive) for destination addresses. |
| `limit` | integer (int32) |  | 500 | Max xrefs (max 5000); 'truncated' means matches were dropped. |

### `get_xrefs_to`

List cross-references to an address or symbol. When the target is a function entry point, indirect caller candidates are included.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `name_or_address` | string | yes |  | Symbol name (case-sensitive) or 0x-prefixed hex address. |
| `ref_types` | array of string |  |  | Filter by category (CALL, COMPUTED_CALL, DATA, READ, WRITE, OTHER) or exact Ghidra type name (e.g. UNCONDITIONAL_CALL). Repeatable or comma-separated. |
| `start_address` | string |  |  | Lower bound (inclusive) for xref source addresses. |
| `end_address` | string |  |  | Upper bound (inclusive) for xref source addresses. |
| `limit` | integer (int32) |  | 500 | Max xrefs (max 5000); 'truncated' means matches were dropped — narrow the filters rather than raise this. |

## Data types

### `add_struct_field`

Add a field to an existing structure.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `struct_name` | string | yes |  | Struct name to modify |
| `field_name` | string | yes |  | Field name (max 256 chars) |
| `type_name` | string | yes |  | Field data type |
| `comment` | string |  |  | Optional field comment (max 4096 chars) |
| `offset` | integer (int32) |  |  | Byte offset at which to place the field within an existing struct gap. The offset must point to undefined (unnamed) bytes — it may not overlap any existing named field. The field must fit entirely within the struct: offset + field_size must be <= struct size. Use this to name a gap left by replace_struct_field shrinking a field, e.g. offset=18 places a 1-byte field at offset 0x12 without inflating the struct. Omit this parameter to append the field after the last defined component (may grow the struct). |

### `create_struct`

Create a new structure data type in the program's Data Type Manager.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `name` | string | yes |  | Struct name (max 256 chars) |
| `size` | integer (int32) |  |  | Initial size in bytes |
| `category` | string |  |  | Category path to place the struct in |
| `override` | boolean |  |  | If true and the struct already exists, clear and resize it in place instead of replacing the data type object |

### `get_struct_layout`

Get the field layout of a structure data type.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `name` | string | yes |  | Exact name of the structure data type. |

### `list_data_type_categories`

List all data type category paths in a program. Returns all categories; no pagination. Use search_data_types with a category path as the query to explore contents.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |

### `remove_struct_field`

Remove a field from a structure by field name without moving later fields.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `struct_name` | string | yes |  | Struct name |
| `field_name` | string | yes |  | Name of the field to remove (max 256 chars) |

### `replace_struct_field`

Replace an existing structure field in place without moving later fields.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `struct_name` | string | yes |  | Struct name |
| `field_name` | string | yes |  | Field name to replace |
| `type_name` | string | yes |  | Replacement field data type |
| `new_name` | string |  |  | Optional replacement field name (max 256 chars) |
| `comment` | string |  |  | Optional replacement field comment (max 4096 chars) |

### `search_data_types`

Search for data types by name (case-insensitive). Pass an empty string to list all data types. Use list_data_type_categories to explore the category hierarchy. Note that the C99 fixed-width spellings (int8_t..int64_t, uint8_t..uint64_t, size_t, ssize_t, intptr_t, uintptr_t, ptrdiff_t) are accepted by every tool that takes a type name even when they are absent here — they resolve to a type of exactly that width.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `query` | string |  |  | Substring filter applied to data type names (case-insensitive). Pass an empty string to list all data types. |
| `limit` | integer (int32) |  | 50 | Max items (max 500); 'truncated' means matches were dropped. |

## Functions

### `get_calling_conventions`

List all calling conventions available in a program's compiler spec. Use this to find valid values for the calling_convention field when calling set_function_prototype.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |

### `get_function_callees`

Get all functions called by the specified function.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `name_or_address` | string | yes |  | Function name (case-sensitive) or 0x-prefixed hex entry point. |

### `get_function_info`

Full details for one function: signature, calling convention, size, thunk status.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `name_or_address` | string | yes |  | Function name (case-sensitive) or 0x-prefixed hex entry point. |

### `get_function_variables`

Get all parameters and local variables of a function.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `name_or_address` | string | yes |  | Function name (case-sensitive) or 0x-prefixed hex entry point. |

### `search_functions`

Find functions by name substring (case-insensitive); empty string lists all. Returns name and address — use get_function_info for full details.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `query` | string |  |  | Name substring (case-insensitive); empty lists all. |
| `limit` | integer (int32) |  | 100 | Max items (max 1000); 'truncated' means matches were dropped. |
| `start_address` | string |  |  | Lower bound (inclusive) for function entry points. |
| `end_address` | string |  |  | Upper bound (inclusive) for function entry points. |

## Program

### `analyze_program`

Run Ghidra's full auto-analysis on an already-imported program and block until completion. Required once for any program imported outside MCP (e.g. via the Ghidra GUI): every other tool rejects a program that has never been analyzed. Also use it to re-run analysis after large structural edits. import_binary already analyzes on import — you do not need to call this after a successful import.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |

### `batch_tool_call`

Run one allowlisted read or write tool many times with different arguments, returning ordered per-call results. Prefer this over one call per item when renaming or commenting several things in a function.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `tool` | string | yes |  | Allowlisted read or write tool operationId to execute. |
| `calls` | array of object | yes |  | List of argument objects, each exactly what the tool takes on its own. One tool call is executed per item, in order; a failed item does not stop the rest. Maximum 50. |

### `check_connection`

Check if the Ghidra MCP server is running and responsive.

### `get_program_info`

Program metadata: image base, executable format, language/compiler IDs, memory blocks.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |

### `import_binary`

Import a binary file into the Ghidra project and run full auto-analysis. The returned program name can be used immediately with all other tools. The format is auto-detected; a headerless image (a raw flash dump or firmware blob) has nothing to detect, so pass language_id and base_address for those.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `file_path` | string | yes |  | Absolute path to the binary file to import, e.g. /home/user/target.exe. |
| `project_dir` | string |  |  | Project folder path where the binary will be saved, e.g. "hello/bin". Intermediate folders are created automatically. Omit or pass "/" to place the binary in the project root. Subject to import.min_directory_depth and import.require_child_path constraints in rules.yaml. |
| `language_id` | string |  |  | Ghidra language/processor id, e.g. "ARM:LE:32:Cortex" or "x86:LE:64:default". Omit for any file with a recognisable header (ELF, PE, Mach-O) — the loader detects it. Required for a headerless image, which carries nothing to detect from. |
| `base_address` | string |  |  | 0-prefixed hex load address, e.g. "0x08000000". Applied before auto-analysis, so recovered addresses and pointers are correct. Omit to load at the format's own base (0x0 for a headerless image). |

### `list_project_files`

List all program files in the Ghidra project.

## Scripting

### `add_script`

Copy a script file into the Ghidra user script directory so run_script can run it. The source path is remembered and re-copied when it changes, so later edits are picked up without calling add_script again — call it again only to point the same filename at a different source. Writing a script: Ghidra already runs it in a transaction, so do not open an outer one, and do not return from run() with an extra transaction open (that is an error, and the program is evicted and reopened). Anything managing its own transaction — Program.setLanguage is the usual case — needs end(true) before it and start() after.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `file_path` | string | yes |  | Path to an existing script file to move into the Ghidra user script directory |

### `delete_script`

Delete a script from the Ghidra user script directory.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `filename` | string | yes |  | Script filename; see list_scripts. |

### `get_script_description`

Get metadata and description for a script — equivalent to clicking a script in Ghidra's Script Manager. The bundled scripts also print their argument list when run_script is called with no args.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `filename` | string | yes |  | Script filename (e.g. AuditFunction.java) |

### `list_scripts`

List available Ghidra scripts. Use mcp_scripts_only=true to list only scripts bundled with this extension (in its ghidra_scripts/ directory, with guaranteed JSON output and built-in help). Without the filter, also includes user scripts added via add_script.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `mcp_scripts_only` | boolean |  | False | When true, return only extension-provided scripts. When false (default), return all scripts. |

### `run_script`

Run a Ghidra script by filename, from the user or extension script directories. Omitting 'args' makes the bundled scripts print their own usage instead of running; see get_script_description. An add_script'd script is re-copied from its source if that changed, so edits need no second add_script.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `filename` | string | yes |  | Script filename; see list_scripts. |
| `args` | array of string |  |  | Arguments passed via getScriptArgs(). Omit to get the script's usage instead. |

## Symbols and memory

### `get_address_info`

Get detailed information about a specific address: the memory segment it belongs to, the function containing it (if any), and all cross-references pointing to it.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `address` | string | yes |  | Address in 0x-prefixed hex, e.g. 0x00401000. |

### `list_exports`

List all exported functions and symbols in a program. Returns all exports; no pagination.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |

### `list_globals`

List named global symbols grouped by functions, data, and labels, with optional section and address-range filters.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `section` | string |  |  | Optional memory block/section name filter, e.g. .data or .bss. |
| `start_address` | string |  |  | Optional start address (inclusive) for symbol address filtering. |
| `end_address` | string |  |  | Optional end address (inclusive) for symbol address filtering. |
| `limit` | integer (int32) |  | 500 | Maximum number of symbols to return across all groups (max 5000). 'truncated' is true when matches were dropped. |

### `list_imports`

List all imported external symbols in a program. Returns all imports; no pagination.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |

### `read_data`

Read raw memory bytes from an address as fixed-size items.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `address` | string | yes |  | Start address in 0x-prefixed hex, e.g. 0x00401000. |
| `item_size` | integer (int32) |  | 1 | Byte width of each item to read. Must be >= 1. |
| `item_count` | integer (int32) |  | 16 | Number of items to read. Must be >= 1. |

### `search_bytes`

Search initialized memory for a hex byte pattern. Supports wildcards with ?? and optional address-range filtering.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `hex_pattern` | string | yes |  | Hex byte pattern, e.g. 'FF ?? 48' or '68 4E 58 50 20'. |
| `start_address` | string |  |  | Optional start address (inclusive) for the search range. |
| `end_address` | string |  |  | Optional end address (inclusive) for the search range. |
| `limit` | integer (int32) |  | 100 | Maximum number of hits to return (max 2000). |

### `search_defined_strings`

Search for defined strings across the program listing.

| Parameter | Type | Required | Default | Description |
|-----------|------|:--------:|---------|-------------|
| `program` | string | yes |  | Program name; see list_project_files. |
| `query` | string |  |  | Optional substring match (case-insensitive) applied to string values. Pass an empty string or omit to list all defined strings. |
| `offset` | integer (int32) |  | 0 | 0-based item offset for pagination. O(n) cost — avoid large offsets on large programs. |
| `limit` | integer (int32) |  | 200 | Max items (max 1000); 'truncated' means matches were dropped — raise 'offset' by 'count' to page on. |

