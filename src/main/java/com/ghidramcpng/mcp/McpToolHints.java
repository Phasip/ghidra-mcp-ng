package com.ghidramcpng.mcp;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Per-tool behaviour hints, published on each operation as an {@code x-mcp} OpenAPI extension.
 *
 * <p>The bridge turns these into the MCP tool annotations a host reads when deciding what it may
 * run without asking — {@code readOnlyHint}, {@code destructiveHint}, {@code idempotentHint},
 * {@code openWorldHint} — and into the HTTP timeout it waits under. Most of it follows from the
 * HTTP method: a GET reads and never destroys, a POST writes and might. Only the exceptions are
 * listed here, and they are listed together rather than scattered across the {@code @Operation}
 * annotations, because "which tools can destroy something?" and "which tools reach outside the
 * project?" are questions worth answering by reading one screen.
 *
 * <p>The default for anything absent from these tables is stated in {@code bridge.py}; keep the
 * two in step.
 */
public final class McpToolHints {

    private McpToolHints() {}

    /**
     * Write tools that only ever add: they may fail on a conflict, but they do not overwrite or
     * remove anything that was already there. Every other POST is assumed destructive, which is
     * also what MCP assumes when the hint is absent.
     */
    private static final Set<String> ADDITIVE = Set.of(
            "add_struct_field",
            "analyze_program",
            "create_label",
            "import_binary");

    /**
     * Tools whose repetition with the same arguments leaves the same state — the setters (writing
     * a value that is already there is a no-op) and the removers (deleting what is already gone
     * changes nothing further). Excludes the tools that accumulate: add_struct_field appends a
     * field, import_binary imports again, run_script does whatever the script does.
     */
    private static final Set<String> IDEMPOTENT = Set.of(
            "analyze_program",
            "create_label",
            "delete_script",
            "remove_struct_field",
            "rename_function",
            "replace_struct_field",
            "set_comment",
            "set_function_prototype",
            "set_global",
            "set_parameter_type",
            "set_variable");

    /**
     * Tools that reach past the Ghidra project into the host: two that read an arbitrary file
     * path, and one that executes arbitrary code. Everything else is bounded by the project, so
     * the bridge defaults to a closed world — the opposite of the MCP default, and the honest
     * answer for a tool surface that only ever touches program databases.
     */
    private static final Set<String> OPEN_WORLD = Set.of(
            "add_script",
            "import_binary",
            "run_script");

    /**
     * How long the bridge should wait for a reply, for the tools that outlast its default. Full
     * auto-analysis of a large binary runs for many minutes, and a script runs for as long as it
     * likes; cutting those off at the default leaves the server working on a request nobody is
     * waiting for any more.
     */
    private static final Map<String, Integer> TIMEOUT_SECONDS = Map.of(
            "analyze_program", 1800,
            "batch_tool_call", 1800,
            "decompile_function", 300,
            "import_binary", 1800,
            "run_script", 1800);

    /** Every tool named by any table above — so a test can check none of them has been renamed away. */
    static Set<String> namedTools() {
        Set<String> named = new java.util.TreeSet<>(ADDITIVE);
        named.addAll(IDEMPOTENT);
        named.addAll(OPEN_WORLD);
        named.addAll(TIMEOUT_SECONDS.keySet());
        return named;
    }

    /** The tools whose hints only make sense on a write; a GET derives all of these. */
    static Set<String> writeOnlyTools() {
        Set<String> named = new java.util.TreeSet<>(ADDITIVE);
        named.addAll(IDEMPOTENT);
        named.addAll(OPEN_WORLD);
        return named;
    }

    /** Adds the {@code x-mcp} extension to every operation the tables above have something to say about. */
    public static void apply(OpenAPI openApi) {
        if (openApi == null || openApi.getPaths() == null) {
            return;
        }
        for (PathItem pathItem : openApi.getPaths().values()) {
            for (Operation operation : pathItem.readOperationsMap().values()) {
                String id = operation.getOperationId();
                if (id == null) {
                    continue;
                }
                Map<String, Object> hints = new LinkedHashMap<>();
                if (ADDITIVE.contains(id)) {
                    hints.put("destructive", false);
                }
                if (IDEMPOTENT.contains(id)) {
                    hints.put("idempotent", true);
                }
                if (OPEN_WORLD.contains(id)) {
                    hints.put("open_world", true);
                }
                Integer timeout = TIMEOUT_SECONDS.get(id);
                if (timeout != null) {
                    hints.put("timeout_seconds", timeout);
                }
                if (!hints.isEmpty()) {
                    operation.addExtension("x-mcp", hints);
                }
            }
        }
    }
}
