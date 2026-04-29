package com.ghidramcpng.tools;

import com.ghidramcpng.program.ProgramManager;
import com.ghidramcpng.tools.ToolHelpers;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.script.ScriptInfo;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/**
 * HTTP tool resource for managing and running Ghidra scripts from the user script directory.
 */
@Path("/tool")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class ScriptTool {

    public static final int TOOL_COUNT = ToolHelpers.countEndpoints(ScriptTool.class);

    private final ProgramManager mgr;

    /**
     * The extension's own ghidra_scripts/ directory. When non-null, used directly by
     * getExtensionScriptsDir(). When null, auto-detected from registered script source
     * directories by looking for a directory whose parent is named "GhidraMcpNg".
     */
    private final java.nio.file.Path extensionScriptsDir;

    public ScriptTool(ProgramManager mgr) {
        this(mgr, null);
    }

    /** Constructor used in tests to inject the extension scripts directory explicitly. */
    public ScriptTool(ProgramManager mgr, java.nio.file.Path extensionScriptsDir) {
        this.mgr = mgr;
        this.extensionScriptsDir = extensionScriptsDir;
    }

    @GET
    @Path("/list_scripts")
    @Operation(
            operationId = "list_scripts",
            summary = "List available Ghidra scripts. Use mcp_scripts_only=true to list only " +
                      "scripts bundled with this extension (in its ghidra_scripts/ directory, " +
                      "with guaranteed JSON output and built-in help). " +
                      "Without the filter, also includes user scripts added via add_script."
    )
    @ApiResponse(responseCode = "200", description = "Available script files",
            content = @Content(schema = @Schema(implementation = ListScriptsResponse.class)))
    public ListScriptsResponse listScripts(
            @Parameter(description = "When true, return only extension-provided scripts. When false (default), return all scripts.")
            @QueryParam("mcp_scripts_only") @DefaultValue("false") boolean mcpOnly) throws Exception {
        return withScriptRuntime(() -> {
            List<String> scripts = new ArrayList<>();
            java.nio.file.Path extDir = getExtensionScriptsDir();

            if (mcpOnly) {
                if (extDir != null) collectScriptNames(extDir, scripts);
            } else {
                // Extension scripts first, then user scripts, then other registered dirs
                if (extDir != null) collectScriptNames(extDir, scripts);
                collectScriptNames(ensureScriptDirectory(), scripts);
                for (ResourceFile dir : GhidraScriptUtil.getScriptSourceDirectories()) {
                    try {
                        java.nio.file.Path dirPath = dir.getFile(false).toPath();
                        if (!dirPath.equals(extDir)) collectScriptNames(dirPath, scripts);
                    } catch (java.io.IOException ignored) {}
                }
            }

            scripts.sort(Comparator.naturalOrder());
            return new ListScriptsResponse(scripts, scripts.size());
        });
    }

    @GET
    @Path("/get_script_description")
    @Operation(
            operationId = "get_script_description",
            summary = "Get metadata and description for a script — equivalent to clicking a script in Ghidra's Script Manager. " +
                      "Call run_script with no args to get runtime help for MCP-provided scripts."
    )
    @ApiResponse(responseCode = "200", description = "Script metadata",
            content = @Content(schema = @Schema(implementation = ScriptDescriptionResponse.class)))
    public ScriptDescriptionResponse getScriptDescription(
            @Parameter(description = "Script filename (e.g. AuditFunction.java)", required = true)
            @QueryParam("filename") String filename) throws Exception {
        return withScriptRuntime(() -> {
            requireText(filename, "filename");
            java.nio.file.Path scriptPath = resolveScript(filename);
            ResourceFile scriptFile = new ResourceFile(scriptPath.toFile());
            ScriptInfo info = GhidraScriptUtil.newScriptInfo(scriptFile);
            String[] category = info.getCategory();
            String[] menuPath = info.getMenuPath();
            return new ScriptDescriptionResponse(
                    info.getName(),
                    info.getDescription(),
                    info.getAuthor(),
                    category != null ? Arrays.asList(category) : List.of(),
                    menuPath != null && menuPath.length > 0 ? info.getMenuPathAsString() : null,
                    isMcpScript(scriptPath));
        });
    }

    @POST
    @Path("/add_script")
    @Operation(
            operationId = "add_script",
            summary = "Copy an existing script file into the Ghidra user script directory, making it available to run_script."
    )
    @ApiResponse(responseCode = "200", description = "Script add result",
            content = @Content(schema = @Schema(implementation = AddScriptResponse.class)))
    public AddScriptResponse addScript(
            @RequestBody(
                    required = true,
                    description = "Script add request",
                    content = @Content(schema = @Schema(implementation = AddScriptRequest.class)))
            JsonObject request) throws Exception {
        return withScriptRuntime(() -> {
            java.nio.file.Path source = java.nio.file.Path.of(requireBodyText(request, "file_path"))
                    .toAbsolutePath()
                    .normalize();
            if (!Files.exists(source)) {
                throw new IllegalArgumentException("Script file not found: " + source);
            }
            if (!Files.isRegularFile(source)) {
                throw new IllegalArgumentException("Script path is not a regular file: " + source);
            }
            String filename = source.getFileName().toString();
            ensureSupportedScriptName(filename);

            java.nio.file.Path target = ensureScriptDirectory().resolve(filename);
            Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING);
            return new AddScriptResponse(true, filename);
        });
    }

    @POST
    @Path("/run_script")
    @Operation(
            operationId = "run_script",
            summary = "Run a Ghidra script against an open program. Searches the user script directory and all extension script directories. " +
                      "Call with no args (omit 'args') to receive the script's built-in help and argument description."
    )
    @ApiResponse(responseCode = "200", description = "Script execution result",
            content = @Content(schema = @Schema(implementation = RunScriptResponse.class)))
    public RunScriptResponse runScript(
            @RequestBody(
                    required = true,
                    description = "Script execution request",
                    content = @Content(schema = @Schema(implementation = RunScriptRequest.class)))
            JsonObject request) throws Exception {
        return withScriptRuntime(() -> {
            String programName = requireBodyText(request, "program");
            String filename = requireFilename(request, "filename");
            String[] args = parseOptionalArgs(request);
            Program program = mgr.getOrOpen(programName);
            java.nio.file.Path scriptPath = resolveScript(filename);
            return executeScript(program, scriptPath, args);
        });
    }

    @POST
    @Path("/delete_script")
    @Operation(
            operationId = "delete_script",
            summary = "Delete a script from the Ghidra user script directory."
    )
    @ApiResponse(responseCode = "200", description = "Script delete result",
            content = @Content(schema = @Schema(implementation = DeleteScriptResponse.class)))
    public DeleteScriptResponse deleteScript(
            @RequestBody(
                    required = true,
                    description = "Script delete request",
                    content = @Content(schema = @Schema(implementation = DeleteScriptRequest.class)))
            JsonObject request) throws Exception {
        return withScriptRuntime(() -> {
            String filename = requireFilename(request, "filename");
            java.nio.file.Path scriptPath = resolveManagedScript(filename);
            ResourceFile scriptFile = new ResourceFile(scriptPath.toFile());
            GhidraScriptProvider provider = findProvider(scriptPath);
            boolean deleted = provider.deleteScript(scriptFile);
            if (!deleted && Files.exists(scriptPath)) {
                throw new IllegalStateException("Failed to delete script: " + filename);
            }
            return new DeleteScriptResponse(true, filename);
        });
    }

    private RunScriptResponse executeScript(Program program, java.nio.file.Path scriptPath, String[] args)
            throws Exception {
        // Hold the per-program lock for the entire script run so that concurrent write
        // tool calls (withTransaction) are blocked rather than racing with a script that
        // opens its own Ghidra transactions internally.
        return mgr.withProgramLock(program, () -> {
            ResourceFile scriptFile = new ResourceFile(scriptPath.toFile());
            GhidraScriptProvider provider = findProvider(scriptPath);

            StringWriter stringWriter = new StringWriter();
            PrintWriter printWriter = new PrintWriter(stringWriter);

            GhidraState state = new GhidraState(
                    null,
                    mgr.getProject(),
                    program,
                    null, null, null);

            GhidraScript script;
            try {
                script = provider.getScriptInstance(scriptFile, printWriter);
            } catch (ghidra.app.script.GhidraScriptLoadException e) {
                printWriter.flush();
                String compilerOutput = stringWriter.toString();
                String msg = e.getMessage() + (compilerOutput.isBlank() ? "" : "\nCompiler output:\n" + compilerOutput);
                throw new ghidra.app.script.GhidraScriptLoadException(msg, e.getCause());
            }
            script.setScriptArgs(args);
            script.execute(state, TaskMonitor.DUMMY, printWriter);
            printWriter.flush();

            return new RunScriptResponse(true, scriptPath.getFileName().toString(),
                    stringWriter.toString(), program.getName());
        });
    }

    private java.nio.file.Path ensureScriptDirectory() throws Exception {
        java.nio.file.Path scriptDir = java.nio.file.Path.of(GhidraScriptUtil.USER_SCRIPTS_DIR);
        Files.createDirectories(scriptDir);
        return scriptDir;
    }

    /**
     * Returns the extension's own ghidra_scripts/ directory, or null if not found.
     * Uses the injected path if provided (tests); otherwise auto-detects from Ghidra's
     * registered script source directories by finding the one whose parent is "GhidraMcpNg"
     * (the extension install directory name).
     */
    private java.nio.file.Path getExtensionScriptsDir() {
        if (extensionScriptsDir != null) return extensionScriptsDir;
        for (ResourceFile dir : GhidraScriptUtil.getScriptSourceDirectories()) {
            java.nio.file.Path path = dir.getFile(false).toPath();
            if (path.getParent() != null &&
                    path.getParent().getFileName().toString().equals("GhidraMcpNg")) {
                return path;
            }
        }
        return null;
    }

    private java.nio.file.Path resolveScript(String filename) throws Exception {
        ensureSupportedScriptName(filename);
        // Extension-bundled scripts take priority
        java.nio.file.Path extDir = getExtensionScriptsDir();
        if (extDir != null) {
            java.nio.file.Path extScript = extDir.resolve(filename);
            if (Files.exists(extScript) && Files.isRegularFile(extScript)) {
                return extScript;
            }
        }
        // User scripts directory
        java.nio.file.Path userScript = ensureScriptDirectory().resolve(filename);
        if (Files.exists(userScript) && Files.isRegularFile(userScript)) {
            return userScript;
        }
        // Other Ghidra extension script directories
        for (ResourceFile dir : GhidraScriptUtil.getScriptSourceDirectories()) {
            java.nio.file.Path candidate = dir.getFile(false).toPath().resolve(filename);
            if (Files.exists(candidate) && Files.isRegularFile(candidate)) {
                return candidate;
            }
        }
        throw new IllegalArgumentException(
                "Script not found: '" + filename + "'. Use list_scripts to see available scripts.");
    }

    private java.nio.file.Path resolveManagedScript(String filename) throws Exception {
        ensureSupportedScriptName(filename);
        java.nio.file.Path scriptPath = ensureScriptDirectory().resolve(filename);
        if (!Files.exists(scriptPath) || !Files.isRegularFile(scriptPath)) {
            throw new IllegalArgumentException("Script not found: " + filename);
        }
        return scriptPath;
    }

    private static String[] parseOptionalArgs(JsonObject body) {
        if (body == null || !body.has("args") || body.get("args").isJsonNull()) {
            return new String[0];
        }
        if (!body.get("args").isJsonArray()) {
            throw new IllegalArgumentException("'args' must be a JSON array of strings");
        }
        JsonArray arr = body.getAsJsonArray("args");
        String[] result = new String[arr.size()];
        for (int i = 0; i < arr.size(); i++) {
            var el = arr.get(i);
            if (el.isJsonNull() || !el.isJsonPrimitive() || !el.getAsJsonPrimitive().isString()) {
                throw new IllegalArgumentException(
                        "'args[" + i + "]' must be a string. Pass numbers as strings " +
                        "(e.g. \"42\" instead of 42).");
            }
            result[i] = el.getAsString();
        }
        return result;
    }

    private boolean isSupportedScriptName(String filename) {
        try {
            findProvider(java.nio.file.Path.of(filename));
            return true;
        } catch (IllegalStateException e) {
            return false;
        }
    }

    private void ensureSupportedScriptName(String filename) {
        requireFilename(filename, "filename");
        findProvider(java.nio.file.Path.of(filename));
    }

    /** Returns true if the given path lives in the extension's ghidra_scripts/ directory. */
    private boolean isMcpScript(java.nio.file.Path scriptPath) {
        java.nio.file.Path extDir = getExtensionScriptsDir();
        return extDir != null &&
               scriptPath != null &&
               scriptPath.getParent() != null &&
               scriptPath.getParent().equals(extDir);
    }

    /** Appends script filenames from a directory to the list (skips already-seen names). */
    private void collectScriptNames(java.nio.file.Path dir, List<String> out) throws java.io.IOException {
        if (!Files.isDirectory(dir)) return;
        try (Stream<java.nio.file.Path> paths = Files.list(dir)) {
            paths.filter(Files::isRegularFile)
                    .map(p -> p.getFileName().toString())
                    .filter(this::isSupportedScriptName)
                    .filter(name -> !out.contains(name))
                    .forEach(out::add);
        }
    }

    private static GhidraScriptProvider findProvider(java.nio.file.Path path) {
        String filename = path.getFileName().toString();
        List<String> extensions = new ArrayList<>();
        for (GhidraScriptProvider provider : GhidraScriptUtil.getProviders()) {
            extensions.add(provider.getExtension());
            if (filename.toLowerCase().endsWith(provider.getExtension().toLowerCase())) {
                return provider;
            }
        }
        throw new IllegalStateException(
                "No GhidraScriptProvider found for script '" + filename + "'. " +
                "Use a supported script extension such as " + String.join(", ", extensions) + ".");
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Required parameter '" + fieldName + "' is missing");
        }
        return value;
    }

    private static String requireBodyText(JsonObject body, String fieldName) {
        if (body == null || !body.has(fieldName) || body.get(fieldName).isJsonNull()) {
            throw new IllegalArgumentException("Required parameter '" + fieldName + "' is missing");
        }
        return body.get(fieldName).getAsString();
    }

    private static String requireFilename(JsonObject body, String fieldName) {
        return requireFilename(requireBodyText(body, fieldName), fieldName);
    }

    private static String requireFilename(String filename, String fieldName) {
        String required = requireText(filename, fieldName);
        java.nio.file.Path path = java.nio.file.Path.of(required);
        if (path.getNameCount() != 1 || !path.getFileName().toString().equals(required)) {
            throw new IllegalArgumentException(
                    "Invalid script filename '" + required + "'. Use the plain filename returned by list_scripts.");
        }
        return required;
    }

    private <T> T withScriptRuntime(ThrowingSupplier<T> action) throws Exception {
        GhidraScriptUtil.acquireBundleHostReference();
        try {
            return action.get();
        } finally {
            GhidraScriptUtil.releaseBundleHostReference();
        }
    }

    @FunctionalInterface
    private interface ThrowingSupplier<T> {
        T get() throws Exception;
    }

    public record ListScriptsResponse(
            @Schema(description = "Script filenames available to run_script")
            List<String> scripts,
            @Schema(description = "Total count")
            int count) {
    }

    public record ScriptDescriptionResponse(
            @Schema(description = "Script filename")
            String filename,
            @Schema(description = "Human-readable description from the script's header comment")
            String description,
            @Schema(description = "Script author from @author tag, or null if not specified")
            String author,
            @Schema(description = "Script categories from @category tag")
            List<String> category,
            @Schema(description = "Menu path string from @menupath tag, or null if not specified")
            String menu_path,
            @Schema(description = "True if this script is bundled with the extension in its ghidra_scripts/ directory (guaranteed JSON output, has built-in help)")
            boolean is_mcp_script) {
    }

    public record AddScriptRequest(
            @Schema(description = "Path to an existing script file to move into the Ghidra user script directory", requiredMode = Schema.RequiredMode.REQUIRED)
            String file_path) {
    }

    public record AddScriptResponse(boolean success, String filename) {
    }

    public record RunScriptRequest(
            @Schema(description = "Program name to bind as the current program", requiredMode = Schema.RequiredMode.REQUIRED)
            String program,
            @Schema(description = "Script filename returned by list_scripts", requiredMode = Schema.RequiredMode.REQUIRED)
            String filename,
            @Schema(description = "Optional arguments passed to the script via getScriptArgs(). Omit to trigger the script's built-in help output.")
            List<String> args) {
    }

    public record RunScriptResponse(boolean success, String filename, String output, String program) {
    }

    public record DeleteScriptRequest(
            @Schema(description = "Script filename returned by list_scripts", requiredMode = Schema.RequiredMode.REQUIRED)
            String filename) {
    }

    public record DeleteScriptResponse(boolean success, String filename) {
    }
}
