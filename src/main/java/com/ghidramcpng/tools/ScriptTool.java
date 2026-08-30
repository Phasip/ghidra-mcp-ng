package com.ghidramcpng.tools;

import com.ghidramcpng.program.ProgramManager;
import com.ghidramcpng.program.TemporaryNames;
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

    /**
     * Suffix of the sidecar file recording where an add_script'd copy came from, written
     * next to the copy in the user script directory. Chosen so that it matches no
     * GhidraScriptProvider extension — list_scripts and Ghidra itself both ignore it.
     */
    private static final String SOURCE_SIDECAR_SUFFIX = ".mcp-source";

    private final ProgramManager mgr;

    /**
     * The extension's own ghidra_scripts/ directory. When non-null, used directly by
     * getExtensionScriptsDir(). When null, auto-detected from registered script source
     * directories by looking for a directory whose parent is named "GhidraMcpNg".
     */
    private final java.nio.file.Path extensionScriptsDir;

    private final TemporaryNames temporaryNames;

    public ScriptTool(ProgramManager mgr, TemporaryNames temporaryNames) {
        this(mgr, temporaryNames, null);
    }

    /** Constructor used in tests to inject the extension scripts directory explicitly. */
    public ScriptTool(ProgramManager mgr, TemporaryNames temporaryNames,
            java.nio.file.Path extensionScriptsDir) {
        this.mgr = mgr;
        this.temporaryNames = temporaryNames;
        this.extensionScriptsDir = extensionScriptsDir;
    }

    @GET
    @Path("/list_scripts")
    @Operation(
            tags = "Scripting",
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
                    } catch (java.io.IOException e) {
                        System.err.println("[ghidra-mcp-ng] WARNING: skipping script directory '" +
                                dir + "': " + e);
                    }
                }
            }

            scripts.sort(Comparator.naturalOrder());
            return new ListScriptsResponse(scripts, scripts.size());
        });
    }

    @GET
    @Path("/get_script_description")
    @Operation(
            tags = "Scripting",
            operationId = "get_script_description",
            summary = "Get metadata and description for a script — equivalent to clicking a script in Ghidra's Script Manager. " +
                      "The bundled scripts also print their argument list when run_script is called with no args."
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
            tags = "Scripting",
            operationId = "add_script",
            summary = "Copy a script file into the Ghidra user script directory so run_script can run it. "
                    + "The source path is remembered and re-copied when it changes, so later edits are picked "
                    + "up without calling add_script again — call it again only to point the same filename at a "
                    + "different source. Writing a script: Ghidra already runs it in a transaction, so do not "
                    + "open an outer one, and do not return from run() with an extra transaction open (that is "
                    + "an error, and the program is evicted and reopened). Anything managing its own transaction "
                    + "— Program.setLanguage is the usual case — needs end(true) before it and start() after."
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

            // resolveScript prefers the extension's own directory, so a colliding name would
            // copy successfully and then never be the thing run_script runs.
            java.nio.file.Path extDir = getExtensionScriptsDir();
            if (extDir != null && Files.isRegularFile(extDir.resolve(filename))) {
                throw new IllegalArgumentException(
                        "'" + filename + "' is the name of a script bundled with this extension, and bundled "
                        + "scripts take priority over the user script directory — the copy would never run. "
                        + "Rename the source file.");
            }

            java.nio.file.Path target = ensureScriptDirectory().resolve(filename);
            Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING);
            // Record where the copy came from so run_script can pick up later edits rather
            // than reporting success while running this snapshot forever.
            Files.writeString(sourceSidecar(target), source.toString());
            return new AddScriptResponse(true, filename, source.toString());
        });
    }

    @POST
    @Path("/run_script")
    @Operation(
            tags = "Scripting",
            operationId = "run_script",
            summary = "Run a Ghidra script by filename, from the user or extension script directories. "
                      + "Omitting 'args' makes the bundled scripts print their own usage instead of running; "
                      + "see get_script_description. An add_script'd script is re-copied from its source if "
                      + "that changed, so edits need no second add_script."
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
            String[] args = parseOptionalArgs(request, "args");
            Program program = mgr.getOrOpen(programName);
            java.nio.file.Path scriptPath = resolveScript(filename);
            SourceSync source = syncWithRegisteredSource(scriptPath);
            try {
                return executeScript(program, scriptPath, args, source);
            } finally {
                // A script can rename or retype anything, and can report names of its own that no
                // read here ever served, so set_variable must stop resolving names through reads
                // taken before it ran. Also on failure: a script that threw may already have
                // written. Costs the caller a re-read, which is the cheap side of the trade.
                temporaryNames.invalidate(program.getName());
            }
        });
    }

    @POST
    @Path("/delete_script")
    @Operation(
            tags = "Scripting",
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
            Files.deleteIfExists(sourceSidecar(scriptPath));
            return new DeleteScriptResponse(true, filename);
        });
    }

    /** Where a runnable script's content came from, and whether it was refreshed before running. */
    private record SourceSync(String path, String state) {
    }

    private static final SourceSync NO_REGISTERED_SOURCE = new SourceSync(null, "no_registered_source");

    /**
     * Brings the copy in the user script directory back in step with the source file
     * add_script was pointed at. add_script copies rather than referencing, so without this
     * an edited script runs its stale snapshot and still reports success — the worst kind of
     * failure, because the response is indistinguishable from a correct run.
     *
     * <p>Comparison is by content, not mtime: a copy is a few KB, and mtime is the thing most
     * likely to differ for reasons that have nothing to do with the script changing.
     */
    private java.nio.file.Path sourceSidecar(java.nio.file.Path scriptPath) {
        return scriptPath.resolveSibling(scriptPath.getFileName() + SOURCE_SIDECAR_SUFFIX);
    }

    private SourceSync syncWithRegisteredSource(java.nio.file.Path scriptPath) throws java.io.IOException {
        java.nio.file.Path sidecar = sourceSidecar(scriptPath);
        if (!Files.isRegularFile(sidecar)) {
            return NO_REGISTERED_SOURCE;
        }
        java.nio.file.Path source = java.nio.file.Path.of(Files.readString(sidecar).strip());
        if (!Files.isRegularFile(source)) {
            return new SourceSync(source.toString(), "source_missing");
        }
        if (Arrays.equals(Files.readAllBytes(source), Files.readAllBytes(scriptPath))) {
            return new SourceSync(source.toString(), "current");
        }
        Files.copy(source, scriptPath, StandardCopyOption.REPLACE_EXISTING);
        return new SourceSync(source.toString(), "refreshed");
    }

    private RunScriptResponse executeScript(Program program, java.nio.file.Path scriptPath, String[] args,
            SourceSync source) throws Exception {
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
                    stringWriter.toString(), program.getName(),
                    source.path(), source.state());
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

    /** Takes the field name, like every other body reader here, so the call site names it. */
    private static String[] parseOptionalArgs(JsonObject body, String fieldName) {
        if (body == null || !body.has(fieldName) || body.get(fieldName).isJsonNull()) {
            return new String[0];
        }
        if (!body.get(fieldName).isJsonArray()) {
            throw new IllegalArgumentException("'" + fieldName + "' must be a JSON array of strings");
        }
        JsonArray arr = body.getAsJsonArray(fieldName);
        String[] result = new String[arr.size()];
        for (int i = 0; i < arr.size(); i++) {
            var el = arr.get(i);
            if (el.isJsonNull() || !el.isJsonPrimitive() || !el.getAsJsonPrimitive().isString()) {
                throw new IllegalArgumentException(
                        "'" + fieldName + "[" + i + "]' must be a string. Pass numbers as strings " +
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

    public record AddScriptResponse(
            boolean success,
            String filename,
            @Schema(description = "Absolute path of the source file now registered for this filename. run_script re-copies from here whenever it has changed.")
            String source_path) {
    }

    public record RunScriptRequest(
            @Schema(description = "Program name; see list_project_files.", requiredMode = Schema.RequiredMode.REQUIRED)
            String program,
            @Schema(description = "Script filename; see list_scripts.", requiredMode = Schema.RequiredMode.REQUIRED)
            String filename,
            @Schema(description = "Arguments passed via getScriptArgs(). Omit to get the script's usage instead.")
            List<String> args) {
    }

    public record RunScriptResponse(
            boolean success,
            String filename,
            String output,
            String program,
            @Schema(description = "Absolute path of the source file registered by add_script, or null if this script was not added that way (a bundled script, or one dropped into the user script directory by hand).")
            String source_path,
            @Schema(description = "Relationship between the script that just ran and its registered source: "
                    + "'current' — the copy already matched the source; "
                    + "'refreshed' — the source had changed and its new content was copied in and run; "
                    + "'source_missing' — the registered source file no longer exists, so the last registered copy ran and may be out of date; "
                    + "'no_registered_source' — the script was not added via add_script, so there is nothing to compare against.")
            String source_state) {
    }

    public record DeleteScriptRequest(
            @Schema(description = "Script filename; see list_scripts.", requiredMode = Schema.RequiredMode.REQUIRED)
            String filename) {
    }

    public record DeleteScriptResponse(boolean success, String filename) {
    }
}
