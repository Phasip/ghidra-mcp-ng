package com.ghidramcpng.tools;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import com.ghidramcpng.model.DataTypeEntry;
import com.ghidramcpng.model.ExportEntry;
import com.ghidramcpng.model.FunctionEntry;
import com.ghidramcpng.model.FunctionRef;
import com.ghidramcpng.model.ImportEntry;
import com.ghidramcpng.model.StringEntry;
import com.ghidramcpng.model.StructField;
import com.ghidramcpng.model.VariableEntry;
import com.ghidramcpng.model.XrefEntry;
import com.ghidramcpng.program.ProgramManager;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import com.ghidramcpng.mcp.ApiSupport;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.Parameter;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;

import java.lang.reflect.Method;
import java.util.Iterator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import static com.ghidramcpng.tools.ToolHelpers.decompileFresh;
import static com.ghidramcpng.tools.ToolHelpers.findDataType;
import static com.ghidramcpng.tools.ToolHelpers.findFunction;
import static com.ghidramcpng.tools.ToolHelpers.findSymbolAddress;
import static com.ghidramcpng.tools.ToolHelpers.optional;
import static com.ghidramcpng.tools.ToolHelpers.optionalInt;
import static com.ghidramcpng.tools.ToolHelpers.required;
import static com.ghidramcpng.tools.ToolHelpers.toAddress;

/**
 * All read-only HTTP tool implementations.
 */
@Path("/tool")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class ReadTools {

    public static final int TOOL_COUNT = ToolHelpers.countEndpoints(ReadTools.class);

    private static final String SERVER_VERSION = loadVersion();

    /** Default and ceiling for the xref tools' 'limit'; shared by both and by the batch dispatch. */
    private static final int DEFAULT_XREF_LIMIT = 500;
    private static final int MAX_XREF_LIMIT = 5000;

    private final ProgramManager mgr;
    private final int decompileTimeoutSeconds;
    /** Batch dispatch target for the write tools; batch_tool_call is the only user. */
    private final WriteTools writeTools;

    public ReadTools(ProgramManager mgr, int decompileTimeoutSeconds, WriteTools writeTools) {
        this.mgr = mgr;
        this.decompileTimeoutSeconds = decompileTimeoutSeconds;
        this.writeTools = writeTools;
    }

    @GET
    @Path("/check_connection")
    @Operation(tags = "Program", operationId = "check_connection", summary = "Check if the Ghidra MCP server is running and responsive.")
    @ApiResponse(responseCode = "200", description = "Connection status",
            content = @Content(schema = @Schema(implementation = CheckConnectionResponse.class)))
    public CheckConnectionResponse checkConnection() {
        return new CheckConnectionResponse("ok", "ghidra-mcp-ng", SERVER_VERSION);
    }

    @GET
    @Path("/list_project_files")
    @Operation(tags = "Program", operationId = "list_project_files", summary = "List all program files in the Ghidra project.")
    @ApiResponse(responseCode = "200", description = "Project file list",
            content = @Content(schema = @Schema(implementation = ListProjectFilesResponse.class)))
    public ListProjectFilesResponse listProjectFiles() {
        List<String> files = mgr.listProjectFiles();
        return new ListProjectFilesResponse(files, files.size());
    }

    @GET
    @Path("/get_program_info")
    @Operation(tags = "Program", operationId = "get_program_info",
            summary = "Program metadata: image base, executable format, language/compiler IDs, memory blocks.")
    @ApiResponse(responseCode = "200", description = "Program metadata",
            content = @Content(schema = @Schema(implementation = GetProgramInfoResponse.class)))
    public GetProgramInfoResponse getProgramInfo(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName) {
        Program program = openProgram(programName);
        List<ProgramMemoryBlock> blocks = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            blocks.add(new ProgramMemoryBlock(
                    block.getName(),
                    block.getStart(),
                    block.getEnd(),
                    block.getSize(),
                    block.isInitialized(),
                    block.isRead(),
                    block.isWrite(),
                    block.isExecute(),
                    block.isVolatile()));
        }

        return new GetProgramInfoResponse(
                program.getName(),
                program.getExecutablePath(),
                program.getExecutableFormat(),
                program.getLanguageID().getIdAsString(),
                program.getCompilerSpec().getCompilerSpecID().getIdAsString(),
                program.getImageBase(),
                blocks,
                blocks.size());
    }

    @GET
    @Path("/list_globals")
    @Operation(tags = "Symbols and memory", operationId = "list_globals",
            summary = "List named global symbols grouped by functions, data, and labels, with optional section and address-range filters.")
    @ApiResponse(responseCode = "200", description = "Global symbol listing",
            content = @Content(schema = @Schema(implementation = ListGlobalsResponse.class)))
    public ListGlobalsResponse listGlobals(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName,
            @Parameter(description = "Optional memory block/section name filter, e.g. .data or .bss.")
            @QueryParam("section") String section,
            @Parameter(description = "Optional start address (inclusive) for symbol address filtering.")
            @QueryParam("start_address") String startAddress,
            @Parameter(description = "Optional end address (inclusive) for symbol address filtering.")
            @QueryParam("end_address") String endAddress,
            @Parameter(description = "Maximum number of symbols to return across all groups (max 5000). 'truncated' is true when matches were dropped.")
            @QueryParam("limit") @DefaultValue("500") int limit) {
        Program program = openProgram(programName);
        int validatedLimit = requireLimit(limit, 5000, "limit");
        AddressRange range = resolveAddressRange(program, startAddress, endAddress,
                "start_address", "end_address");
        String sectionFilter = section == null ? null : section.trim();

        List<GlobalSymbolEntry> functions = new ArrayList<>();
        List<GlobalSymbolEntry> data = new ArrayList<>();
        List<GlobalSymbolEntry> labels = new ArrayList<>();

        int total = 0;
        boolean truncated = false;
        for (Symbol symbol : program.getSymbolTable().getAllSymbols(true)) {
            if (!isGlobalCandidate(symbol)) {
                continue;
            }
            Address address = symbol.getAddress();
            if (address == null || address.isExternalAddress()) {
                continue;
            }
            if (range != null && !isWithinRange(address, range)) {
                continue;
            }
            MemoryBlock block = program.getMemory().getBlock(address);
            String blockName = block != null ? block.getName() : null;
            if (sectionFilter != null && !sectionFilter.isBlank()) {
                if (blockName == null || !blockName.equalsIgnoreCase(sectionFilter)) {
                    continue;
                }
            }

            // Checked after the filters so 'truncated' means "a matching symbol was dropped",
            // never "the page happened to fill exactly".
            if (total >= validatedLimit) {
                truncated = true;
                break;
            }

            GlobalSymbolEntry entry = new GlobalSymbolEntry(
                    symbol.getName(),
                    address,
                    symbol.getSymbolType().toString(),
                    blockName,
                    symbol.getParentNamespace() != null ? symbol.getParentNamespace().getName() : "Global");

            if (symbol.getSymbolType() == SymbolType.FUNCTION) {
                functions.add(entry);
            } else if (symbol.getSymbolType() == SymbolType.LABEL) {
                labels.add(entry);
            } else {
                data.add(entry);
            }
            total++;
        }

        return new ListGlobalsResponse(functions, data, labels, total, truncated);
    }

    @POST
    @Path("/batch_tool_call")
    @Operation(tags = "Program", operationId = "batch_tool_call",
            summary = "Run one allowlisted read or write tool many times with different arguments, returning ordered per-call results. "
                    + "Prefer this over one call per item when renaming or commenting several things in a function.")
    @ApiResponse(responseCode = "200", description = "Batch tool call results",
            content = @Content(schema = @Schema(implementation = BatchToolCallResponse.class)))
    public BatchToolCallResponse batchToolCall(
            @RequestBody(
                    required = true,
                    description = "Batch tool call request",
                    content = @Content(schema = @Schema(implementation = BatchToolCallRequest.class)))
            JsonObject request) {
        String tool = required(request, "tool");
        List<JsonObject> calls = requireBodyObjectList(request, "calls");
        if (calls.isEmpty()) {
            throw new IllegalArgumentException("Parameter 'calls' must contain at least one argument set.");
        }
        if (calls.size() > 50) {
            throw new IllegalArgumentException("Maximum supported batch size is 50 calls.");
        }
        if ("batch_tool_call".equals(tool)) {
            throw new IllegalArgumentException("Nested batch_tool_call invocations are not supported.");
        }
        if (NOT_BATCHABLE.containsKey(tool)) {
            throw new IllegalArgumentException(NOT_BATCHABLE.get(tool));
        }
        if (!BATCH_ALLOWLIST.contains(tool)) {
            throw new IllegalArgumentException(
                "Tool '" + tool + "' is not allowlisted for batch_tool_call. " +
                "Pass the bare operationId (e.g. \"rename_variable\"), not a namespaced MCP tool name. " +
                "Allowed tools: " + String.join(", ", BATCH_ALLOWLIST) + ".");
        }

        List<BatchToolCallItemResult> results = new ArrayList<>();
        int failed = 0;
        for (int i = 0; i < calls.size(); i++) {
            JsonObject args = calls.get(i);
            try {
                Object result = dispatchBatchTool(tool, args);
                results.add(new BatchToolCallItemResult(i, true, result, null));
            } catch (Exception e) {
                // Each item is an independent call, so a failure does not abandon the rest —
                // one bad name in fourteen renames should not cost the other thirteen.
                results.add(new BatchToolCallItemResult(i, false, null, e.getMessage()));
                failed++;
            }
        }
        return new BatchToolCallResponse(tool, results, results.size(), failed);
    }

    /**
     * Applies the same unknown-argument rejection a standalone call gets. A batch item never
     * passes through the HTTP filters — its arguments arrive as a nested object — so without this
     * a misspelled key would be silently dropped here while being refused on the direct route.
     */
    private static void rejectUnknownBatchArguments(String tool, JsonObject args) {
        Method endpoint = ToolHelpers.findEndpoint(tool, ReadTools.class, WriteTools.class);
        if (endpoint == null) {
            return;
        }
        Set<String> allowed = ToolHelpers.argumentNames(endpoint);
        if (allowed == null) {
            return;
        }
        List<String> unknown = new ArrayList<>();
        for (String provided : args.keySet()) {
            if (!allowed.contains(provided)) {
                unknown.add(provided);
            }
        }
        if (!unknown.isEmpty()) {
            throw new IllegalArgumentException(
                    ApiSupport.unknownNamesMessage("field", unknown, allowed, "tool '" + tool + "'"));
        }
    }

    /** Tools deliberately excluded from batching, each with the reason the agent needs. */
    private static final Map<String, String> NOT_BATCHABLE = Map.of(
            "run_script",
            "run_script is intentionally not batchable because scripts may mutate program state, " +
            "open their own transactions, and run for a long time. Call run_script once per invocation.",
            "analyze_program",
            "analyze_program is intentionally not batchable because a full analysis pass takes minutes " +
            "and only needs to run once per program. Call analyze_program once per program.",
            "import_binary",
            "import_binary is intentionally not batchable because it runs a full analysis pass per file. " +
            "Call import_binary once per binary.");

    /**
     * Tools allowed inside batch_tool_call: every read tool, plus the write tools that make one
     * short, self-contained edit. Each item runs its own transaction and saves on success, exactly
     * as it would as a standalone call — batching removes the round-trips, not the durability.
     * Program lifecycle tools (analyze/import) and script execution are excluded via
     * {@link #NOT_BATCHABLE}. Order is preserved (TreeSet sorted) for stable error messages.
     */
    private static final java.util.Set<String> BATCH_ALLOWLIST = new java.util.TreeSet<>(java.util.List.of(
            "add_struct_field",
            "create_label",
            "create_struct",
            "remove_struct_field",
            "rename_function",
            "rename_global",
            "rename_variable",
            "replace_struct_field",
            "set_comment",
            "set_function_prototype",
            "set_parameter_type",
            "check_connection",
            "decompile_function",
            "get_address_info",
            "get_calling_conventions",
            "get_disassembly",
            "get_function_callees",
            "get_function_info",
            "get_function_variables",
            "get_program_info",
            "get_struct_layout",
            "get_xrefs_from",
            "get_xrefs_to",
            "list_data_type_categories",
            "list_exports",
            "list_globals",
            "list_imports",
            "list_project_files",
            "read_data",
            "search_bytes",
            "search_constant_references",
            "search_data_types",
            "search_defined_strings",
            "search_functions",
            "search_instructions"
    ));

    @GET
    @Path("/list_exports")
    @Operation(tags = "Symbols and memory", operationId = "list_exports", summary = "List all exported functions and symbols in a program. Returns all exports; no pagination.")
    @ApiResponse(responseCode = "200", description = "Export list",
            content = @Content(schema = @Schema(implementation = ListExportsResponse.class)))
    public ListExportsResponse listExports(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName) {
        Program program = openProgram(programName);
        List<ExportEntry> exports = new ArrayList<>();
        AddressIterator iterator = program.getSymbolTable().getExternalEntryPointIterator();
        while (iterator.hasNext()) {
            var address = iterator.next();
            Function function = program.getFunctionManager().getFunctionAt(address);
            Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
            String name = function != null ? function.getName()
                    : (symbol != null ? symbol.getName() : "(unknown)");
            exports.add(new ExportEntry(address, name, function != null));
        }
        return new ListExportsResponse(exports, exports.size());
    }

    @GET
    @Path("/list_imports")
    @Operation(tags = "Symbols and memory", operationId = "list_imports", summary = "List all imported external symbols in a program. Returns all imports; no pagination.")
    @ApiResponse(responseCode = "200", description = "Import list",
            content = @Content(schema = @Schema(implementation = ListImportsResponse.class)))
    public ListImportsResponse listImports(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName) {
        Program program = openProgram(programName);
        List<ImportEntry> imports = new ArrayList<>();
        for (String libraryName : program.getExternalManager().getExternalLibraryNames()) {
            Iterator<ExternalLocation> locations = program.getExternalManager().getExternalLocations(libraryName);
            while (locations.hasNext()) {
                ExternalLocation location = locations.next();
                imports.add(new ImportEntry(libraryName, location.getLabel(), location.getAddress()));
            }
        }
        return new ListImportsResponse(imports, imports.size());
    }

    @GET
    @Path("/list_data_type_categories")
    @Operation(tags = "Data types", operationId = "list_data_type_categories", summary = "List all data type category paths in a program. Returns all categories; no pagination. Use search_data_types with a category path as the query to explore contents.")
    @ApiResponse(responseCode = "200", description = "Data type categories",
            content = @Content(schema = @Schema(implementation = ListDataTypeCategoriesResponse.class)))
    public ListDataTypeCategoriesResponse listDataTypeCategories(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName) {
        Program program = openProgram(programName);
        List<String> categories = new ArrayList<>();
        collectCategories(program.getDataTypeManager().getRootCategory(), categories);
        return new ListDataTypeCategoriesResponse(categories, categories.size());
    }

    @GET
    @Path("/get_function_info")
    @Operation(tags = "Functions", operationId = "get_function_info", summary = "Full details for one function: signature, calling convention, size, thunk status.")
    @ApiResponse(responseCode = "200", description = "Full function details",
            content = @Content(schema = @Schema(implementation = FunctionEntry.class)))
    public FunctionEntry getFunctionInfo(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName,
            @Parameter(description = "Function name (case-sensitive) or 0x-prefixed hex entry point.", required = true)
            @QueryParam("name_or_address") String nameOrAddress) {
        Program program = openProgram(programName);
        return FunctionEntry.from(findFunction(program, requireText(nameOrAddress, "name_or_address")));
    }

    @GET
    @Path("/get_address_info")
    @Operation(tags = "Symbols and memory", operationId = "get_address_info",
            summary = "Get detailed information about a specific address: the memory segment it belongs to, " +
                    "the function containing it (if any), and all cross-references pointing to it.")
    @ApiResponse(responseCode = "200", description = "Address information",
            content = @Content(schema = @Schema(implementation = GetAddressInfoResponse.class)))
    public GetAddressInfoResponse getAddressInfo(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName,
            @Parameter(description = "Address in 0x-prefixed hex, e.g. 0x00401000.", required = true)
            @QueryParam("address") String addressText) {
        Program program = openProgram(programName);
        var address = toAddress(program, requireText(addressText, "address"));

        MemoryBlock block = program.getMemory().getBlock(address);
        GetAddressInfoResponse.SegmentInfo segment = block != null
                ? new GetAddressInfoResponse.SegmentInfo(
                        block.getName(), block.getStart(), block.getEnd(),
                        block.isRead(), block.isWrite(), block.isExecute(), block.isInitialized())
                : null;

        Function function = program.getFunctionManager().getFunctionContaining(address);
        FunctionEntry functionEntry = function != null ? FunctionEntry.from(function) : null;

        List<XrefEntry> xrefs = new ArrayList<>();
        for (Reference reference : program.getReferenceManager().getReferencesTo(address)) {
            xrefs.add(XrefEntry.from(program, reference));
        }

        return new GetAddressInfoResponse(address, segment, functionEntry, xrefs, xrefs.size());
    }

        @GET
        @Path("/read_data")
        @Operation(tags = "Symbols and memory", operationId = "read_data",
            summary = "Read raw memory bytes from an address as fixed-size items.")
        @ApiResponse(responseCode = "200", description = "Raw data read result",
            content = @Content(schema = @Schema(implementation = ReadDataResponse.class)))
        public ReadDataResponse readData(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName,
            @Parameter(description = "Start address in 0x-prefixed hex, e.g. 0x00401000.", required = true)
            @QueryParam("address") String addressText,
            @Parameter(description = "Byte width of each item to read. Must be >= 1.")
            @QueryParam("item_size") @DefaultValue("1") int itemSize,
            @Parameter(description = "Number of items to read. Must be >= 1.")
            @QueryParam("item_count") @DefaultValue("16") int itemCount) {
        Program program = openProgram(programName);
        Address start = toAddress(program, requireText(addressText, "address"));
        int validatedItemSize = requirePositive(itemSize, "item_size");
        int validatedItemCount = requirePositive(itemCount, "item_count");
        long totalBytesLong = (long) validatedItemSize * (long) validatedItemCount;
        if (totalBytesLong > 65536L) {
            throw new IllegalArgumentException(
                "Requested read is too large: item_size * item_count = " + totalBytesLong +
                " bytes. Maximum supported read size is 65536 bytes.");
        }
        int totalBytes = (int) totalBytesLong;

        byte[] bytes = new byte[totalBytes];
        Memory memory = program.getMemory();
        try {
            memory.getBytes(start, bytes);
        } catch (MemoryAccessException e) {
            throw new IllegalArgumentException(
                "Unable to read " + totalBytes + " byte(s) from address " + addressText +
                ". Ensure the range is mapped and initialized in program memory.");
        }

        List<ReadDataItem> items = new ArrayList<>();
        for (int i = 0; i < validatedItemCount; i++) {
            int begin = i * validatedItemSize;
            int end = begin + validatedItemSize;
            byte[] chunk = java.util.Arrays.copyOfRange(bytes, begin, end);
            Address itemAddress = start.add(begin);
            items.add(new ReadDataItem(itemAddress, bytesToHex(chunk), bytesToAscii(chunk)));
        }

        return new ReadDataResponse(
            start,
            validatedItemSize,
            validatedItemCount,
            totalBytes,
            bytesToHex(bytes),
            bytesToAscii(bytes),
            items);
        }

        @GET
        @Path("/get_disassembly")
        @Operation(tags = "Code", operationId = "get_disassembly",
            summary = "Disassemble a fixed number of instructions from an address.")
        @ApiResponse(responseCode = "200", description = "Disassembly result",
            content = @Content(schema = @Schema(implementation = GetDisassemblyResponse.class)))
        public GetDisassemblyResponse getDisassembly(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName,
            @Parameter(description = "0x-prefixed hex address, or a symbol name (case-sensitive) to start at its address.", required = true)
            @QueryParam("address") String addressText,
            @Parameter(description = "Max instructions (max 2000); when more follow, 'truncated' is true and 'next_address' is the first not returned.")
            @QueryParam("limit") @DefaultValue("20") int limit) {
        Program program = openProgram(programName);
        // Accept either a 0x-prefixed address or a symbol/function name so this endpoint is
        // consistent with the name-or-address tools and does not force a separate lookup call.
        Address start = resolveDisassemblyStart(program, requireText(addressText, "address"));
        int validatedLimit = requireLimit(limit, 2000, "limit");

        Instruction current = program.getListing().getInstructionAt(start);
        if (current == null) {
            throw new IllegalArgumentException(
                "No instruction starts at address " + start.toString() +
                " (resolved from '" + addressText + "'). Provide an exact instruction address (use 0x prefix) " +
                "or a function/symbol name. Use get_address_info first if you need segment/function context.");
        }

        List<DisassemblyLine> lines = new ArrayList<>();
        while (current != null && lines.size() < validatedLimit) {
            Function containing = program.getFunctionManager().getFunctionContaining(current.getAddress());
            lines.add(new DisassemblyLine(
                current.getAddress(),
                bytesToHex(safeInstructionBytes(current)),
                current.getMnemonicString(),
                formatOperands(current),
                containing != null ? containing.getName() : null));
            current = current.getNext();
        }

        // If a next instruction remains, the caller's window did not reach the end — report it so
        // a short default window is never mistaken for "there are no more instructions".
        boolean truncated = current != null;
        Address nextAddress = current != null ? current.getAddress() : null;
        return new GetDisassemblyResponse(start, lines, lines.size(), truncated, nextAddress);
        }

        /**
         * Resolve a get_disassembly start location. A 0x-prefixed value is parsed as a hex
         * address; anything else is resolved as a case-sensitive symbol/function name.
         */
        private static Address resolveDisassemblyStart(Program program, String addressOrName) {
            if (addressOrName.startsWith("0x") || addressOrName.startsWith("0X")) {
                return toAddress(program, addressOrName);
            }
            return findSymbolAddress(program, addressOrName);
        }

    @GET
    @Path("/get_calling_conventions")
    @Operation(tags = "Functions", operationId = "get_calling_conventions", summary = "List all calling conventions available in a program's compiler spec. Use this to find valid values for the calling_convention field when calling set_function_prototype.")
    @ApiResponse(responseCode = "200", description = "Calling convention list",
            content = @Content(schema = @Schema(implementation = GetCallingConventionsResponse.class)))
    public GetCallingConventionsResponse getCallingConventions(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName) {
        Program program = openProgram(programName);
        List<String> conventions = new ArrayList<>();
        for (ghidra.program.model.lang.PrototypeModel model :
                program.getCompilerSpec().getCallingConventions()) {
            conventions.add(model.getName());
        }
        ghidra.program.model.lang.PrototypeModel defaultModel =
                program.getCompilerSpec().getDefaultCallingConvention();
        String defaultConvention = defaultModel != null ? defaultModel.getName() : null;
        return new GetCallingConventionsResponse(conventions, defaultConvention);
    }

    @GET
    @Path("/get_function_variables")
    @Operation(tags = "Functions", operationId = "get_function_variables", summary = "Get all parameters and local variables of a function.")
    @ApiResponse(responseCode = "200", description = "Function variables",
            content = @Content(schema = @Schema(implementation = GetFunctionVariablesResponse.class)))
    public GetFunctionVariablesResponse getFunctionVariables(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName,
            @Parameter(description = "Function name (case-sensitive) or 0x-prefixed hex entry point.", required = true)
            @QueryParam("name_or_address") String nameOrAddress) {
        Program program = openProgram(programName);
        Function function = findFunction(program, requireText(nameOrAddress, "name_or_address"));
        List<VariableEntry> variables = new ArrayList<>();
        for (var parameter : function.getParameters()) {
            variables.add(VariableEntry.from(parameter));
        }
        for (var variable : function.getLocalVariables()) {
            variables.add(VariableEntry.from(variable));
        }
        return new GetFunctionVariablesResponse(
                function.getName(),
                function.getEntryPoint(),
                variables);
    }

    public DecompileFunctionResponse decompileFunction(String programName, String nameOrAddress) {
        return decompileFunction(programName, nameOrAddress, 0);
    }

    @GET
    @Path("/decompile_function")
    @Operation(tags = "Code", operationId = "decompile_function", summary = "Decompile a function to C pseudocode.")
    @ApiResponse(responseCode = "200", description = "Decompiled function",
            content = @Content(schema = @Schema(implementation = DecompileFunctionResponse.class)))
    public DecompileFunctionResponse decompileFunction(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName,
            @Parameter(description = "Function name (case-sensitive) or 0x-prefixed hex entry point.", required = true)
            @QueryParam("name_or_address") String nameOrAddress,
            @Parameter(description = "Decompile timeout override in seconds; 0 uses the default.")
            @DefaultValue("0") @QueryParam("timeout_seconds") int timeoutSeconds) {
        Program program = openProgram(programName);
        Function function = findFunction(program, requireText(nameOrAddress, "name_or_address"));
        int validatedTimeoutSeconds = requireNonNegative(timeoutSeconds, "timeout_seconds");
        int effectiveTimeoutSeconds = validatedTimeoutSeconds > 0
                ? validatedTimeoutSeconds
                : decompileTimeoutSeconds;
        String code = decompileFresh(program, function, effectiveTimeoutSeconds);
        return new DecompileFunctionResponse(
            function.getName(),
            function.getEntryPoint(),
            code);
    }

    public SearchFunctionsResponse searchFunctions(
            String programName,
            String query,
            int limit) {
        return searchFunctions(programName, query, limit, null, null);
    }

    @GET
    @Path("/search_functions")
    @Operation(tags = "Functions", operationId = "search_functions", summary = "Find functions by name substring (case-insensitive); empty string lists all. Returns name and address — use get_function_info for full details.")
    @ApiResponse(responseCode = "200", description = "Function search results",
            content = @Content(schema = @Schema(implementation = SearchFunctionsResponse.class)))
    public SearchFunctionsResponse searchFunctions(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName,
            @Parameter(description = "Name substring (case-insensitive); empty lists all.")
            @QueryParam("query") @DefaultValue("") String query,
            @Parameter(description = "Max items (max 1000); 'truncated' means matches were dropped.")
            @QueryParam("limit") @DefaultValue("100") int limit,
            @Parameter(description = "Lower bound (inclusive) for function entry points.")
            @QueryParam("start_address") String startAddress,
            @Parameter(description = "Upper bound (inclusive) for function entry points.")
            @QueryParam("end_address") String endAddress) {
        Program program = openProgram(programName);
        int validatedLimit = requireLimit(limit, 1000, "limit");
        String loweredQuery = query == null ? "" : query.trim().toLowerCase();
        AddressRange range = resolveAddressRange(program, startAddress, endAddress,
                "start_address", "end_address");

        List<FunctionRef> found = new ArrayList<>();
        boolean truncated = false;
        for (Function function : program.getFunctionManager().getFunctions(true)) {
            if (range != null && !isWithinRange(function.getEntryPoint(), range)) {
                continue;
            }
            if (!loweredQuery.isEmpty() && !function.getName().toLowerCase().contains(loweredQuery)) {
                continue;
            }
            // Checked after the filters so 'truncated' means "a matching function was dropped",
            // never "the page happened to fill exactly".
            if (found.size() >= validatedLimit) {
                truncated = true;
                break;
            }
            found.add(FunctionRef.from(function));
        }
        return new SearchFunctionsResponse(found, found.size(), truncated);
    }

    @GET
    @Path("/search_data_types")
    @Operation(tags = "Data types", operationId = "search_data_types", summary = "Search for data types by name (case-insensitive). Pass an empty string to list all data types. Use list_data_type_categories to explore the category hierarchy. "
            + "Note that the C99 fixed-width spellings (int8_t..int64_t, uint8_t..uint64_t, size_t, ssize_t, intptr_t, uintptr_t, ptrdiff_t) are accepted by every tool that takes a type name even when they are absent here — they resolve to a type of exactly that width.")
    @ApiResponse(responseCode = "200", description = "Data type search results",
            content = @Content(schema = @Schema(implementation = SearchDataTypesResponse.class)))
    public SearchDataTypesResponse searchDataTypes(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName,
            @Parameter(description = "Substring filter applied to data type names (case-insensitive). Pass an empty string to list all data types.")
            @QueryParam("query") @DefaultValue("") String query,
            @Parameter(description = "Max items (max 500); 'truncated' means matches were dropped.")
            @QueryParam("limit") @DefaultValue("50") int limit) {
        Program program = openProgram(programName);
        int validatedLimit = requireLimit(limit, 500, "limit");
        String loweredQuery = query == null ? "" : query.trim().toLowerCase();
        List<DataTypeEntry> found = new ArrayList<>();
        boolean truncated = false;

        // Collect type names already gathered to avoid duplicates when built-in types
        // are also present in the program's DataTypeManager (e.g. after auto-analysis).
        Set<String> seen = new java.util.HashSet<>();

        Iterator<DataType> iterator = program.getDataTypeManager().getAllDataTypes();
        while (iterator.hasNext()) {
            DataType dataType = iterator.next();
            if (!loweredQuery.isEmpty() && !dataType.getName().toLowerCase().contains(loweredQuery)) {
                continue;
            }
            // Checked after the filter so 'truncated' means "a matching type was dropped",
            // never "the page happened to fill exactly".
            if (found.size() >= validatedLimit) {
                truncated = true;
                break;
            }
            found.add(DataTypeEntry.from(dataType));
            seen.add(dataType.getDataTypePath().getPath());
        }

        // Also include built-in types (int, byte, dword, etc.) which live in
        // BuiltInDataTypeManager and are absent from the program's manager on
        // programs without debug symbols. Skipped entirely once the program's own
        // manager has already overflowed the page.
        Iterator<DataType> builtInIterator = truncated
                ? Collections.emptyIterator()
                : BuiltInDataTypeManager.getDataTypeManager().getAllDataTypes();
        while (builtInIterator.hasNext()) {
            DataType dataType = builtInIterator.next();
            String path = dataType.getDataTypePath().getPath();
            if (seen.contains(path)) continue;
            if (!loweredQuery.isEmpty() && !dataType.getName().toLowerCase().contains(loweredQuery)) {
                continue;
            }
            if (found.size() >= validatedLimit) {
                truncated = true;
                break;
            }
            found.add(DataTypeEntry.from(dataType));
        }

        return new SearchDataTypesResponse(found, found.size(), truncated);
    }

    @GET
    @Path("/search_defined_strings")
    @Operation(tags = "Symbols and memory", operationId = "search_defined_strings", summary = "Search for defined strings across the program listing.")
    @ApiResponse(responseCode = "200", description = "Defined string search results",
            content = @Content(schema = @Schema(implementation = SearchDefinedStringsResponse.class)))
    public SearchDefinedStringsResponse searchDefinedStrings(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName,
            @Parameter(description = "Optional substring match (case-insensitive) applied to string values. Pass an empty string or omit to list all defined strings.")
            @QueryParam("query") String query,
            @Parameter(description = "0-based item offset for pagination. O(n) cost — avoid large offsets on large programs.")
            @QueryParam("offset") @DefaultValue("0") int offset,
            @Parameter(description = "Max items (max 1000); 'truncated' means matches were dropped — raise 'offset' by 'count' to page on.")
            @QueryParam("limit") @DefaultValue("200") int limit) {
        Program program = openProgram(programName);
        int validatedOffset = requireNonNegative(offset, "offset");
        int validatedLimit = requireLimit(limit, 1000, "limit");
        List<StringEntry> strings = new ArrayList<>();
        boolean truncated = false;
        int skip = validatedOffset;
        // O(n) pagination: Ghidra's defined-data iterator does not support random access;
        // offset items must be consumed linearly.
        for (Data data : program.getListing().getDefinedData(true)) {
            if (!data.hasStringValue()) {
                continue;
            }
            String value = data.getValue().toString();
            if (query != null && !value.toLowerCase().contains(query.toLowerCase())) {
                continue;
            }
            if (skip > 0) {
                skip--;
                continue;
            }
            // Checked after the filters and the offset skip so 'truncated' means "a matching
            // string past this page was dropped", never "the page happened to fill exactly".
            if (strings.size() >= validatedLimit) {
                truncated = true;
                break;
            }
            strings.add(StringEntry.from(data));
        }
        return new SearchDefinedStringsResponse(strings, strings.size(), truncated);
    }

    @GET
    @Path("/search_bytes")
    @Operation(tags = "Symbols and memory", operationId = "search_bytes",
            summary = "Search initialized memory for a hex byte pattern. Supports wildcards with ?? and optional address-range filtering.")
    @ApiResponse(responseCode = "200", description = "Byte-pattern search results",
            content = @Content(schema = @Schema(implementation = SearchBytesResponse.class)))
    public SearchBytesResponse searchBytes(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName,
            @Parameter(description = "Hex byte pattern, e.g. 'FF ?? 48' or '68 4E 58 50 20'.", required = true)
            @QueryParam("hex_pattern") String hexPattern,
            @Parameter(description = "Optional start address (inclusive) for the search range.")
            @QueryParam("start_address") String startAddress,
            @Parameter(description = "Optional end address (inclusive) for the search range.")
            @QueryParam("end_address") String endAddress,
            @Parameter(description = "Maximum number of hits to return (max 2000).")
            @QueryParam("limit") @DefaultValue("100") int limit) {
        Program program = openProgram(programName);
        int validatedLimit = requireLimit(limit, 2000, "limit");
        BytePattern pattern = parseBytePattern(requireText(hexPattern, "hex_pattern"));
        AddressRange range = resolveAddressRange(program, startAddress, endAddress,
                "start_address", "end_address");

        // Scan one hit past the page so 'truncated' means "a matching hit was dropped",
        // never "the page happened to fill exactly".
        List<PatternHit> hits = new ArrayList<>();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (!block.isInitialized()) {
                continue;
            }
            AddressRange blockRange = intersectRange(range, new AddressRange(block.getStart(), block.getEnd()));
            if (blockRange == null) {
                continue;
            }
            scanBlockForPattern(program, blockRange, pattern, validatedLimit + 1, hits);
            if (hits.size() > validatedLimit) {
                break;
            }
        }

        boolean truncated = hits.size() > validatedLimit;
        if (truncated) {
            hits.remove(hits.size() - 1);
        }
        return new SearchBytesResponse(pattern.normalized, hits, hits.size(), truncated);
    }

    @GET
    @Path("/search_instructions")
    @Operation(tags = "Code", operationId = "search_instructions",
            summary = "Search decoded instructions for a byte-pattern prefix (supports ?? wildcards) with optional address-range filtering.")
    @ApiResponse(responseCode = "200", description = "Instruction-pattern search results",
            content = @Content(schema = @Schema(implementation = SearchInstructionsResponse.class)))
    public SearchInstructionsResponse searchInstructions(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName,
            @Parameter(description = "Instruction byte pattern, e.g. 'FF ?? 48'.", required = true)
            @QueryParam("pattern") String patternText,
            @Parameter(description = "Optional start address (inclusive) for instruction filtering.")
            @QueryParam("start_address") String startAddress,
            @Parameter(description = "Optional end address (inclusive) for instruction filtering.")
            @QueryParam("end_address") String endAddress,
            @Parameter(description = "Maximum number of hits to return (max 2000).")
            @QueryParam("limit") @DefaultValue("100") int limit) {
        Program program = openProgram(programName);
        int validatedLimit = requireLimit(limit, 2000, "limit");
        BytePattern pattern = parseBytePattern(requireText(patternText, "pattern"));
        AddressRange range = resolveAddressRange(program, startAddress, endAddress,
                "start_address", "end_address");

        List<PatternHit> hits = new ArrayList<>();
        boolean truncated = false;
        var listing = program.getListing();
        var iterator = range == null
                ? listing.getInstructions(true)
                : listing.getInstructions(new AddressSet(range.start, range.end), true);
        while (iterator.hasNext()) {
            Instruction insn = iterator.next();
            byte[] bytes = safeInstructionBytes(insn);
            if (!pattern.matchesPrefix(bytes)) {
                continue;
            }
            // Checked after the match so 'truncated' means "a matching instruction was
            // dropped", never "the page happened to fill exactly".
            if (hits.size() >= validatedLimit) {
                truncated = true;
                break;
            }
            Function containing = program.getFunctionManager().getFunctionContaining(insn.getAddress());
            hits.add(new PatternHit(
                    insn.getAddress(),
                    containing != null ? containing.getName() : null,
                    formatInstruction(insn)));
        }

        return new SearchInstructionsResponse(pattern.normalized, hits, hits.size(), truncated);
    }

    @GET
    @Path("/get_struct_layout")
    @Operation(tags = "Data types", operationId = "get_struct_layout", summary = "Get the field layout of a structure data type.")
    @ApiResponse(responseCode = "200", description = "Structure layout",
            content = @Content(schema = @Schema(implementation = GetStructLayoutResponse.class)))
    public GetStructLayoutResponse getStructLayout(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName,
            @Parameter(description = "Exact name of the structure data type.", required = true)
            @QueryParam("name") String name) {
        Program program = openProgram(programName);
        String structName = requireText(name, "name");
        DataType dataType = findDataType(program, structName);
        if (!(dataType instanceof Structure)) {
            throw new IllegalArgumentException(
                    "'" + structName + "' is not a Structure (found: " + dataType.getClass().getSimpleName() + ")");
        }
        Structure struct = (Structure) dataType;
        List<StructField> fields = new ArrayList<>();
        for (var component : struct.getDefinedComponents()) {
            fields.add(StructField.from(component));
        }
        return new GetStructLayoutResponse(
                struct.getName(),
                struct.getCategoryPath().getPath(),
                struct.getLength(),
                struct.isPackingEnabled(),
                fields);
    }

    public XrefsResponse getXrefsTo(String programName, String nameOrAddress) {
        return getXrefsTo(programName, nameOrAddress, null, null, null, DEFAULT_XREF_LIMIT);
    }

    @GET
    @Path("/get_xrefs_to")
    @Operation(tags = "Cross-references", operationId = "get_xrefs_to",
            summary = "List cross-references to an address or symbol. When the target is a function "
                    + "entry point, indirect caller candidates are included.")
    @ApiResponse(responseCode = "200", description = "Cross-references to address",
            content = @Content(schema = @Schema(implementation = XrefsResponse.class)))
    public XrefsResponse getXrefsTo(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName,
            @Parameter(description = "Symbol name (case-sensitive) or 0x-prefixed hex address.", required = true)
            @QueryParam("name_or_address") String nameOrAddress,
            @Parameter(description = "Filter by category (CALL, COMPUTED_CALL, DATA, READ, WRITE, OTHER) or exact Ghidra type name (e.g. UNCONDITIONAL_CALL). Repeatable or comma-separated.")
            @QueryParam("ref_types") List<String> refTypes,
            @Parameter(description = "Lower bound (inclusive) for xref source addresses.")
            @QueryParam("start_address") String startAddress,
            @Parameter(description = "Upper bound (inclusive) for xref source addresses.")
            @QueryParam("end_address") String endAddress,
            @Parameter(description = "Max xrefs (max 5000); 'truncated' means matches were dropped — narrow the filters rather than raise this.")
            @QueryParam("limit") @DefaultValue("500") int limit) {
        Program program = openProgram(programName);
        int validatedLimit = requireLimit(limit, MAX_XREF_LIMIT, "limit");
        Address address = findSymbolAddress(program, requireText(nameOrAddress, "name_or_address"));
        AddressRange fromRange = resolveAddressRange(program, startAddress, endAddress,
                "start_address", "end_address");
        Set<String> requestedTypes = normalizeRefTypeFilter(refTypes);
        List<XrefEntry> xrefs = new ArrayList<>();
        boolean truncated = false;
        for (Reference reference : program.getReferenceManager().getReferencesTo(address)) {
            if (fromRange != null && !isWithinRange(reference.getFromAddress(), fromRange)) {
                continue;
            }
            if (!matchesRequestedRefType(reference, requestedTypes)) {
                continue;
            }
            // Checked after the filters so 'truncated' means "a matching xref was dropped",
            // never "the page happened to fill exactly".
            if (xrefs.size() >= validatedLimit) {
                truncated = true;
                break;
            }
            xrefs.add(XrefEntry.from(program, reference));
        }

        Function targetFunction = program.getFunctionManager().getFunctionAt(address);
        List<IndirectCallerEntry> indirectCallers = targetFunction != null
                ? inferIndirectCallers(program, address)
                : List.of();
        return XrefsResponse.fromEntries(xrefs, truncated, indirectCallers);
    }

    public XrefsResponse getXrefsFrom(String programName, String addressText) {
        return getXrefsFrom(programName, addressText, null, null, null, DEFAULT_XREF_LIMIT);
    }

    @GET
    @Path("/get_xrefs_from")
    @Operation(tags = "Cross-references", operationId = "get_xrefs_from", summary = "List cross-references originating from an address with optional destination-range and ref-type filters.")
    @ApiResponse(responseCode = "200", description = "Cross-references from address",
            content = @Content(schema = @Schema(implementation = XrefsResponse.class)))
    public XrefsResponse getXrefsFrom(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName,
            @Parameter(description = "Hex address with 0x prefix, e.g. 0x00401000. Use search_functions to find entry points.", required = true)
            @QueryParam("address") String addressText,
            @Parameter(description = "Filter by category (CALL, COMPUTED_CALL, DATA, READ, WRITE, OTHER) or exact Ghidra type name (e.g. UNCONDITIONAL_CALL). Repeatable or comma-separated.")
            @QueryParam("ref_types") List<String> refTypes,
            @Parameter(description = "Optional lower bound (inclusive) for destination addresses.")
            @QueryParam("start_address") String startAddress,
            @Parameter(description = "Optional upper bound (inclusive) for destination addresses.")
            @QueryParam("end_address") String endAddress,
            @Parameter(description = "Max xrefs (max 5000); 'truncated' means matches were dropped.")
            @QueryParam("limit") @DefaultValue("500") int limit) {
        Program program = openProgram(programName);
        int validatedLimit = requireLimit(limit, MAX_XREF_LIMIT, "limit");
        var address = toAddress(program, requireText(addressText, "address"));
        AddressRange toRange = resolveAddressRange(program, startAddress, endAddress,
                "start_address", "end_address");
        Set<String> requestedTypes = normalizeRefTypeFilter(refTypes);
        List<XrefEntry> xrefs = new ArrayList<>();
        boolean truncated = false;
        for (Reference reference : program.getReferenceManager().getReferencesFrom(address)) {
            if (toRange != null && !isWithinRange(reference.getToAddress(), toRange)) {
                continue;
            }
            if (!matchesRequestedRefType(reference, requestedTypes)) {
                continue;
            }
            if (xrefs.size() >= validatedLimit) {
                truncated = true;
                break;
            }
            xrefs.add(XrefEntry.from(program, reference));
        }
        return XrefsResponse.fromEntries(xrefs, truncated, List.of());
    }

    @GET
    @Path("/get_function_callees")
    @Operation(tags = "Functions", operationId = "get_function_callees", summary = "Get all functions called by the specified function.")
    @ApiResponse(responseCode = "200", description = "Function callees",
            content = @Content(schema = @Schema(implementation = FunctionCalleesResponse.class)))
    public FunctionCalleesResponse getFunctionCallees(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName,
            @Parameter(description = "Function name (case-sensitive) or 0x-prefixed hex entry point.", required = true)
            @QueryParam("name_or_address") String nameOrAddress) {
        Program program = openProgram(programName);
        Function function = findFunction(program, requireText(nameOrAddress, "name_or_address"));
        List<FunctionRef> callees = new ArrayList<>();
        for (Function callee : function.getCalledFunctions(TaskMonitor.DUMMY)) {
            callees.add(FunctionRef.from(callee));
        }
        return new FunctionCalleesResponse(function.getName(), callees, callees.size());
    }

    @GET
    @Path("/search_constant_references")
    @Operation(tags = "Code", operationId = "search_constant_references",
            summary = "Find all instructions that use a specific constant as an immediate operand. " +
                    "Useful for locating every usage of a magic number, error code, or flag value, " +
                    "e.g. passing 0x100D0 to find all mov/cmp/push instructions referencing that constant.")
    @ApiResponse(responseCode = "200", description = "Constant reference search results",
            content = @Content(schema = @Schema(implementation = SearchConstantReferencesResponse.class)))
    public SearchConstantReferencesResponse searchConstantReferences(
            @Parameter(description = "Program name; see list_project_files.", required = true)
            @QueryParam("program") String programName,
            @Parameter(description = "Constant to search for. Accepts decimal (e.g. 65744), 0x-prefixed hex (e.g. 0x100D0), or a negative value treated as its unsigned bit pattern (e.g. -1 matches 0xFFFFFFFFFFFFFFFF).", required = true)
            @QueryParam("value") String valueText,
            @Parameter(description = "Maximum number of hits to return (max 2000). 'truncated' is true when matches were dropped.")
            @QueryParam("limit") @DefaultValue("200") int limit) {
        Program program = openProgram(programName);
        int validatedLimit = requireLimit(limit, 2000, "limit");
        String rawValue = requireText(valueText, "value").toLowerCase().trim();
        long targetValue;
        if (!rawValue.startsWith("0x") && rawValue.startsWith("0")) {
            // Do not allow octal notation
            throw new IllegalArgumentException(
                    "Invalid value '" + rawValue + "': octal notation is not supported. " +
                    "Use 0x prefix for hex (e.g. 0x100d0) or pass a decimal integer without leading zeros (e.g. 65744).");
        }
        
        try {
            targetValue = Long.decode(rawValue);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "Invalid value '" + rawValue + "': expected a decimal integer or 0x-prefixed hex, e.g. 0x100D0 or 65744.");
        }
        List<ConstantHit> hits = new ArrayList<>();
        boolean truncated = false;
        scan:
        for (Instruction insn : program.getListing().getInstructions(true)) {
            for (int op = 0; op < insn.getNumOperands(); op++) {
                Scalar scalar = insn.getScalar(op);

                if (scalar != null && scalar.getUnsignedValue() == targetValue) {
                    // Checked after the match so 'truncated' means "a matching instruction was
                    // dropped", never "the page happened to fill exactly".
                    if (hits.size() >= validatedLimit) {
                        truncated = true;
                        break scan;
                    }
                    Function fn = program.getFunctionManager().getFunctionContaining(insn.getAddress());
                    hits.add(new ConstantHit(
                            insn.getAddress(),
                            fn != null ? fn.getName() : null,
                            insn.getMnemonicString()));
                    break; // count each instruction once
                }
            }
        }
        return new SearchConstantReferencesResponse(targetValue, hits, hits.size(), truncated);
    }

    private static AddressRange resolveAddressRange(Program program,
            String startAddressText,
            String endAddressText,
            String startField,
            String endField) {
        if ((startAddressText == null || startAddressText.isBlank()) &&
                (endAddressText == null || endAddressText.isBlank())) {
            return null;
        }

        Address start = (startAddressText == null || startAddressText.isBlank())
                ? program.getMemory().getMinAddress()
                : toAddress(program, startAddressText);
        Address end = (endAddressText == null || endAddressText.isBlank())
                ? program.getMemory().getMaxAddress()
                : toAddress(program, endAddressText);
        if (start.compareTo(end) > 0) {
            throw new IllegalArgumentException(
                    "Invalid address range: '" + startField + "' must be <= '" + endField + "'.");
        }
        return new AddressRange(start, end);
    }

    private static AddressRange intersectRange(AddressRange a, AddressRange b) {
        if (a == null) {
            return b;
        }
        if (b == null) {
            return a;
        }
        Address start = a.start.compareTo(b.start) >= 0 ? a.start : b.start;
        Address end = a.end.compareTo(b.end) <= 0 ? a.end : b.end;
        if (start.compareTo(end) > 0) {
            return null;
        }
        return new AddressRange(start, end);
    }

    private static boolean isWithinRange(Address address, AddressRange range) {
        return address.compareTo(range.start) >= 0 && address.compareTo(range.end) <= 0;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) {
                sb.append(' ');
            }
            sb.append(String.format("%02X", bytes[i] & 0xFF));
        }
        return sb.toString();
    }

    private static String bytesToAscii(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length);
        for (byte b : bytes) {
            int v = b & 0xFF;
            sb.append(v >= 32 && v <= 126 ? (char) v : '.');
        }
        return sb.toString();
    }

    private static byte[] safeInstructionBytes(Instruction insn) {
        try {
            return insn.getBytes();
        } catch (MemoryAccessException e) {
            return new byte[0];
        }
    }

    private static String formatOperands(Instruction insn) {
        StringBuilder operands = new StringBuilder();
        for (int i = 0; i < insn.getNumOperands(); i++) {
            if (i > 0) {
                operands.append(", ");
            }
            operands.append(insn.getDefaultOperandRepresentation(i));
        }
        return operands.toString();
    }

    private static String formatInstruction(Instruction insn) {
        String operands = formatOperands(insn);
        return operands.isBlank() ? insn.getMnemonicString() : insn.getMnemonicString() + " " + operands;
    }

    private static BytePattern parseBytePattern(String patternText) {
        String normalized = patternText.trim().replaceAll("\\s+", " ");
        if (normalized.isBlank()) {
            throw new IllegalArgumentException("Required parameter 'hex_pattern' must not be empty");
        }
        String[] tokens = normalized.split(" ");
        byte[] bytes = new byte[tokens.length];
        boolean[] wildcard = new boolean[tokens.length];
        for (int i = 0; i < tokens.length; i++) {
            String token = tokens[i].toUpperCase(Locale.ROOT);
            if ("??".equals(token)) {
                wildcard[i] = true;
                continue;
            }
            if (!token.matches("[0-9A-F]{2}")) {
                throw new IllegalArgumentException(
                        "Invalid hex pattern token '" + tokens[i] + "'. Use two hex digits or ?? wildcard.");
            }
            bytes[i] = (byte) Integer.parseInt(token, 16);
        }
        return new BytePattern(normalized.toUpperCase(Locale.ROOT), bytes, wildcard);
    }

    private static void scanBlockForPattern(
            Program program,
            AddressRange range,
            BytePattern pattern,
            int limit,
            List<PatternHit> hits) {
        if (pattern.bytes.length == 0) {
            return;
        }
        long startOffset = range.start.getOffset();
        long endOffset = range.end.getOffset();
        long maxStart = endOffset - pattern.bytes.length + 1;
        if (maxStart < startOffset) {
            return;
        }

        var addressSpace = range.start.getAddressSpace();
        Memory memory = program.getMemory();
        for (long offset = startOffset; offset <= maxStart && hits.size() < limit; offset++) {
            Address candidate = addressSpace.getAddress(offset);
            boolean matched = true;
            for (int i = 0; i < pattern.bytes.length; i++) {
                if (pattern.wildcard[i]) {
                    continue;
                }
                try {
                    byte actual = memory.getByte(candidate.add(i));
                    if (actual != pattern.bytes[i]) {
                        matched = false;
                        break;
                    }
                } catch (MemoryAccessException e) {
                    // Hit an unmapped/uninitialised byte — pattern doesn't match here.
                    matched = false;
                    break;
                }
            }
            if (!matched) {
                continue;
            }
            Instruction insn = program.getListing().getInstructionAt(candidate);
            Function containing = program.getFunctionManager().getFunctionContaining(candidate);
            hits.add(new PatternHit(
                    candidate,
                    containing != null ? containing.getName() : null,
                    insn != null ? formatInstruction(insn) : null));
        }
    }

    /** The coarse groupings {@link #classifyReferenceType} folds Ghidra's reference types into. */
    private static final Set<String> REF_TYPE_CATEGORIES =
            new LinkedHashSet<>(List.of("CALL", "COMPUTED_CALL", "DATA", "READ", "WRITE", "OTHER"));

    /**
     * Every name {@link #matchesRequestedRefType} can match: the categories above plus the exact
     * names Ghidra publishes. Read off {@link RefType}'s own constants so it cannot fall behind
     * the Ghidra version in use.
     */
    private static final Set<String> KNOWN_REF_TYPES = knownRefTypes();

    private static Set<String> knownRefTypes() {
        Set<String> names = new LinkedHashSet<>(REF_TYPE_CATEGORIES);
        for (java.lang.reflect.Field field : RefType.class.getFields()) {
            if (!java.lang.reflect.Modifier.isStatic(field.getModifiers())
                    || !RefType.class.isAssignableFrom(field.getType())) {
                continue;
            }
            try {
                names.add(((RefType) field.get(null)).getName().toUpperCase(Locale.ROOT));
            } catch (IllegalAccessException e) {
                // A non-readable constant simply is not offered; the filter still works.
            }
        }
        return names;
    }

    /**
     * Parses the {@code ref_types} filter, rejecting any name that could never match. An
     * unrecognised type is the worst kind of bad argument here: it filters every reference out
     * and the tool answers "no cross-references", which reads as a fact about the program rather
     * than a typo.
     */
    private static Set<String> normalizeRefTypeFilter(List<String> raw) {
        if (raw == null || raw.isEmpty()) {
            return Set.of();
        }
        Set<String> normalized = new LinkedHashSet<>();
        for (String value : raw) {
            if (value == null || value.isBlank()) {
                continue;
            }
            for (String token : value.split(",")) {
                String trimmed = token.trim().toUpperCase(Locale.ROOT);
                if (trimmed.isEmpty()) {
                    continue;
                }
                if (!KNOWN_REF_TYPES.contains(trimmed)) {
                    String suggestion = ApiSupport.suggestClosest(trimmed, KNOWN_REF_TYPES);
                    throw new IllegalArgumentException(
                            "Unknown reference type '" + token.trim() + "' in 'ref_types'. " +
                            (suggestion != null ? "Did you mean '" + suggestion + "'? " : "") +
                            "Use one of the categories " + String.join(", ", REF_TYPE_CATEGORIES) +
                            ", or an exact Ghidra reference type name such as UNCONDITIONAL_CALL.");
                }
                normalized.add(trimmed);
            }
        }
        return normalized;
    }

    private static boolean matchesRequestedRefType(Reference reference, Set<String> requestedTypes) {
        if (requestedTypes.isEmpty()) {
            return true;
        }
        String exact = reference.getReferenceType().getName().toUpperCase(Locale.ROOT);
        String category = classifyReferenceType(exact);
        return requestedTypes.contains(exact) || requestedTypes.contains(category);
    }

    private static String classifyReferenceType(String refTypeName) {
        if (refTypeName.contains("COMPUTED_CALL")) {
            return "COMPUTED_CALL";
        }
        if (refTypeName.contains("CALL")) {
            return "CALL";
        }
        if (refTypeName.contains("DATA")) {
            return "DATA";
        }
        if (refTypeName.contains("READ")) {
            return "READ";
        }
        if (refTypeName.contains("WRITE")) {
            return "WRITE";
        }
        return "OTHER";
    }

    private static List<IndirectCallerEntry> inferIndirectCallers(Program program, Address targetAddress) {
        Set<Function> candidateFunctions = new LinkedHashSet<>();
        for (Reference ref : program.getReferenceManager().getReferencesTo(targetAddress)) {
            String refType = ref.getReferenceType().getName().toUpperCase(Locale.ROOT);
            if (!refType.contains("DATA") && !refType.contains("READ")) {
                continue;
            }
            Function fromFunction = program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
            if (fromFunction != null) {
                candidateFunctions.add(fromFunction);
            }
        }

        Set<String> seenCallsites = new LinkedHashSet<>();
        List<IndirectCallerEntry> hits = new ArrayList<>();
        for (Function function : candidateFunctions) {
            var it = program.getListing().getInstructions(function.getBody(), true);
            while (it.hasNext()) {
                Instruction insn = it.next();
                if (!insn.getFlowType().isCall() || !insn.getFlowType().isComputed()) {
                    continue;
                }
                String callsiteKey = insn.getAddress().toString();
                if (!seenCallsites.add(callsiteKey)) {
                    continue;
                }
                hits.add(new IndirectCallerEntry(
                        insn.getAddress(),
                        function.getName(),
                        function.getEntryPoint(),
                        formatInstruction(insn),
                        "Function contains a data/read reference to the target function pointer and executes a computed call."));
            }
        }
        return hits;
    }

    private void collectCategories(Category category, List<String> out) {
        out.add(category.getCategoryPathName());
        for (Category subCategory : category.getCategories()) {
            collectCategories(subCategory, out);
        }
    }

    private Program openProgram(String programName) {
        try {
            return mgr.getOrOpen(requireText(programName, "program"));
        } catch (RuntimeException e) {
            throw e; // IllegalArgumentException → 400, others bubble as-is → 500
        } catch (Exception e) {
            throw new RuntimeException("Failed to open program '" + programName + "': " + e.getMessage(), e);
        }
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Required parameter '" + fieldName + "' is missing");
        }
        return value;
    }

    private static int requireNonNegative(int value, String fieldName) {
        if (value < 0) {
            throw new IllegalArgumentException(
                    "Invalid value for '" + fieldName + "': " + value + ". Expected a non-negative integer.");
        }
        return value;
    }

    private static int requireLimit(int value, int maxValue, String fieldName) {
        int validatedValue = requireNonNegative(value, fieldName);
        if (validatedValue > maxValue) {
            throw new IllegalArgumentException(
                    "Invalid value for '" + fieldName + "': " + validatedValue + ". Maximum supported value is " + maxValue + ".");
        }
        return validatedValue;
    }

    private static int requirePositive(int value, String fieldName) {
        if (value <= 0) {
            throw new IllegalArgumentException(
                    "Invalid value for '" + fieldName + "': " + value + ". Expected a positive integer.");
        }
        return value;
    }

    private static String loadVersion() {
        try (var in = ReadTools.class.getClassLoader().getResourceAsStream("extension.properties")) {
            if (in == null) return "unknown";
            var props = new java.util.Properties();
            props.load(in);
            var version = props.getProperty("version");
            return version != null && !version.isBlank() ? version.trim() : "unknown";
        } catch (Exception e) {
            return "unknown";
        }
    }

    private static List<String> requireBodyStringList(JsonObject body, String fieldName) {
        if (body == null || !body.has(fieldName) || body.get(fieldName).isJsonNull()) {
            throw new IllegalArgumentException("Required parameter '" + fieldName + "' is missing");
        }
        if (!body.get(fieldName).isJsonArray()) {
            throw new IllegalArgumentException(
                    "Parameter '" + fieldName + "' must be a JSON array of strings.");
        }
        JsonArray array = body.getAsJsonArray(fieldName);
        List<String> values = new java.util.ArrayList<>();
        for (int i = 0; i < array.size(); i++) {
            if (!array.get(i).isJsonPrimitive() || !array.get(i).getAsJsonPrimitive().isString()) {
                throw new IllegalArgumentException(
                        "Parameter '" + fieldName + "[" + i + "]' must be a string.");
            }
            String value = array.get(i).getAsString();
            if (value.isBlank()) {
                throw new IllegalArgumentException(
                        "Parameter '" + fieldName + "[" + i + "]' must not be empty.");
            }
            values.add(value);
        }
        return values;
    }

        private static List<JsonObject> requireBodyObjectList(JsonObject body, String fieldName) {
        if (body == null || !body.has(fieldName) || body.get(fieldName).isJsonNull()) {
            throw new IllegalArgumentException("Required parameter '" + fieldName + "' is missing");
        }
        if (!body.get(fieldName).isJsonArray()) {
            throw new IllegalArgumentException(
                "Parameter '" + fieldName + "' must be a JSON array of objects.");
        }
        JsonArray array = body.getAsJsonArray(fieldName);
        List<JsonObject> values = new ArrayList<>();
        for (int i = 0; i < array.size(); i++) {
            if (!array.get(i).isJsonObject()) {
            throw new IllegalArgumentException(
                "Parameter '" + fieldName + "[" + i + "]' must be an object.");
            }
            values.add(array.get(i).getAsJsonObject());
        }
        return values;
        }

        private Object dispatchBatchTool(String tool, JsonObject args) {
        if (args == null) {
            throw new IllegalArgumentException("Batch call arguments must be a JSON object.");
        }
        rejectUnknownBatchArguments(tool, args);
        return switch (tool) {
            case "search_functions" -> searchFunctions(
                required(args, "program"),
                optional(args, "query", ""),
                optionalInt(args, "limit", 100),
                optional(args, "start_address", null),
                optional(args, "end_address", null));
            case "get_function_info" -> getFunctionInfo(
                required(args, "program"),
                required(args, "name_or_address"));
            case "decompile_function" -> decompileFunction(
                required(args, "program"),
                required(args, "name_or_address"),
                optionalInt(args, "timeout_seconds", 0));
            case "get_address_info" -> getAddressInfo(
                required(args, "program"),
                required(args, "address"));
            case "get_disassembly" -> getDisassembly(
                required(args, "program"),
                required(args, "address"),
                optionalInt(args, "limit", 20));
            case "read_data" -> readData(
                required(args, "program"),
                required(args, "address"),
                optionalInt(args, "item_size", 1),
                optionalInt(args, "item_count", 16));
            case "search_bytes" -> searchBytes(
                required(args, "program"),
                required(args, "hex_pattern"),
                optional(args, "start_address", null),
                optional(args, "end_address", null),
                optionalInt(args, "limit", 100));
            case "search_instructions" -> searchInstructions(
                required(args, "program"),
                required(args, "pattern"),
                optional(args, "start_address", null),
                optional(args, "end_address", null),
                optionalInt(args, "limit", 100));
            case "get_xrefs_to" -> {
            List<String> refTypes = args.has("ref_types") && !args.get("ref_types").isJsonNull()
                ? requireBodyStringList(args, "ref_types") : List.of();
                yield getXrefsTo(
                required(args, "program"),
                required(args, "name_or_address"),
                refTypes,
                optional(args, "start_address", null),
                optional(args, "end_address", null),
                optionalInt(args, "limit", DEFAULT_XREF_LIMIT));
            }
            case "get_xrefs_from" -> {
            List<String> refTypes = args.has("ref_types") && !args.get("ref_types").isJsonNull()
                ? requireBodyStringList(args, "ref_types") : List.of();
                yield getXrefsFrom(
                required(args, "program"),
                required(args, "address"),
                refTypes,
                optional(args, "start_address", null),
                optional(args, "end_address", null),
                optionalInt(args, "limit", DEFAULT_XREF_LIMIT));
            }
            case "get_program_info" -> getProgramInfo(required(args, "program"));
            case "list_globals" -> listGlobals(
                required(args, "program"),
                optional(args, "section", null),
                optional(args, "start_address", null),
                optional(args, "end_address", null),
                optionalInt(args, "limit", 500));
            case "check_connection" -> checkConnection();
            case "list_project_files" -> listProjectFiles();
            case "list_exports" -> listExports(required(args, "program"));
            case "list_imports" -> listImports(required(args, "program"));
            case "list_data_type_categories" -> listDataTypeCategories(required(args, "program"));
            case "get_calling_conventions" -> getCallingConventions(required(args, "program"));
            case "get_function_callees" -> getFunctionCallees(
                required(args, "program"),
                required(args, "name_or_address"));
            case "get_function_variables" -> getFunctionVariables(
                required(args, "program"),
                required(args, "name_or_address"));
            case "get_struct_layout" -> getStructLayout(
                required(args, "program"),
                required(args, "name"));
            case "search_data_types" -> searchDataTypes(
                required(args, "program"),
                optional(args, "query", ""),
                optionalInt(args, "limit", 50));
            case "search_defined_strings" -> searchDefinedStrings(
                required(args, "program"),
                optional(args, "query", null),
                optionalInt(args, "offset", 0),
                optionalInt(args, "limit", 200));
            case "search_constant_references" -> searchConstantReferences(
                required(args, "program"),
                required(args, "value"),
                optionalInt(args, "limit", 200));
            // Write tools take the request body verbatim, so a batch item is that same body —
            // there is nothing to unpack and no second spelling of any parameter to keep in sync.
            case "rename_function" -> writeTools.renameFunction(args);
            case "rename_variable" -> writeTools.renameVariable(args);
            case "rename_global" -> writeTools.renameGlobal(args);
            case "create_label" -> writeTools.createLabel(args);
            case "set_function_prototype" -> writeTools.setFunctionPrototype(args);
            case "set_parameter_type" -> writeTools.setParameterType(args);
            case "create_struct" -> writeTools.createStruct(args);
            case "add_struct_field" -> writeTools.addStructField(args);
            case "remove_struct_field" -> writeTools.removeStructField(args);
            case "replace_struct_field" -> writeTools.replaceStructField(args);
            case "set_comment" -> writeTools.setComment(args);
            default -> throw new IllegalArgumentException(
                "Tool '" + tool + "' is not allowlisted for batch_tool_call. " +
                "Allowed tools: " + String.join(", ", BATCH_ALLOWLIST) + ".");
        };
        }

        private static boolean isGlobalCandidate(Symbol symbol) {
        Namespace parent = symbol.getParentNamespace();
        if (parent == null) {
            return true;
        }
        if (parent.isGlobal()) {
            return true;
        }
        return parent.getName() != null && parent.getName().equalsIgnoreCase("Global");
        }

    public record CheckConnectionResponse(String status, String server, String version) {
    }

    public record ListProjectFilesResponse(List<String> files, int count) {
    }

        public record GetProgramInfoResponse(
            String program,
            String executable_path,
            String executable_format,
            String language_id,
            String compiler_spec_id,
            @Schema(type = "string", description = "Program image base in 0x-prefixed hex.")
            Address image_base,
            List<ProgramMemoryBlock> memory_blocks,
            int memory_block_count) {
        }

        public record ProgramMemoryBlock(
            String name,
            @Schema(type = "string", description = "Start address in 0x-prefixed hex.")
            Address start,
            @Schema(type = "string", description = "End address in 0x-prefixed hex.")
            Address end,
            long size,
            boolean initialized,
            boolean readable,
            boolean writable,
            boolean executable,
            boolean is_volatile) {
        }

        public record ListGlobalsResponse(
            List<GlobalSymbolEntry> functions,
            List<GlobalSymbolEntry> data,
            List<GlobalSymbolEntry> labels,
            @Schema(description = "Number of items in this response. This is the size of the returned page, bounded by 'limit' — not the total number of matches in the program.")
            int count,
            @Schema(description = "True when a matching symbol was dropped because 'limit' was reached. Narrow with 'section' or the address range rather than raising 'limit'.")
            boolean truncated) {
        }

        public record GlobalSymbolEntry(
            String name,
            @Schema(type = "string", description = "Symbol address in 0x-prefixed hex.")
            Address address,
            String symbol_type,
            String section,
            String namespace) {
        }

        public record BatchToolCallRequest(
            @Schema(description = "Allowlisted read or write tool operationId to execute.", requiredMode = Schema.RequiredMode.REQUIRED)
            String tool,
            @Schema(description = "List of argument objects, each exactly what the tool takes on its own. "
                    + "One tool call is executed per item, in order; a failed item does not stop the rest. "
                    + "Maximum 50.", requiredMode = Schema.RequiredMode.REQUIRED)
            List<Map<String, Object>> calls) {
        }

        public record BatchToolCallResponse(
            String tool,
            List<BatchToolCallItemResult> results,
            int count,
            @Schema(description = "Number of items in results with ok=false.")
            int failed) {
        }

        public record BatchToolCallItemResult(
            int index,
            boolean ok,
            Object result,
            String error) {
        }

    public record ListExportsResponse(List<ExportEntry> exports, int count) {
    }

    public record ListImportsResponse(List<ImportEntry> imports, int count) {
    }

    public record ListDataTypeCategoriesResponse(List<String> categories, int count) {
    }

    public record GetFunctionVariablesResponse(String function, Address address,
            List<VariableEntry> variables) {
    }

    public record DecompileFunctionResponse(String name, Address address, String decompiled) {
    }

    public record SearchFunctionsResponse(
            List<FunctionRef> functions,
            @Schema(description = "Number of items in this response. This is the size of the returned page, bounded by 'limit' — not the total number of matches in the program.")
            int count,
            @Schema(description = "True when a matching function was dropped because 'limit' was reached. Narrow 'query' or the address range rather than raising 'limit'.")
            boolean truncated) {
    }

    public record GetCallingConventionsResponse(
            @Schema(description = "All calling convention names valid for this program.")
            List<String> calling_conventions,
            @Schema(description = "Default calling convention name for this program's architecture.")
            String default_convention) {
    }

    public record SearchDataTypesResponse(
            List<DataTypeEntry> data_types,
            @Schema(description = "Number of items in this response. This is the size of the returned page, bounded by 'limit' — not the total number of matches in the program.")
            int count,
            @Schema(description = "True when a matching data type was dropped because 'limit' was reached. Narrow 'query' rather than raising 'limit'.")
            boolean truncated) {
    }

    public record SearchDefinedStringsResponse(
            List<StringEntry> strings,
            @Schema(description = "Number of items in this response. This is the size of the returned page, bounded by 'limit' — not the total number of matches in the program.")
            int count,
            @Schema(description = "True when a matching string past this page was dropped because 'limit' was reached. Page on with 'offset', or narrow 'query'.")
            boolean truncated) {
    }

        public record ReadDataResponse(
            @Schema(type = "string", description = "Start address of the read in 0x-prefixed hex.")
            Address start_address,
            int item_size,
            int item_count,
            int bytes_read,
            @Schema(description = "Full read bytes as uppercase hex pairs separated by spaces.")
            String hex,
            @Schema(description = "ASCII preview where non-printable bytes are shown as '.'.")
            String ascii,
            List<ReadDataItem> items) {
        }

        public record ReadDataItem(
            @Schema(type = "string", description = "Address of this item in 0x-prefixed hex.")
            Address address,
            String hex,
            String ascii) {
        }

        public record GetDisassemblyResponse(
            @Schema(type = "string", description = "Address requested for disassembly start.")
            Address start_address,
            List<DisassemblyLine> lines,
            int count,
            @Schema(description = "True when more instructions follow the returned window ('limit' was reached before the end of mapped code). Re-request from 'next_address' to continue.")
            boolean truncated,
            @Schema(type = "string", description = "Address of the first instruction not included, or null when the disassembly ran to the end of mapped code.")
            Address next_address) {
        }

        public record DisassemblyLine(
            @Schema(type = "string", description = "Instruction address in 0x-prefixed hex.")
            Address address,
            @Schema(description = "Instruction bytes as uppercase hex pairs separated by spaces.")
            String bytes,
            String mnemonic,
            String operands,
            String function_name) {
        }

        public record PatternHit(
            @Schema(type = "string", description = "Match address in 0x-prefixed hex.")
            Address address,
            String function_name,
            @Schema(description = "Instruction text when an instruction starts at the match address; null otherwise.")
            String instruction) {
        }

        public record SearchBytesResponse(
            String pattern,
            List<PatternHit> hits,
            @Schema(description = "Number of items in this response. This is the size of the returned page, bounded by 'limit' — not the total number of matches in the program.")
            int count,
            @Schema(description = "True when a matching hit was dropped because 'limit' was reached. Narrow the address range rather than raising 'limit'.")
            boolean truncated) {
        }

        public record SearchInstructionsResponse(
            String pattern,
            List<PatternHit> hits,
            @Schema(description = "Number of items in this response. This is the size of the returned page, bounded by 'limit' — not the total number of matches in the program.")
            int count,
            @Schema(description = "True when a matching instruction was dropped because 'limit' was reached. Narrow the address range rather than raising 'limit'.")
            boolean truncated) {
        }

    public record GetStructLayoutResponse(String name, String path, int size, boolean is_packed,
            List<StructField> fields) {
    }

        public record XrefsResponse(
            List<XrefEntry> xrefs,
            @Schema(description = "Number of cross-references in this response, not the total in the program.")
            int count,
            @Schema(description = "True when 'limit' was reached and further matching cross-references were not returned.")
            boolean truncated,
            List<XrefEntry> call_refs,
            List<XrefEntry> computed_call_refs,
            List<XrefEntry> data_refs,
            List<XrefEntry> read_refs,
            List<XrefEntry> write_refs,
            List<XrefEntry> other_refs,
            @Schema(description = "Inferred indirect-call candidates. Derived from the full reference set, so this list is not subject to 'limit'.")
            List<IndirectCallerEntry> indirect_calls) {

        public static XrefsResponse fromEntries(List<XrefEntry> xrefs, boolean truncated,
                List<IndirectCallerEntry> indirectCalls) {
            List<XrefEntry> callRefs = new ArrayList<>();
            List<XrefEntry> computedCallRefs = new ArrayList<>();
            List<XrefEntry> dataRefs = new ArrayList<>();
            List<XrefEntry> readRefs = new ArrayList<>();
            List<XrefEntry> writeRefs = new ArrayList<>();
            List<XrefEntry> otherRefs = new ArrayList<>();

            for (XrefEntry xref : xrefs) {
            String category = classifyReferenceType(xref.ref_type().toUpperCase(Locale.ROOT));
            switch (category) {
                case "CALL" -> callRefs.add(xref);
                case "COMPUTED_CALL" -> computedCallRefs.add(xref);
                case "DATA" -> dataRefs.add(xref);
                case "READ" -> readRefs.add(xref);
                case "WRITE" -> writeRefs.add(xref);
                default -> otherRefs.add(xref);
            }
            }

            return new XrefsResponse(
                xrefs,
                xrefs.size(),
                truncated,
                callRefs,
                computedCallRefs,
                dataRefs,
                readRefs,
                writeRefs,
                otherRefs,
                indirectCalls);
        }
        }

        public record IndirectCallerEntry(
            @Schema(type = "string", description = "Address of the computed call instruction.")
            Address callsite_address,
            String function_name,
            @Schema(type = "string", description = "Entry-point address of the containing function.")
            Address function_address,
            String instruction,
            String reason) {
    }

    public record GetAddressInfoResponse(
            @Schema(type = "string", description = "The queried address in 0x-prefixed hex.")
            Address address,
            @Schema(description = "Memory segment containing this address, or null if the address is unmapped.")
            SegmentInfo segment,
            @Schema(description = "Function containing this address, or null if not inside a known function body.")
            FunctionEntry function,
            @Schema(description = "All cross-references pointing to this address.")
            List<XrefEntry> xrefs,
            int xref_count) {

        public record SegmentInfo(
                @Schema(description = "Segment name, e.g. .text, .data, .rodata.")
                String name,
                @Schema(type = "string", description = "First address of the segment in 0x-prefixed hex.")
                Address start,
                @Schema(type = "string", description = "Last address of the segment in 0x-prefixed hex.")
                Address end,
                boolean readable,
                boolean writable,
                boolean executable,
                boolean initialized) {
        }
    }

    public record FunctionCalleesResponse(String function, List<FunctionRef> callees, int count) {
    }

    public record ConstantHit(
            @Schema(type = "string", description = "Address of the instruction in 0x-prefixed hex.")
            Address address,
            @Schema(description = "Name of the containing function, or null if not inside a known function.")
            String function_name,
            @Schema(description = "Instruction mnemonic, e.g. MOV, CMP, PUSH.")
            String mnemonic) {
    }

    public record SearchConstantReferencesResponse(
            @Schema(description = "The constant value that was searched for (unsigned decimal).")
            long value,
            @Schema(description = "Instructions that reference the constant as an immediate operand.")
            List<ConstantHit> hits,
            @Schema(description = "Number of items in this response. This is the size of the returned page, bounded by 'limit' — not the total number of matches in the program.")
            int count,
            @Schema(description = "True when a matching instruction was dropped because 'limit' was reached.")
            boolean truncated) {
    }

    private record AddressRange(Address start, Address end) {
    }

    private record BytePattern(String normalized, byte[] bytes, boolean[] wildcard) {
        boolean matchesPrefix(byte[] candidate) {
            if (candidate.length < bytes.length) {
                return false;
            }
            for (int i = 0; i < bytes.length; i++) {
                if (!wildcard[i] && candidate[i] != bytes[i]) {
                    return false;
                }
            }
            return true;
        }
    }
}
