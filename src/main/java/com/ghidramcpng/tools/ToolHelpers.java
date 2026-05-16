package com.ghidramcpng.tools;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * Shared utility methods used by the tool resources.
 */
public final class ToolHelpers {

    /** Maximum character length for name fields (function, variable, struct, field names). */
    public static final int MAX_NAME_LENGTH = 256;

    /** Maximum character length for comment fields. */
    public static final int MAX_COMMENT_LENGTH = 4096;

    private ToolHelpers() {}

    /**
     * Counts the public {@code @GET} and {@code @POST} endpoint methods declared on a tool class.
     * Used to derive {@code TOOL_COUNT} dynamically so it stays in sync when endpoints are added.
     */
    public static int countEndpoints(Class<?> toolClass) {
        int count = 0;
        for (Method m : toolClass.getDeclaredMethods()) {
            if (Modifier.isPublic(m.getModifiers())
                    && (m.isAnnotationPresent(GET.class) || m.isAnnotationPresent(POST.class))) {
                count++;
            }
        }
        return count;
    }

    // Parameter extraction from JSON arguments

    public static String required(JsonObject args, String name) {
        if (args == null || !args.has(name) || args.get(name).isJsonNull()) {
            throw new IllegalArgumentException("Required parameter '" + name + "' is missing");
        }
        if (!args.get(name).isJsonPrimitive() || !args.get(name).getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException("Parameter '" + name + "' must be a string.");
        }
        String value = args.get(name).getAsString();
        if (value.isBlank()) {
            throw new IllegalArgumentException("Parameter '" + name + "' must not be blank.");
        }
        return value;
    }

    public static String optional(JsonObject args, String name, String defaultValue) {
        if (args == null || !args.has(name) || args.get(name).isJsonNull()) return defaultValue;
        if (!args.get(name).isJsonPrimitive() || !args.get(name).getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException("Parameter '" + name + "' must be a string.");
        }
        return args.get(name).getAsString();
    }

    public static int optionalInt(JsonObject args, String name, int defaultValue) {
        if (args == null || !args.has(name) || args.get(name).isJsonNull()) return defaultValue;
        try {
            return args.get(name).getAsInt();
        } catch (ClassCastException | UnsupportedOperationException | NumberFormatException e) {
            throw new IllegalArgumentException(
                    "Parameter '" + name + "' must be an integer.");
        }
    }

    public static boolean optionalBool(JsonObject args, String name, boolean defaultValue) {
        if (args == null || !args.has(name) || args.get(name).isJsonNull()) return defaultValue;
        var el = args.get(name);
        if (!el.isJsonPrimitive() || !el.getAsJsonPrimitive().isBoolean()) {
            throw new IllegalArgumentException(
                    "Parameter '" + name + "' must be a boolean (true or false).");
        }
        return el.getAsBoolean();
    }

    public static JsonArray optionalArray(JsonObject args, String name) {
        if (args == null || !args.has(name) || args.get(name).isJsonNull()) return new JsonArray();
        return args.get(name).getAsJsonArray();
    }

    // Ghidra lookups

    /**
     * Resolve a name-or-address string to a Function.
     *
     * <p>Resolution rules (no fallbacks):
     * <ul>
     *   <li>If the value starts with {@code 0x} — parsed as a hex address.</li>
     *   <li>Otherwise — looked up as an exact, case-sensitive function name via the symbol table.</li>
     * </ul>
     *
     * @throws IllegalArgumentException with guidance if the function cannot be found.
     */
    public static Function findFunction(Program program, String nameOrAddress) {
        if (nameOrAddress == null || nameOrAddress.isBlank()) {
            throw new IllegalArgumentException(
                    "Function name or address must not be empty. " +
                    "Pass an exact function name (case-sensitive) or a 0x-prefixed hex address.");
        }

        // Hex address — 0x prefix is required
        if (nameOrAddress.startsWith("0x") || nameOrAddress.startsWith("0X")) {
            String stripped = nameOrAddress.substring(2);
            try {
                long offset = Long.parseUnsignedLong(stripped, 16);
                Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
                Function f = program.getFunctionManager().getFunctionAt(addr);
                if (f != null) return f;
                throw new IllegalArgumentException(
                        "No function at address " + nameOrAddress + ". " +
                        "The address must be a function entry point. " +
                        "Use list_functions or list_exports to find valid entry points.");
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(
                        "Invalid hex address '" + nameOrAddress + "'. " +
                        "Expected format: 0x followed by hex digits, e.g. 0x00401000");
            }
        }

        // Exact name lookup via symbol table (case-sensitive)
        for (Symbol sym : program.getSymbolTable().getSymbols(nameOrAddress)) {
            if (sym.getSymbolType() == SymbolType.FUNCTION) {
                Function f = program.getFunctionManager().getFunctionAt(sym.getAddress());
                if (f != null) return f;
            }
        }

        throw new IllegalArgumentException(
                "Function not found: '" + nameOrAddress + "'. " +
                "Names are case-sensitive. " +
                "To find the correct name use search_functions or list_functions. " +
                "To address by location use a 0x-prefixed hex address, e.g. 0x00401000.");
    }

    /**
     * Resolve any named symbol (function, global, label, etc.) or a 0x-prefixed hex address
     * to an {@link Address}.
     *
     * <p>Resolution rules:
     * <ul>
     *   <li>If the value starts with {@code 0x} — parsed as a hex address.</li>
     *   <li>Otherwise — the symbol table is searched (case-sensitive) for any symbol with that
     *       name, accepting all symbol types. If multiple symbols share the name the first
     *       match is returned. Use a 0x-prefixed address to disambiguate.</li>
     * </ul>
     *
     * @throws IllegalArgumentException with guidance if nothing matches.
     */
    public static Address findSymbolAddress(Program program, String nameOrAddress) {
        if (nameOrAddress == null || nameOrAddress.isBlank()) {
            throw new IllegalArgumentException(
                    "Name or address must not be empty. " +
                    "Pass a symbol name (case-sensitive) or a 0x-prefixed hex address.");
        }
        if (nameOrAddress.startsWith("0x") || nameOrAddress.startsWith("0X")) {
            return toAddress(program, nameOrAddress);
        }
        // Accept any symbol type: function, global variable, label, data, …
        List<Symbol> matches = new ArrayList<>();
        for (Symbol sym : program.getSymbolTable().getSymbols(nameOrAddress)) {
            matches.add(sym);
        }
        if (matches.size() > 1) {
            StringBuilder sb = new StringBuilder();
            sb.append("Ambiguous symbol name '").append(nameOrAddress)
              .append("': ").append(matches.size()).append(" symbols share this name. ")
              .append("Use a 0x-prefixed hex address to disambiguate:");
            for (Symbol sym : matches) {
                sb.append("\n  0x").append(sym.getAddress())
                  .append(" (").append(sym.getSymbolType()).append(")");
            }
            throw new IllegalArgumentException(sb.toString());
        }
        if (matches.size() == 1) {
            return matches.get(0).getAddress();
        }
        throw new IllegalArgumentException(
                "Symbol not found: '" + nameOrAddress + "'. " +
                "Names are case-sensitive and match functions, globals, labels, and other symbols. " +
                "Use search_functions or list_exports to discover valid names, " +
                "or pass a 0x-prefixed hex address, e.g. 0x00401000.");
    }

    /**
     * Parse a hex address string into a Ghidra {@link Address}.
     * The {@code 0x} prefix is required.
     */
    public static Address toAddress(Program program, String addressStr) {
        if (addressStr == null || addressStr.isBlank()) {
            throw new IllegalArgumentException(
                    "Address must not be empty. Expected format: 0x followed by hex digits, e.g. 0x00401000");
        }
        if (!addressStr.startsWith("0x") && !addressStr.startsWith("0X")) {
            throw new IllegalArgumentException(
                    "Address '" + addressStr + "' is missing the 0x prefix. " +
                    "Expected format: 0x followed by hex digits, e.g. 0x00401000");
        }
        String stripped = addressStr.substring(2);
        try {
            long offset = Long.parseUnsignedLong(stripped.trim(), 16);
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "Invalid hex address '" + addressStr + "'. " +
                    "Expected format: 0x followed by hex digits, e.g. 0x00401000");
        }
    }

    /** Returns a sorted, comma-separated list of all names in the BuiltInDataTypeManager. */
    private static String builtInTypeNames() {
        Iterator<DataType> it = BuiltInDataTypeManager.getDataTypeManager().getAllDataTypes();
        Iterable<DataType> iterable = () -> it;
        return StreamSupport.stream(iterable.spliterator(), false)
                .map(DataType::getName)
                .sorted()
                .collect(Collectors.joining(", "));
    }

    /**
     * Find a data type by name. Searches the program's DataTypeManager.
     * Handles pointer notation (e.g. "int*" or "SomeStruct *") recursively.
     */
    public static DataType findDataType(Program program, String typeName) {
        if (typeName == null || typeName.isBlank()) {
            throw new IllegalArgumentException("Type name must not be empty");
        }
        String trimmed = typeName.trim();
        String canonical = trimmed.replace(" ", "");

        // VoidDataType is a built-in singleton and may not appear in findDataTypes results.
        if ("void".equalsIgnoreCase(trimmed)) {
            return ghidra.program.model.data.VoidDataType.dataType;
        }

        if (canonical.equalsIgnoreCase("code") || canonical.matches("(?i)code\\*+")) {
            throw new IllegalArgumentException(
                    "Data type '" + typeName + "' is not supported here. " +
                    "'code*' is a Ghidra internal generated type, not a stable type name for API calls. " +
                    "Use void* for an unknown code pointer, or use an actual function definition type " +
                    "when setting signatures or struct fields.");
        }

        // Pointer notation
        if (trimmed.endsWith("*")) {
            String inner = trimmed.substring(0, trimmed.length() - 1).trim();
            DataType innerType = findDataType(program, inner);
            return new ghidra.program.model.data.PointerDataType(
                    innerType, program.getDataTypeManager());
        }

        // Array notation: type[count], e.g. byte[16], char[32], IntStruct[4]
        // Use canonical (space-stripped) to tolerate "byte [16]" etc.
        if (canonical.endsWith("]")) {
            int bracket = canonical.lastIndexOf('[');
            if (bracket > 0) {
                String elementTypeName = canonical.substring(0, bracket);
                String countStr = canonical.substring(bracket + 1, canonical.length() - 1);
                int count;
                try {
                    count = Integer.parseInt(countStr);
                } catch (NumberFormatException e) {
                    throw new IllegalArgumentException(
                            "Invalid array element count '" + countStr + "' in type '" + typeName + "'. " +
                            "Use the format type[count], e.g. byte[16] or char[32].");
                }
                if (count <= 0) {
                    throw new IllegalArgumentException(
                            "Array element count must be a positive integer, got '" + countStr +
                            "' in type '" + typeName + "'.");
                }
                DataType elementType = findDataType(program, elementTypeName);
                int elementLength = elementType.getLength();
                if (elementLength <= 0) {
                    throw new IllegalArgumentException(
                            "Array element type '" + elementTypeName + "' does not have a fixed size " +
                            "and cannot be used in an array definition.");
                }
                return new ghidra.program.model.data.ArrayDataType(
                        elementType, count, elementLength, program.getDataTypeManager());
            }
        }

        // Search by name
        List<DataType> matches = new ArrayList<>();
        program.getDataTypeManager().findDataTypes(trimmed, matches);
        if (matches.size() == 1) {
            return matches.get(0);
        }
        if (matches.size() > 1) {
            // Multiple types share the same name — require a fully-qualified category path.
            String candidates = matches.stream()
                    .map(dt -> dt.getDataTypePath().getPath())
                    .collect(Collectors.joining(", "));
            throw new IllegalArgumentException(
                    "Ambiguous data type '" + typeName + "': " + matches.size() + " types with this name exist. " +
                    "Use the full category path to disambiguate. Candidates: " + candidates);
        }

        // Try as category path (e.g. "/Windows Types/DWORD")
        DataType dt = program.getDataTypeManager().getDataType(trimmed);
        if (dt != null) return dt;

        // Fall back to built-in types (int, byte, short, etc.) which live in
        // BuiltInDataTypeManager and are not always present in the program's manager.
        List<DataType> builtInMatches = new ArrayList<>();
        BuiltInDataTypeManager.getDataTypeManager().findDataTypes(trimmed, builtInMatches);
        if (!builtInMatches.isEmpty()) {
            return builtInMatches.get(0);
        }

        throw new IllegalArgumentException(
                "Data type not found: '" + typeName + "'. " +
                "Use list_data_types or search_data_types to find valid type names. " +
                "Built-in types include: " + builtInTypeNames() +
                ", and any struct you have created.");
    }

    /**
     * Create and open a {@link DecompInterface} against {@code program}.
     * The caller is responsible for calling {@code dispose()} when finished.
     * Prefer {@link #decompileFresh} for one-off calls; use this directly when
     * decompiling multiple functions in a batch to amortise the setup cost.
     */
    public static DecompInterface openDecompiler(Program program) {
        DecompInterface decompiler = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        decompiler.setOptions(opts);
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(program);
        return decompiler;
    }

    /**
     * Decompile {@code function} using a pre-opened {@link DecompInterface} and return
     * the full {@link DecompileResults} for callers that need the {@link ghidra.program.model.pcode.HighFunction}.
     * Use {@link #openDecompiler} to obtain the instance and dispose it when done.
     *
     * @param decompiler     an already-opened decompiler (must match the function's program)
     * @param timeoutSeconds maximum decompilation time in seconds (must be &gt; 0)
     */
    public static DecompileResults decompileWithResults(DecompInterface decompiler, Function function,
            int timeoutSeconds) {
        if (timeoutSeconds <= 0) {
            throw new IllegalArgumentException(
                    "Decompile timeout must be a positive integer number of seconds, got: " + timeoutSeconds);
        }
        DecompileResults results = decompiler.decompileFunction(function, timeoutSeconds, TaskMonitor.DUMMY);
        if (!results.decompileCompleted()) {
            String err = results.getErrorMessage();
            String errLower = err == null ? "" : err.toLowerCase();
            String hint;
            if (errLower.contains("unique hash") || errLower.contains("varnode")) {
                hint = "This usually means the function's body has not been fully analysed. " +
                        "Try running auto-analysis again, or call disassemble at the function's entry point first.";
            } else if (errLower.contains("timed out") || errLower.contains("timeout")) {
                hint = "The decompiler timed out. Increase timeouts.decompile_seconds in rules.yaml " +
                        "or pass a larger 'timeout_seconds' override.";
            } else {
                hint = "If this is a large function, increase timeouts.decompile_seconds in rules.yaml " +
                        "or pass 'timeout_seconds'. Otherwise, re-run auto-analysis on the program.";
            }
            throw new IllegalStateException(
                    "Decompilation of function '" + function.getName() + "' failed after " + timeoutSeconds +
                    " second(s). " +
                    (err != null && !err.isBlank() ? err + ". " : "") + hint);
        }
        if (results.getDecompiledFunction() == null) {
            throw new IllegalStateException(
                    "Decompilation of function '" + function.getName() + "' completed without output. " +
                    "Try decompiling a different function or increasing timeouts.decompile_seconds in rules.yaml.");
        }
        return results;
    }

    /**
     * Decompile {@code function} using a pre-opened {@link DecompInterface} and return the C code string.
     * Use {@link #openDecompiler} to obtain the instance and dispose it when done.
     *
     * @param decompiler     an already-opened decompiler (must match the function's program)
     * @param timeoutSeconds maximum decompilation time in seconds (must be &gt; 0)
     */
    public static String decompileWith(DecompInterface decompiler, Function function,
            int timeoutSeconds) {
        return decompileWithResults(decompiler, function, timeoutSeconds)
                .getDecompiledFunction().getC();
    }

    /**
     * Decompile a single function using a freshly created {@link DecompInterface}.
     * The interface is disposed before returning. For batch decompilation use
     * {@link #openDecompiler} + {@link #decompileWith} to share one instance.
     *
     * @param timeoutSeconds maximum decompilation time in seconds (must be &gt; 0)
     */
    public static String decompileFresh(Program program, Function function, int timeoutSeconds) {
        DecompInterface decompiler = openDecompiler(program);
        try {
            return decompileWith(decompiler, function, timeoutSeconds);
        } finally {
            decompiler.dispose();
        }
    }

    /**
     * Decompile a single function using a freshly created {@link DecompInterface} and return
     * the full {@link DecompileResults} for callers that need the {@link ghidra.program.model.pcode.HighFunction}.
     * The interface is disposed before returning.
     *
     * @param timeoutSeconds maximum decompilation time in seconds (must be &gt; 0)
     */
    public static DecompileResults decompileFreshWithResults(Program program, Function function,
            int timeoutSeconds) {
        DecompInterface decompiler = openDecompiler(program);
        try {
            return decompileWithResults(decompiler, function, timeoutSeconds);
        } finally {
            decompiler.dispose();
        }
    }

    /**
     * Validates that {@code value} does not exceed {@code maxLength} characters.
     * Returns {@code value} unchanged for fluent use.
     *
     * @throws IllegalArgumentException if the value exceeds the limit
     */
    public static String requireMaxLength(String value, String fieldName, int maxLength) {
        if (value != null && value.length() > maxLength) {
            throw new IllegalArgumentException(
                    "Parameter '" + fieldName + "' exceeds maximum length of " + maxLength +
                    " characters (got " + value.length() + ").");
        }
        return value;
    }

}