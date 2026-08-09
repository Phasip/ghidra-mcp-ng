package com.ghidramcpng.tools;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractIntegerDataType;
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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

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
        return listEndpoints(toolClass).size();
    }

    /**
     * Names the tools a class declares, taken from each endpoint's {@code @Path} segment —
     * which is the operationId, and therefore the MCP tool name. Derived by reflection for the
     * same reason as {@link #countEndpoints}: it cannot drift as endpoints are added.
     */
    public static List<String> listEndpoints(Class<?> toolClass) {
        List<String> names = new ArrayList<>();
        for (Method m : toolClass.getDeclaredMethods()) {
            if (!Modifier.isPublic(m.getModifiers())
                    || !(m.isAnnotationPresent(GET.class) || m.isAnnotationPresent(POST.class))) {
                continue;
            }
            jakarta.ws.rs.Path path = m.getAnnotation(jakarta.ws.rs.Path.class);
            names.add(path != null ? path.value().replaceAll("^/+", "") : m.getName());
        }
        return names;
    }

    /**
     * The argument names an endpoint accepts: the {@code @QueryParam} names of a GET, or the
     * components of the record its {@code @RequestBody} names for a POST. Derived by reflection
     * for the same reason as {@link #listEndpoints} — a parameter added to a tool cannot be
     * forgotten here, so the accepted set and the published schema are the same thing.
     *
     * @return null when a POST declares no request-body schema, meaning there is no vocabulary
     *         to check an argument against
     */
    public static Set<String> argumentNames(Method method) {
        Set<String> names = new LinkedHashSet<>();
        boolean isPost = method.isAnnotationPresent(POST.class);
        for (java.lang.reflect.Parameter p : method.getParameters()) {
            jakarta.ws.rs.QueryParam queryParam = p.getAnnotation(jakarta.ws.rs.QueryParam.class);
            if (queryParam != null) {
                names.add(queryParam.value());
                continue;
            }
            if (!isPost) {
                continue;
            }
            Class<?> schema = requestBodySchema(p);
            if (schema != null && schema.isRecord()) {
                for (java.lang.reflect.RecordComponent c : schema.getRecordComponents()) {
                    names.add(c.getName());
                }
            }
        }
        return isPost && names.isEmpty() ? null : names;
    }

    /** The record class a parameter's {@code @RequestBody} names as its schema, or null. */
    private static Class<?> requestBodySchema(java.lang.reflect.Parameter parameter) {
        var body = parameter.getAnnotation(io.swagger.v3.oas.annotations.parameters.RequestBody.class);
        if (body == null || body.content().length == 0) {
            return null;
        }
        Class<?> implementation = body.content()[0].schema().implementation();
        return implementation == Void.class ? null : implementation;
    }

    /**
     * Looks up an endpoint method by its operationId (the {@code @Path} segment) across the
     * tool classes that {@code batch_tool_call} can dispatch to.
     */
    public static Method findEndpoint(String operationId, Class<?>... toolClasses) {
        for (Class<?> toolClass : toolClasses) {
            for (Method m : toolClass.getDeclaredMethods()) {
                if (!Modifier.isPublic(m.getModifiers())
                        || !(m.isAnnotationPresent(GET.class) || m.isAnnotationPresent(POST.class))) {
                    continue;
                }
                jakarta.ws.rs.Path path = m.getAnnotation(jakarta.ws.rs.Path.class);
                if (path != null && path.value().replaceAll("^/+", "").equals(operationId)) {
                    return m;
                }
            }
        }
        return null;
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
        JsonElement el = args.get(name);
        // Gson's getAsInt() is lenient in three ways that all read as a successful call:
        // it parses the string "5", truncates 5.7 to 5, and unwraps the single-element array [5].
        // A truncated offset or limit is a wrong answer that looks like a right one.
        if (!el.isJsonPrimitive() || !el.getAsJsonPrimitive().isNumber()) {
            throw new IllegalArgumentException(
                    "Parameter '" + name + "' must be an integer, got " + describeJson(el) + ".");
        }
        try {
            return el.getAsBigDecimal().intValueExact();
        } catch (ArithmeticException | NumberFormatException e) {
            throw new IllegalArgumentException(
                    "Parameter '" + name + "' must be a whole number in the range " +
                    Integer.MIN_VALUE + " to " + Integer.MAX_VALUE + ", got " + el + ".");
        }
    }

    public static boolean optionalBool(JsonObject args, String name, boolean defaultValue) {
        if (args == null || !args.has(name) || args.get(name).isJsonNull()) return defaultValue;
        JsonElement el = args.get(name);
        if (!el.isJsonPrimitive() || !el.getAsJsonPrimitive().isBoolean()) {
            throw new IllegalArgumentException(
                    "Parameter '" + name + "' must be a boolean (true or false), got " +
                    describeJson(el) + ".");
        }
        return el.getAsBoolean();
    }

    public static JsonArray optionalArray(JsonObject args, String name) {
        if (args == null || !args.has(name) || args.get(name).isJsonNull()) return new JsonArray();
        JsonElement el = args.get(name);
        if (!el.isJsonArray()) {
            throw new IllegalArgumentException(
                    "Parameter '" + name + "' must be a JSON array, got " + describeJson(el) + ".");
        }
        return el.getAsJsonArray();
    }

    /**
     * Names the JSON type of a value for an error message, so a rejection says what was sent
     * rather than only what was expected.
     */
    public static String describeJson(JsonElement el) {
        if (el == null || el.isJsonNull()) return "null";
        if (el.isJsonArray()) return "an array";
        if (el.isJsonObject()) return "an object";
        JsonPrimitive p = el.getAsJsonPrimitive();
        if (p.isString()) return "the string " + p;
        if (p.isBoolean()) return "a boolean";
        return "the number " + p;
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
            Address addr = parseHexOffset(program, nameOrAddress,
                    "Invalid hex address '" + nameOrAddress + "'. " +
                    "Expected format: 0x followed by hex digits, e.g. 0x00401000");
            Function f = program.getFunctionManager().getFunctionAt(addr);
            if (f != null) return f;
            // Diagnose the common mistake of passing a mid-function address: point at the
            // containing function's actual entry point rather than a generic hint.
            Function containing = program.getFunctionManager().getFunctionContaining(addr);
            if (containing != null) {
                throw new IllegalArgumentException(
                        "Address " + nameOrAddress + " is inside function '" + containing.getName() +
                        "' but is not its entry point. Pass the entry point 0x" +
                        containing.getEntryPoint() + " to reference this function.");
            }
            throw new IllegalArgumentException(
                    "No function at address " + nameOrAddress + ", and the address is not inside any " +
                    "defined function. Use search_functions or list_exports to find valid entry points.");
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
     *       name, accepting all symbol types. A name shared by several symbols is rejected,
     *       listing each address so the caller can pick one.</li>
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
        return parseHexOffset(program, addressStr, "Invalid hex address '" + addressStr + "'. " +
                "Expected format: 0x followed by hex digits, e.g. 0x00401000");
    }

    /**
     * Parses the hex digits after an already-checked {@code 0x} prefix.
     *
     * <p>The digits are taken exactly as sent. {@code Long.parseUnsignedLong} accepts a leading
     * {@code +} and would ignore surrounding whitespace if it were stripped first, so
     * {@code "0x +1000"} would resolve to 0x1000 — a coerced address, which is the one thing an
     * address parser must never do.
     */
    private static Address parseHexOffset(Program program, String addressStr, String errorMessage) {
        String digits = addressStr.substring(2);
        if (!digits.matches("[0-9a-fA-F]+")) {
            throw new IllegalArgumentException(errorMessage);
        }
        try {
            long offset = Long.parseUnsignedLong(digits, 16);
            return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(errorMessage);
        }
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
        if (builtInMatches.size() > 1) {
            // Same rule as for the program's own types: which one was meant is the caller's to say.
            throw new IllegalArgumentException(
                    "Ambiguous built-in data type '" + typeName + "': " + builtInMatches.size() +
                    " types with this name exist. Use the full category path to disambiguate. Candidates: " +
                    builtInMatches.stream().map(match -> match.getDataTypePath().getPath())
                            .collect(Collectors.joining(", ")));
        }
        if (builtInMatches.size() == 1) {
            return builtInMatches.get(0);
        }

        DataType stdint = resolveStdintName(program, trimmed);
        if (stdint != null) {
            return stdint;
        }

        String suggestions = suggestDataTypeNames(program, trimmed);
        throw new IllegalArgumentException(
                "Data type not found: '" + typeName + "'. " +
                (suggestions != null
                        ? "Did you mean: " + suggestions + "? "
                        : "") +
                "Use search_data_types to find valid type names (names are case-sensitive).");
    }

    private static final java.util.regex.Pattern STDINT_FIXED_WIDTH =
            java.util.regex.Pattern.compile("^(u?)int(8|16|32|64)_t$");

    /**
     * Resolves a {@code <stdint.h>} spelling to a type of exactly the width it names.
     *
     * <p>Every prototype typed from a datasheet or a C header reaches for these, and a stripped
     * binary carries no such definition, so each one otherwise costs a guaranteed round-trip to
     * discover Ghidra's own spelling.
     *
     * <p>This runs only after every real lookup has failed, so a program that defines its own
     * {@code uint32_t} (from DWARF, say) always wins. The width comes from
     * {@code AbstractIntegerDataType}, which returns the program's generic spelling when the sizes
     * agree ({@code uint} where int is 4 bytes) and a fixed-size builtin ({@code dword}) otherwise
     * — so the result is never the wrong width for the target.
     */
    private static DataType resolveStdintName(Program program, String typeName) {
        var dtm = program.getDataTypeManager();
        java.util.regex.Matcher fixed = STDINT_FIXED_WIDTH.matcher(typeName);
        if (fixed.matches()) {
            int bytes = Integer.parseInt(fixed.group(2)) / 8;
            return fixed.group(1).isEmpty()
                    ? AbstractIntegerDataType.getSignedDataType(bytes, dtm)
                    : AbstractIntegerDataType.getUnsignedDataType(bytes, dtm);
        }
        // Pointer-width spellings. Sized from the program's own pointer size, not assumed.
        int pointerBytes = program.getDefaultPointerSize();
        return switch (typeName) {
            case "size_t", "uintptr_t" -> AbstractIntegerDataType.getUnsignedDataType(pointerBytes, dtm);
            case "ssize_t", "intptr_t", "ptrdiff_t" -> AbstractIntegerDataType.getSignedDataType(pointerBytes, dtm);
            default -> null;
        };
    }

    /**
     * Returns a short comma-separated list of existing data-type names closest to {@code query}
     * (program types and built-ins), or {@code null} if none are similar enough. Keeps a failed
     * lookup actionable without dumping the entire type catalogue into the error message.
     */
    private static String suggestDataTypeNames(Program program, String query) {
        String lowerQuery = query.toLowerCase();
        java.util.TreeMap<Integer, java.util.LinkedHashSet<String>> ranked = new java.util.TreeMap<>();
        java.util.function.Consumer<String> consider = candidate -> {
            if (candidate == null || candidate.isBlank()) {
                return;
            }
            String lowerCandidate = candidate.toLowerCase();
            int distance = levenshtein(lowerQuery, lowerCandidate);
            boolean substring = lowerCandidate.contains(lowerQuery) || lowerQuery.contains(lowerCandidate);
            int threshold = Math.max(2, query.length() / 2);
            if (distance > threshold && !substring) {
                return;
            }
            int score = substring ? Math.min(distance, 1) : distance;
            ranked.computeIfAbsent(score, k -> new java.util.LinkedHashSet<>()).add(candidate);
        };

        Iterator<DataType> programTypes = program.getDataTypeManager().getAllDataTypes();
        while (programTypes.hasNext()) {
            consider.accept(programTypes.next().getName());
        }
        Iterator<DataType> builtInTypes = BuiltInDataTypeManager.getDataTypeManager().getAllDataTypes();
        while (builtInTypes.hasNext()) {
            consider.accept(builtInTypes.next().getName());
        }

        List<String> best = new ArrayList<>();
        for (java.util.LinkedHashSet<String> bucket : ranked.values()) {
            for (String name : bucket) {
                best.add(name);
                if (best.size() == 5) {
                    return String.join(", ", best);
                }
            }
        }
        return best.isEmpty() ? null : String.join(", ", best);
    }

    private static int levenshtein(String a, String b) {
        int[] prev = new int[b.length() + 1];
        int[] curr = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) {
            prev[j] = j;
        }
        for (int i = 1; i <= a.length(); i++) {
            curr[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                curr[j] = Math.min(Math.min(curr[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
            }
            int[] tmp = prev;
            prev = curr;
            curr = tmp;
        }
        return prev[b.length()];
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