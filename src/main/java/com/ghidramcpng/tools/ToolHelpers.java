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
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.CompilerSpec;
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
        if (nameOrAddress.matches("[0-9a-fA-F]+")) {
            // Hex digits with no prefix are an address the caller forgot to mark as one, not a
            // symbol name — say that instead of sending them looking for a symbol.
            throw new IllegalArgumentException(
                    "'" + nameOrAddress + "' is missing the 0x prefix and matches no symbol name. " +
                    "Write an address as 0x" + nameOrAddress + ".");
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
                    "Give the pointer the signature it actually has, as a function-pointer declarator " +
                    "— 'int (*)(void *dst, int nbytes)' — or void* if that is still unknown.");
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

    /**
     * A C function-pointer declarator: a return type, a parenthesised {@code *} carrying an
     * optional calling convention and an optional name, and a parameter list —
     * {@code int (*)(void *dst, int nbytes)}.
     *
     * <p>The name C writes inside those parentheses names the callback <em>type</em>. It is
     * optional here: written, the definition takes it; omitted, one is derived from the signature.
     */
    private static final java.util.regex.Pattern FUNCTION_POINTER = java.util.regex.Pattern.compile(
            "(.+?)\\(\\s*(?:([A-Za-z_][A-Za-z0-9_]*)\\s+)?\\*\\s*([A-Za-z_][A-Za-z0-9_]*)?\\s*\\)\\s*\\((.*)\\)",
            java.util.regex.Pattern.DOTALL);

    /** A parameter written as a type followed by a name, {@code void *dst} or {@code int nbytes}. */
    private static final java.util.regex.Pattern NAMED_PARAMETER =
            java.util.regex.Pattern.compile("(.*[\\s*])([A-Za-z_][A-Za-z0-9_]*)");

    /** Where minted callback definitions live, clear of the program's own types. */
    private static final CategoryPath CALLBACK_CATEGORY = new CategoryPath("/functions");

    /** Leading word of every derived definition name. */
    private static final String DERIVED_PREFIX = "func_";

    /** Longest derived definition name before the parameter list is cut short. */
    private static final int MAX_DERIVED_NAME = 96;

    /** How far a derived name will step past unrelated types squatting it before giving up. */
    private static final int MAX_DERIVED_ATTEMPTS = 64;

    /**
     * Resolves a type to apply: everything {@link #findDataType} resolves, plus a C
     * function-pointer declarator — {@code int (*)(void *dst, int nbytes)} — for a callback
     * type the program does not have yet.
     *
     * <p>Every tool that applies a type resolves through here, because a function pointer is
     * where a type is worth the most: with none on it, the decompiler infers each indirect
     * call's arity from the pushes at that call site, so one callback comes out with a
     * different signature at every site it is called from. One applied type fixes them all.
     *
     * <p>The result is returned unresolved, exactly as the pointer and array types built above
     * are: Ghidra stores it in the program's data type manager when the caller applies it,
     * inside the caller's own transaction.
     */
    public static DataType findOrCreateDataType(Program program, String typeName) {
        if (typeName != null) {
            java.util.regex.Matcher declarator = FUNCTION_POINTER.matcher(typeName.trim());
            if (declarator.matches()) {
                return functionPointerType(program, declarator, typeName.trim());
            }
        }
        try {
            return findDataType(program, typeName);
        } catch (IllegalArgumentException notAType) {
            // A spelling that named no type and reads as a function is a declarator the caller
            // got wrong; "did you mean" over the program's type names cannot help there.
            if (typeName != null && typeName.indexOf('(') >= 0) {
                throw new IllegalArgumentException(
                        "'" + typeName.trim() + "' is not a data type this program has, and does " +
                        "not parse as a function pointer either. A callback type is written as a C " +
                        "function-pointer declarator, e.g. 'int (*)(void *dst, int nbytes)'.");
            }
            throw notAType;
        }
    }

    /**
     * Builds the callback type a declarator describes, as a pointer to a function definition —
     * the shape a parameter, struct field or vtable slot actually holds. Ghidra has no anonymous
     * function definition, so applying a signature always creates one; the only question is what
     * it is called.
     *
     * <p>An unnamed declarator gets a name derived from its own signature. That makes the name a
     * property of the signature and nothing else: the same declarator written at the second and
     * third site finds the definition the first one made, and two different signatures can never
     * want the same name.
     *
     * <p>A declarator that writes a name gets exactly that name, and is refused rather than
     * redefined when the name is taken by something that is not the same signature: every site
     * already typed with it would change with it, silently, from a call that asked to type one
     * thing.
     */
    private static DataType functionPointerType(Program program, java.util.regex.Matcher declarator,
            String typeName) {
        DataTypeManager dtm = program.getDataTypeManager();
        String requestedName = declarator.group(3);
        FunctionDefinitionDataType definition = new FunctionDefinitionDataType(
                CALLBACK_CATEGORY, requestedName != null ? requestedName : DERIVED_PREFIX, dtm);
        try {
            definition.setReturnType(findDataType(program, declarator.group(1)));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Return type of '" + typeName + "': " + e.getMessage());
        }
        String convention = declarator.group(2);
        if (convention != null) {
            setCallingConvention(program, definition, convention);
        }
        definition.setArguments(parametersOf(program, declarator.group(4).trim(), typeName, definition));

        if (requestedName != null) {
            List<DataType> taken = typesNamed(dtm, requestedName);
            DataType reusable = equivalentDefinition(taken, definition);
            if (reusable != null) {
                return new PointerDataType(reusable, dtm);
            }
            if (!taken.isEmpty()) {
                throw new IllegalArgumentException(
                        nameTakenMessage(typeName, requestedName, taken.get(0)));
            }
            return new PointerDataType(definition, dtm);
        }

        String derived = derivedName(definition);
        for (int attempt = 1; attempt <= MAX_DERIVED_ATTEMPTS; attempt++) {
            String candidateName = attempt == 1 ? derived : derived + "_" + attempt;
            rename(definition, candidateName);
            List<DataType> taken = typesNamed(dtm, candidateName);
            DataType reusable = equivalentDefinition(taken, definition);
            if (reusable != null) {
                return new PointerDataType(reusable, dtm);
            }
            if (taken.isEmpty()) {
                return new PointerDataType(definition, dtm);
            }
            // Something unrelated holds the derived name. The caller never wrote that name and
            // cannot be asked about it, so step past it rather than failing on it.
        }
        throw new IllegalArgumentException(
                "Cannot create the callback type for '" + typeName + "': this program already has " +
                MAX_DERIVED_ATTEMPTS + " unrelated types named '" + derived + "', '" + derived +
                "_2' and so on. Name the callback type yourself by writing the name where C puts " +
                "it — '" + withName(typeName, "my_callback") + "'.");
    }

    /** Every type in the program's manager with this exact name, in any category. */
    private static List<DataType> typesNamed(DataTypeManager dtm, String name) {
        List<DataType> found = new ArrayList<>();
        dtm.findDataTypes(name, found);
        return found;
    }

    /** The stored definition {@code definition} may be replaced by, or null if there is none. */
    private static DataType equivalentDefinition(List<DataType> taken,
            FunctionDefinitionDataType definition) {
        for (DataType candidate : taken) {
            if (candidate instanceof FunctionDefinition && candidate.isEquivalent(definition)) {
                return candidate;
            }
        }
        return null;
    }

    /** Renames a definition that is not yet stored; a definition's name is part of its identity. */
    private static void rename(FunctionDefinitionDataType definition, String name) {
        try {
            definition.setName(name);
        } catch (ghidra.util.InvalidNameException e) {
            throw new IllegalArgumentException(
                    "'" + name + "' cannot be used as a data type name: " + e.getMessage());
        }
    }

    /**
     * Explains a name written into a declarator that this program has already given to something
     * else.
     *
     * <p>The name inside {@code (* ... )} is the one thing about a declarator that does not read
     * as itself: it names a data type being created here, not the variable, field or parameter
     * the call is typing, and it is checked against every type in the program rather than
     * anything in the function at hand. So the message says which name it is talking about,
     * what already holds it, and that dropping it entirely is a valid answer.
     */
    private static String nameTakenMessage(String typeName, String name, DataType existing) {
        String preamble = "'" + name + "' in '" + typeName + "' names the callback data type this " +
                "call would create — not the variable, parameter or field being typed — and this " +
                "program already has ";
        String orDropIt = "Either drop the name — '" + withName(typeName, "") + "' names the type " +
                "after its own signature and never collides — or write a different one";
        if (existing instanceof FunctionDefinition definition) {
            return preamble + "a different function definition called '" + name + "': " +
                    definition.getPrototypeString() + ". It is not redefined here, because every " +
                    "site already typed with it would change with it. " + orDropIt +
                    ", or apply '" + name + " *' if that existing definition is the type you meant.";
        }
        return preamble + "a " + kindOf(existing) + " called '" + name + "' at " +
                existing.getDataTypePath().getPath() + ". " + orDropIt + ".";
    }

    /** What kind of thing a data type is, in the words the tool surface uses for it. */
    private static String kindOf(DataType type) {
        if (type instanceof ghidra.program.model.data.Structure) return "struct";
        if (type instanceof ghidra.program.model.data.Union) return "union";
        if (type instanceof ghidra.program.model.data.Enum) return "enum";
        if (type instanceof ghidra.program.model.data.TypeDef) return "typedef";
        if (type instanceof ghidra.program.model.data.Pointer) return "pointer type";
        if (type instanceof ghidra.program.model.data.Array) return "array type";
        return "data type";
    }

    /** The same declarator with {@code name} written where C puts it; {@code ""} removes it. */
    private static String withName(String typeName, String name) {
        java.util.regex.Matcher declarator = FUNCTION_POINTER.matcher(typeName);
        if (!declarator.matches()) {
            return typeName;
        }
        String convention = declarator.group(2) != null ? declarator.group(2) + " " : "";
        return declarator.group(1).trim() + " (" + convention + "*" + name + ")("
                + declarator.group(4).trim() + ")";
    }

    /**
     * Names a definition after the signature it holds, so that name is reached again by anyone
     * who writes the same signature and by nobody who writes a different one. Parameter names are
     * left out because they are not part of what makes two definitions equivalent.
     */
    private static String derivedName(FunctionDefinitionDataType definition) {
        StringBuilder name = new StringBuilder(DERIVED_PREFIX);
        String convention = definition.getCallingConventionName();
        if (convention != null && !CompilerSpec.CALLING_CONVENTION_unknown.equals(convention)) {
            name.append(sanitize(convention)).append('_');
        }
        name.append(sanitize(definition.getReturnType().getDisplayName())).append("__");

        List<String> parameters = new ArrayList<>();
        for (ParameterDefinition parameter : definition.getArguments()) {
            parameters.add(sanitize(parameter.getDataType().getDisplayName()));
        }
        if (definition.hasVarArgs()) {
            parameters.add("varargs");
        }
        name.append(parameters.isEmpty() ? "void" : String.join("_", parameters));

        // A long parameter list is cut short rather than spelled out. Two signatures cut to the
        // same name are told apart by the equivalence check, which suffixes the second one.
        if (name.length() <= MAX_DERIVED_NAME) {
            return name.toString();
        }
        String cut = name.substring(0, MAX_DERIVED_NAME);
        return cut.endsWith("_") ? cut.substring(0, cut.length() - 1) : cut;
    }

    /** A type's display name as a name-safe word: {@code void *} becomes {@code void_ptr}. */
    private static String sanitize(String displayName) {
        String word = displayName.replace("*", "_ptr").replaceAll("[^A-Za-z0-9_]", "_")
                .replaceAll("_+", "_");
        word = word.startsWith("_") ? word.substring(1) : word;
        word = word.endsWith("_") ? word.substring(0, word.length() - 1) : word;
        return word.isEmpty() ? "anon" : word;
    }

    /** Parses the declarator's parameter list; {@code (void)} and {@code ()} both mean none. */
    private static ParameterDefinition[] parametersOf(Program program, String parameterList,
            String typeName, FunctionDefinitionDataType definition) {
        if (parameterList.isEmpty() || parameterList.equalsIgnoreCase("void")) {
            return new ParameterDefinition[0];
        }
        List<ParameterDefinition> parameters = new ArrayList<>();
        String[] pieces = parameterList.split(",", -1);
        for (int i = 0; i < pieces.length; i++) {
            String piece = pieces[i].trim();
            if (piece.equals("...")) {
                if (i != pieces.length - 1) {
                    throw new IllegalArgumentException(
                            "'...' is parameter " + (i + 1) + " of " + pieces.length + " in '" +
                            typeName + "'; varargs must come last.");
                }
                definition.setVarArgs(true);
                continue;
            }
            if (piece.isEmpty()) {
                throw new IllegalArgumentException(
                        "Parameter " + (i + 1) + " of '" + typeName + "' is empty. Write each one " +
                        "as a type, optionally followed by a name: 'void *dst' or 'int'.");
            }
            if (piece.indexOf('(') >= 0) {
                throw new IllegalArgumentException(
                        "Parameter " + (i + 1) + " of '" + typeName + "' is itself a function " +
                        "pointer ('" + piece + "'), which cannot be written inline. Give that " +
                        "callback its own name first — apply '" + withName(piece, "my_callback") +
                        "' somewhere — then write it here as 'my_callback *'.");
            }
            parameters.add(parameterOf(program, piece, i + 1, typeName));
        }
        return parameters.toArray(new ParameterDefinition[0]);
    }

    private static ParameterDefinition parameterOf(Program program, String piece, int position,
            String typeName) {
        try {
            java.util.regex.Matcher named = NAMED_PARAMETER.matcher(piece);
            if (named.matches()) {
                try {
                    return new ParameterDefinitionImpl(
                            named.group(2), findDataType(program, named.group(1).trim()), null);
                } catch (IllegalArgumentException splitFailed) {
                    // "unsigned int" reads as a named parameter: a type this program does not have
                    // followed by half of the type it does. Re-read the whole piece as one type,
                    // and if that is not one either, report the split reading — for 'MyStruct dst'
                    // the missing type is what the caller needs to hear about.
                    try {
                        return new ParameterDefinitionImpl(null, findDataType(program, piece), null);
                    } catch (IllegalArgumentException notATypeEither) {
                        throw splitFailed;
                    }
                }
            }
            return new ParameterDefinitionImpl(null, findDataType(program, piece), null);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "Parameter " + position + " of '" + typeName + "': " + e.getMessage());
        }
    }

    /** Applies a calling convention this program's compiler spec has, naming the ones it does. */
    private static void setCallingConvention(Program program, FunctionDefinitionDataType definition,
            String convention) {
        List<String> known = new ArrayList<>();
        for (ghidra.program.model.lang.PrototypeModel model
                : program.getCompilerSpec().getCallingConventions()) {
            known.add(model.getName());
        }
        if (!known.contains(convention)) {
            throw new IllegalArgumentException(
                    "Unknown calling convention '" + convention + "' for this program. " +
                    "Valid conventions: " + String.join(", ", known) + ".");
        }
        try {
            definition.setCallingConvention(convention);
        } catch (ghidra.util.exception.InvalidInputException e) {
            throw new IllegalArgumentException(
                    "Calling convention '" + convention + "' was rejected: " + e.getMessage());
        }
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