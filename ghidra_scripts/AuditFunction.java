// Audits a single function for reverse-engineering completeness.
//
// Usage (via run_script):
//   { "program": "<name>", "filename": "AuditFunction.java", "args": ["<name_or_address>"] }
//
// When called with no args the script prints a JSON help object and exits.
//
// Output: a single JSON object written to println() — captured in run_script's "output" field.
//   {
//     "name":               string,
//     "address":            string (hex or external address),
//     "size":               number,
//     "signature":          string,
//     "is_thunk":           boolean,
//     "calling_convention": string,
//     "callers":            [ { "name", "address" } … ],
//     "callees":            [ { "name", "address" } … ],
//     "xref_count":         number,
//     "reversing_status":   [ { "code", "message" } … ]
//   }
//
// reversing_status codes:
//   UNNAMED_FUNCTION           — function still has an auto-generated FUN_xxxx name
//   UNKNOWN_CALLING_CONVENTION — calling convention is 'unknown' or unset
//   WRONG_CALLING_CONVENTION   — decompiled output contains in_ECX/in_EDX register vars
//                                meaning ECX/EDX is used as an implicit this/arg but not
//                                declared — fix by switching to __fastcall with explicit params
//   MISSING_RETURN_TYPE        — return type is undefined/void*
//   UNNAMED_PARAM              — parameter still named param_N in decompiled output
//   UNDEFINED_PARAM_TYPE       — parameter type is undefined
//   MISSING_STRUCT             — pointer accessed at raw offsets in decompiled output;
//                                struct definition is incomplete at those offsets
//   TYPE_MISMATCH              — argument type differs from callee parameter type at a call site
//
// @category GhidraTools

import com.google.gson.*;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

import java.util.*;

public class AuditFunction extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length == 0 || args[0].isBlank()) {
            printHelp();
            return;
        }

        String nameOrAddress = args[0].trim();
        Function function = resolveFunction(nameOrAddress);
        if (function == null) {
            JsonObject err = new JsonObject();
            err.addProperty("error", "Function not found: " + nameOrAddress);
            println(new Gson().toJson(err));
            return;
        }

        DecompileResults decompileResults = decompile(function);
        JsonObject result = buildResult(function, decompileResults);
        println(new GsonBuilder().setPrettyPrinting().create().toJson(result));
    }

    // -------------------------------------------------------------------------
    // Result construction
    // -------------------------------------------------------------------------

    private JsonObject buildResult(Function function, DecompileResults dr) {
        Address entry = function.getEntryPoint();
        JsonObject obj = new JsonObject();
        obj.addProperty("name", function.getName());
        obj.addProperty("address", formatAddress(entry));
        obj.addProperty("size", function.getBody().getNumAddresses());
        obj.addProperty("signature", function.getPrototypeString(true, false));
        obj.addProperty("is_thunk", function.isThunk());
        obj.addProperty("calling_convention", function.getCallingConventionName());

        // Callers
        JsonArray callers = new JsonArray();
        for (Function c : function.getCallingFunctions(TaskMonitor.DUMMY)) {
            callers.add(functionRefJson(c));
        }
        obj.add("callers", callers);

        // Callees
        JsonArray callees = new JsonArray();
        for (Function c : function.getCalledFunctions(TaskMonitor.DUMMY)) {
            callees.add(functionRefJson(c));
        }
        obj.add("callees", callees);

        // Xref count
        int xrefCount = 0;
        for (Reference ignored : currentProgram.getReferenceManager().getReferencesTo(entry)) {
            xrefCount++;
        }
        obj.addProperty("xref_count", xrefCount);

        // Reversing status
        JsonArray status = new JsonArray();
        for (ReversingIssue issue : computeReversingStatus(function, dr)) {
            JsonObject issueObj = new JsonObject();
            issueObj.addProperty("code", issue.code);
            issueObj.addProperty("message", issue.message);
            status.add(issueObj);
        }
        obj.add("reversing_status", status);

        return obj;
    }

    // -------------------------------------------------------------------------
    // Reversing status checks
    // -------------------------------------------------------------------------

    private List<ReversingIssue> computeReversingStatus(Function function, DecompileResults dr) {
        List<ReversingIssue> issues = new ArrayList<>();
        ClangTokenGroup markup = dr != null ? dr.getCCodeMarkup() : null;
        HighFunction highFunc  = dr != null ? dr.getHighFunction() : null;

        // Auto-generated name
        if (function.getName().matches("FUN_[0-9a-fA-F]+")) {
            issues.add(new ReversingIssue("UNNAMED_FUNCTION",
                    "Function '" + function.getName() + "' has an auto-generated name — rename to reflect its purpose"));
        }

        // Calling convention — unknown/unset is a hard blocker for correct decompilation
        String cc = function.getCallingConventionName();
        if (cc == null || cc.equalsIgnoreCase("unknown") || cc.isBlank()) {
            issues.add(new ReversingIssue("UNKNOWN_CALLING_CONVENTION",
                    "Calling convention is '" + cc + "' — set to __fastcall, __cdecl, or __stdcall"));
        }

        // Implicit register parameters visible in decompiled output (in_ECX, in_EDX, …)
        // These mean the calling convention is wrong — ECX/EDX is a hidden this/arg not declared
        if (markup != null) {
            detectImplicitRegisterParams(markup, issues);
        }

        // Return type
        DataType returnType = function.getReturnType();
        if (isUndefinedType(returnType)) {
            issues.add(new ReversingIssue("MISSING_RETURN_TYPE",
                    "Return type is '" + returnType.getName() + "' — assign a concrete return type"));
        }

        // Unnamed parameters — use the decompiled output as ground truth so we also catch
        // params the decompiler inferred but that are not in the formal parameter list
        if (markup != null) {
            detectAutoNamedParams(markup, function, issues);
        } else {
            // Fallback to metadata when decompile result unavailable
            for (Parameter param : function.getParameters()) {
                if (param.isAutoParameter()) continue;
                if (isAutoParamName(param.getName())) {
                    issues.add(new ReversingIssue("UNNAMED_PARAM",
                            "Parameter " + param.getOrdinal() + " '" + param.getName() +
                            "' has an auto-generated name — rename to reflect its role"));
                }
            }
        }

        // Parameter types — still use metadata (types are not easily read from ClangAST tokens).
        // Auto-parameters (e.g. the implicit ECX 'this' on __thiscall) are generated by Ghidra
        // from the calling convention and cannot be user-typed, so skip them.
        for (Parameter param : function.getParameters()) {
            if (param.isAutoParameter()) continue;
            if (isUndefinedType(param.getDataType())) {
                issues.add(new ReversingIssue("UNDEFINED_PARAM_TYPE",
                        "Parameter " + param.getOrdinal() + " '" + param.getName() +
                        "': type '" + param.getDataType().getName() + "' is undefined — assign a concrete type"));
            }
        }

        // Pcode-based checks (MISSING_STRUCT uses ClangAST; TYPE_MISMATCH uses PCode CALL ops)
        if (highFunc != null) {
            detectMissingStructs(highFunc, dr, issues);
            detectTypeMismatches(highFunc, issues);
        }

        return issues;
    }

    /**
     * Scans the decompiled output for implicit register variable tokens.
     *
     * Two Ghidra token families indicate a wrong/incomplete calling convention:
     *   in_EAX / in_ECX / in_EDX / in_EBX …  — register was WRITTEN by the caller
     *                                            and READ by this function without a
     *                                            corresponding declared parameter.
     *   unaff_EBX / unaff_ESI / unaff_EDI … — register was USED by this function but
     *                                            never written inside it (i.e., it carries
     *                                            an implicit argument from the call site,
     *                                            often the 'this' pointer passed in a
     *                                            non-standard register such as EBX or ESI).
     *
     * Fix: switch to __fastcall and declare the register as an explicit typed parameter.
     */
    private void detectImplicitRegisterParams(ClangNode node, List<ReversingIssue> issues) {
        Set<String> found = new LinkedHashSet<>();
        collectClangVarNames(node, found, name ->
                name.matches("in_[A-Z0-9]+") || name.matches("unaff_[A-Z0-9]+"));
        for (String name : found) {
            issues.add(new ReversingIssue("WRONG_CALLING_CONVENTION",
                    "Decompiled output contains register variable '" + name +
                    "' — calling convention is wrong; use __fastcall and declare '" + name +
                    "' as an explicit typed parameter (e.g. 'SomeStruct * maybe_this')"));
        }
    }

    /**
     * Scans the decompiled output for auto-named parameter tokens (param_N).
     * This catches both formally-declared params with auto names AND params the decompiler
     * inferred from usage but that are missing from the function signature entirely.
     * Already-reported formal params are deduplicated.
     */
    private void detectAutoNamedParams(ClangNode node, Function function, List<ReversingIssue> issues) {
        // Collect param_N names the metadata check will already have emitted
        Set<String> alreadyFlagged = new HashSet<>();
        for (Parameter p : function.getParameters()) {
            if (isAutoParamName(p.getName())) alreadyFlagged.add(p.getName());
        }
        Set<String> found = new LinkedHashSet<>();
        collectClangVarNames(node, found, name -> isAutoParamName(name) && !alreadyFlagged.contains(name));
        for (String name : found) {
            issues.add(new ReversingIssue("UNNAMED_PARAM",
                    "Decompiled output contains undeclared auto-named parameter '" + name +
                    "' — add it to the function signature with a concrete type"));
        }
        // Also emit issues for the formal auto-named params (avoids double-scan)
        for (Parameter param : function.getParameters()) {
            if (isAutoParamName(param.getName())) {
                issues.add(new ReversingIssue("UNNAMED_PARAM",
                        "Parameter " + param.getOrdinal() + " '" + param.getName() +
                        "' has an auto-generated name — rename to reflect its role"));
            }
        }
    }

    /**
     * Generic recursive ClangAST walker. Collects the text of every ClangVariableToken
     * whose text satisfies the given predicate into the provided set.
     */
    private void collectClangVarNames(ClangNode node, Set<String> collected,
                                      java.util.function.Predicate<String> predicate) {
        if (node instanceof ClangVariableToken) {
            String text = ((ClangToken) node).getText();
            if (text != null && predicate.test(text)) {
                collected.add(text);
            }
        }
        for (int i = 0; i < node.numChildren(); i++) {
            collectClangVarNames(node.Child(i), collected, predicate);
        }
    }

    /**
     * Detects pointer variables that are accessed via raw (unresolved) integer offsets in the
     * DECOMPILED output — i.e., cases where the decompiler could not resolve the access to a
     * named struct field and emitted arithmetic instead of "->fieldname".
     *
     * Strategy:
     *   1. Walk the ClangAST markup from the decompile result. Every time the decompiler
     *      successfully resolves a struct-field access it emits a ClangFieldToken. We collect
     *      the PcodeOp (and any PTRSUB that fed into it) associated with each ClangFieldToken —
     *      those are "resolved" accesses.
     *   2. Walk all PCode LOAD/STORE ops. For each one whose address was computed by a
     *      PTRSUB/INT_ADD on a pointer-typed base, check whether that PTRSUB was in the
     *      "resolved" set. If not, the decompiler showed a raw offset in the C output.
     *   3. Report variables that have 2+ genuinely unresolved offset accesses.
     *
     * This directly uses the decompiled output as the ground truth, so a pointer to a fully-
     * defined struct with all fields named will produce zero MISSING_STRUCT issues.
     */
    private void detectMissingStructs(HighFunction highFunc, DecompileResults dr, List<ReversingIssue> issues) {
        // Step 1 — collect PTRSUB/INT_ADD ops that produced a named field in the C output
        Set<PcodeOp> resolvedPtrsubOps = new HashSet<>();
        if (dr != null && dr.getCCodeMarkup() != null) {
            collectResolvedFieldOps(dr.getCCodeMarkup(), resolvedPtrsubOps);
        }

        // Step 2 — find unresolved PTRSUB/INT_ADD accesses on pointer-typed bases
        Map<String, Set<Long>> unresolvedOffsets = new LinkedHashMap<>();
        Map<String, String>   varNames           = new LinkedHashMap<>();
        Map<String, DataType> varTypes            = new LinkedHashMap<>();

        Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            int opcode = op.getOpcode();
            if (opcode != PcodeOp.LOAD && opcode != PcodeOp.STORE) continue;

            Varnode addrVarnode = op.getInput(1);
            if (addrVarnode == null) continue;

            PcodeOp defOp = addrVarnode.getDef();
            if (defOp == null) continue;
            int defOpcode = defOp.getOpcode();
            if (defOpcode != PcodeOp.PTRSUB && defOpcode != PcodeOp.INT_ADD) continue;

            // The decompiler resolved this access to a named field — not a problem
            if (resolvedPtrsubOps.contains(defOp)) continue;

            Varnode base = defOp.getInput(0);
            Varnode offsetVarnode = defOp.getInput(1);
            if (base == null || offsetVarnode == null || !offsetVarnode.isConstant()) continue;

            HighVariable highBase = base.getHigh();
            if (highBase == null) continue;

            // Only care about pointer-typed bases (not plain integer arithmetic)
            DataType baseType = highBase.getDataType();
            if (!(baseType instanceof Pointer) && !(baseType instanceof Array)) continue;

            String key = highBase.getName() + "@" + highBase.getRepresentative().getOffset();
            unresolvedOffsets.computeIfAbsent(key, k -> new LinkedHashSet<>()).add(offsetVarnode.getOffset());
            varNames.put(key, highBase.getName() != null ? highBase.getName() : "?");
            varTypes.put(key, baseType);
        }

        // Step 3 — report variables with 2+ unresolved offsets
        for (Map.Entry<String, Set<Long>> entry : unresolvedOffsets.entrySet()) {
            if (entry.getValue().size() < 2) continue;

            String varName  = varNames.get(entry.getKey());
            DataType ptrType = varTypes.get(entry.getKey());
            String typeName = (ptrType instanceof Pointer)
                    ? ((Pointer) ptrType).getDataType().getName()
                    : ptrType.getName();

            List<String> offsetStrs = new ArrayList<>();
            for (long off : entry.getValue()) {
                offsetStrs.add("0x" + Long.toHexString(off));
            }
            issues.add(new ReversingIssue("MISSING_STRUCT",
                    "Variable '" + varName + "' has " + entry.getValue().size() +
                    " raw offset(s) in decompiled output (" + String.join(", ", offsetStrs) +
                    ") — struct '" + typeName + "' is missing fields at these offsets"));
        }
    }

    /**
     * Recursively walks the ClangAST and collects PcodeOps that produced a named field access
     * (ClangFieldToken). Also traces back through any LOAD/STORE to find the PTRSUB that computed
     * the field address, so we can match it against the PCode walk in detectMissingStructs.
     */
    private void collectResolvedFieldOps(ClangNode node, Set<PcodeOp> resolved) {
        if (node instanceof ClangFieldToken) {
            PcodeOp op = ((ClangToken) node).getPcodeOp();
            if (op != null) {
                resolved.add(op);
                // The token's op is often the LOAD/STORE; trace back to the PTRSUB that fed it
                if (op.getOpcode() == PcodeOp.LOAD || op.getOpcode() == PcodeOp.STORE) {
                    Varnode addrVn = op.getInput(1);
                    if (addrVn != null && addrVn.getDef() != null) {
                        int defOpc = addrVn.getDef().getOpcode();
                        if (defOpc == PcodeOp.PTRSUB || defOpc == PcodeOp.INT_ADD) {
                            resolved.add(addrVn.getDef());
                        }
                    }
                }
            }
        }
        // Recurse into children (ClangTokenGroup nodes); ClangToken leaves have 0 children
        for (int i = 0; i < node.numChildren(); i++) {
            collectResolvedFieldOps(node.Child(i), resolved);
        }
    }

    private void detectTypeMismatches(HighFunction highFunc, List<ReversingIssue> issues) {
        Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            if (op.getOpcode() != PcodeOp.CALL) continue;

            Varnode calleeAddrVarnode = op.getInput(0);
            if (calleeAddrVarnode == null || !calleeAddrVarnode.isAddress()) continue;

            Function callee = currentProgram.getFunctionManager()
                    .getFunctionAt(calleeAddrVarnode.getAddress());
            if (callee == null) continue;

            Parameter[] calleeParams = callee.getParameters();
            int argCount = Math.min(calleeParams.length, op.getNumInputs() - 1);

            for (int i = 0; i < argCount; i++) {
                Parameter calleeParam = calleeParams[i];
                DataType expectedType = calleeParam.getDataType();
                if (isUndefinedType(expectedType)) continue;

                Varnode argVarnode = op.getInput(i + 1);
                if (argVarnode == null) continue;

                HighVariable highVar = argVarnode.getHigh();
                if (highVar == null) continue;

                DataType argType = highVar.getDataType();
                if (argType == null || isUndefinedType(argType)) continue;

                if (!typesCompatible(argType, expectedType)) {
                    String varName = highVar.getName() != null ? highVar.getName() : ("arg" + i);
                    issues.add(new ReversingIssue("TYPE_MISMATCH",
                            "Variable '" + varName + "' (type '" + argType.getName() +
                            "') passed to '" + callee.getName() + "' parameter '" +
                            calleeParam.getName() + "' which expects '" + expectedType.getName() + "'"));
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private DecompileResults decompile(Function function) {
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        try {
            return ifc.decompileFunction(function, 60, TaskMonitor.DUMMY);
        } finally {
            ifc.dispose();
        }
    }

    private Function resolveFunction(String nameOrAddress) {
        if (nameOrAddress.startsWith("0x") || nameOrAddress.startsWith("0X")) {
            try {
                Address addr = currentProgram.getAddressFactory().getAddress(nameOrAddress);
                if (addr != null) {
                    return currentProgram.getFunctionManager().getFunctionAt(addr);
                }
            } catch (Exception ignored) {}
        }
        // Search by name
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.getName().equals(nameOrAddress)) return f;
        }
        return null;
    }

    private static boolean isAutoParamName(String name) {
        return name != null && name.matches("param_\\d+");
    }

    private static boolean isUndefinedType(DataType dt) {
        if (dt == null) return false;
        String name = dt.getName().toLowerCase();
        if (name.startsWith("undefined")) return true;
        if (name.equals("void *") || name.equals("void*")) return true;
        return false;
    }

    private static boolean typesCompatible(DataType a, DataType b) {
        if (a == null || b == null) return true;
        if (a.getName().equals(b.getName())) return true;
        boolean aIsPtr = a instanceof Pointer;
        boolean bIsPtr = b instanceof Pointer;
        if (aIsPtr && bIsPtr) return true;
        if (aIsPtr != bIsPtr) return false;
        return true;
    }

    private static JsonObject functionRefJson(Function f) {
        JsonObject o = new JsonObject();
        o.addProperty("name", f.getName());
        o.addProperty("address", formatAddress(f.getEntryPoint()));
        return o;
    }

    private static String formatAddress(Address address) {
        String addr = address.toString();
        if (addr.startsWith("0x") || addr.startsWith("0X") || addr.contains(":")) {
            return addr;
        }
        return "0x" + addr;
    }

    private void printHelp() {
        JsonObject help = new JsonObject();
        help.addProperty("help", true);
        help.addProperty("script", "AuditFunction.java");
        help.addProperty("description",
                "Audits a function for reverse-engineering completeness. Returns metadata " +
                "(signature, callers, callees, xref_count) plus a reversing_status " +
                "list identifying unnamed params, undefined types, likely struct pointers, " +
                "and type mismatches at call sites. Does NOT return decompiled pseudocode — " +
                "use decompile_function for that.");
        JsonArray arguments = new JsonArray();
        JsonObject arg0 = new JsonObject();
        arg0.addProperty("name", "name_or_address");
        arg0.addProperty("description", "Function name (exact, case-sensitive) or 0x-prefixed hex entry-point address");
        arg0.addProperty("required", true);
        arguments.add(arg0);
        help.add("arguments", arguments);
        JsonObject example = new JsonObject();
        example.addProperty("program", "mybinary");
        example.addProperty("filename", "AuditFunction.java");
        JsonArray exArgs = new JsonArray();
        exArgs.add("main");
        example.add("args", exArgs);
        help.add("example", example);
        println(new GsonBuilder().setPrettyPrinting().create().toJson(help));
    }

    // -------------------------------------------------------------------------
    // Inner record equivalent (Java 16+ records not available in script runtime)
    // -------------------------------------------------------------------------

    private static class ReversingIssue {
        final String code;
        final String message;

        ReversingIssue(String code, String message) {
            this.code = code;
            this.message = message;
        }
    }
}
