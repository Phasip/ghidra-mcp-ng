// Audits an entire program for reverse-engineering completeness.
//
// Iterates all functions using cheap metadata checks only (no decompilation) to
// produce program-wide statistics and a ranked list of the most important
// incomplete functions — those with the highest (xref_count + callee_count) score,
// meaning they are either central helper functions (called from many places) or
// large orchestration functions (call many others).
//
// Usage (via run_script):
//   { "program": "<name>", "filename": "AuditProgram.java" }
//   { "program": "<name>", "filename": "AuditProgram.java", "args": ["20"] }
//
// When called with no args the top 10 incomplete functions are returned.
// Pass a single integer argument to change N (e.g. "20" for top 20).
//
// Output: a single JSON object written to println() — captured in run_script's "output" field.
//   {
//     "program":    string,
//     "statistics": {
//       "total_functions":   number,
//       "thunks":            number,  — short jump stubs, excluded from incomplete list
//       "unnamed_functions": number   — names matching FUN_xxxx
//     },
//     "top_incomplete": [
//       {
//         "name":         string,
//         "address":      string,
//         "xref_count":   number,
//         "callee_count": number,
//         "issues":       [ string … ]  — subset of AuditFunction issue codes (metadata only)
//       }, …
//     ]
//   }
//
// Issue codes (metadata-only subset — no decompiler required):
//   UNNAMED_FUNCTION           — auto-generated FUN_xxxx name
//   UNKNOWN_CALLING_CONVENTION — calling convention is 'unknown' or unset
//   MISSING_RETURN_TYPE        — return type is undefined
//   UNNAMED_PARAM              — at least one param still named param_N
//   UNDEFINED_PARAM_TYPE       — at least one param has an undefined type
//
// Note: MISSING_STRUCT, TYPE_MISMATCH, and WRONG_CALLING_CONVENTION require
// decompilation per function and are NOT checked here. Use AuditFunction on the
// individual entries from top_incomplete to get the full picture.
//
// @category GhidraTools

import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.util.task.TaskMonitor;

import java.util.*;
import java.util.stream.Collectors;

public class AuditProgram extends GhidraScript {

    private static final int DEFAULT_TOP_N = 10;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();

        // No args → help
        if (args == null || args.length == 0 || args[0].isBlank()) {
            printHelp();
            return;
        }

        // Single arg must be a positive integer N
        int topN = DEFAULT_TOP_N;
        if (!args[0].isBlank()) {
            try {
                topN = Integer.parseInt(args[0].trim());
                if (topN <= 0) throw new NumberFormatException();
            } catch (NumberFormatException e) {
                JsonObject err = new JsonObject();
                err.addProperty("error",
                        "Invalid argument '" + args[0] + "': expected a positive integer for N " +
                        "(number of top incomplete functions to return). Example: \"20\"");
                println(new Gson().toJson(err));
                return;
            }
        }

        JsonObject result = buildResult(topN);
        println(new GsonBuilder().setPrettyPrinting().create().toJson(result));
    }

    // -------------------------------------------------------------------------
    // Core audit
    // -------------------------------------------------------------------------

    private JsonObject buildResult(int topN) {
        // Phase 1: cheap pass — iterate all functions, score by xref count only.
        // Callee traversal is deferred to phase 2 to avoid paying the cost for
        // every function in the program.
        int totalFunctions   = 0;
        int thunks           = 0;
        int unnamedFunctions = 0;

        List<Function> all        = new ArrayList<>();
        List<Integer>  xrefCounts = new ArrayList<>();

        for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
            totalFunctions++;
            if (func.isThunk()) { thunks++; continue; }
            if (func.getName().matches("FUN_[0-9a-fA-F]+")) unnamedFunctions++;
            all.add(func);
            xrefCounts.add(countXrefsTo(func.getEntryPoint()));
        }

        // Sort indices by xref count descending and select top `oversample` candidates.
        // This avoids expensive callee traversal for every function in the program.
        int n          = all.size();
        int oversample = Math.min(n, Math.max(topN * 10, 200));
        List<Integer> ranking = new ArrayList<>(n);
        for (int i = 0; i < n; i++) ranking.add(i);
        ranking.sort((a, b) -> Integer.compare(xrefCounts.get(b), xrefCounts.get(a)));

        // Phase 2: issue detection + callee count only for top `oversample` functions
        List<FunctionCandidate> candidates = new ArrayList<>();
        for (int k = 0; k < oversample; k++) {
            int          idx    = ranking.get(k);
            Function     func   = all.get(idx);
            List<String> issues = cheapIssues(func);
            if (!issues.isEmpty()) {
                int xrefCount   = xrefCounts.get(idx);
                int calleeCount = func.getCalledFunctions(TaskMonitor.DUMMY).size();
                candidates.add(new FunctionCandidate(func, xrefCount + calleeCount,
                                                     xrefCount, calleeCount, issues));
            }
        }

        // --- statistics -------------------------------------------------------
        JsonObject stats = new JsonObject();
        stats.addProperty("total_functions",   totalFunctions);
        stats.addProperty("thunks",            thunks);
        stats.addProperty("unnamed_functions", unnamedFunctions);

        // --- top-N ranking ----------------------------------------------------
        candidates.sort((a, b) -> {
            int cmp = Integer.compare(b.score, a.score);
            if (cmp != 0) return cmp;
            boolean aUnnamed = a.func.getName().matches("FUN_[0-9a-fA-F]+");
            boolean bUnnamed = b.func.getName().matches("FUN_[0-9a-fA-F]+");
            if (aUnnamed != bUnnamed) return aUnnamed ? -1 : 1;
            return a.func.getEntryPoint().compareTo(b.func.getEntryPoint());
        });

        JsonArray topIncomplete = new JsonArray();
        int limit = Math.min(topN, candidates.size());
        for (int i = 0; i < limit; i++) {
            FunctionCandidate c = candidates.get(i);
            JsonObject entry = new JsonObject();
            entry.addProperty("name",         c.func.getName());
            entry.addProperty("address",      formatAddress(c.func.getEntryPoint()));
            entry.addProperty("xref_count",   c.xrefCount);
            entry.addProperty("callee_count", c.calleeCount);
            JsonArray issueArr = new JsonArray();
            for (String code : c.issues) issueArr.add(code);
            entry.add("issues", issueArr);
            topIncomplete.add(entry);
        }

        // --- assemble result --------------------------------------------------
        JsonObject result = new JsonObject();
        result.addProperty("program", currentProgram.getName());
        result.add("statistics",     stats);
        result.add("top_incomplete", topIncomplete);
        return result;
    }

    // -------------------------------------------------------------------------
    // Cheap (no-decompiler) issue detection
    // -------------------------------------------------------------------------

    /**
     * Returns the set of issue codes detectable from function metadata alone.
     */
    private List<String> cheapIssues(Function func) {
        List<String> codes = new ArrayList<>();

        if (func.getName().matches("FUN_[0-9a-fA-F]+")) {
            codes.add("UNNAMED_FUNCTION");
        }

        String cc = func.getCallingConventionName();
        if (cc == null || cc.equalsIgnoreCase("unknown") || cc.isBlank()) {
            codes.add("UNKNOWN_CALLING_CONVENTION");
        }

        if (isUndefinedType(func.getReturnType())) {
            codes.add("MISSING_RETURN_TYPE");
        }

        boolean unnamedAdded = false, undefinedAdded = false;
        for (Parameter param : func.getParameters()) {
            if (param.isAutoParameter()) continue;
            if (!unnamedAdded && isAutoParamName(param.getName())) {
                codes.add("UNNAMED_PARAM");
                unnamedAdded = true;
            }
            if (!undefinedAdded && isUndefinedType(param.getDataType())) {
                codes.add("UNDEFINED_PARAM_TYPE");
                undefinedAdded = true;
            }
            if (unnamedAdded && undefinedAdded) break;
        }

        return codes;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private int countXrefsTo(Address address) {
        return currentProgram.getReferenceManager().getReferenceCountTo(address);
    }

    private static boolean isAutoParamName(String name) {
        return name != null && name.matches("param_\\d+");
    }

    private static boolean isUndefinedType(DataType dt) {
        if (dt == null) return false;
        String name = dt.getName().toLowerCase();
        return name.startsWith("undefined") || name.equals("void *") || name.equals("void*");
    }

    private static String formatAddress(Address address) {
        String addr = address.toString();
        if (addr.startsWith("0x") || addr.startsWith("0X") || addr.contains(":")) {
            return addr;
        }
        return "0x" + addr;
    }

    // -------------------------------------------------------------------------
    // Data holders
    // -------------------------------------------------------------------------

    private static final class FunctionCandidate {
        final Function     func;
        final int          score;
        final int          xrefCount;
        final int          calleeCount;
        final List<String> issues;

        FunctionCandidate(Function func, int score, int xrefCount, int calleeCount,
                          List<String> issues) {
            this.func        = func;
            this.score       = score;
            this.xrefCount   = xrefCount;
            this.calleeCount = calleeCount;
            this.issues      = issues;
        }
    }

    // -------------------------------------------------------------------------
    // Help
    // -------------------------------------------------------------------------

    private void printHelp() {
        JsonObject help = new JsonObject();
        help.addProperty("help", true);
        help.addProperty("script", "AuditProgram.java");
        help.addProperty("description",
                "Audits an entire program for reverse-engineering completeness. " +
                "Uses cheap metadata checks only (no decompilation) to produce " +
                "program-wide statistics and a ranked list of the most important " +
                "incomplete functions ordered by xref_count + callee_count. " +
                "Run AuditFunction on individual entries to get the full decompiler-based audit.");

        JsonArray arguments = new JsonArray();
        JsonObject argN = new JsonObject();
        argN.addProperty("name",        "n");
        argN.addProperty("description", "Number of top incomplete functions to return (default: 10)");
        argN.addProperty("required",    false);
        arguments.add(argN);
        help.add("arguments", arguments);

        JsonObject example = new JsonObject();
        example.addProperty("program",  "<your_program>");
        example.addProperty("filename", "AuditProgram.java");
        JsonArray exArgs = new JsonArray();
        exArgs.add("20");
        example.add("args", exArgs);
        help.add("example", example);

        println(new GsonBuilder().setPrettyPrinting().create().toJson(help));
    }
}
