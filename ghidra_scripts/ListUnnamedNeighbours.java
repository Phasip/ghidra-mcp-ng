// Finds functions whose name starts with one of the given prefixes (e.g. maybe_, likely_)
// and reports which of their immediate neighbours in address order — the function directly
// above and below in the listing, NOT call-graph callers/callees — still have an
// auto-generated FUN_xxxx name.
//
// Use case: after tentatively naming a function maybe_foo/likely_foo, the adjacent function is
// often part of the same logical unit (e.g. a helper inlined-then-outlined by the compiler, or
// a sibling in the same source file) and worth reversing next.
//
// Usage (via run_script):
//   { "program": "<name>", "filename": "ListUnnamedNeighbours.java", "args": ["<prefixes>"] }
//
// Arguments:
//   prefixes   comma-separated list of name prefixes to match, e.g. "maybe_,likely_" (required)
//
// Output:
//   {
//     "matches": [
//       {
//         "function": "maybe_alloc",
//         "unnamed_neighbours": [ "0x400fe0", "0x401050" ]
//       }, …
//     ],
//     "count": number   // number of matched functions that have at least one unnamed neighbour
//   }
//
// @category GhidraTools

import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

import java.util.*;

public class ListUnnamedNeighbours extends GhidraScript {

    private static final String UNNAMED_PATTERN = "FUN_[0-9a-fA-F]+";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length == 0 || args[0].isBlank()) {
            printHelp();
            return;
        }

        List<String> prefixes = new ArrayList<>();
        for (String p : args[0].split(",")) {
            String trimmed = p.trim();
            if (!trimmed.isEmpty()) prefixes.add(trimmed);
        }
        if (prefixes.isEmpty()) {
            JsonObject err = new JsonObject();
            err.addProperty("error", "No valid prefixes found in '" + args[0] +
                    "' — expected a comma-separated list, e.g. 'maybe_,likely_'");
            println(new Gson().toJson(err));
            return;
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        List<Function> functions = new ArrayList<>();
        for (Function f : fm.getFunctions(true)) {
            functions.add(f);
        }

        JsonArray matches = new JsonArray();
        for (int i = 0; i < functions.size(); i++) {
            Function f = functions.get(i);
            if (!matchesAnyPrefix(f.getName(), prefixes)) continue;

            JsonArray unnamedNeighbours = new JsonArray();
            if (i > 0) addIfUnnamed(unnamedNeighbours, functions.get(i - 1));
            if (i < functions.size() - 1) addIfUnnamed(unnamedNeighbours, functions.get(i + 1));
            if (unnamedNeighbours.isEmpty()) continue;

            JsonObject match = new JsonObject();
            match.addProperty("function", f.getName());
            match.add("unnamed_neighbours", unnamedNeighbours);
            matches.add(match);
        }

        JsonObject out = new JsonObject();
        out.add("matches", matches);
        out.addProperty("count", matches.size());
        println(new GsonBuilder().setPrettyPrinting().create().toJson(out));
    }

    private static boolean matchesAnyPrefix(String name, List<String> prefixes) {
        for (String prefix : prefixes) {
            if (name.startsWith(prefix)) return true;
        }
        return false;
    }

    private void addIfUnnamed(JsonArray out, Function neighbour) {
        if (!neighbour.getName().matches(UNNAMED_PATTERN)) return;
        out.add(formatAddress(neighbour.getEntryPoint()));
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
        help.addProperty("script", "ListUnnamedNeighbours.java");
        help.addProperty("description",
                "Finds functions whose name starts with one of the given prefixes (e.g. maybe_, " +
                "likely_) and reports which of their immediate address-order neighbours — the " +
                "function directly above and below in the listing, not call-graph callers/callees " +
                "— still have an auto-generated FUN_xxxx name. Useful for finding the next function " +
                "worth reversing near one you've already tentatively named.");
        JsonArray arguments = new JsonArray();
        JsonObject arg0 = new JsonObject();
        arg0.addProperty("name", "prefixes");
        arg0.addProperty("description", "Comma-separated list of name prefixes to match, e.g. 'maybe_,likely_'");
        arg0.addProperty("required", true);
        arguments.add(arg0);
        help.add("arguments", arguments);
        JsonObject example = new JsonObject();
        example.addProperty("program", "mybinary");
        example.addProperty("filename", "ListUnnamedNeighbours.java");
        JsonArray exArgs = new JsonArray();
        exArgs.add("maybe_,likely_");
        example.add("args", exArgs);
        help.add("example", example);
        println(new GsonBuilder().setPrettyPrinting().create().toJson(help));
    }
}
