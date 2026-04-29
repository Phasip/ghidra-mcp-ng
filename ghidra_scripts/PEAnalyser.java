// Outputs PE/program metadata and optional relocation entries as JSON.
//
// Usage via run_script:
// {
//   "program": "<name>",
//   "filename": "PEAnalyser.java",
//   "args": ["<include_relocations>", "<offset>", "<limit>"]
// }
//
// Defaults:
//   include_relocations = true
//   offset              = 0
//   limit               = 500
//
// @category GhidraTools

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;

import java.util.Iterator;

public class PEAnalyser extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length == 0) {
            printHelp();
            return;
        }

        boolean includeRelocations;
        int offset;
        int limit;
        try {
            includeRelocations = args.length > 0 ? parseBool(args[0], "include_relocations") : true;
            offset = args.length > 1 ? parseInt(args[1], "offset", 0, 1_000_000) : 0;
            limit = args.length > 2 ? parseInt(args[2], "limit", 1, 10_000) : 500;
        } catch (IllegalArgumentException e) {
            JsonObject err = new JsonObject();
            err.addProperty("error", e.getMessage());
            println(new Gson().toJson(err));
            return;
        }

        JsonObject out = new JsonObject();
        out.addProperty("program", currentProgram.getName());
        out.addProperty("executable_path", currentProgram.getExecutablePath());
        out.addProperty("executable_format", currentProgram.getExecutableFormat());
        out.addProperty("image_base", "0x" + currentProgram.getImageBase().toString());
        out.addProperty("language_id", currentProgram.getLanguageID().getIdAsString());
        out.addProperty("compiler_spec_id", currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());

        JsonArray sections = new JsonArray();
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            JsonObject s = new JsonObject();
            s.addProperty("name", b.getName());
            s.addProperty("start", "0x" + b.getStart().toString());
            s.addProperty("end", "0x" + b.getEnd().toString());
            s.addProperty("size", b.getSize());
            s.addProperty("initialized", b.isInitialized());
            s.addProperty("readable", b.isRead());
            s.addProperty("writable", b.isWrite());
            s.addProperty("executable", b.isExecute());
            sections.add(s);
        }
        out.add("sections", sections);
        out.addProperty("section_count", sections.size());

        JsonArray relocs = new JsonArray();
        int skipped = offset;
        int produced = 0;
        if (includeRelocations) {
            Iterator<Relocation> it = currentProgram.getRelocationTable().getRelocations();
            while (it.hasNext() && produced < limit) {
                Relocation r = it.next();
                if (skipped > 0) {
                    skipped--;
                    continue;
                }
                JsonObject o = new JsonObject();
                o.addProperty("address", "0x" + r.getAddress().toString());
                o.addProperty("type", r.getType());
                o.addProperty("symbol_name", r.getSymbolName());
                relocs.add(o);
                produced++;
            }
        }
        out.add("relocations", relocs);
        out.addProperty("relocation_count", relocs.size());
        out.addProperty("relocations_truncated", includeRelocations && relocs.size() >= limit);

        println(new Gson().toJson(out));
    }

    private static int parseInt(String raw, String name, int min, int max) {
        int v;
        try {
            v = Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "Invalid value for '" + name + "': '" + raw + "' is not an integer.");
        }
        if (v < min || v > max) {
            throw new IllegalArgumentException(
                    "Invalid value for '" + name + "': " + v + ". Expected " + min + ".." + max + ".");
        }
        return v;
    }

    private static boolean parseBool(String raw, String name) {
        String v = raw == null ? "" : raw.trim();
        if (v.equalsIgnoreCase("true")) return true;
        if (v.equalsIgnoreCase("false")) return false;
        throw new IllegalArgumentException(
                "Invalid value for '" + name + "': '" + raw + "'. Expected true or false.");
    }

    private void printHelp() {
        JsonObject help = new JsonObject();
        help.addProperty("help", true);
        help.addProperty("script", "PEAnalyser.java");
        help.addProperty("description",
                "Returns core executable metadata (image base, sections) and optional relocation entries.");

        JsonArray args = new JsonArray();
        args.add(arg("include_relocations", "true|false (default: true)", false));
        args.add(arg("offset", "0-based relocation offset (default: 0)", false));
        args.add(arg("limit", "max relocations to return, 1..10000 (default: 500)", false));
        help.add("arguments", args);

        println(new Gson().toJson(help));
    }

    private static JsonObject arg(String name, String desc, boolean required) {
        JsonObject o = new JsonObject();
        o.addProperty("name", name);
        o.addProperty("description", desc);
        o.addProperty("required", required);
        return o;
    }
}
