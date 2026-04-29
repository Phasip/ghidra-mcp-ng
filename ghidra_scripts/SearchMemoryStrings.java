// Searches raw initialized memory for printable ASCII and UTF-16LE strings.
//
// Unlike search_defined_strings, this operates directly on bytes and surfaces
// strings that were never recognised or defined by Ghidra's analysis passes.
//
// Usage (via run_script):
//   { "program": "<name>", "filename": "SearchMemoryStrings.java",
//     "args": ["<filter>", "<offset>", "<limit>", "<min_length>", "<include_unicode>"] }
//
// Arguments (all optional — defaults shown):
//   filter          substring filter applied to found strings (default: "", no filter)
//   offset          0-based skip count for pagination (default: 0)
//   limit           maximum strings to return (default: 200)
//   min_length      minimum string length to include, must be >= 1 (default: 4)
//   include_unicode also scan for UTF-16LE strings (default: true)
//
// Output:
//   {
//     "strings": [ { "address": "0x...", "value": "...", "encoding": "ascii"|"unicode16" }, … ],
//     "count":   number
//   }
//
// @category GhidraTools

import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

import java.util.*;

public class SearchMemoryStrings extends GhidraScript {

    private static final int CHUNK_SIZE = 4 * 1024 * 1024; // 4 MB

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length == 0) {
            printHelp();
            return;
        }

        String filter;
        int offset, limit, minLength;
        boolean incUnicode;
        try {
            filter     = args.length > 0 && !args[0].isBlank() ? args[0] : null;
            offset     = args.length > 1 ? parseInt(args[1], "offset",     0,    0) : 0;
            limit      = args.length > 2 ? parseInt(args[2], "limit",      1, 1000) : 200;
            minLength  = args.length > 3 ? parseInt(args[3], "min_length", 1,  256) : 4;
            incUnicode = args.length > 4 ? parseBool(args[4], "include_unicode") : true;
        } catch (IllegalArgumentException e) {
            JsonObject err = new JsonObject();
            err.addProperty("error", e.getMessage());
            println(new Gson().toJson(err));
            return;
        }

        List<JsonObject> results = new ArrayList<>();
        int[] skip = {offset};

        Memory memory = currentProgram.getMemory();
        outer:
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized() || block.getSize() <= 0) continue;
            long blockSize = block.getSize();
            long chunkBase = 0;
            while (chunkBase < blockSize) {
                int chunkLen = (int) Math.min(CHUNK_SIZE, blockSize - chunkBase);
                byte[] chunk = new byte[chunkLen];
                try {
                    int read = block.getBytes(block.getStart().add(chunkBase), chunk);
                    if (read <= 0) { chunkBase += chunkLen; continue; }
                } catch (MemoryAccessException e) {
                    chunkBase += chunkLen;
                    continue;
                }
                appendAscii(results, skip, block, chunk, chunkBase, filter, minLength, limit);
                if (results.size() >= limit) break outer;
                if (incUnicode) {
                    appendUnicode16(results, skip, block, chunk, chunkBase, filter, minLength, limit);
                    if (results.size() >= limit) break outer;
                }
                chunkBase += chunkLen;
            }
        }

        JsonObject out = new JsonObject();
        JsonArray arr = new JsonArray();
        for (JsonObject s : results) arr.add(s);
        out.add("strings", arr);
        out.addProperty("count", results.size());
        println(new Gson().toJson(out));
    }

    // -------------------------------------------------------------------------

    private void appendAscii(List<JsonObject> out, int[] skip, MemoryBlock block,
            byte[] bytes, long base, String filter, int minLen, int limit) {
        int i = 0;
        while (i < bytes.length && out.size() < limit) {
            if (!isPrintable(bytes[i])) { i++; continue; }
            int start = i;
            StringBuilder sb = new StringBuilder();
            while (i < bytes.length && isPrintable(bytes[i])) { sb.append((char)(bytes[i] & 0xff)); i++; }
            if (sb.length() < minLen || !matches(sb, filter)) continue;
            if (skip[0] > 0) { skip[0]--; continue; }
            out.add(hit(block.getStart().add(base + start), escape(sb), "ascii"));
        }
    }

    private void appendUnicode16(List<JsonObject> out, int[] skip, MemoryBlock block,
            byte[] bytes, long base, String filter, int minLen, int limit) {
        int i = 0;
        while (i + 1 < bytes.length && out.size() < limit) {
            if (!isPrintable(bytes[i]) || bytes[i + 1] != 0) { i++; continue; }
            int start = i;
            StringBuilder sb = new StringBuilder();
            while (i + 1 < bytes.length && isPrintable(bytes[i]) && bytes[i + 1] == 0) {
                sb.append((char)(bytes[i] & 0xff)); i += 2;
            }
            if (sb.length() < minLen || !matches(sb, filter)) continue;
            if (skip[0] > 0) { skip[0]--; continue; }
            out.add(hit(block.getStart().add(base + start), escape(sb), "unicode16"));
        }
    }

    private JsonObject hit(Address addr, String value, String encoding) {
        JsonObject o = new JsonObject();
        o.addProperty("address", "0x" + addr.toString());
        o.addProperty("value", value);
        o.addProperty("encoding", encoding);
        return o;
    }

    private static boolean isPrintable(byte b) {
        int u = b & 0xff;
        return u == '\t' || u == '\n' || u == '\r' || (u >= 0x20 && u <= 0x7e);
    }

    private static boolean matches(CharSequence s, String filter) {
        return filter == null || s.toString().toLowerCase().contains(filter.toLowerCase());
    }

    private static String escape(CharSequence s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default   -> sb.append(ch);
            }
        }
        return sb.toString();
    }

    private static int parseInt(String raw, String name, int min, int max) {
        int v;
        try { v = Integer.parseInt(raw.trim()); }
        catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "Invalid value for '" + name + "': '" + raw.trim() + "' is not an integer. " +
                    "Expected a whole number, e.g. " + min + ".");
        }
        if (v < min) throw new IllegalArgumentException(
                "Invalid value for '" + name + "': " + v + ". Expected a value >= " + min + ".");
        if (max > 0 && v > max) throw new IllegalArgumentException(
                "Invalid value for '" + name + "': " + v + ". Maximum supported value is " + max + ".");
        return v;
    }

    private static boolean parseBool(String raw, String name) {
        String trimmed = raw.trim();
        if (trimmed.equalsIgnoreCase("true"))  return true;
        if (trimmed.equalsIgnoreCase("false")) return false;
        throw new IllegalArgumentException(
                "Invalid value for '" + name + "': '" + trimmed + "'. Expected 'true' or 'false'.");
    }

    private void printHelp() {
        JsonObject help = new JsonObject();
        help.addProperty("help", true);
        help.addProperty("script", "SearchMemoryStrings.java");
        help.addProperty("description",
                "Scans raw initialized memory for printable ASCII and UTF-16LE strings, " +
                "including strings not yet defined by Ghidra analysis. Supports substring " +
                "filtering, pagination, minimum length, and optional Unicode scanning.");
        JsonArray arguments = new JsonArray();
        for (String[] a : new String[][]{
                {"filter",          "Substring filter applied to found strings (default: empty, no filter)",  "false"},
                {"offset",          "0-based skip count for pagination (default: 0)",                        "false"},
                {"limit",           "Maximum strings to return, max 1000 (default: 200)",                    "false"},
                {"min_length",      "Minimum string length to include, >= 1 (default: 4)",                   "false"},
                {"include_unicode", "Also scan for UTF-16LE strings: true or false (default: true)",          "false"},
        }) {
            JsonObject arg = new JsonObject();
            arg.addProperty("name",     a[0]);
            arg.addProperty("description", a[1]);
            arg.addProperty("required", Boolean.parseBoolean(a[2]));
            arguments.add(arg);
        }
        help.add("arguments", arguments);
        JsonObject example = new JsonObject();
        example.addProperty("program",  "mybinary");
        example.addProperty("filename", "SearchMemoryStrings.java");
        JsonArray exArgs = new JsonArray();
        exArgs.add("error");   // filter
        exArgs.add("0");       // offset
        exArgs.add("50");      // limit
        example.add("args", exArgs);
        help.addProperty("example", new Gson().toJson(example));
        println(new Gson().toJson(help));
    }
}
