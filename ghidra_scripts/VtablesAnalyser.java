// Heuristic vtable scanner for read-only initialized memory blocks.
//
// Usage via run_script:
// {
//   "program": "<name>",
//   "filename": "VtablesAnalyser.java",
//   "args": ["<min_slots>", "<offset>", "<limit>"]
// }
//
// Defaults:
//   min_slots = 3
//   offset    = 0
//   limit     = 200
//
// @category GhidraTools

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;

public class VtablesAnalyser extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length == 0) {
            printHelp();
            return;
        }

        int minSlots;
        int offset;
        int limit;
        try {
            minSlots = args.length > 0 ? parseInt(args[0], "min_slots", 1, 256) : 3;
            offset = args.length > 1 ? parseInt(args[1], "offset", 0, 1_000_000) : 0;
            limit = args.length > 2 ? parseInt(args[2], "limit", 1, 10_000) : 200;
        } catch (IllegalArgumentException e) {
            JsonObject err = new JsonObject();
            err.addProperty("error", e.getMessage());
            println(new Gson().toJson(err));
            return;
        }

        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        int ptrSize = currentProgram.getDefaultPointerSize();

        JsonArray found = new JsonArray();
        int skipped = offset;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.isInitialized() || block.isWrite() || block.getSize() <= 0) {
                continue;
            }

            long start = block.getStart().getOffset();
            long end = block.getEnd().getOffset();
            long cursor = start;
            while (cursor + ptrSize <= end + 1 && found.size() < limit) {
                Address vtableAddr = space.getAddress(cursor);
                int slots = countFunctionPointerRun(vtableAddr, ptrSize);
                if (slots >= minSlots) {
                    if (skipped > 0) {
                        skipped--;
                    } else {
                        JsonObject vt = new JsonObject();
                        vt.addProperty("vtable_address", "0x" + vtableAddr.toString());
                        vt.addProperty("slot_count", slots);
                        vt.addProperty("section", block.getName());
                        vt.add("slots", sampleSlots(vtableAddr, ptrSize, Math.min(slots, 16)));
                        found.add(vt);
                    }
                    cursor += (long) slots * ptrSize;
                } else {
                    cursor += ptrSize;
                }
            }
            if (found.size() >= limit) {
                break;
            }
        }

        JsonObject out = new JsonObject();
        out.addProperty("program", currentProgram.getName());
        out.addProperty("pointer_size", ptrSize);
        out.add("vtables", found);
        out.addProperty("count", found.size());
        out.addProperty("truncated", found.size() >= limit);
        println(new Gson().toJson(out));
    }

    private int countFunctionPointerRun(Address start, int ptrSize) {
        int slots = 0;
        Address cursor = start;
        while (true) {
            Address target = readPointer(cursor, ptrSize);
            if (target == null) {
                break;
            }
            Function f = currentProgram.getFunctionManager().getFunctionAt(target);
            if (f == null) {
                break;
            }
            slots++;
            try {
                cursor = cursor.add(ptrSize);
            } catch (Exception e) {
                break;
            }
        }
        return slots;
    }

    private JsonArray sampleSlots(Address start, int ptrSize, int slotCount) {
        JsonArray arr = new JsonArray();
        Address cursor = start;
        for (int i = 0; i < slotCount; i++) {
            Address target = readPointer(cursor, ptrSize);
            if (target == null) {
                break;
            }
            Function f = currentProgram.getFunctionManager().getFunctionAt(target);
            JsonObject o = new JsonObject();
            o.addProperty("slot_index", i);
            o.addProperty("offset", i * ptrSize);
            o.addProperty("function_address", "0x" + target.toString());
            o.addProperty("function_name", f != null ? f.getName() : null);
            arr.add(o);
            try {
                cursor = cursor.add(ptrSize);
            } catch (Exception e) {
                break;
            }
        }
        return arr;
    }

    private Address readPointer(Address at, int ptrSize) {
        try {
            long value;
            if (ptrSize == 8) {
                value = currentProgram.getMemory().getLong(at);
            } else {
                value = Integer.toUnsignedLong(currentProgram.getMemory().getInt(at));
            }
            if (value == 0) {
                return null;
            }
            Address target = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
            if (!currentProgram.getMemory().contains(target)) {
                return null;
            }
            return target;
        } catch (Exception e) {
            return null;
        }
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

    private void printHelp() {
        JsonObject help = new JsonObject();
        help.addProperty("help", true);
        help.addProperty("script", "VtablesAnalyser.java");
        help.addProperty("description",
                "Heuristically scans read-only memory for contiguous runs of function pointers (likely vtables).");

        JsonArray args = new JsonArray();
        args.add(arg("min_slots", "minimum contiguous function-pointer entries (default: 3)", false));
        args.add(arg("offset", "0-based vtable candidate offset (default: 0)", false));
        args.add(arg("limit", "max vtable candidates to return, 1..10000 (default: 200)", false));
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
