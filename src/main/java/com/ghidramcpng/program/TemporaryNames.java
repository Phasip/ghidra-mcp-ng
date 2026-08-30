package com.ghidramcpng.program;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;

import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Remembers which value each decompiler-invented variable name referred to the last time a read
 * showed a function to the caller.
 *
 * <p>The decompiler numbers the variables it invents in the order they appear, so committing a
 * name to one of them renumbers every later one: naming {@code piVar1} turns {@code uVar2} into
 * {@code uVar1}, {@code iVar3} into {@code iVar2}, and so on. The renumbering is a side effect of
 * the write this server just performed, in the window between the caller's read and its next
 * write — the caller's plan was correct when it was made. So this is the record that lets a later
 * write be resolved in the frame the caller is actually working in, rather than being refused for
 * a numbering it had no way to see.
 *
 * <p>A value is identified by its storage and the address at which it is defined, which is derived
 * from the code and does not renumber. Names that the database holds ({@link HighSymbol#isNameLocked()})
 * are not recorded: they never renumber, so a write to one is never ambiguous.
 *
 * <p>Only reads write this record, and a write deliberately leaves it alone: it holds what the
 * caller last saw, not what is currently true, and a write that renumbers must not move the frame
 * it is resolved against. What does clear it is a script run, which can rename anything and can
 * show the caller names this never served.
 *
 * <p>State lives only in this server process and only for the most recently read functions. A
 * function this has never seen read resolves by its current names — absence of evidence is not
 * evidence of renumbering.
 */
public final class TemporaryNames {

    /** Functions retained, least-recently-read evicted first. Reads are cheap to repeat. */
    private static final int MAX_FUNCTIONS = 256;

    private final Map<String, Map<String, String>> byFunction =
            Collections.synchronizedMap(new LinkedHashMap<>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Map<String, String>> eldest) {
                    return size() > MAX_FUNCTIONS;
                }
            });

    /**
     * Identifies the value behind a symbol: its storage and where that value is defined. Stable
     * across decompiles in a way the symbol's name is not.
     */
    public static String identityOf(HighSymbol symbol) {
        Address definedAt = symbol.getPCAddress();
        // Spelled the way get_function_variables reports the same value — storage, then the
        // 0x-prefixed address it is defined at — so an identity in an error message is a value
        // the caller can paste straight back into set_variable's name_or_storage.
        return definedAt != null ? symbol.getStorage() + "@0x" + definedAt
                                 : String.valueOf(symbol.getStorage());
    }

    /** Records the decompiler-invented names a read just reported for one function. */
    public void record(String programName, Address entryPoint, HighFunction highFunction) {
        Map<String, String> names = new HashMap<>();
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            if (!symbol.isNameLocked()) {
                names.put(symbol.getName(), identityOf(symbol));
            }
        }
        byFunction.put(key(programName, entryPoint), names);
    }

    /**
     * The value {@code name} referred to when this function was last read, or null if it was not
     * read here or did not carry that name.
     */
    public String lastRead(String programName, Address entryPoint, String name) {
        Map<String, String> names = byFunction.get(key(programName, entryPoint));
        return names == null ? null : names.get(name);
    }

    /**
     * Forgets everything recorded for one program. A script can rename and retype anything, and
     * can report names of its own that no read here ever served, so what was recorded before it
     * ran is no longer a sound account of what the caller has seen.
     */
    public void invalidate(String programName) {
        synchronized (byFunction) {
            // The entry point is appended after the last '@', and an address never contains one,
            // so this splits the key exactly however the program is named.
            byFunction.keySet().removeIf(key -> {
                int separator = key.lastIndexOf('@');
                return separator >= 0 && key.substring(0, separator).equals(programName);
            });
        }
    }

    private static String key(String programName, Address entryPoint) {
        return programName + "@" + entryPoint;
    }
}
