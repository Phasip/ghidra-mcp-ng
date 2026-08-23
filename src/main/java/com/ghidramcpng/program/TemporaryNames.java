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
 * {@code uVar1}, {@code iVar3} into {@code iVar2}, and so on. A caller working from a decompile it
 * read before that write would then rename a different value than the one it meant, successfully
 * and silently. Comparing what a name meant at read time with what it means now is what turns that
 * into a refusal.
 *
 * <p>A value is identified by its storage and the address at which it is defined, which is derived
 * from the code and does not renumber. Names that the database holds ({@link HighSymbol#isNameLocked()})
 * are not recorded: they never renumber, so a write to one is never stale.
 *
 * <p>State lives only in this server process and only for the most recently read functions. A
 * function this has never seen read is not reported as stale — absence of evidence is not
 * evidence of staleness, and a false refusal costs the caller more than the check saves.
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
        return symbol.getStorage() + "@" + symbol.getPCAddress();
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

    private static String key(String programName, Address entryPoint) {
        return programName + "@" + entryPoint;
    }
}
