package com.ghidramcpng.model;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighSymbol;
import io.swagger.v3.oas.annotations.media.Schema;

/** A function parameter, local variable, or decompiler temporary. */
public record VariableEntry(
        @Schema(description = "Variable name as seen in the decompiler.")
        String name,
        @Schema(description = "Ghidra data type name, e.g. int, char *, LPVOID.")
        String type_name,
        @Schema(description = "Ghidra storage descriptor: register name, stack offset (Stack[0x10]), or memory address.")
        String storage,
        @Schema(description = "Variable kind: 'parameter', 'local', or 'temporary'.")
        String kind,
        @Schema(description = "0-based parameter index (parameters only); -1 otherwise.")
        int ordinal,
        @Schema(description = "Address at which a temporary's value is defined; null for parameters and locals.")
        Address defined_at) {

    /** Sentinel value meaning this entry is not a parameter (no ordinal). */
    private static final int NOT_A_PARAMETER = -1;

    public static VariableEntry from(Variable v) {
        if (v instanceof Parameter p) {
            return new VariableEntry(
                    v.getName(),
                    v.getDataType() != null ? v.getDataType().getName() : "undefined",
                    v.getVariableStorage() != null ? v.getVariableStorage().toString() : "",
                    "parameter",
                    p.getOrdinal(),
                    null);
        }
        return new VariableEntry(
                v.getName(),
                v.getDataType() != null ? v.getDataType().getName() : "undefined",
                v.getVariableStorage() != null ? v.getVariableStorage().toString() : "",
                "local",
                NOT_A_PARAMETER,
                null);
    }

    /**
     * Builds an entry for a value the decompiler shows but the program database does not hold —
     * a register or intermediate value. Its storage is recovered on every decompile, so
     * {@code defined_at} (where the value is computed) is what identifies it, not its name.
     */
    public static VariableEntry fromTemporary(HighSymbol symbol) {
        return new VariableEntry(
                symbol.getName(),
                symbol.getDataType() != null ? symbol.getDataType().getName() : "undefined",
                symbol.getStorage() != null ? symbol.getStorage().toString() : "",
                "temporary",
                NOT_A_PARAMETER,
                symbol.getPCAddress());
    }
}
