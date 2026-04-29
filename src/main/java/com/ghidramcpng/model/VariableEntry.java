package com.ghidramcpng.model;

import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import io.swagger.v3.oas.annotations.media.Schema;

/** A function parameter or local variable. */
public record VariableEntry(
        @Schema(description = "Variable name as seen in the decompiler.")
        String name,
        @Schema(description = "Ghidra data type name, e.g. int, char *, LPVOID.")
        String type,
        @Schema(description = "Ghidra storage descriptor: register name, stack offset (Stack[0x10]), or memory address.")
        String storage,
        @Schema(description = "Variable kind: 'parameter' or 'local'.")
        String kind,
        @Schema(description = "0-based parameter index (parameters only); -1 for local variables.")
        int ordinal) {

    /** Sentinel value meaning this entry is a local variable (no ordinal). */
    private static final int NOT_A_PARAMETER = -1;

    public static VariableEntry from(Variable v) {
        if (v instanceof Parameter p) {
            return new VariableEntry(
                    v.getName(),
                    v.getDataType() != null ? v.getDataType().getName() : "undefined",
                    v.getVariableStorage() != null ? v.getVariableStorage().toString() : "",
                    "parameter",
                    p.getOrdinal());
        }
        return new VariableEntry(
                v.getName(),
                v.getDataType() != null ? v.getDataType().getName() : "undefined",
                v.getVariableStorage() != null ? v.getVariableStorage().toString() : "",
                "local",
                NOT_A_PARAMETER);
    }
}
