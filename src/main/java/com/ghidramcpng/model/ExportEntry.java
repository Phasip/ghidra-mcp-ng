package com.ghidramcpng.model;

import ghidra.program.model.address.Address;
import io.swagger.v3.oas.annotations.media.Schema;

/** An exported symbol or function entry point. */
public record ExportEntry(
        @Schema(type = "string", description = "Export address in 0x-prefixed hex.")
        Address address,
        @Schema(description = "Exported symbol name.")
        String name,
        @Schema(description = "True if this export is a function entry point.")
        boolean is_function) {
}
