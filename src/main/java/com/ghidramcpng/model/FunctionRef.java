package com.ghidramcpng.model;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import io.swagger.v3.oas.annotations.media.Schema;

/** A minimal function reference: name and entry-point address. */
public record FunctionRef(
        @Schema(description = "Function name.")
        String name,
        @Schema(type = "string", description = "Function entry-point address in 0x-prefixed hex.")
        Address address) {

    public static FunctionRef from(Function f) {
        return new FunctionRef(f.getName(), f.getEntryPoint());
    }
}
