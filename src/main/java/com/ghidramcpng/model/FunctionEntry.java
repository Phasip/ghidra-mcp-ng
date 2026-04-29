package com.ghidramcpng.model;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Full function metadata matching the output of the {@code list_functions_enhanced}
 * and {@code get_function_by_address} tools.
 */
public record FunctionEntry(
        @Schema(description = "Function name (exact symbol name).")
        String name,
        @Schema(type = "string", description = "Entry-point address in 0x-prefixed hex.")
        Address address,
        @Schema(description = "Number of addresses (bytes) in the function body.")
        long size,
        @Schema(description = "Full C-style function prototype including return type and parameter types.")
        String signature,
        @Schema(description = "True if this function is a thunk (delegating stub or trampoline).")
        boolean is_thunk,
        @Schema(description = "Calling convention name, e.g. __cdecl, __stdcall, default.")
        String calling_convention) {

    public static FunctionEntry from(Function f) {
        return new FunctionEntry(
                f.getName(),
                f.getEntryPoint(),
                f.getBody().getNumAddresses(),
                f.getPrototypeString(true, false),
                f.isThunk(),
                f.getCallingConventionName());
    }
}
