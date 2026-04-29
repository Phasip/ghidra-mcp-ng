package com.ghidramcpng.model;

import ghidra.program.model.address.Address;
import io.swagger.v3.oas.annotations.media.Schema;

/** An external symbol imported from a shared library. */
public record ImportEntry(
        @Schema(description = "Shared library name, e.g. KERNEL32.DLL or libc.so.6.")
        String library,
        @Schema(description = "Imported symbol name.")
        String name,
        @Schema(type = "string", description = "Thunk or external address in 0x-prefixed hex, or null if unknown.")
        Address address) {
}
