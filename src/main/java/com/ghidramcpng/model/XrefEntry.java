package com.ghidramcpng.model;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import io.swagger.v3.oas.annotations.media.Schema;

/** A cross-reference between two addresses, with optional enclosing-function context. */
public record XrefEntry(
        @Schema(type = "string", description = "Source address in 0x-prefixed hex.")
        Address from,
        @Schema(type = "string", description = "Destination address in 0x-prefixed hex.")
        Address to,
        @Schema(description = "Ghidra reference type, e.g. UNCONDITIONAL_CALL, DATA, UNCONDITIONAL_JUMP.")
        String ref_type,
        @Schema(description = "Name of the function containing the source address, or null.")
        String from_function,
        @Schema(description = "Name of the function at the destination address, or null.")
        String to_function) {

    public static XrefEntry from(Program program, Address fromAddr, Address toAddr, String refType) {
        Function fromFunc = program.getFunctionManager().getFunctionContaining(fromAddr);
        Function toFunc   = program.getFunctionManager().getFunctionAt(toAddr);
        return new XrefEntry(
                fromAddr,
                toAddr,
                refType,
                fromFunc != null ? fromFunc.getName() : null,
                toFunc   != null ? toFunc.getName()   : null);
    }

    public static XrefEntry from(Program program, Reference ref) {
        return from(program, ref.getFromAddress(), ref.getToAddress(),
                ref.getReferenceType().getName());
    }
}
