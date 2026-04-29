package com.ghidramcpng.model;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import io.swagger.v3.oas.annotations.media.Schema;

/** A defined string value found in the program listing. */
public record StringEntry(
        @Schema(type = "string", description = "Address where the string is defined, in 0x-prefixed hex.")
        Address address,
        @Schema(description = "String content.")
        String value,
        @Schema(description = "Ghidra data type name, e.g. string, unicode, TerminatedCString.")
        String type) {

    public static StringEntry from(Data d) {
        return new StringEntry(
                d.getAddress(),
                d.getValue().toString(),
                d.getDataType().getName());
    }
}
