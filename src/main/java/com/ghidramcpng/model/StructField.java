package com.ghidramcpng.model;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import io.swagger.v3.oas.annotations.media.Schema;

/** A single field within a struct layout. */
public record StructField(
        @Schema(description = "0-based field index within the struct.")
        int ordinal,
        @Schema(description = "Byte offset from the start of the struct.")
        int offset,
        @Schema(description = "Field size in bytes.")
        int length,
        @Schema(description = "Field name ('(unnamed)' if the field has no name).")
        String name,
        @Schema(description = "Data type name of the field.")
        String type,
        @Schema(description = "Category path of the field's data type.")
        String type_path,
        @Schema(description = "Field comment, if any.")
        String comment) {

    public static StructField from(DataTypeComponent comp) {
        DataType ft = comp.getDataType();
        return new StructField(
                comp.getOrdinal(),
                comp.getOffset(),
                comp.getLength(),
                comp.getFieldName() != null ? comp.getFieldName() : "(unnamed)",
                ft != null ? ft.getName() : "undefined",
                ft != null ? ft.getCategoryPath().getPath() : "",
                comp.getComment() != null ? comp.getComment() : "");
    }
}
