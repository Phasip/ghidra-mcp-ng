package com.ghidramcpng.model;

import ghidra.program.model.data.DataType;
import io.swagger.v3.oas.annotations.media.Schema;

/** A data type defined in a program's data type manager. */
public record DataTypeEntry(
        @Schema(description = "Data type name.")
        String name,
        @Schema(description = "Category path, e.g. /RTTI/TypeDescriptor.")
        String path,
        @Schema(description = "Java class name of the Ghidra data type implementation, e.g. StructureDB, EnumDB, TypedefDB.")
        String type_class,
        @Schema(description = "Size in bytes; -1 if unknown.")
        int size) {

    public static DataTypeEntry from(DataType dt) {
        return new DataTypeEntry(
                dt.getName(),
                dt.getCategoryPath().getPath(),
                dt.getClass().getSimpleName(),
                dt.getLength());
    }
}
