package com.ghidramcpng.tools;

import com.ghidramcpng.mcp.ApiSupport;
import com.ghidramcpng.program.ProgramManager;
import com.ghidramcpng.program.TemporaryNames;
import com.ghidramcpng.rules.RulesEngine;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import static com.ghidramcpng.tools.ToolHelpers.findDataType;
import static com.ghidramcpng.tools.ToolHelpers.findFunction;
import static com.ghidramcpng.tools.ToolHelpers.findSymbolAddress;
import static com.ghidramcpng.tools.ToolHelpers.optional;
import static com.ghidramcpng.tools.ToolHelpers.optionalArray;
import static com.ghidramcpng.tools.ToolHelpers.optionalBool;
import static com.ghidramcpng.tools.ToolHelpers.optionalInt;
import static com.ghidramcpng.tools.ToolHelpers.required;
import static com.ghidramcpng.tools.ToolHelpers.requireMaxLength;
import static com.ghidramcpng.tools.ToolHelpers.toAddress;
import static com.ghidramcpng.tools.ToolHelpers.MAX_NAME_LENGTH;
import static com.ghidramcpng.tools.ToolHelpers.MAX_COMMENT_LENGTH;

/**
 * All write-capable HTTP tool implementations.
 */
@Path("/tool")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class WriteTools {

    public static final int TOOL_COUNT = ToolHelpers.countEndpoints(WriteTools.class);

    private final ProgramManager mgr;
    private final RulesEngine rules;
    /** What the caller last read, so a rename of a renumbered temporary can be refused. */
    private final TemporaryNames temporaryNames;

    public WriteTools(ProgramManager mgr, RulesEngine rules, TemporaryNames temporaryNames) {
        this.mgr = mgr;
        this.rules = rules;
        this.temporaryNames = temporaryNames;
    }

    @POST
    @Path("/rename_function")
    @Operation(tags = "Annotation", operationId = "rename_function", summary = "Rename a function.")
    @ApiResponse(responseCode = "200", description = "Rename function result",
            content = @Content(schema = @Schema(implementation = RenameFunctionResponse.class)))
    public RenameFunctionResponse renameFunction(
            @RequestBody(
                    required = true,
                    description = "Rename function request",
                    content = @Content(schema = @Schema(implementation = RenameFunctionRequest.class)))
            JsonObject request) {
        String programName = required(request, "program");
        String current = required(request, "name_or_address");
        String newName = requireMaxLength(required(request, "new_name"), "new_name", MAX_NAME_LENGTH);

        rules.validate("function_name", newName);

        Program program = openProgram(programName);
        runTransaction(program, "Rename function: " + current + " -> " + newName, () -> {
            Function func = findFunction(program, current);
            try {
                func.setName(newName, SourceType.USER_DEFINED);
            } catch (DuplicateNameException e) {
                throw new IllegalArgumentException(
                        "A function named '" + newName + "' already exists in '" + programName + "'. " +
                        "Use a unique name — append a suffix such as '_b', '_c', or '_2' to disambiguate.");
            }
        });

        return recorded(new RenameFunctionResponse(true, newName));
    }

    @POST
    @Path("/set_variable")
    @Operation(tags = "Annotation", operationId = "set_variable",
            summary = "Rename and/or retype one parameter, local, or decompiler temporary in a function.")
    @ApiResponse(responseCode = "200", description = "Set variable result",
            content = @Content(schema = @Schema(implementation = SetVariableResponse.class)))
    public SetVariableResponse setVariable(
            @RequestBody(
                    required = true,
                    description = "Set variable request",
                    content = @Content(schema = @Schema(implementation = SetVariableRequest.class)))
            JsonObject request) {
        String programName = required(request, "program");
        String funcRef = required(request, "name_or_address");
        String variableName = required(request, "variable_name");
        String newName = optional(request, "new_name", null);
        String typeName = optional(request, "type_name", null);

        if (newName == null && typeName == null) {
            throw new IllegalArgumentException(
                    "Nothing to change for variable '" + variableName + "': pass 'new_name', " +
                    "'type_name', or both.");
        }
        if (newName != null) {
            requireMaxLength(newName, "new_name", MAX_NAME_LENGTH);
            rules.validate("variable_name", newName);
        }

        Program program = openProgram(programName);
        Function func = findFunction(program, funcRef);
        DataType dataType = typeName != null ? findDataType(program, typeName) : null;
        Variable found = findCommittedVariable(func, variableName);
        if (found == null) {
            // A global read out of a decompiled body reads like a local to the caller, but the
            // decompiler never lists one among a function's variables. Say so here rather than
            // after a decompile that would only report the name as missing.
            Symbol global = globalSymbolNamed(program, variableName);
            if (global != null) {
                throw new IllegalArgumentException(
                        "'" + variableName + "' is not a variable in function '" + func.getName() +
                        "': it is a global symbol at " + global.getAddress() + ". Rename or retype " +
                        "it with set_global, passing name_or_address='" + variableName + "'.");
            }
        }
        if (found == null || !hasStoredStorage(found)) {
            // Everything the database does not hold in stack or memory storage — every register
            // and intermediate value — has to be committed through the decompiler's own view.
            return setTemporary(program, func, variableName, newName, dataType, typeName);
        }

        runTransaction(program, "Set variable: " + func.getName() + "." + variableName, () -> {
            if (dataType != null) {
                try {
                    found.setDataType(dataType, SourceType.USER_DEFINED);
                } catch (InvalidInputException e) {
                    throw new IllegalArgumentException(
                            "Cannot apply type '" + typeName + "' to '" + variableName + "' in '" +
                            func.getName() + "': " + e.getMessage());
                }
            }
            if (newName != null) {
                try {
                    found.setName(newName, SourceType.USER_DEFINED);
                } catch (DuplicateNameException e) {
                    throw new IllegalArgumentException(
                            "A variable named '" + newName + "' already exists in function '" +
                            func.getName() + "'. Use a unique name.");
                }
            }
        });

        return recorded(new SetVariableResponse(true,
                newName != null ? newName : variableName,
                found.getDataType() != null ? found.getDataType().getName() : null,
                found instanceof Parameter ? "parameter" : "local"));
    }

    @POST
    @Path("/set_global")
    @Operation(tags = "Annotation", operationId = "set_global",
            summary = "Rename and/or retype a global symbol (data, label, or import) by name or hex address.")
    @ApiResponse(responseCode = "200", description = "Set global result",
            content = @Content(schema = @Schema(implementation = SetGlobalResponse.class)))
    public SetGlobalResponse setGlobal(
            @RequestBody(
                    required = true,
                    description = "Set global request",
                    content = @Content(schema = @Schema(implementation = SetGlobalRequest.class)))
            JsonObject request) {
        String programName = required(request, "program");
        String nameOrAddress = required(request, "name_or_address");
        String newName = optional(request, "new_name", null);
        String typeName = optional(request, "type_name", null);

        if (newName == null && typeName == null) {
            throw new IllegalArgumentException(
                    "Nothing to change for global '" + nameOrAddress + "': pass 'new_name', " +
                    "'type_name', or both.");
        }
        if (newName != null) {
            requireMaxLength(newName, "new_name", MAX_NAME_LENGTH);
            // Its own rule key, not function_name: a global's name is often *recovered* rather than
            // inferred (a CMSIS peripheral, a symbol from a map file), and a recovered name is a fact,
            // not a guess. Projects that want the maybe_/likely_ prefixes here can still configure it.
            rules.validate("global_name", newName);
        }

        Program program = openProgram(programName);
        Symbol target = findGlobalSymbol(program, nameOrAddress);
        Address address = target.getAddress();
        DataType dataType = null;
        if (typeName != null) {
            if (address.isExternalAddress()) {
                throw new IllegalArgumentException(
                        "'" + nameOrAddress + "' is an external import with no memory-backed storage " +
                        "to retype. Only 'new_name' can be set on an import.");
            }
            dataType = findDataType(program, typeName);
        }
        DataType finalDataType = dataType;

        runTransaction(program, "Set global: " + nameOrAddress, () -> {
            if (finalDataType != null) {
                try {
                    DataUtilities.createData(program, address, finalDataType, -1,
                            DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                } catch (CodeUnitInsertionException e) {
                    throw new IllegalArgumentException(
                            "Cannot apply type '" + typeName + "' at " + address + ": " + e.getMessage());
                }
            }
            if (newName != null) {
                try {
                    target.setName(newName, SourceType.USER_DEFINED);
                } catch (DuplicateNameException e) {
                    throw new IllegalArgumentException(
                            "A symbol named '" + newName + "' already exists. Use a unique name.");
                }
            }
        });

        Data data = program.getListing().getDataAt(address);
        return recorded(new SetGlobalResponse(true,
                newName != null ? newName : target.getName(),
                data != null ? data.getDataType().getName() : null));
    }

    @POST
    @Path("/create_label")
    @Operation(tags = "Annotation", operationId = "create_label", summary = "Create a named label at the given address.")
    @ApiResponse(responseCode = "200", description = "Create label result",
            content = @Content(schema = @Schema(implementation = CreateLabelResponse.class)))
    public CreateLabelResponse createLabel(
            @RequestBody(
                    required = true,
                    description = "Create label request",
                    content = @Content(schema = @Schema(implementation = CreateLabelRequest.class)))
            JsonObject request) {
        String programName = required(request, "program");
        String address = required(request, "address");
        String name = requireMaxLength(required(request, "name"), "name", MAX_NAME_LENGTH);

        rules.validate("label_name", name);

        Program program = openProgram(programName);
        runTransaction(program, "Create label: " + name + " @ " + address, () -> {
            Address addr = toAddress(program, address);
            try {
                program.getSymbolTable().createLabel(addr, name, SourceType.USER_DEFINED);
            } catch (InvalidInputException e) {
                throw new IllegalArgumentException("Invalid label name '" + name + "': " + e.getMessage());
            }
        });

        return recorded(new CreateLabelResponse(true, name, address));
    }

    @POST
    @Path("/set_function_prototype")
    @Operation(tags = "Annotation", operationId = "set_function_prototype", summary = "Set a function's return type, calling convention, and parameter list.")
    @ApiResponse(responseCode = "200", description = "Set function prototype result",
            content = @Content(schema = @Schema(implementation = SetFunctionPrototypeResponse.class)))
    public SetFunctionPrototypeResponse setFunctionPrototype(
            @RequestBody(
                    required = true,
                    description = "Set function prototype request",
                    content = @Content(schema = @Schema(implementation = SetFunctionPrototypeRequest.class)))
            JsonObject request) {
        String programName = required(request, "program");
        String funcRef = required(request, "name_or_address");
        String returnTypeName = required(request, "return_type_name");
        JsonArray paramsJson = optionalArray(request, "parameters");
        String callingConvention = optional(request, "calling_convention", null);

        Program program = openProgram(programName);
        List<ParameterImpl> params = new ArrayList<>();
        for (int i = 0; i < paramsJson.size(); i++) {
            if (!paramsJson.get(i).isJsonObject()) {
                throw new IllegalArgumentException(
                        "'parameters[" + i + "]' must be a JSON object with 'name' and 'type_name' fields, got: " +
                        paramsJson.get(i));
            }
            JsonObject parameter = paramsJson.get(i).getAsJsonObject();
            rejectUnknownParameterFields(parameter, i);
            String paramName = requireMaxLength(requireParameterText(parameter, i, "name"), "name", MAX_NAME_LENGTH);
            String paramType = requireParameterText(parameter, i, "type_name");
            rules.validate("variable_name", paramName);
            DataType dataType = findDataType(program, paramType);
            params.add(createParameter(paramName, dataType, program));
        }

        DataType returnType = findDataType(program, returnTypeName);
        runTransaction(program, "Set prototype: " + funcRef, () -> {
            Function func = findFunction(program, funcRef);
            ReturnParameterImpl returnParam = new ReturnParameterImpl(returnType, program);
            String cc = callingConvention != null ? callingConvention : func.getCallingConventionName();
            func.updateFunction(cc, returnParam, params,
                    FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
                    SourceType.USER_DEFINED);
        });

        return recorded(new SetFunctionPrototypeResponse(true, funcRef, returnTypeName, params.size()));
    }

    @POST
    @Path("/set_parameter_type")
    @Operation(tags = "Annotation", operationId = "set_parameter_type", summary = "Set the data type and optionally the name of a specific function parameter by index.")
    @ApiResponse(responseCode = "200", description = "Set parameter type result",
            content = @Content(schema = @Schema(implementation = SetParameterTypeResponse.class)))
    public SetParameterTypeResponse setParameterType(
            @RequestBody(
                    required = true,
                    description = "Set parameter type request",
                    content = @Content(schema = @Schema(implementation = SetParameterTypeRequest.class)))
            JsonObject request) {
        String programName = required(request, "program");
        String funcRef = required(request, "name_or_address");
        int parameterIndex = optionalInt(request, "parameter_index", -1);
        if (!request.has("parameter_index") || request.get("parameter_index").isJsonNull()) {
            throw new IllegalArgumentException("Required parameter 'parameter_index' is missing. " +
                    "Provide the 0-based index of the parameter to update.");
        }
        if (parameterIndex < 0) {
            throw new IllegalArgumentException("parameter_index must be >= 0");
        }
        String typeName = required(request, "type_name");
        String newName = optional(request, "new_name", null);

        if (newName != null) {
            requireMaxLength(newName, "new_name", MAX_NAME_LENGTH);
            rules.validate("variable_name", newName);
        }

        Program program = openProgram(programName);
        DataType dataType = findDataType(program, typeName);
        runTransaction(program, "Set param type: " + funcRef + "[" + parameterIndex + "]", () -> {
            Function func = findFunction(program, funcRef);
            Parameter[] params = func.getParameters();
            if (parameterIndex >= params.length) {
                String hint = params.length == 0
                        ? " The function has no formal parameters — use set_function_prototype to define its parameter list first."
                        : " Valid indices are 0 to " + (params.length - 1) + ".";
                throw new IllegalArgumentException(
                        "Parameter index " + parameterIndex + " out of range " +
                        "(function '" + func.getName() + "' has " + params.length +
                        " parameter" + (params.length == 1 ? "" : "s") + ")." + hint);
            }
            Parameter param = params[parameterIndex];
            if (param.isAutoParameter()) {
                throw new IllegalArgumentException(
                        "Parameter index " + parameterIndex + " is an auto-parameter ('" + param.getName() +
                        "') generated by the calling convention, so it cannot be set directly. " +
                        "Retype it with set_function_prototype: keep the same calling_convention and pass " +
                        "the pointer type as the first explicit parameter ('void *' if the struct is not " +
                        "defined yet); Ghidra derives the auto-parameter from it.");
            }
            param.setDataType(dataType, SourceType.USER_DEFINED);
            if (newName != null) {
                param.setName(newName, SourceType.USER_DEFINED);
            }
        });

        return recorded(new SetParameterTypeResponse(true, parameterIndex, typeName, newName));
    }

    @POST
    @Path("/create_struct")
    @Operation(tags = "Data types", operationId = "create_struct", summary = "Create a new structure data type in the program's Data Type Manager.")
    @ApiResponse(responseCode = "200", description = "Create struct result",
            content = @Content(schema = @Schema(implementation = CreateStructResponse.class)))
    public CreateStructResponse createStruct(
            @RequestBody(
                    required = true,
                    description = "Create struct request",
                    content = @Content(schema = @Schema(implementation = CreateStructRequest.class)))
            JsonObject request) {
        String programName = required(request, "program");
        String name = requireMaxLength(required(request, "name"), "name", MAX_NAME_LENGTH);
        int size = optionalInt(request, "size", 0);
        String category = optional(request, "category", null);
        boolean override = optionalBool(request, "override", false);

        rules.validate("struct_name", name);
        if (size < 0) {
            throw new IllegalArgumentException("size must be >= 0");
        }

        Program program = openProgram(programName);
        runTransaction(program, "Create struct: " + name, () -> {
            DataType existingType = findExistingStructType(program, name, category);
            if (existingType != null) {
                if (!(existingType instanceof Structure existingStruct)) {
                    throw new IllegalArgumentException(
                            "Cannot override data type '" + name + "' because it already exists as " +
                            existingType.getClass().getSimpleName() + ". " +
                            "Use list_data_types to inspect the existing type or choose a different struct name.");
                }
                if (!override) {
                    throw new IllegalArgumentException(
                            "Struct '" + name + "' already exists. " +
                            "Use create_struct with override=true to reset its layout in place without breaking existing applications, " +
                            "or use add_struct_field / replace_struct_field to edit it incrementally.");
                }
                ensureStableStructLayout(existingStruct, name, "override create_struct");
                existingStruct.deleteAll();
                existingStruct.setLength(size);
                return;
            }

            ghidra.program.model.data.CategoryPath catPath =
                    category != null
                            ? new ghidra.program.model.data.CategoryPath(category)
                            : ghidra.program.model.data.CategoryPath.ROOT;
            StructureDataType struct = new StructureDataType(catPath, name, size,
                    program.getDataTypeManager());
            program.getDataTypeManager().addDataType(struct,
                    DataTypeConflictHandler.REPLACE_HANDLER);
        });

        return recorded(new CreateStructResponse(true, name));
    }

    @POST
    @Path("/add_struct_field")
    @Operation(tags = "Data types", operationId = "add_struct_field", summary = "Add a field to an existing structure.")
    @ApiResponse(responseCode = "200", description = "Add struct field result",
            content = @Content(schema = @Schema(implementation = AddStructFieldResponse.class)))
    public AddStructFieldResponse addStructField(
            @RequestBody(
                    required = true,
                    description = "Add struct field request",
                    content = @Content(schema = @Schema(implementation = AddStructFieldRequest.class)))
            JsonObject request) {
        String programName = required(request, "program");
        String structName = required(request, "struct_name");
        String fieldName = requireMaxLength(required(request, "field_name"), "field_name", MAX_NAME_LENGTH);
        String typeName = required(request, "type_name");
        String comment = optional(request, "comment", null);
        if (comment != null) requireMaxLength(comment, "comment", MAX_COMMENT_LENGTH);
        // -1 = sentinel for "not specified" (append behavior); 0+ = explicit byte offset
        final boolean offsetSpecified = request.has("offset") && !request.get("offset").isJsonNull();
        final int requestedOffset = optionalInt(request, "offset", -1);
        if (offsetSpecified && requestedOffset < 0) {
            throw new IllegalArgumentException(
                    "offset must be >= 0 when specified (negative offsets are not valid struct field positions).");
        }

        rules.validate("struct_field_name", fieldName);

        Program program = openProgram(programName);
        DataType fieldType = findDataType(program, typeName);
        final int[] ordinalOut = {-1};
        final int requestedOffsetFinal = requestedOffset;
        runTransaction(program, "Add field: " + structName + "." + fieldName, () -> {
            Structure struct = requireStructure(program, structName);
            ensureStableStructLayout(struct, structName, "add_struct_field");
            if (findDefinedStructFieldByName(struct, fieldName) != null) {
                throw new IllegalArgumentException(
                        "Struct '" + structName + "' already has a field named '" + fieldName + "'. " +
                        "Use replace_struct_field to change an existing field's type, or choose a different field name.");
            }
            int fieldLength = requireFixedLengthStructFieldType(fieldType, typeName, "add_struct_field");
            int targetOffset;
            if (requestedOffsetFinal >= 0) {
                // Explicit offset: the field must fit in the GAP — it may not grow the struct
                // and may not overwrite any existing named component.
                if (requestedOffsetFinal + fieldLength > struct.getLength()) {
                    throw new IllegalArgumentException(
                            "Cannot place field '" + fieldName + "' at offset " + requestedOffsetFinal +
                            " (size " + fieldLength + ") because it extends past the end of struct '" + structName +
                            "' (size " + struct.getLength() + "). " +
                            "offset + field_size must be <= struct size when targeting a gap. " +
                            "Use add_struct_field without offset to append and grow the struct.");
                }
                for (DataTypeComponent existing : struct.getDefinedComponents()) {
                    int eStart = existing.getOffset();
                    int eEnd = eStart + existing.getLength();
                    int nEnd = requestedOffsetFinal + fieldLength;
                    if (eStart < nEnd && eEnd > requestedOffsetFinal) {
                        throw new IllegalArgumentException(
                                "Cannot place field '" + fieldName + "' at offset " + requestedOffsetFinal +
                                ": it would overlap existing field '" + existing.getFieldName() +
                                "' at offset " + eStart + " (length " + existing.getLength() + "). " +
                                "Use remove_struct_field to remove the overlapping field or get_struct_layout to see the current field positions and find a valid gap offset.");
                    }
                }
                targetOffset = requestedOffsetFinal;
            } else {
                targetOffset = nextAppendOffset(struct);
                ensureStructCapacity(struct, targetOffset + fieldLength);
            }
            DataTypeComponent comp = struct.replaceAtOffset(targetOffset, fieldType, fieldLength, fieldName, comment);
            ordinalOut[0] = comp.getOrdinal();
        });

        return recorded(new AddStructFieldResponse(true, structName, fieldName, ordinalOut[0]));
    }

    @POST
    @Path("/remove_struct_field")
        @Operation(tags = "Data types", operationId = "remove_struct_field", summary = "Remove a field from a structure by field name without moving later fields.")
    @ApiResponse(responseCode = "200", description = "Remove struct field result",
            content = @Content(schema = @Schema(implementation = RemoveStructFieldResponse.class)))
    public RemoveStructFieldResponse removeStructField(
            @RequestBody(
                    required = true,
                    description = "Remove struct field request",
                    content = @Content(schema = @Schema(implementation = RemoveStructFieldRequest.class)))
            JsonObject request) {
        String programName = required(request, "program");
        String structName = required(request, "struct_name");
        String fieldName = required(request, "field_name");

        Program program = openProgram(programName);
        final int[] removedOrdinal = {-1};
        runTransaction(program, "Remove field from: " + structName, () -> {
            Structure struct = requireStructure(program, structName);
            ensureStableStructLayout(struct, structName, "remove_struct_field");
            DataTypeComponent target = requireDefinedStructField(struct, structName, fieldName);
            removedOrdinal[0] = target.getOrdinal();
            struct.clearAtOffset(target.getOffset());
        });

        return recorded(new RemoveStructFieldResponse(true, structName, removedOrdinal[0]));
    }

    @POST
    @Path("/replace_struct_field")
    @Operation(tags = "Data types", operationId = "replace_struct_field", summary = "Replace an existing structure field in place without moving later fields.")
    @ApiResponse(responseCode = "200", description = "Replace struct field result",
            content = @Content(schema = @Schema(implementation = ReplaceStructFieldResponse.class)))
    public ReplaceStructFieldResponse replaceStructField(
            @RequestBody(
                    required = true,
                    description = "Replace struct field request",
                    content = @Content(schema = @Schema(implementation = ReplaceStructFieldRequest.class)))
            JsonObject request) {
        String programName = required(request, "program");
        String structName = required(request, "struct_name");
        String fieldName = required(request, "field_name");
        String typeName = required(request, "type_name");
        String newName = optional(request, "new_name", null);
        String comment = optional(request, "comment", null);
        if (newName != null) {
            requireMaxLength(newName, "new_name", MAX_NAME_LENGTH);
            rules.validate("struct_field_name", newName);
        }
        if (comment != null) requireMaxLength(comment, "comment", MAX_COMMENT_LENGTH);

        Program program = openProgram(programName);
        DataType replacementType = findDataType(program, typeName);
        final int[] ordinalOut = {-1};
        final String[] resolvedName = {fieldName};
        runTransaction(program, "Replace field in: " + structName, () -> {
            Structure struct = requireStructure(program, structName);
            ensureStableStructLayout(struct, structName, "replace_struct_field");
            DataTypeComponent target = requireDefinedStructField(struct, structName, fieldName);
            if (target.getLength() <= 0) {
                throw new IllegalArgumentException(
                        "Field '" + target.getFieldName() + "' in struct '" + structName + "' is zero-length or unsupported. " +
                        "replace_struct_field only supports normal sized fields.");
            }
            int replacementLength = requireFixedLengthStructFieldType(replacementType, typeName, "replace_struct_field");
            int available = availableBytesWithoutMovingLaterFields(struct, target);
            if (replacementLength > available) {
                throw new IllegalArgumentException(
                        "Cannot replace field '" + target.getFieldName() + "' in struct '" + structName + "' with type '" + typeName +
                        "' because it needs " + replacementLength + " byte(s), but only " + available +
                        " byte(s) are available before the next field. " +
                        "Use a same-size or smaller type, or recreate the struct with create_struct override=true.");
            }

            String finalFieldName = newName != null ? newName : target.getFieldName();
            DataTypeComponent replaced = struct.replaceAtOffset(
                    target.getOffset(),
                    replacementType,
                    replacementLength,
                    finalFieldName,
                    comment != null ? comment : target.getComment());
            ordinalOut[0] = replaced.getOrdinal();
            resolvedName[0] = finalFieldName;
        });

        return recorded(new ReplaceStructFieldResponse(true, structName, resolvedName[0], ordinalOut[0], typeName));
    }

    @POST
    @Path("/set_comment")
    @Operation(tags = "Annotation", operationId = "set_comment",
            summary = "Set a comment on the code unit at an address, or at a function or symbol's address.")
    @ApiResponse(responseCode = "200", description = "Set comment result",
            content = @Content(schema = @Schema(implementation = SetCommentResponse.class)))
    public SetCommentResponse setComment(
            @RequestBody(
                    required = true,
                    description = "Set comment request",
                    content = @Content(schema = @Schema(implementation = SetCommentRequest.class)))
            JsonObject request) {
        String programName = required(request, "program");
        String target = required(request, "name_or_address");
        String comment = requireMaxLength(required(request, "comment"), "comment", MAX_COMMENT_LENGTH);
        String commentTypeName = optional(request, "comment_type", "PRE");

        CommentType commentType = switch (commentTypeName.toUpperCase()) {
            case "PRE" -> CommentType.PRE;
            case "POST" -> CommentType.POST;
            case "EOL" -> CommentType.EOL;
            case "PLATE" -> CommentType.PLATE;
            case "REPEATABLE" -> CommentType.REPEATABLE;
            default -> throw new IllegalArgumentException(
                    "Unknown comment type '" + commentTypeName + "' — must be PRE, POST, EOL, PLATE, or REPEATABLE");
        };

        Program program = openProgram(programName);
        // Resolve and validate before the transaction opens (coding standard 5) — the comment
        // rules need the enclosing function, which is a listing read.
        Address addr = findSymbolAddress(program, target);
        if (rules.hasCommentRules()) {
            Function containing = program.getFunctionManager().getFunctionContaining(addr);
            rules.validateComment(commentTypeName.toUpperCase(), comment,
                    containing == null ? null : containing.getName(),
                    () -> countAutoNamedVariables(containing));
        }

        runTransaction(program, "Set comment @ " + addr, () -> {
            var cu = program.getListing().getCodeUnitAt(addr);
            if (cu == null) {
                throw new IllegalArgumentException("No code unit starts at 0x" + addr +
                        " (resolved from '" + target + "'). A comment attaches to an instruction or " +
                        "a defined data item; use get_disassembly to find the address of one.");
            }
            cu.setComment(commentType, comment.isEmpty() ? null : comment);
        });

        return new SetCommentResponse(true, addr, commentTypeName.toUpperCase());
    }

    /**
     * Counts the function's variables that still carry a Ghidra-generated name.
     *
     * <p>Only listing variables are visible here — the decompiler's own inventions
     * ({@code uVar7}, {@code iVar3}) live in its view and never reach the listing, so they are
     * not counted. Reading them would cost a decompile on every set_comment call, which is not
     * worth it: the stack and parameter spellings this does see are the bulk of what a
     * still-unanalysed function carries.
     */
    private static int countAutoNamedVariables(Function function) {
        if (function == null) return 0;
        int count = 0;
        for (Variable variable : function.getAllVariables()) {
            if (RulesEngine.isAutoGeneratedVariableName(variable.getName())) {
                count++;
            }
        }
        return count;
    }

    @POST
    @Path("/analyze_program")
    @Operation(tags = "Program", operationId = "analyze_program",
            summary = "Run Ghidra's full auto-analysis on an already-imported program and block until completion. " +
                    "Required once for any program imported outside MCP (e.g. via the Ghidra GUI): every other tool " +
                    "rejects a program that has never been analyzed. Also use it to re-run analysis after large " +
                    "structural edits. import_binary already analyzes on import — you do not need to call this after " +
                    "a successful import.")
    @ApiResponse(responseCode = "200", description = "Analysis result",
            content = @Content(schema = @Schema(implementation = AnalyzeProgramResponse.class)))
    public AnalyzeProgramResponse analyzeProgram(
            @RequestBody(required = true,
                    content = @Content(schema = @Schema(implementation = AnalyzeProgramRequest.class)))
            com.google.gson.JsonObject request) {
        String programName = required(request, "program");
        // The one tool that must accept an unanalyzed program — every other open requires
        // analysis to have run already.
        Program program = openProgramForAnalysis(programName);
        try {
            mgr.analyzeProgram(program);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Auto-analysis of '" + programName + "' failed: " + e.getMessage(), e);
        }
        int functionCount = program.getFunctionManager().getFunctionCount();
        return new AnalyzeProgramResponse(true, programName, functionCount);
    }

    @POST
    @Path("/import_binary")
    @Operation(tags = "Program", operationId = "import_binary", summary = "Import a binary file into the Ghidra project and run full auto-analysis. The returned program name can be used immediately with all other tools. "
            + "The format is auto-detected; a headerless image (a raw flash dump or firmware blob) has nothing to detect, so pass language_id and base_address for those.")
    @ApiResponse(responseCode = "200", description = "Import result",
            content = @Content(schema = @Schema(implementation = ImportBinaryResponse.class)))
    public ImportBinaryResponse importBinary(
            @RequestBody(required = true,
                    content = @Content(schema = @Schema(implementation = ImportBinaryRequest.class)))
            com.google.gson.JsonObject request) {
        String filePath = required(request, "file_path");
        String projectDir = optional(request, "project_dir", null);
        String languageId = optional(request, "language_id", null);
        String baseAddress = optional(request, "base_address", null);

        rules.validateImport(filePath, projectDir);

        try {
            String programName = mgr.importBinary(filePath, projectDir, languageId, baseAddress);
            return new ImportBinaryResponse(programName, projectDir != null ? projectDir : "/", true, null);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Import failed: " + e.getMessage(), e);
        }
    }

    private Program openProgram(String programName) {
        try {
            return mgr.getOrOpen(programName);
        } catch (RuntimeException e) {
            throw e; // IllegalArgumentException → 400, others bubble as-is → 500
        } catch (Exception e) {
            throw new RuntimeException("Failed to open program '" + programName + "': " + e.getMessage(), e);
        }
    }

    /** As {@link #openProgram}, but permits a program that has not been analyzed yet. */
    private Program openProgramForAnalysis(String programName) {
        try {
            return mgr.getOrOpenForAnalysis(programName);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to open program '" + programName + "': " + e.getMessage(), e);
        }
    }

    /**
     * Marks that this tool has recorded a finding, clearing the {@code reads.max_without_write}
     * budget in rules.yaml. Wrapped around the success return rather than folded into
     * {@link #runTransaction} so the budget clears exactly when a tool reports success — a
     * transaction that committed and then failed validation has recorded nothing.
     *
     * <p>Deliberately not used by set_comment: prose is the thing the budget exists to stop
     * substituting for names and types, so a comment must not buy more reading. analyze_program
     * and import_binary are program lifecycle, not findings, and also do not clear it.
     */
    private <T> T recorded(T response) {
        rules.noteRecordedWrite();
        return response;
    }

    private void runTransaction(Program program, String description, ThrowingAction action) {
        try {
            mgr.withTransaction(program, description, action::run);
        } catch (RuntimeException e) {
            throw e; // preserve IllegalArgumentException (→ 400) and NamingRuleViolation (→ 400)
        } catch (Exception e) {
            throw new RuntimeException("Transaction '" + description + "' failed: " + e.getMessage(), e);
        }
    }

    private ParameterImpl createParameter(String name, DataType dataType, Program program) {
        try {
            return new ParameterImpl(name, dataType, program);
        } catch (Exception e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    /** The only fields a prototype parameter object may carry; anything else is a typo. */
    private static final List<String> PROTOTYPE_PARAMETER_FIELDS = List.of("name", "type_name");

    /**
     * Rejects unrecognised keys in a prototype parameter object, mirroring what
     * UnknownQueryParamFilter does for query parameters. Without it, a misspelled key — most
     * often 'type', this field's former spelling — reads only as a missing required field and
     * says nothing about the key that was actually sent.
     */
    private static void rejectUnknownParameterFields(JsonObject parameter, int index) {
        List<String> unknown = parameter.keySet().stream()
                .filter(key -> !PROTOTYPE_PARAMETER_FIELDS.contains(key))
                .toList();
        if (!unknown.isEmpty()) {
            throw new IllegalArgumentException(ApiSupport.unknownNamesMessage(
                    "field", unknown, PROTOTYPE_PARAMETER_FIELDS, "'parameters[" + index + "]'"));
        }
    }

    private static String requireParameterText(JsonObject parameter, int index, String fieldName) {
        if (!parameter.has(fieldName) || parameter.get(fieldName).isJsonNull()) {
            throw new IllegalArgumentException(
                    "'parameters[" + index + "]." + fieldName + "' is required.");
        }
        if (!parameter.get(fieldName).isJsonPrimitive()
                || !parameter.get(fieldName).getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException(
                    "'parameters[" + index + "]." + fieldName + "' must be a string.");
        }
        String value = parameter.get(fieldName).getAsString();
        if (value.isBlank()) {
            throw new IllegalArgumentException(
                    "'parameters[" + index + "]." + fieldName + "' must not be empty.");
        }
        return value;
    }

    private DataType findExistingStructType(Program program, String structName, String category) {
        if (category != null && !category.isBlank()) {
            String normalizedCategory = category.endsWith("/") ? category.substring(0, category.length() - 1) : category;
            DataType exact = program.getDataTypeManager().getDataType(normalizedCategory + "/" + structName);
            if (exact != null) {
                return exact;
            }
        }

        List<DataType> matches = new ArrayList<>();
        program.getDataTypeManager().findDataTypes(structName, matches);
        return matches.isEmpty() ? null : matches.get(0);
    }

    private Structure requireStructure(Program program, String structName) {
        DataType dt = findDataType(program, structName);
        if (!(dt instanceof Structure structure)) {
            throw new IllegalArgumentException(
                    "'" + structName + "' is not a Structure " +
                    "(found: " + dt.getClass().getSimpleName() + "). " +
                    "Use list_data_types to see all available structures, or use create_struct to create one first.");
        }
        return structure;
    }

    private void ensureStableStructLayout(Structure struct, String structName, String operation) {
        if (struct.isPackingEnabled()) {
            String guidance = "Use get_struct_layout to inspect the current offsets and recreate the struct as a non-packed struct if you need layout-stable edits.";
            if ("remove_struct_field".equals(operation)) {
                guidance = "remove_struct_field would let Ghidra repack later fields in a packed struct. " +
                        "Use get_struct_layout to inspect the current offsets, then recreate the struct as non-packed with create_struct override=true if you need a stable removal.";
            }
            throw new IllegalArgumentException(
                    "Struct '" + structName + "' is packed, so Ghidra may repack fields during " + operation + ". " +
                    "This API only supports non-packed structs for layout-stable edits. " +
                    guidance);
        }
    }

    private int requireFixedLengthStructFieldType(DataType dataType, String typeName, String operation) {
        int length = dataType.getLength();
        if (length <= 0) {
            throw new IllegalArgumentException(
                    "Type '" + typeName + "' cannot be used with " + operation + " because it does not have a fixed byte size. " +
                    "Use a concrete sized type, a specific struct type, or a resolved function definition instead.");
        }
        return length;
    }

    private void ensureStructCapacity(Structure struct, int requiredLength) {
        int currentLength = struct.getLength();
        if (requiredLength > currentLength) {
            struct.growStructure(requiredLength - currentLength);
        }
    }

    private int nextAppendOffset(Structure struct) {
        int offset = 0;
        for (DataTypeComponent component : struct.getDefinedComponents()) {
            if (component.getLength() <= 0) {
                offset = Math.max(offset, component.getOffset());
                continue;
            }
            offset = Math.max(offset, component.getEndOffset() + 1);
        }
        return offset;
    }

    private int availableBytesWithoutMovingLaterFields(Structure struct, DataTypeComponent target) {
        int nextOffset = struct.getLength();
        for (DataTypeComponent component : struct.getDefinedComponents()) {
            if (component.getOffset() > target.getOffset()) {
                nextOffset = component.getOffset();
                break;
            }
        }
        return Math.max(nextOffset - target.getOffset(), target.getLength());
    }

    private DataTypeComponent findDefinedStructFieldByName(Structure struct, String fieldName) {
        if (fieldName == null) {
            return null;
        }
        for (DataTypeComponent component : struct.getDefinedComponents()) {
            if (fieldName.equals(component.getFieldName())) {
                return component;
            }
        }
        return null;
    }

    private DataTypeComponent requireDefinedStructField(
            Structure struct,
            String structName,
            String fieldName) {
        DataTypeComponent byName = findDefinedStructFieldByName(struct, fieldName);
        if (byName != null) {
            return byName;
        }
        throw new IllegalArgumentException(
                "Field '" + fieldName + "' not found in struct '" + structName + "'. " +
                "Names are case-sensitive. Use get_struct_layout to list the current fields.");
    }

    @FunctionalInterface
    private interface ThrowingAction {
        void run() throws Exception;
    }

    private static Symbol findGlobalSymbol(Program program, String nameOrAddress) {
        if (nameOrAddress.startsWith("0x") || nameOrAddress.startsWith("0X")) {
            Address addr = toAddress(program, nameOrAddress);
            for (Symbol sym : program.getSymbolTable().getSymbols(addr)) {
                if (isGlobalTarget(sym)) {
                    return requireNamableGlobal(program, sym, nameOrAddress);
                }
            }
            throw new IllegalArgumentException(
                    "No global symbol at address " + nameOrAddress + ". " +
                    "Use list_globals to find valid symbol names and addresses.");
        }
        Symbol found = globalSymbolNamed(program, nameOrAddress);
        if (found != null) {
            return requireNamableGlobal(program, found, nameOrAddress);
        }
        throw new IllegalArgumentException(
                "Global symbol '" + nameOrAddress + "' not found. " +
                "Names are case-sensitive. Use list_globals to find valid global symbol names, " +
                "or pass a 0x-prefixed hex address.");
    }

    /**
     * Refuses the targets that only *look* like globals. A dynamic symbol (DAT_/LAB_) is not stored
     * in the database — Ghidra synthesises it for any referenced address — so naming one converts it
     * into a permanent label wherever the address happens to point. That is what the agent wants at
     * data, and a mistake everywhere else: at a code address it makes an untyped label that belongs
     * to create_label, and offcut into a datum it marks a meaningless boundary. A symbol somebody
     * already stored is always fine: its location was decided when it was created.
     */
    private static Symbol requireNamableGlobal(Program program, Symbol symbol, String nameOrAddress) {
        Address addr = symbol.getAddress();
        if (!symbol.isDynamic() || !addr.isMemoryAddress()) {
            return symbol;
        }

        Instruction instruction = program.getListing().getInstructionContaining(addr);
        if (instruction != null) {
            Function containing = program.getFunctionManager().getFunctionContaining(addr);
            throw new IllegalArgumentException(
                    "'" + nameOrAddress + "' is the automatic label " + symbol.getName() + " at 0x" + addr +
                    ", which is code: the instruction at 0x" + instruction.getAddress() +
                    (containing != null ? " in function '" + containing.getName() + "'" : "") +
                    ". set_global names data globals, so naming it would only leave an untyped label. " +
                    "Use create_label to label a code address, or set_comment to record a note there.");
        }

        Data data = program.getListing().getDataContaining(addr);
        if (data != null && data.isDefined() && !data.getMinAddress().equals(addr)) {
            throw new IllegalArgumentException(
                    "'" + nameOrAddress + "' is the automatic label " + symbol.getName() + " at 0x" + addr +
                    ", which is inside the " + data.getDataType().getName() + " at 0x" + data.getMinAddress() +
                    ", not its start. Pass 0x" + data.getMinAddress() + " to name that global, " +
                    "or use create_label if you meant to label this offset.");
        }
        return symbol;
    }

    /** The global symbol named {@code name}, or null when nothing set_global can act on has it. */
    private static Symbol globalSymbolNamed(Program program, String name) {
        for (Symbol sym : program.getSymbolTable().getSymbols(name)) {
            if (isGlobalTarget(sym)) {
                return sym;
            }
        }
        return null;
    }

    /**
     * True for the symbols set_global owns: data, labels and external imports. A function defined
     * in the program belongs to rename_function, and a parameter or local — which lives in a
     * function's frame, not in memory — belongs to set_variable, so neither may be matched by name
     * here. An imported function is the exception: it has no body for rename_function to find, so
     * set_global is the only tool that can name it.
     */
    private static boolean isGlobalTarget(Symbol symbol) {
        Address address = symbol.getAddress();
        if (address == null) {
            return false;
        }
        if (address.isExternalAddress()) {
            return true;
        }
        SymbolType type = symbol.getSymbolType();
        return address.isMemoryAddress()
                && type != SymbolType.FUNCTION
                && type != SymbolType.PARAMETER
                && type != SymbolType.LOCAL_VAR;
    }

    /**
     * Finds a parameter or local variable the program database actually holds, or null when the
     * name belongs to a value only the decompiler knows about (see {@link #setTemporary}).
     */
    private static Variable findCommittedVariable(Function func, String name) {
        for (Parameter p : func.getParameters()) {
            if (p.getName().equals(name)) {
                return p;
            }
        }
        for (Variable v : func.getLocalVariables()) {
            if (v.getName().equals(name)) {
                return v;
            }
        }
        return null;
    }

    /**
     * True when a committed variable can be updated straight through the database. Register- and
     * hash-backed locals cannot: their storage is recovered by the decompiler, so a write to them
     * has to go back through {@link HighFunctionDBUtil} like any other temporary.
     */
    private static boolean hasStoredStorage(Variable variable) {
        if (variable instanceof Parameter) {
            return true;
        }
        VariableStorage storage = variable.getVariableStorage();
        return storage != null && (storage.isStackStorage() || storage.isMemoryStorage());
    }

    /**
     * Applies a name and/or type to a value the decompiler shows but the database does not hold —
     * a register or intermediate value, what Ghidra calls a decompiler temporary. Committing one
     * creates a real local variable, which the decompiler may then fail to match back to any value
     * on the next decompile; that is a silent no-op, so the write is verified and rolled back
     * rather than reported as a success that later vanishes.
     */
    private SetVariableResponse setTemporary(Program program, Function func, String variableName,
            String newName, DataType dataType, String typeName) {
        int timeoutSeconds = rules.getDecompileTimeoutSeconds();
        HighFunction highFunction = requireHighFunction(program, func, timeoutSeconds);
        HighSymbol symbol = findHighSymbolIn(highFunction, variableName);
        requireNameStillMeansWhatWasRead(program, func, highFunction, symbol, variableName);
        if (symbol == null) {
            throw notFound(highFunction, func, variableName);
        }

        if (newName == null && !symbol.isNameLocked()) {
            throw new IllegalArgumentException(
                    "Retyping '" + variableName + "' in function '" + func.getName() + "' needs " +
                    "'new_name' too. It is a decompiler temporary, and the decompiler derives a " +
                    "temporary's name from its type — retyping it alone would leave a variable with " +
                    "a new auto-generated name and nothing stable to address it by. Pass 'new_name' " +
                    "and 'type_name' together.");
        }

        String finalName = newName != null ? newName : variableName;
        runTransaction(program, "Set temporary: " + func.getName() + "." + variableName, () -> {
            try {
                HighFunctionDBUtil.updateDBVariable(symbol, newName, dataType, SourceType.USER_DEFINED);
            } catch (DuplicateNameException e) {
                throw new IllegalArgumentException(
                        "A variable named '" + finalName + "' already exists in function '" +
                        func.getName() + "'. Use a unique name.");
            } catch (InvalidInputException | UnsupportedOperationException e) {
                throw new IllegalArgumentException(
                        "Cannot apply " + (typeName != null ? "type '" + typeName + "' " : "a name ") +
                        "to '" + variableName + "' in function '" + func.getName() + "': " +
                        e.getMessage() + " Its storage is " + symbol.getStorage() +
                        ", so a type of a different size does not fit.");
            }
        });

        HighSymbol applied = findHighSymbol(program, func, finalName, timeoutSeconds);
        if (applied == null) {
            throw new IllegalArgumentException(
                    "Ghidra accepted the write but did not keep it: '" + variableName + "' (" +
                    symbol.getStorage() + " at " + symbol.getPCAddress() + ") is a value the " +
                    "decompiler re-derives on every decompile, and it did not match the local " +
                    "variable the write created. " + rollBackUnmatchedLocal(program, func, finalName) +
                    " This value cannot be named; record it with set_comment at " +
                    symbol.getPCAddress() + " instead.");
        }
        // Report the type the database now holds, which is what get_function_variables will
        // show — not the decompiler's inference for the same value.
        Variable committed = findCommittedVariable(func, finalName);
        DataType appliedType = committed != null ? committed.getDataType() : applied.getDataType();
        return recorded(new SetVariableResponse(true, finalName,
                appliedType != null ? appliedType.getName() : null, "temporary"));
    }

    /**
     * Deletes the local variable left behind by a commit the decompiler did not match, so a failed
     * write leaves no half-applied state. Returns the sentence describing what happened, for the
     * error the caller is about to throw.
     */
    private String rollBackUnmatchedLocal(Program program, Function func, String name) {
        try {
            runTransaction(program, "Roll back unmatched local: " + name, () -> {
                for (Variable v : func.getLocalVariables()) {
                    if (v.getName().equals(name)) {
                        func.removeVariable(v);
                    }
                }
            });
            return "The write has been rolled back.";
        } catch (RuntimeException e) {
            return "Rolling the write back also failed (" + e.getMessage() + "), so the unmatched " +
                    "local '" + name + "' is still in the database — remove it in the Ghidra UI.";
        }
    }

    /** The decompiler's symbol named {@code name} in {@code func}, or null if it shows no such name. */
    private static HighSymbol findHighSymbol(Program program, Function func, String name,
            int timeoutSeconds) {
        DecompileResults results =
                ToolHelpers.decompileFreshWithResults(program, func, timeoutSeconds);
        HighFunction highFunction = results.getHighFunction();
        if (highFunction == null) {
            return null;
        }
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            if (name.equals(symbol.getName())) {
                return symbol;
            }
        }
        return null;
    }

    /** The decompiler's symbol named {@code name} in an already-decompiled function, or null. */
    private static HighSymbol findHighSymbolIn(HighFunction highFunction, String name) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol symbol = symbols.next();
            if (name.equals(symbol.getName())) {
                return symbol;
            }
        }
        return null;
    }

    /** Reports a name the decompiler does not show, against the names it does. */
    private static IllegalArgumentException notFound(HighFunction highFunction, Function func,
            String name) {
        List<String> known = new ArrayList<>();
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            known.add(symbols.next().getName());
        }
        String suggestion = ApiSupport.suggestClosest(name, known);
        return new IllegalArgumentException(
                "Variable '" + name + "' not found in function '" + func.getName() + "'. " +
                "Names are case-sensitive. " +
                (suggestion != null ? "Did you mean '" + suggestion + "'? " : "") +
                "Use get_function_variables to list the parameters, locals and temporaries with " +
                "their exact current names.");
    }

    /**
     * Refuses a write to a decompiler-invented name that no longer refers to the value the caller
     * last read under it. Naming one temporary renumbers the rest, so the second write of a pair
     * planned from a single decompile would land on a different value — successfully, and without
     * any sign that it went to the wrong place. Renumbering can also retire the name outright,
     * which is why this runs before the name is reported as missing: "did you mean uVar1?" would
     * be pointing at exactly the wrong value. Only a name whose meaning has demonstrably changed
     * is refused; a name that still means what it meant, and a function that was never read here,
     * both pass through.
     */
    private void requireNameStillMeansWhatWasRead(Program program, Function func,
            HighFunction highFunction, HighSymbol symbol, String variableName) {
        if (symbol != null && symbol.isNameLocked()) {
            return; // A name the database holds does not renumber.
        }
        String asRead = temporaryNames.lastRead(
                program.getName(), func.getEntryPoint(), variableName);
        if (asRead == null) {
            return;
        }
        String now = symbol != null ? TemporaryNames.identityOf(symbol) : null;
        if (asRead.equals(now)) {
            return;
        }
        throw new IllegalArgumentException(
                "'" + variableName + "' in function '" + func.getName() + "' no longer refers to " +
                "the value it did when you last read this function: " +
                (now != null ? "it now refers to " + now + ", not " + asRead
                             : "the name is gone from the current decompile, where it meant " + asRead) +
                ". Naming one temporary makes Ghidra renumber the rest. " +
                whereThatValueWentNow(highFunction, asRead) +
                " Decompile '" + func.getName() + "' again and work from the new names.");
    }

    /** Tells the caller what the value it meant is called now, which is the whole fix. */
    private static String whereThatValueWentNow(HighFunction highFunction, String identity) {
        Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol candidate = symbols.next();
            if (identity.equals(TemporaryNames.identityOf(candidate))) {
                return "The value you meant is now called '" + candidate.getName() + "'.";
            }
        }
        return "The value you meant is no longer a variable of its own.";
    }

    /** The decompiler's model of {@code func}, which is where its temporaries live. */
    private static HighFunction requireHighFunction(Program program, Function func,
            int timeoutSeconds) {
        HighFunction highFunction = ToolHelpers
                .decompileFreshWithResults(program, func, timeoutSeconds)
                .getHighFunction();
        if (highFunction == null) {
            throw new IllegalStateException(
                    "The decompiler produced no variable model for function '" + func.getName() +
                    "', so its variables cannot be addressed. Re-run auto-analysis on the program.");
        }
        return highFunction;
    }

    public record RenameFunctionRequest(
            @Schema(description = "Program name; see list_project_files.", requiredMode = Schema.RequiredMode.REQUIRED)
            String program,
            @Schema(description = "Function name (case-sensitive) or 0x-prefixed hex entry point.", requiredMode = Schema.RequiredMode.REQUIRED)
            String name_or_address,
            @Schema(description = "New function name (max 256 chars)", requiredMode = Schema.RequiredMode.REQUIRED)
            String new_name) {
    }

    public record SetVariableRequest(
            @Schema(description = "Program name; see list_project_files.", requiredMode = Schema.RequiredMode.REQUIRED)
            String program,
            @Schema(description = "Function name (case-sensitive) or 0x-prefixed hex entry point.", requiredMode = Schema.RequiredMode.REQUIRED)
            String name_or_address,
            @Schema(description = "Current variable or parameter name; see get_function_variables.", requiredMode = Schema.RequiredMode.REQUIRED)
            String variable_name,
            @Schema(description = "New variable name (max 256 chars); omit to keep the current one.")
            String new_name,
            @Schema(description = "Data type to assign, e.g. int, char *, MyStruct *; omit to keep the current one.")
            String type_name) {
    }

    public record PrototypeParameterRequest(
            @Schema(description = "Parameter name (max 256 chars)", requiredMode = Schema.RequiredMode.REQUIRED)
            String name,
            @Schema(description = "Data type to assign, e.g. int, char *, MyStruct *", requiredMode = Schema.RequiredMode.REQUIRED)
            String type_name) {
    }

    public record SetFunctionPrototypeRequest(
            @Schema(description = "Program name; see list_project_files.", requiredMode = Schema.RequiredMode.REQUIRED)
            String program,
            @Schema(description = "Function name or hex address", requiredMode = Schema.RequiredMode.REQUIRED)
            String name_or_address,
            @Schema(description = "Data type to return, e.g. int, char *, MyStruct *", requiredMode = Schema.RequiredMode.REQUIRED)
            String return_type_name,
            @Schema(description = "Ordered parameter list; each entry is {name, type_name}. Replaces the function's existing parameters — omit or pass an empty array for a no-argument function.")
            List<PrototypeParameterRequest> parameters,
            @Schema(description = "Calling convention name (e.g. __cdecl, __stdcall, __fastcall, __thiscall). Use get_calling_conventions to see valid values for this program.")
            String calling_convention) {
    }

    public record SetParameterTypeRequest(
            @Schema(description = "Program name; see list_project_files.", requiredMode = Schema.RequiredMode.REQUIRED)
            String program,
            @Schema(description = "Function name or hex address", requiredMode = Schema.RequiredMode.REQUIRED)
            String name_or_address,
            @Schema(description = "0-based parameter index", requiredMode = Schema.RequiredMode.REQUIRED)
            Integer parameter_index,
            @Schema(description = "Data type to assign", requiredMode = Schema.RequiredMode.REQUIRED)
            String type_name,
            @Schema(description = "Optional new parameter name (max 256 chars)")
            String new_name) {
    }

    public record CreateStructRequest(
            @Schema(description = "Program name; see list_project_files.", requiredMode = Schema.RequiredMode.REQUIRED)
            String program,
            @Schema(description = "Struct name (max 256 chars)", requiredMode = Schema.RequiredMode.REQUIRED)
            String name,
            @Schema(description = "Initial size in bytes")
            Integer size,
            @Schema(description = "Category path to place the struct in")
            String category,
            @Schema(description = "If true and the struct already exists, clear and resize it in place instead of replacing the data type object")
            Boolean override) {
    }

    public record AddStructFieldRequest(
            @Schema(description = "Program name; see list_project_files.", requiredMode = Schema.RequiredMode.REQUIRED)
            String program,
            @Schema(description = "Struct name to modify", requiredMode = Schema.RequiredMode.REQUIRED)
            String struct_name,
            @Schema(description = "Field name (max 256 chars)", requiredMode = Schema.RequiredMode.REQUIRED)
            String field_name,
            @Schema(description = "Field data type", requiredMode = Schema.RequiredMode.REQUIRED)
            String type_name,
            @Schema(description = "Optional field comment (max 4096 chars)")
            String comment,
            @Schema(description = "Byte offset at which to place the field within an existing struct gap. " +
                    "The offset must point to undefined (unnamed) bytes — it may not overlap any existing named field. " +
                    "The field must fit entirely within the struct: offset + field_size must be <= struct size. " +
                    "Use this to name a gap left by replace_struct_field shrinking a field, " +
                    "e.g. offset=18 places a 1-byte field at offset 0x12 without inflating the struct. " +
                    "Omit this parameter to append the field after the last defined component (may grow the struct).")
            Integer offset) {
    }

    public record RemoveStructFieldRequest(
            @Schema(description = "Program name; see list_project_files.", requiredMode = Schema.RequiredMode.REQUIRED)
            String program,
            @Schema(description = "Struct name", requiredMode = Schema.RequiredMode.REQUIRED)
            String struct_name,
            @Schema(description = "Name of the field to remove (max 256 chars)", requiredMode = Schema.RequiredMode.REQUIRED)
            String field_name) {
    }

        public record ReplaceStructFieldRequest(
            @Schema(description = "Program name; see list_project_files.", requiredMode = Schema.RequiredMode.REQUIRED)
            String program,
            @Schema(description = "Struct name", requiredMode = Schema.RequiredMode.REQUIRED)
            String struct_name,
            @Schema(description = "Field name to replace", requiredMode = Schema.RequiredMode.REQUIRED)
            String field_name,
            @Schema(description = "Replacement field data type", requiredMode = Schema.RequiredMode.REQUIRED)
            String type_name,
            @Schema(description = "Optional replacement field name (max 256 chars)")
            String new_name,
            @Schema(description = "Optional replacement field comment (max 4096 chars)")
            String comment) {
        }

    public record SetCommentRequest(
            @Schema(description = "Program name; see list_project_files.", requiredMode = Schema.RequiredMode.REQUIRED)
            String program,
            @Schema(description = "0x-prefixed hex address, or a function or symbol name (case-sensitive) to comment at its address.", requiredMode = Schema.RequiredMode.REQUIRED)
            String name_or_address,
            @Schema(description = "Comment text (max 4096 chars)", requiredMode = Schema.RequiredMode.REQUIRED)
            String comment,
            @Schema(description = "Comment type: PRE, POST, EOL, PLATE, or REPEATABLE")
            String comment_type) {
    }

    public record RenameFunctionResponse(boolean success, String new_name) {
    }

    public record SetVariableResponse(boolean success, String name, String type_name,
            String kind) {
    }

    public record SetGlobalRequest(
            @Schema(description = "Program name; see list_project_files.", requiredMode = Schema.RequiredMode.REQUIRED)
            String program,
            @Schema(description = "Current name or 0x-prefixed hex address of the global symbol", requiredMode = Schema.RequiredMode.REQUIRED)
            String name_or_address,
            @Schema(description = "New symbol name (max 256 chars); omit to keep the current one.")
            String new_name,
            @Schema(description = "Data type to assign, e.g. int, char *, MyStruct *; omit to keep the current one. Not valid on an external import.")
            String type_name) {
    }

    public record SetGlobalResponse(boolean success, String name, String type_name) {
    }

    public record CreateLabelRequest(
            @Schema(description = "Program name; see list_project_files.", requiredMode = Schema.RequiredMode.REQUIRED)
            String program,
            @Schema(description = "0x-prefixed hex address at which to create the label", requiredMode = Schema.RequiredMode.REQUIRED)
            String address,
            @Schema(description = "Label name (max 256 chars)", requiredMode = Schema.RequiredMode.REQUIRED)
            String name) {
    }

    public record CreateLabelResponse(boolean success, String name, String address) {
    }

    public record SetFunctionPrototypeResponse(boolean success, String function,
            String return_type_name, int parameter_count) {
    }

    public record SetParameterTypeResponse(boolean success, int parameter_index,
            String type_name, String new_name) {
    }

    public record CreateStructResponse(boolean success, String name) {
    }

    public record AddStructFieldResponse(boolean success, String struct,
            String field_name, int ordinal) {
    }

    public record RemoveStructFieldResponse(boolean success, String struct,
            int removed_ordinal) {
    }

    public record ReplaceStructFieldResponse(boolean success, String struct,
            String field_name, int ordinal, String type_name) {
    }

    public record SetCommentResponse(boolean success, Address address, String comment_type) {
    }

    public record ImportBinaryRequest(
            @Schema(description = "Absolute path to the binary file to import, e.g. /home/user/target.exe.",
                    requiredMode = Schema.RequiredMode.REQUIRED)
            String file_path,
            @Schema(description = "Project folder path where the binary will be saved, e.g. \"hello/bin\". " +
                    "Intermediate folders are created automatically. " +
                    "Omit or pass \"/\" to place the binary in the project root. " +
                    "Subject to import.min_directory_depth and import.require_child_path constraints in rules.yaml.")
            String project_dir,
            @Schema(description = "Ghidra language/processor id, e.g. \"ARM:LE:32:Cortex\" or \"x86:LE:64:default\". " +
                    "Omit for any file with a recognisable header (ELF, PE, Mach-O) — the loader detects it. " +
                    "Required for a headerless image, which carries nothing to detect from.")
            String language_id,
            @Schema(description = "0-prefixed hex load address, e.g. \"0x08000000\". Applied before auto-analysis, " +
                    "so recovered addresses and pointers are correct. Omit to load at the format's own base " +
                    "(0x0 for a headerless image).")
            String base_address) {
    }

    public record ImportBinaryResponse(
            @Schema(description = "Program name as registered in the Ghidra project. Use this value as the 'program' parameter in all subsequent tool calls.")
            String program,
            @Schema(description = "Project folder path where the program was saved.")
            String project_dir,
            @Schema(description = "True if import and auto-analysis completed successfully.")
            boolean success,
            @Schema(description = "Error message if import failed (null on success).")
            String error) {
    }

    public record AnalyzeProgramRequest(
            @Schema(description = "Program name; see list_project_files.",
                    requiredMode = Schema.RequiredMode.REQUIRED)
            String program) {
    }

    public record AnalyzeProgramResponse(
            @Schema(description = "True when auto-analysis completed and the program was saved.")
            boolean success,
            @Schema(description = "Program name that was analyzed.")
            String program,
            @Schema(description = "Number of functions discovered after analysis.")
            int function_count) {
    }
}
