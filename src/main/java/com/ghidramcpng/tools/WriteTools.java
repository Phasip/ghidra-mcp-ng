package com.ghidramcpng.tools;

import com.ghidramcpng.program.ProgramManager;
import com.ghidramcpng.rules.RulesEngine;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
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
import java.util.List;

import static com.ghidramcpng.tools.ToolHelpers.findDataType;
import static com.ghidramcpng.tools.ToolHelpers.findFunction;
import static com.ghidramcpng.tools.ToolHelpers.optional;
import static com.ghidramcpng.tools.ToolHelpers.optionalArray;
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

    public WriteTools(ProgramManager mgr, RulesEngine rules) {
        this.mgr = mgr;
        this.rules = rules;
    }

    @POST
    @Path("/rename_function")
    @Operation(operationId = "rename_function", summary = "Rename a function.")
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

        return new RenameFunctionResponse(true, newName);
    }

    @POST
    @Path("/rename_variable")
    @Operation(operationId = "rename_variable", summary = "Rename a local variable or parameter in a function.")
    @ApiResponse(responseCode = "200", description = "Rename variable result",
            content = @Content(schema = @Schema(implementation = RenameVariableResponse.class)))
    public RenameVariableResponse renameVariable(
            @RequestBody(
                    required = true,
                    description = "Rename variable request",
                    content = @Content(schema = @Schema(implementation = RenameVariableRequest.class)))
            JsonObject request) {
        String programName = required(request, "program");
        String funcRef = required(request, "name_or_address");
        String variableName = required(request, "variable_name");
        String newName = requireMaxLength(required(request, "new_name"), "new_name", MAX_NAME_LENGTH);

        rules.validate("variable_name", newName);

        Program program = openProgram(programName);
        runTransaction(program, "Rename variable: " + variableName + " -> " + newName, () -> {
            Function func = findFunction(program, funcRef);
            Variable found = findVariable(func, variableName);
            found.setName(newName, SourceType.USER_DEFINED);
        });

        return new RenameVariableResponse(true, newName);
    }

    @POST
    @Path("/rename_global")
    @Operation(operationId = "rename_global", summary = "Rename a global symbol (data, label, or import) by name or hex address.")
    @ApiResponse(responseCode = "200", description = "Rename global result",
            content = @Content(schema = @Schema(implementation = RenameGlobalResponse.class)))
    public RenameGlobalResponse renameGlobal(
            @RequestBody(
                    required = true,
                    description = "Rename global request",
                    content = @Content(schema = @Schema(implementation = RenameGlobalRequest.class)))
            JsonObject request) {
        String programName = required(request, "program");
        String nameOrAddress = required(request, "name_or_address");
        String newName = requireMaxLength(required(request, "new_name"), "new_name", MAX_NAME_LENGTH);

        rules.validate("function_name", newName);

        Program program = openProgram(programName);
        runTransaction(program, "Rename global: " + nameOrAddress + " -> " + newName, () -> {
            Symbol target = findGlobalSymbol(program, nameOrAddress);
            try {
                target.setName(newName, SourceType.USER_DEFINED);
            } catch (DuplicateNameException e) {
                throw new IllegalArgumentException(
                        "A symbol named '" + newName + "' already exists. Use a unique name.");
            }
        });

        return new RenameGlobalResponse(true, newName);
    }

    @POST
    @Path("/create_label")
    @Operation(operationId = "create_label", summary = "Create a named label at the given address.")
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

        rules.validate("function_name", name);

        Program program = openProgram(programName);
        runTransaction(program, "Create label: " + name + " @ " + address, () -> {
            Address addr = toAddress(program, address);
            try {
                program.getSymbolTable().createLabel(addr, name, SourceType.USER_DEFINED);
            } catch (InvalidInputException e) {
                throw new IllegalArgumentException("Invalid label name '" + name + "': " + e.getMessage());
            }
        });

        return new CreateLabelResponse(true, name, address);
    }

    @POST
    @Path("/set_function_prototype")
    @Operation(operationId = "set_function_prototype", summary = "Set a function's return type, calling convention, and parameter list.")
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
        String returnTypeName = required(request, "return_type");
        JsonArray paramsJson = optionalArray(request, "parameters");
        String callingConvention = optional(request, "calling_convention", null);

        Program program = openProgram(programName);
        List<ParameterImpl> params = new ArrayList<>();
        for (int i = 0; i < paramsJson.size(); i++) {
            if (!paramsJson.get(i).isJsonObject()) {
                throw new IllegalArgumentException(
                        "'parameters[" + i + "]' must be a JSON object with 'name' and 'type' fields, got: " +
                        paramsJson.get(i));
            }
            JsonObject parameter = paramsJson.get(i).getAsJsonObject();
            String paramName = requireMaxLength(requireParameterText(parameter, i, "name"), "name", MAX_NAME_LENGTH);
            String paramType = requireParameterText(parameter, i, "type");
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

        return new SetFunctionPrototypeResponse(true, funcRef, returnTypeName, params.size());
    }

    @POST
    @Path("/set_parameter_type")
    @Operation(operationId = "set_parameter_type", summary = "Set the data type and optionally the name of a specific function parameter by index.")
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
                        "') generated by the calling convention and cannot be modified directly. " +
                        "To retype the 'this' pointer use set_function_prototype with the same " +
                        "calling_convention and include the desired pointer type as the first explicit " +
                        "parameter — Ghidra will derive the auto-parameter from it. " +
                        "Use 'void *' as a placeholder if the struct is not yet defined.");
            }
            param.setDataType(dataType, SourceType.USER_DEFINED);
            if (newName != null) {
                param.setName(newName, SourceType.USER_DEFINED);
            }
        });

        return new SetParameterTypeResponse(true, parameterIndex, typeName, newName);
    }

    @POST
    @Path("/create_struct")
    @Operation(operationId = "create_struct", summary = "Create a new structure data type in the program's Data Type Manager.")
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
        boolean override = request.has("override") && !request.get("override").isJsonNull() &&
                request.get("override").getAsBoolean();

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

        return new CreateStructResponse(true, name);
    }

    @POST
    @Path("/add_struct_field")
    @Operation(operationId = "add_struct_field", summary = "Add a field to an existing structure.")
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
        final int requestedOffset = offsetSpecified ? request.get("offset").getAsInt() : -1;
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

        return new AddStructFieldResponse(true, structName, fieldName, ordinalOut[0]);
    }

    @POST
    @Path("/remove_struct_field")
        @Operation(operationId = "remove_struct_field", summary = "Remove a field from a structure by field name without moving later fields.")
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

        return new RemoveStructFieldResponse(true, structName, removedOrdinal[0]);
    }

    @POST
    @Path("/replace_struct_field")
    @Operation(operationId = "replace_struct_field", summary = "Replace an existing structure field in place without moving later fields.")
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

        return new ReplaceStructFieldResponse(true, structName, resolvedName[0], ordinalOut[0], typeName);
    }

    @POST
    @Path("/set_comment")
    @Operation(operationId = "set_comment", summary = "Set a comment on a code unit at the specified address.")
    @ApiResponse(responseCode = "200", description = "Set comment result",
            content = @Content(schema = @Schema(implementation = SetCommentResponse.class)))
    public SetCommentResponse setComment(
            @RequestBody(
                    required = true,
                    description = "Set comment request",
                    content = @Content(schema = @Schema(implementation = SetCommentRequest.class)))
            JsonObject request) {
        String programName = required(request, "program");
        String address = required(request, "address");
        String comment = requireMaxLength(required(request, "comment"), "comment", MAX_COMMENT_LENGTH);
        String type = optional(request, "type", "PRE");

        CommentType commentType = switch (type.toUpperCase()) {
            case "PRE" -> CommentType.PRE;
            case "POST" -> CommentType.POST;
            case "EOL" -> CommentType.EOL;
            case "PLATE" -> CommentType.PLATE;
            case "REPEATABLE" -> CommentType.REPEATABLE;
            default -> throw new IllegalArgumentException(
                    "Unknown comment type '" + type + "' — must be PRE, POST, EOL, PLATE, or REPEATABLE");
        };

        Program program = openProgram(programName);
        runTransaction(program, "Set comment @ " + address, () -> {
            var addr = toAddress(program, address);
            var cu = program.getListing().getCodeUnitAt(addr);
            if (cu == null) {
                throw new IllegalArgumentException("No code unit at address " + address + ". " +
                        "Ensure the address is within a defined function or data block, and uses the 0x prefix.");
            }
            cu.setComment(commentType, comment.isEmpty() ? null : comment);
        });

        return new SetCommentResponse(true, address, type.toUpperCase());
    }

    @POST
    @Path("/analyze_program")
    @Operation(operationId = "analyze_program",
            summary = "Run Ghidra's full auto-analysis on an already-imported program and block until completion. " +
                    "Use this when a project was imported outside MCP (e.g. via the Ghidra GUI) and analysis was not run, " +
                    "or to re-run analysis after large structural edits. import_binary already analyzes on import — you " +
                    "do not need to call this after a successful import.")
    @ApiResponse(responseCode = "200", description = "Analysis result",
            content = @Content(schema = @Schema(implementation = AnalyzeProgramResponse.class)))
    public AnalyzeProgramResponse analyzeProgram(
            @RequestBody(required = true,
                    content = @Content(schema = @Schema(implementation = AnalyzeProgramRequest.class)))
            com.google.gson.JsonObject request) {
        String programName = required(request, "program");
        Program program = openProgram(programName);
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
    @Operation(operationId = "import_binary", summary = "Import a binary file into the Ghidra project and run full auto-analysis. The returned program name can be used immediately with all other tools.")
    @ApiResponse(responseCode = "200", description = "Import result",
            content = @Content(schema = @Schema(implementation = ImportBinaryResponse.class)))
    public ImportBinaryResponse importBinary(
            @RequestBody(required = true,
                    content = @Content(schema = @Schema(implementation = ImportBinaryRequest.class)))
            com.google.gson.JsonObject request) {
        String filePath = required(request, "file_path");
        String projectDir = optional(request, "project_dir", null);

        rules.validateImport(filePath, projectDir);

        try {
            String programName = mgr.importBinary(filePath, projectDir);
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
                if (sym.getSymbolType() != SymbolType.FUNCTION) {
                    return sym;
                }
            }
            throw new IllegalArgumentException(
                    "No renameable global symbol at address " + nameOrAddress + ". " +
                    "Use list_globals to find valid symbol names and addresses.");
        }
        for (Symbol sym : program.getSymbolTable().getSymbols(nameOrAddress)) {
            if (sym.getSymbolType() != SymbolType.FUNCTION) {
                return sym;
            }
        }
        throw new IllegalArgumentException(
                "Global symbol '" + nameOrAddress + "' not found. " +
                "Names are case-sensitive. Use list_globals to find valid global symbol names, " +
                "or pass a 0x-prefixed hex address.");
    }

    private static Variable findVariable(Function func, String name) {
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
        throw new IllegalArgumentException(
                "Variable '" + name + "' not found in function '" + func.getName() + "'. " +
                "Names are case-sensitive. Use get_function_variables to list all " +
                "parameters and locals with their exact names.");
    }

    public record RenameFunctionRequest(
            @Schema(description = "Program name", requiredMode = Schema.RequiredMode.REQUIRED)
            String program,
            @Schema(description = "Current name or hex address of the function", requiredMode = Schema.RequiredMode.REQUIRED)
            String name_or_address,
            @Schema(description = "New function name (max 256 chars)", requiredMode = Schema.RequiredMode.REQUIRED)
            String new_name) {
    }

    public record RenameVariableRequest(
            @Schema(description = "Program name", requiredMode = Schema.RequiredMode.REQUIRED)
            String program,
            @Schema(description = "Function containing the variable", requiredMode = Schema.RequiredMode.REQUIRED)
            String name_or_address,
            @Schema(description = "Current variable or parameter name", requiredMode = Schema.RequiredMode.REQUIRED)
            String variable_name,
            @Schema(description = "New variable name (max 256 chars)", requiredMode = Schema.RequiredMode.REQUIRED)
            String new_name) {
    }

    public record PrototypeParameterRequest(
            @Schema(description = "Parameter name (max 256 chars)", requiredMode = Schema.RequiredMode.REQUIRED)
            String name,
            @Schema(description = "Parameter type", requiredMode = Schema.RequiredMode.REQUIRED)
            String type) {
    }

    public record SetFunctionPrototypeRequest(
            @Schema(description = "Program name", requiredMode = Schema.RequiredMode.REQUIRED)
            String program,
            @Schema(description = "Function name or hex address", requiredMode = Schema.RequiredMode.REQUIRED)
            String name_or_address,
            @Schema(description = "Return type name", requiredMode = Schema.RequiredMode.REQUIRED)
            String return_type,
            @Schema(description = "Parameter descriptors")
            List<PrototypeParameterRequest> parameters,
            @Schema(description = "Calling convention name (e.g. __cdecl, __stdcall, __fastcall, __thiscall). Use get_calling_conventions to see valid values for this program.")
            String calling_convention) {
    }

    public record SetParameterTypeRequest(
            @Schema(description = "Program name", requiredMode = Schema.RequiredMode.REQUIRED)
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
            @Schema(description = "Program name", requiredMode = Schema.RequiredMode.REQUIRED)
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
            @Schema(description = "Program name", requiredMode = Schema.RequiredMode.REQUIRED)
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
            @Schema(description = "Program name", requiredMode = Schema.RequiredMode.REQUIRED)
            String program,
            @Schema(description = "Struct name", requiredMode = Schema.RequiredMode.REQUIRED)
            String struct_name,
            @Schema(description = "Name of the field to remove (max 256 chars)", requiredMode = Schema.RequiredMode.REQUIRED)
            String field_name) {
    }

        public record ReplaceStructFieldRequest(
            @Schema(description = "Program name", requiredMode = Schema.RequiredMode.REQUIRED)
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
            @Schema(description = "Program name", requiredMode = Schema.RequiredMode.REQUIRED)
            String program,
            @Schema(description = "Hex address", requiredMode = Schema.RequiredMode.REQUIRED)
            String address,
            @Schema(description = "Comment text (max 4096 chars)", requiredMode = Schema.RequiredMode.REQUIRED)
            String comment,
            @Schema(description = "Comment type: PRE, POST, EOL, PLATE, or REPEATABLE")
            String type) {
    }

    public record RenameFunctionResponse(boolean success, String new_name) {
    }

    public record RenameVariableResponse(boolean success, String new_name) {
    }

    public record RenameGlobalRequest(
            @Schema(description = "Program name", requiredMode = Schema.RequiredMode.REQUIRED)
            String program,
            @Schema(description = "Current name or 0x-prefixed hex address of the global symbol", requiredMode = Schema.RequiredMode.REQUIRED)
            String name_or_address,
            @Schema(description = "New symbol name (max 256 chars)", requiredMode = Schema.RequiredMode.REQUIRED)
            String new_name) {
    }

    public record RenameGlobalResponse(boolean success, String new_name) {
    }

    public record CreateLabelRequest(
            @Schema(description = "Program name", requiredMode = Schema.RequiredMode.REQUIRED)
            String program,
            @Schema(description = "0x-prefixed hex address at which to create the label", requiredMode = Schema.RequiredMode.REQUIRED)
            String address,
            @Schema(description = "Label name (max 256 chars)", requiredMode = Schema.RequiredMode.REQUIRED)
            String name) {
    }

    public record CreateLabelResponse(boolean success, String name, String address) {
    }

    public record SetFunctionPrototypeResponse(boolean success, String function,
            String return_type, int parameter_count) {
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

    public record SetCommentResponse(boolean success, String address, String type) {
    }

    public record ImportBinaryRequest(
            @Schema(description = "Absolute path to the binary file to import, e.g. /home/user/target.exe.",
                    requiredMode = Schema.RequiredMode.REQUIRED)
            String file_path,
            @Schema(description = "Project folder path where the binary will be saved, e.g. \"hello/bin\". " +
                    "Intermediate folders are created automatically. " +
                    "Omit or pass \"/\" to place the binary in the project root. " +
                    "Subject to import.min_directory_depth and import.require_child_path constraints in rules.yaml.")
            String project_dir) {
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
            @Schema(description = "Program name as listed by list_project_files.",
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
