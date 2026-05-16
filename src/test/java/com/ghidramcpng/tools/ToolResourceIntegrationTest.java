package com.ghidramcpng.tools;

import ghidra.program.model.address.Address;
import com.ghidramcpng.model.FunctionEntry;
import com.ghidramcpng.model.FunctionRef;
import com.ghidramcpng.model.StringEntry;
import com.ghidramcpng.model.StructField;
import com.ghidramcpng.model.VariableEntry;
import com.ghidramcpng.program.ProgramManager;
import com.ghidramcpng.rules.RulesEngine;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.GhidraApplicationLayout;
import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import generic.jar.ResourceFile;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ToolResourceIntegrationTest {

    // Known function names in the test fixture (tests/fixture/test_target.c)
    private static final String FN_ADD     = "add";
    private static final String FN_MULTIPLY = "multiply";
    private static final String FN_COMPUTE = "compute";
    private static final String FN_MAIN    = "main";
    private static final String TEST_SENTINEL = "GHIDRA_MCP_TEST_SENTINEL";

    private static Path compiledFixtureBinary;
    /** A second minimal binary, distinct from the one pre-loaded in @BeforeEach, used by importBinary tests. */
    private static Path secondFixtureBinary;
    /** The project's ghidra_scripts/ directory, registered as a system bundle in @BeforeAll. */
    private static Path extensionScriptsDir;

    private GhidraProject ghidraProject;
    private Program importedProgram;
    private ProgramManager programManager;
    private ReadTools readTools;
    private WriteTools writeTools;
    private ScriptTool scriptTool;
    private String programName;

    @BeforeAll
    static void initializeApplication() throws Exception {
        if (!Application.isInitialized()) {
            String ghidraHome = System.getenv("GHIDRA_HOME");
            if (ghidraHome == null || ghidraHome.isBlank()) {
                throw new IllegalStateException(
                        "GHIDRA_HOME must be set for Java integration tests");
            }

            HeadlessGhidraApplicationConfiguration config =
                    new HeadlessGhidraApplicationConfiguration();
            config.setInitializeLogging(false);
            Application.initializeApplication(
                    new GhidraApplicationLayout(new File(ghidraHome)),
                    config);
        }

        // Register the project's ghidra_scripts/ as a SYSTEM bundle so scripts there
        // can access feature-specific Ghidra modules (e.g. ghidra.feature.fid.*).
        // In production this happens automatically when the extension is installed;
        // in headless tests we must do it explicitly because the project root is not
        // a recognised Ghidra module root.
        //
        // We intentionally do NOT call releaseBundleHostReference() here — we hold the
        // reference open for the entire test class lifecycle so the registration survives
        // across all test methods.  @AfterAll tearDownApplication() releases it.
        GhidraScriptUtil.acquireBundleHostReference();
        extensionScriptsDir = Path.of(System.getProperty("user.dir"), "ghidra_scripts");
        if (Files.isDirectory(extensionScriptsDir)) {
            BundleHost bundleHost = GhidraScriptUtil.getBundleHost();
            bundleHost.add(new ResourceFile(extensionScriptsDir.toFile()), true, true);
        }

        compiledFixtureBinary = compileFixtureBinary();
        secondFixtureBinary = compileMinimalBinary();
    }

    @BeforeEach
    void setUp() throws Exception {
        Path projectDir = Files.createTempDirectory("ghidra-mcp-ng-project");
        ghidraProject = GhidraProject.createProject(
                projectDir.toString(),
                "ghidra_mcp_ng_" + UUID.randomUUID(),
                true);

        importedProgram = ghidraProject.importProgram(compiledFixtureBinary.toFile());
        ghidraProject.analyze(importedProgram);
        ghidraProject.saveAs(importedProgram, "/", importedProgram.getName(), true);
        programName = importedProgram.getDomainFile().getName();
        ghidraProject.close(importedProgram);
        importedProgram = null;

        programManager = new ProgramManager(ghidraProject);
        readTools = new ReadTools(programManager, 60);
        writeTools = new WriteTools(programManager, RulesEngine.load((File) null));
        scriptTool = new ScriptTool(programManager, extensionScriptsDir);
    }

    @org.junit.jupiter.api.AfterAll
    static void tearDownApplication() {
        // Release the BundleHost reference held since @BeforeAll.
        // We hold it open for the whole test class so that the ghidra_scripts/
        // system-bundle registration survives across all test methods.
        GhidraScriptUtil.releaseBundleHostReference();
    }

    @AfterEach
    void tearDown() {
        if (programManager != null) {
            programManager.closeAll();
        }
        if (ghidraProject != null) {
            ghidraProject.close();
        }
    }

    // -------------------------------------------------------------------------
    // ReadTools – 25 routes
    // -------------------------------------------------------------------------

    @Test
    void checkConnection_returnsOk() {
        ReadTools.CheckConnectionResponse connection = readTools.checkConnection();
        assertEquals("ok", connection.status());
        assertNotNull(connection.version(), "version must not be null");
        assertFalse(connection.version().isBlank(), "version must not be blank");
    }

    @Test
    void listProjectFiles_containsImportedProgram() {
        ReadTools.ListProjectFilesResponse projectFiles = readTools.listProjectFiles();
        assertTrue(anyEndsWith(projectFiles.files(), programName));
    }

    @Test
    void invalidProgram_errorListsOptionsWhenFew() {
        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> readTools.searchFunctions("__no_such_program__", "", 1));
        String msg = ex.getMessage().toLowerCase();
        // With only one program in the test project, the error should name it.
        assertTrue(msg.contains("invalid program"), "Expected 'invalid program' in: " + ex.getMessage());
        assertTrue(msg.contains("valid options") || msg.contains("list_project_files"),
                "Expected either valid options or list_project_files hint in: " + ex.getMessage());
    }

    @Test
    void searchFunctions_emptyQueryListsAllFunctions() {
        ReadTools.SearchFunctionsResponse all = readTools.searchFunctions(programName, "", 500);
        Set<String> names = functionNamesFromRefs(all.functions());
        assertTrue(names.contains(FN_ADD));
        assertTrue(names.contains(FN_MULTIPLY));
        assertTrue(names.contains(FN_COMPUTE));
        assertTrue(names.contains(FN_MAIN));

        // substring search still works
        ReadTools.SearchFunctionsResponse filtered = readTools.searchFunctions(programName, FN_ADD, 10);
        assertTrue(functionNamesFromRefs(filtered.functions()).contains(FN_ADD));
    }

    @Test
    void getFunctionInfo_returnsFullDetails() {
        FunctionEntry compute = readTools.getFunctionInfo(programName, FN_COMPUTE);
        assertNotNull(compute);
        assertEquals(FN_COMPUTE, compute.name());
        assertNotNull(compute.signature());
        assertNotNull(compute.calling_convention());
        assertNotNull(compute.address());

        // also works by address
        Address addAddress = functionAddress(readTools.searchFunctions(programName, "", 200).functions(), FN_ADD);
        FunctionEntry addByAddr = readTools.getFunctionInfo(programName, withHexPrefix(addAddress));
        assertEquals(FN_ADD, addByAddr.name());

        // non-prefixed hex address must be rejected for address parsing
        assertThrows(IllegalArgumentException.class,
                () -> readTools.getFunctionInfo(programName, addAddress.toString()));

        // unknown name must be rejected
        assertThrows(IllegalArgumentException.class,
                () -> readTools.getFunctionInfo(programName, "__no_such_fn__"));
    }

    @Test
    void getAddressInfo_addressInsideFunction_returnsFunctionAndSegment() {
        Address addAddress = functionAddress(readTools.searchFunctions(programName, "", 200).functions(), FN_ADD);
        ReadTools.GetAddressInfoResponse info = readTools.getAddressInfo(programName, withHexPrefix(addAddress));
        assertNotNull(info.function(), "Entry point of add() must be inside a function body");
        assertEquals(FN_ADD, info.function().name());
        assertEquals(addAddress, info.function().address());
        assertNotNull(info.segment(), "Entry point of add() must be in a mapped segment");
        assertNotNull(info.segment().name());
    }

    @Test
    void getAddressInfo_returnsXrefsToAddress() {
        Address addAddress = functionAddress(readTools.searchFunctions(programName, "", 200).functions(), FN_ADD);
        ReadTools.GetAddressInfoResponse info = readTools.getAddressInfo(programName, withHexPrefix(addAddress));
        assertTrue(info.xref_count() > 0, "add() must have at least one xref to its entry point");
        assertEquals(info.xrefs().size(), info.xref_count());
    }

    @Test
    void getAddressInfo_requiresHexPrefix() {
        Address addAddress = functionAddress(readTools.searchFunctions(programName, "", 200).functions(), FN_ADD);
        assertThrows(IllegalArgumentException.class,
                () -> readTools.getAddressInfo(programName, addAddress.toString()));
    }

    @Test
    void getXrefsTo_byFunctionName_returnsXrefs() {
        // get_xrefs_to accepts any symbol name — functions, globals, labels, etc.
        ReadTools.XrefsResponse xrefs = readTools.getXrefsTo(programName, FN_ADD);
        assertNotNull(xrefs.xrefs());
        assertTrue(xrefs.count() > 0, "add() must have at least one xref when looked up by name");
        assertEquals(xrefs.xrefs().size(), xrefs.count());
    }

    @Test
    void getXrefsTo_unknownSymbol_throwsIllegalArgument() {
        // An unrecognised name (no 0x prefix, not a known symbol) must throw.
        assertThrows(IllegalArgumentException.class,
                () -> readTools.getXrefsTo(programName, "__no_such_symbol_xyz__"));
    }

    @Test
    void getXrefsTo_ambiguousSymbolName_throwsWithAddressListing() throws Exception {
        // Create two labels with the same name at different addresses, then verify that
        // looking up that name throws an error listing both addresses and their types.
        List<FunctionRef> functions = readTools.searchFunctions(programName, "", 200).functions();
        assertTrue(functions.size() >= 2, "Fixture must have at least two functions for this test");
        Address addr1 = functions.get(0).address();
        Address addr2 = functions.get(1).address();
        String dupName = "__ambig_label_test__";

        Program program = programManager.getOrOpen(programName);
        programManager.withTransaction(program, "create duplicate labels for ambiguity test", () -> {
            program.getSymbolTable().createLabel(addr1, dupName, SourceType.USER_DEFINED);
            program.getSymbolTable().createLabel(addr2, dupName, SourceType.USER_DEFINED);
        });

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> readTools.getXrefsTo(programName, dupName));
        String msg = ex.getMessage();
        assertTrue(msg.contains("Ambiguous"), "Error must mention 'Ambiguous': " + msg);
        assertTrue(msg.contains("0x"), "Error must list at least one hex address: " + msg);
    }

    @Test
    void decompileFunction_requiresHexPrefixForAddressArgument() {
        Address addAddress = functionAddress(readTools.searchFunctions(programName, "", 200).functions(), FN_ADD);
        assertThrows(IllegalArgumentException.class,
                () -> readTools.decompileFunction(programName, addAddress.toString()));
    }

    @Test
    void setComment_requiresHexPrefix() {
        Address addAddress = functionAddress(readTools.searchFunctions(programName, "", 200).functions(), FN_ADD);
        assertThrows(IllegalArgumentException.class,
                () -> writeTools.setComment(json(
                        "program", programName,
                        "address", addAddress.toString(),
                        "comment", "test",
                        "type", "PRE")));
    }

    @Test
    void listExports_countMatchesListSize() {
        ReadTools.ListExportsResponse exports = readTools.listExports(programName);
        assertNotNull(exports.exports());
        assertEquals(exports.exports().size(), exports.count());
    }

    @Test
    void listImports_hasAtLeastOneEntry() {
        ReadTools.ListImportsResponse imports = readTools.listImports(programName);
        assertNotNull(imports.imports());
        assertTrue(imports.count() > 0);
        assertEquals(imports.imports().size(), imports.count(), "count must match list size");
    }

    @Test
    void searchDataTypes_emptyQueryListsAllDataTypes() {
        ReadTools.SearchDataTypesResponse dataTypes = readTools.searchDataTypes(programName, "", 200);
        assertTrue(dataTypes.count() > 0);
    }

    @Test
    void listDataTypeCategories_includesRootCategory() {
        ReadTools.ListDataTypeCategoriesResponse categories =
                readTools.listDataTypeCategories(programName);
        assertTrue(stringValues(categories.categories()).contains("/"));
    }

    @Test
    void getCallingConventions_returnsNonEmptyList() {
        ReadTools.GetCallingConventionsResponse result =
                readTools.getCallingConventions(programName);
        assertNotNull(result.calling_conventions());
        assertFalse(result.calling_conventions().isEmpty());
        assertNotNull(result.default_convention());
    }

    @Test
    void getFunctionVariables_returnsVariablesForAdd() {
        ReadTools.GetFunctionVariablesResponse variables =
                readTools.getFunctionVariables(programName, FN_ADD);
        assertEquals(FN_ADD, variables.function());
        assertNotNull(variables.variables());
        assertFalse(variables.variables().isEmpty(), "add() must have at least one parameter");
    }

    @Test
    void getFunctionVariables_unknownFunction_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class,
                () -> readTools.getFunctionVariables(programName, "__no_such_fn__"));
    }

    @Test
    void decompileFunction_returnsDecompiledCode() {
        ReadTools.DecompileFunctionResponse decompiledAdd =
                readTools.decompileFunction(programName, FN_ADD);
        assertEquals(FN_ADD, decompiledAdd.name());
        assertNotNull(decompiledAdd.address());
        assertNotNull(decompiledAdd.decompiled());
        assertTrue(decompiledAdd.decompiled().length() > 10);
        assertTrue(decompiledAdd.decompiled().contains("return"),
                "Decompiled output of 'add' must contain a return statement");

        // unknown function must be rejected
        assertThrows(IllegalArgumentException.class,
                () -> readTools.decompileFunction(programName, "__no_such_fn__"));
    }

    @Test
    void searchFunctions_findsByName() {
        ReadTools.SearchFunctionsResponse result =
                readTools.searchFunctions(programName, FN_ADD, 10);
        assertTrue(functionNamesFromRefs(result.functions()).contains(FN_ADD));
    }

    @Test
    void searchFunctions_isCaseInsensitiveForExactAndPrefix() {
        ReadTools.SearchFunctionsResponse byExactUpper =
                readTools.searchFunctions(programName, FN_ADD.toUpperCase(), 10);
        assertTrue(functionNamesFromRefs(byExactUpper.functions()).contains(FN_ADD));

        ReadTools.SearchFunctionsResponse byPrefixMixed =
                readTools.searchFunctions(programName, FN_ADD.substring(0, 2).toUpperCase(), 10);
        assertTrue(functionNamesFromRefs(byPrefixMixed.functions()).contains(FN_ADD));
    }

    @Test
    void importBinary_importsAndAnalyzesFile() throws Exception {
        // Happy path: import a valid binary not yet in the project
        WriteTools.ImportBinaryResponse response = writeTools.importBinary(
                json("file_path", secondFixtureBinary.toString()));
        assertTrue(response.success());
        assertNotNull(response.program(), "Imported program must have a name");
        assertFalse(response.program().isBlank(), "Imported program name must not be blank");

        // The newly imported program must appear in the project file list
        ReadTools.ListProjectFilesResponse files = readTools.listProjectFiles();
        assertTrue(anyEndsWith(files.files(), response.program()),
                "Imported program must appear in list_project_files");

        // Error path: non-existent file must be rejected with a clear message
        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> writeTools.importBinary(json("file_path", "/no/such/file.exe")));
        assertTrue(ex.getMessage().contains("File not found"));
    }

    @Test
    void searchDataTypes_findsByQuery() {
        ReadTools.SearchDataTypesResponse result =
                readTools.searchDataTypes(programName, "int", 20);
        assertTrue(result.count() > 0);
    }

    @Test
    void searchDefinedStrings_returnsValidEntries() {
        ReadTools.SearchDefinedStringsResponse result =
                readTools.searchDefinedStrings(programName, "sentinel", 0, 20);
        assertNotNull(result.strings());
        assertEquals(result.strings().size(), result.count(), "count must match list size");
        // Any returned entries must have non-blank values
        assertTrue(allStringEntriesHaveValues(result.strings()),
                "All returned string entries must have non-blank values");
    }

    @Test
    void searchMemoryStrings_findsSentinelString() throws Exception {
        ScriptTool.RunScriptResponse result = scriptTool.runScript(json(
                "program", programName,
                "filename", "SearchMemoryStrings.java",
                "args", array(TEST_SENTINEL, "0", "20", "4", "true")));
        assertTrue(result.success(), "Script must execute without error");
        JsonObject output = parseJsonOutput(result.output());
        assertTrue(output.has("strings"), "Output must have 'strings' array");
        assertTrue(output.has("count"), "Output must have 'count'");
        int count = output.get("count").getAsInt();
        assertTrue(count > 0, "Must find at least one string matching the sentinel");
        boolean found = false;
        for (var el : output.getAsJsonArray("strings")) {
            if (el.getAsJsonObject().get("value").getAsString().contains(TEST_SENTINEL)) {
                found = true;
                break;
            }
        }
        assertTrue(found, "At least one result must contain the sentinel value");
    }

    @Test
    void getStructLayout_returnsCreatedStruct() {
        writeTools.createStruct(json(
                "program", programName,
                "name", "LayoutTestStruct",
                "size", 8,
                "category", "/mcp"));
        writeTools.addStructField(json(
                "program", programName,
                "struct_name", "LayoutTestStruct",
                "field_name", "first_field",
                "type_name", "int",
                "comment", "first"));
        writeTools.addStructField(json(
                "program", programName,
                "struct_name", "LayoutTestStruct",
                "field_name", "second_field",
                "type_name", "int",
                "comment", "second"));

        ReadTools.GetStructLayoutResponse layout =
                readTools.getStructLayout(programName, "LayoutTestStruct");
        assertEquals("LayoutTestStruct", layout.name());
        assertTrue(structFieldNames(layout.fields()).contains("first_field"));
        StructField first = requireStructField(layout.fields(), "first_field");
        StructField second = requireStructField(layout.fields(), "second_field");
        assertEquals(0, first.offset());
        assertEquals(4, second.offset());
    }

    @Test
    void getXrefsTo_returnsXrefsWithMatchingCount() {
        Address addAddress = functionAddress(
                readTools.searchFunctions(programName, "", 200).functions(), FN_ADD);
        ReadTools.XrefsResponse xrefs =
                readTools.getXrefsTo(programName, withHexPrefix(addAddress));
        assertNotNull(xrefs.xrefs());
        assertEquals(xrefs.xrefs().size(), xrefs.count());
        // add() is called by compute() and multiply() in the fixture
        assertTrue(xrefs.count() > 0, "add() must have at least one caller xref in the fixture");
    }

    @Test
    void getXrefsFrom_returnsXrefsWithMatchingCount() {
        Address computeAddress = functionAddress(
                readTools.searchFunctions(programName, "", 200).functions(), FN_COMPUTE);
        ReadTools.XrefsResponse xrefs =
                readTools.getXrefsFrom(programName, withHexPrefix(computeAddress));
        assertNotNull(xrefs.xrefs());
        assertEquals(xrefs.xrefs().size(), xrefs.count(),
                "count must equal list size — getXrefsFrom returns refs from a single instruction");
    }

    @Test
    void getXrefsTo_includesDataRefFromFunctionPointer() {
        // call_via_ptr stores add's address in a function-pointer local; Ghidra records a DATA xref.
        // Also verifies that get_xrefs_to works with a function name rather than a hex address.
        ReadTools.XrefsResponse xrefs = readTools.getXrefsTo(programName, FN_ADD);
        assertNotNull(xrefs.xrefs());
        boolean hasCall = xrefs.xrefs().stream().anyMatch(x -> x.ref_type().contains("CALL"));
        assertTrue(hasCall, "add() must have at least one CALL reference; got: " + xrefs.xrefs());
        boolean hasData = xrefs.xrefs().stream()
                .anyMatch(x -> x.ref_type().toUpperCase().contains("DATA"));
        assertTrue(hasData, "add() must have a DATA reference from call_via_ptr; got: " + xrefs.xrefs());
    }

    @Test
    void searchConstantReferences_returnsHitsForKnownConstant() {
        // constant 3 appears in main(): int b = 3; — guaranteed to be an immediate in the binary
        ReadTools.SearchConstantReferencesResponse result =
                readTools.searchConstantReferences(programName, "3", 200);
        assertNotNull(result.hits());
        assertEquals(result.hits().size(), result.count(), "count must match list size");
        assertTrue(result.count() > 0, "constant 3 must appear at least once in the fixture binary");
        for (ReadTools.ConstantHit hit : result.hits()) {
            assertNotNull(hit.address());
            assertNotNull(hit.mnemonic());
        }
    }

    @Test
    void searchConstantReferences_hexAndDecimalGiveSameResults() {
        ReadTools.SearchConstantReferencesResponse decimal =
                readTools.searchConstantReferences(programName, "3", 200);
        ReadTools.SearchConstantReferencesResponse hex =
                readTools.searchConstantReferences(programName, "0x3", 200);
        assertEquals(decimal.count(), hex.count(),
                "hex and decimal representations of the same value must yield identical results");
    }

    @Test
    void searchConstantReferences_invalidValue_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class,
                () -> readTools.searchConstantReferences(programName, "not-a-number", 200));
    }

    @Test
    void searchConstantReferences_negativeValue_treatedAsUnsigned() {
        // -1 as a Java long has the bit pattern 0xFFFFFFFFFFFFFFFF.
        // No instruction in the fixture stores that exact 64-bit scalar, so expect 0 hits.
        // This verifies the code path does not throw and handles negative values gracefully.
        ReadTools.SearchConstantReferencesResponse result =
                readTools.searchConstantReferences(programName, "-1", 200);
        assertNotNull(result);
        assertEquals(0, result.count(), "No instruction in the fixture should use 0xFFFFFFFFFFFFFFFF");
    }

    @Test
    void searchConstantReferences_negativeLongMatchesMOVABSImmediate() {
        String signedDecimal = "-2401053088876216593"; //0xDEADBEEFDEADBEEFL
        ReadTools.SearchConstantReferencesResponse result =
                readTools.searchConstantReferences(programName, signedDecimal, 200);
        assertNotNull(result);
        assertTrue(result.count() > 0,
                "check_64bit_magic uses 0xDEADBEEFDEADBEEF as a 64-bit immediate; " +
                "searching by its signed decimal form must find it via getUnsignedValue() == targetValue");
    }

    @Test
    void getFunctionCallees_returnsCalleesForCompute() {
        ReadTools.FunctionCalleesResponse callees =
                readTools.getFunctionCallees(programName, FN_COMPUTE);
        assertNotNull(callees.callees());
        assertEquals(callees.callees().size(), callees.count(), "count must match list size");
        assertTrue(callees.count() > 0, "compute() must call at least one function in the fixture");
        Set<String> calleeNames = functionNamesFromRefs(callees.callees());
        assertTrue(calleeNames.contains(FN_ADD) || calleeNames.contains(FN_MULTIPLY),
                "compute() must call add or multiply; got: " + calleeNames);
    }

    @Test
    void getFunctionCallees_add_hasNoCallees() {
        // add() is pure arithmetic — it calls no other functions
        ReadTools.FunctionCalleesResponse callees =
                readTools.getFunctionCallees(programName, FN_ADD);
        assertNotNull(callees.callees());
        assertEquals(0, callees.count(), "add() must have no callees in the fixture");
        assertEquals(callees.callees().size(), callees.count(), "count must match list size");
    }

    // -------------------------------------------------------------------------
    // WriteTools – 9 routes
    // -------------------------------------------------------------------------

    @Test
    void renameFunction_changesName() {
        WriteTools.RenameFunctionResponse response = writeTools.renameFunction(json(
                "program", programName,
                "name_or_address", FN_MULTIPLY,
                "new_name", "multiply_renamed"));
        assertTrue(response.success());

        ReadTools.SearchFunctionsResponse search =
                readTools.searchFunctions(programName, "multiply_renamed", 10);
        assertTrue(functionNamesFromRefs(search.functions()).contains("multiply_renamed"));

        // blank new_name must be rejected
        assertThrows(IllegalArgumentException.class,
                () -> writeTools.renameFunction(json(
                        "program", programName,
                        "name_or_address", FN_ADD,
                        "new_name", "   ")));
    }

    @Test
    void renameVariable_changesVariableName() {
        ReadTools.GetFunctionVariablesResponse before =
                readTools.getFunctionVariables(programName, FN_ADD);
        assertFalse(before.variables().isEmpty(), "add() must have at least one variable to rename");
        String originalName = before.variables().get(0).name();
        assertNotNull(originalName, "Variable must have a name before renaming");

        WriteTools.RenameVariableResponse response = writeTools.renameVariable(json(
                "program", programName,
                "name_or_address", FN_ADD,
                "variable_name", originalName,
                "new_name", "renamed_add_variable"));
        assertTrue(response.success());

        ReadTools.GetFunctionVariablesResponse after =
                readTools.getFunctionVariables(programName, FN_ADD);
        assertTrue(variableNames(after.variables()).contains("renamed_add_variable"));
    }

    @Test
    void renameVariable_unknownFunction_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class,
                () -> writeTools.renameVariable(json(
                        "program", programName,
                        "name_or_address", "__no_such_fn__",
                        "variable_name", "x",
                        "new_name", "y")));
    }

    @Test
    void setFunctionPrototype_updatesSignatureAndRejectsInvalidParams() {
        WriteTools.SetFunctionPrototypeResponse response = writeTools.setFunctionPrototype(json(
                "program", programName,
                "name_or_address", FN_COMPUTE,
                "return_type", "int",
                "parameters", parameterArray(
                        parameter("x", "int"),
                        parameter("y", "int"),
                        parameter("mode", "int"))));
        assertTrue(response.success());
        assertEquals(3, response.parameter_count());

        // Verify the names were actually applied
        Set<String> varNames = variableNames(
                readTools.getFunctionVariables(programName, FN_COMPUTE).variables());
        assertTrue(varNames.contains("x") || varNames.contains("y") || varNames.contains("mode"),
                "Parameter names must be reflected in function variables after setFunctionPrototype");

        // validation: missing type in parameter
        IllegalArgumentException missingType = assertThrows(
                IllegalArgumentException.class,
                () -> writeTools.setFunctionPrototype(json(
                        "program", programName,
                        "name_or_address", FN_COMPUTE,
                        "return_type", "int",
                        "parameters", parameterArray(json("name", "x")))));
        assertTrue(missingType.getMessage().contains("parameters[0].type"));

        // validation: blank name in parameter
        IllegalArgumentException blankName = assertThrows(
                IllegalArgumentException.class,
                () -> writeTools.setFunctionPrototype(json(
                        "program", programName,
                        "name_or_address", FN_COMPUTE,
                        "return_type", "int",
                        "parameters", parameterArray(json("name", "   ", "type", "int")))));
        assertTrue(blankName.getMessage().contains("parameters[0].name"));
    }

    @Test
    void setParameterType_updatesParameterAndRejectsInternalTypes() {
        // Ensure compute has parameters first
        writeTools.setFunctionPrototype(json(
                "program", programName,
                "name_or_address", FN_COMPUTE,
                "return_type", "int",
                "parameters", parameterArray(
                        parameter("x", "int"),
                        parameter("y", "int"),
                        parameter("mode", "int"))));

        WriteTools.SetParameterTypeResponse response = writeTools.setParameterType(json(
                "program", programName,
                "name_or_address", FN_COMPUTE,
                "parameter_index", 0,
                "type_name", "int",
                "new_name", "lhs"));
        assertTrue(response.success());

        ReadTools.GetFunctionVariablesResponse variables =
                readTools.getFunctionVariables(programName, FN_COMPUTE);
        assertTrue(variableNames(variables.variables()).contains("lhs"));

        // validation: internal Ghidra type must be rejected
        IllegalArgumentException codePointerError = assertThrows(
                IllegalArgumentException.class,
                () -> writeTools.setParameterType(json(
                        "program", programName,
                        "name_or_address", FN_COMPUTE,
                        "parameter_index", 0,
                        "type_name", "code*")));
        assertTrue(codePointerError.getMessage().contains("Ghidra internal generated type"));
        assertTrue(codePointerError.getMessage().contains("void*"));
    }

    @Test
    void setParameterType_outOfBoundsIndex_throwsIllegalArgument() {
        // Ensure compute has 3 parameters so index=99 is definitely out of range
        writeTools.setFunctionPrototype(json(
                "program", programName,
                "name_or_address", FN_COMPUTE,
                "return_type", "int",
                "parameters", parameterArray(
                        parameter("x", "int"),
                        parameter("y", "int"),
                        parameter("mode", "int"))));

        assertThrows(IllegalArgumentException.class,
                () -> writeTools.setParameterType(json(
                        "program", programName,
                        "name_or_address", FN_COMPUTE,
                        "parameter_index", 99,
                        "type_name", "int")));
    }

    @Test
    void setParameterType_zeroIndexOnFunctionWithNoParams_givesHelpfulError() {
        // Edge-case: calling set_parameter_type on a function that has no formal parameters
        // (not the auto-param scenario, but ensures the out-of-range path gives the
        // "use set_function_prototype first" hint rather than a bare index error).
        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> writeTools.setParameterType(json(
                        "program", programName,
                        "name_or_address", FN_ADD,
                        "parameter_index", 0,
                        "type_name", "int")));
        String msg = ex.getMessage();
        // The error should either be "out of range" (if add has params) or mention
        // set_function_prototype (if add has no formal params after analysis).
        assertTrue(msg.contains("parameter") || msg.contains("out of range"),
                "Error should relate to parameter: " + msg);
    }

    @Test
    void createStruct_createsEmptyStructAndSupportsOverride() {
        WriteTools.CreateStructResponse create = writeTools.createStruct(json(
                "program", programName,
                "name", "CreateStructTest",
                "size", 8,
                "category", "/mcp"));
        assertTrue(create.success());

        // override replaces the struct entirely
        WriteTools.CreateStructResponse override = writeTools.createStruct(json(
                "program", programName,
                "name", "CreateStructTest",
                "size", 16,
                "override", true));
        assertTrue(override.success());

        ReadTools.GetStructLayoutResponse layout =
                readTools.getStructLayout(programName, "CreateStructTest");
        assertTrue(layout.fields().isEmpty());
        assertEquals(16, layout.size());

        // non-existent struct must be rejected
        assertThrows(IllegalArgumentException.class,
                () -> readTools.getStructLayout(programName, "__no_such_struct__"));
    }

    @Test
    void createStruct_duplicate_withoutOverride_throwsIllegalArgument() {
        writeTools.createStruct(json(
                "program", programName,
                "name", "DuplicateStructTest",
                "size", 8,
                "category", "/mcp"));

        // creating same struct without override=true must be rejected with a clear message
        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> writeTools.createStruct(json(
                        "program", programName,
                        "name", "DuplicateStructTest",
                        "size", 16)));
        assertTrue(ex.getMessage().contains("already exists"),
                "Error must mention 'already exists': " + ex.getMessage());
        assertTrue(ex.getMessage().contains("override"),
                "Error must mention 'override=true': " + ex.getMessage());
    }

    @Test
    void addStructField_appendsFieldToStruct() {
        writeTools.createStruct(json(
                "program", programName,
                "name", "AddFieldTestStruct",
                "size", 8,
                "category", "/mcp"));

        WriteTools.AddStructFieldResponse response = writeTools.addStructField(json(
                "program", programName,
                "struct_name", "AddFieldTestStruct",
                "field_name", "size_field",
                "type_name", "int",
                "comment", "Field added by Java integration test"));
        assertTrue(response.success());

        ReadTools.GetStructLayoutResponse layout =
                readTools.getStructLayout(programName, "AddFieldTestStruct");
        assertTrue(structFieldNames(layout.fields()).contains("size_field"));
        assertEquals(0, requireStructField(layout.fields(), "size_field").offset());
    }

    @Test
    void addStructField_unknownStruct_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class,
                () -> writeTools.addStructField(json(
                        "program", programName,
                        "struct_name", "__NoSuchStructXyz__",
                        "field_name", "my_field",
                        "type_name", "int")));
    }

    @Test
    void removeStructField_removesFieldByName() {
        writeTools.createStruct(json(
                "program", programName,
                "name", "RemoveFieldTestStruct",
                "size", 8,
                "category", "/mcp"));
        writeTools.addStructField(json(
                "program", programName,
                "struct_name", "RemoveFieldTestStruct",
                "field_name", "to_remove",
                "type_name", "int",
                "comment", "to be removed"));
        writeTools.addStructField(json(
                "program", programName,
                "struct_name", "RemoveFieldTestStruct",
                "field_name", "to_keep",
                "type_name", "int",
                "comment", "to be kept"));

        WriteTools.RemoveStructFieldResponse response = writeTools.removeStructField(json(
                "program", programName,
                "struct_name", "RemoveFieldTestStruct",
                "field_name", "to_remove"));
        assertTrue(response.success());

        ReadTools.GetStructLayoutResponse layout =
                readTools.getStructLayout(programName, "RemoveFieldTestStruct");
        assertFalse(structFieldNames(layout.fields()).contains("to_remove"));
        assertEquals(4, requireStructField(layout.fields(), "to_keep").offset());

        // validation: missing field_name must be rejected
        IllegalArgumentException missing = assertThrows(
                IllegalArgumentException.class,
                () -> writeTools.removeStructField(json(
                        "program", programName,
                        "struct_name", "RemoveFieldTestStruct",
                        "ordinal", 0)));
        assertTrue(missing.getMessage().contains("field_name"));
    }

    @Test
    void removeStructField_nonExistentField_throwsIllegalArgument() {
        writeTools.createStruct(json(
                "program", programName,
                "name", "RemoveNonExistentFieldStruct",
                "size", 8,
                "category", "/mcp"));
        writeTools.addStructField(json(
                "program", programName,
                "struct_name", "RemoveNonExistentFieldStruct",
                "field_name", "real_field",
                "type_name", "int"));

        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> writeTools.removeStructField(json(
                        "program", programName,
                        "struct_name", "RemoveNonExistentFieldStruct",
                        "field_name", "__no_such_field__")));
        assertTrue(ex.getMessage().contains("__no_such_field__"),
                "Error must mention the missing field name: " + ex.getMessage());
    }

    @Test
    void replaceStructField_replacesFieldByName() {
        writeTools.createStruct(json(
                "program", programName,
                "name", "ReplaceFieldTestStruct",
                "size", 8,
                "category", "/mcp"));
        writeTools.addStructField(json(
                "program", programName,
                "struct_name", "ReplaceFieldTestStruct",
                "field_name", "original_field",
                "type_name", "int",
                "comment", "original"));

        WriteTools.ReplaceStructFieldResponse response = writeTools.replaceStructField(json(
                "program", programName,
                "struct_name", "ReplaceFieldTestStruct",
                "field_name", "original_field",
                "type_name", "byte",
                "new_name", "replaced_field"));
        assertTrue(response.success());

        ReadTools.GetStructLayoutResponse layout =
                readTools.getStructLayout(programName, "ReplaceFieldTestStruct");
        StructField replaced = requireStructField(layout.fields(), "replaced_field");
        assertEquals(0, replaced.offset());
        assertEquals("byte", replaced.type());

        // validation: missing field_name must be rejected
        IllegalArgumentException missing = assertThrows(
                IllegalArgumentException.class,
                () -> writeTools.replaceStructField(json(
                        "program", programName,
                        "struct_name", "ReplaceFieldTestStruct",
                        "ordinal", 0,
                        "type_name", "byte")));
        assertTrue(missing.getMessage().contains("field_name"));
    }

    @Test
    void replaceStructField_nonExistentField_throwsIllegalArgument() {
        writeTools.createStruct(json(
                "program", programName,
                "name", "ReplaceNonExistentFieldStruct",
                "size", 8,
                "category", "/mcp"));
        writeTools.addStructField(json(
                "program", programName,
                "struct_name", "ReplaceNonExistentFieldStruct",
                "field_name", "real_field",
                "type_name", "int"));

        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> writeTools.replaceStructField(json(
                        "program", programName,
                        "struct_name", "ReplaceNonExistentFieldStruct",
                        "field_name", "__no_such_field__",
                        "type_name", "byte")));
        assertTrue(ex.getMessage().contains("__no_such_field__"),
                "Error must mention the missing field name: " + ex.getMessage());
    }

    // addStructField with offset — gap-fill regression tests

    /**
     * Reproduces the exact scenario from the bug report:
     * 1. struct with two int fields (8 bytes total)
     * 2. replace first int with byte -> 3-byte gap at offset 1
     * 3. add_struct_field with explicit offset=1 fills the gap byte without growing the struct
     */
    @Test
    void addStructField_atOffset_fillsGapCreatedByShrink() {
        writeTools.createStruct(json(
                "program", programName,
                "name", "GapFillTestStruct",
                "size", 8,
                "category", "/mcp"));
        writeTools.addStructField(json(
                "program", programName,
                "struct_name", "GapFillTestStruct",
                "field_name", "maybe_big_0x0",
                "type_name", "int"));
        writeTools.addStructField(json(
                "program", programName,
                "struct_name", "GapFillTestStruct",
                "field_name", "maybe_tail_0x4",
                "type_name", "int"));

        // Shrink offset-0 field from int(4) to byte(1) — creates a 3-byte gap at offsets 1-3
        writeTools.replaceStructField(json(
                "program", programName,
                "struct_name", "GapFillTestStruct",
                "field_name", "maybe_big_0x0",
                "type_name", "byte",
                "new_name", "maybe_small_0x0"));

        ReadTools.GetStructLayoutResponse before = readTools.getStructLayout(programName, "GapFillTestStruct");
        assertEquals(8, before.size(), "Struct size must be 8 after shrink-replace");

        // Fill one byte of the gap at offset 1 using the explicit offset parameter
        WriteTools.AddStructFieldResponse resp = writeTools.addStructField(json(
                "program", programName,
                "struct_name", "GapFillTestStruct",
                "field_name", "maybe_gap_0x1",
                "type_name", "byte",
                "offset", 1));
        assertTrue(resp.success());

        ReadTools.GetStructLayoutResponse after = readTools.getStructLayout(programName, "GapFillTestStruct");
        assertEquals(8, after.size(),
                "Struct must NOT inflate when add_struct_field targets a gap via offset");
        assertEquals(1, requireStructField(after.fields(), "maybe_gap_0x1").offset(),
                "New field must be placed at the requested offset, not appended at the end");
    }

    /**
     * add_struct_field with an explicit offset that would extend past the end of the struct
     * must be rejected — offset may only be used to fill existing gaps, not to grow.
     */
    @Test
    void addStructField_atOffset_pastEnd_throwsIllegalArgument() {
        writeTools.createStruct(json(
                "program", programName,
                "name", "OffsetPastEndTestStruct",
                "size", 4,
                "category", "/mcp"));
        writeTools.addStructField(json(
                "program", programName,
                "struct_name", "OffsetPastEndTestStruct",
                "field_name", "maybe_a_0x0",
                "type_name", "int"));

        // offset=4 + int(4) = 8 > struct.getLength()=4 → must be rejected
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> writeTools.addStructField(json(
                        "program", programName,
                        "struct_name", "OffsetPastEndTestStruct",
                        "field_name", "maybe_b_0x4",
                        "type_name", "int",
                        "offset", 4)));
        assertTrue(ex.getMessage().contains("extends past the end") || ex.getMessage().contains("offset + field_size"),
                "Error must explain that offset+size exceeds struct boundary: " + ex.getMessage());

        // Plain append (no offset) is still allowed and must grow the struct normally
        WriteTools.AddStructFieldResponse appended = writeTools.addStructField(json(
                "program", programName,
                "struct_name", "OffsetPastEndTestStruct",
                "field_name", "maybe_b_0x4",
                "type_name", "int"));
        assertTrue(appended.success());
        ReadTools.GetStructLayoutResponse layout = readTools.getStructLayout(programName, "OffsetPastEndTestStruct");
        assertEquals(8, layout.size(), "Plain append must still grow the struct");
        assertEquals(4, requireStructField(layout.fields(), "maybe_b_0x4").offset());
    }

    /**
     * add_struct_field with offset that overlaps an existing named field must be rejected.
     */
    @Test
    void addStructField_atOffset_overlapsExistingField_throwsIllegalArgument() {
        writeTools.createStruct(json(
                "program", programName,
                "name", "OverlapTestStruct",
                "size", 8,
                "category", "/mcp"));
        writeTools.addStructField(json(
                "program", programName,
                "struct_name", "OverlapTestStruct",
                "field_name", "maybe_a_0x0",
                "type_name", "int"));
        writeTools.addStructField(json(
                "program", programName,
                "struct_name", "OverlapTestStruct",
                "field_name", "maybe_b_0x4",
                "type_name", "int"));

        // Offset 2 would place a 4-byte field at [2,6), which overlaps maybe_a_0x0 [0,4)
        // and maybe_b_0x4 [4,8)
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> writeTools.addStructField(json(
                        "program", programName,
                        "struct_name", "OverlapTestStruct",
                        "field_name", "maybe_overlap_0x2",
                        "type_name", "int",
                        "offset", 2)));
        assertTrue(ex.getMessage().contains("overlap") || ex.getMessage().contains("conflict"),
                "Error must mention overlap/conflict: " + ex.getMessage());
    }

    /**
     * Negative offset must be rejected.
     */
    @Test
    void addStructField_negativeOffset_throwsIllegalArgument() {
        writeTools.createStruct(json(
                "program", programName,
                "name", "NegOffsetTestStruct",
                "size", 4,
                "category", "/mcp"));
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> writeTools.addStructField(json(
                        "program", programName,
                        "struct_name", "NegOffsetTestStruct",
                        "field_name", "maybe_x_0x0",
                        "type_name", "int",
                        "offset", -1)));
        assertTrue(ex.getMessage().contains("offset must be"),
                "Error must explain the offset constraint: " + ex.getMessage());
    }

    @Test
    void setComment_writesCommentAtAddress() throws Exception {
        Address addAddress = functionAddress(
                readTools.searchFunctions(programName, "", 200).functions(), "add");
        String commentText = "Integration test comment - ghidra-mcp-ng";

        WriteTools.SetCommentResponse response = writeTools.setComment(json(
                "program", programName,
                "address", withHexPrefix(addAddress),
                "comment", commentText,
                "type", "PRE"));
        assertTrue(response.success());

        Program program = programManager.getOrOpen(programName);
        Address address = program.getAddressFactory().getAddress(withHexPrefix(addAddress));
        CodeUnit codeUnit = program.getListing().getCodeUnitAt(address);
        assertNotNull(codeUnit);
        assertEquals(commentText, codeUnit.getComment(CommentType.PRE));
    }

    @Test
    void setComment_allTypes_succeed() throws Exception {
        Address addAddress = functionAddress(
                readTools.searchFunctions(programName, "", 200).functions(), FN_ADD);

        for (String type : List.of("POST", "EOL", "PLATE", "REPEATABLE")) {
            WriteTools.SetCommentResponse response = writeTools.setComment(json(
                    "program", programName,
                    "address", withHexPrefix(addAddress),
                    "comment", "Comment type test: " + type,
                    "type", type));
            assertTrue(response.success(), "setComment must succeed for type: " + type);
            assertEquals(type, response.type(), "Response type must match requested type: " + type);
        }
    }

    @Test
    void setComment_invalidType_throwsIllegalArgument() {
        Address addAddress = functionAddress(
                readTools.searchFunctions(programName, "", 200).functions(), FN_ADD);

        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> writeTools.setComment(json(
                        "program", programName,
                        "address", withHexPrefix(addAddress),
                        "comment", "test",
                        "type", "UNKNOWN_TYPE")));
        assertTrue(ex.getMessage().contains("UNKNOWN_TYPE"),
                "Error must mention the unknown type: " + ex.getMessage());
    }

    // -------------------------------------------------------------------------
    // WriteTools – every write operation must persist after a program reopen
    // -------------------------------------------------------------------------

    /**
     * Closes all currently open programs and reinitialises the manager, readTools,
     * and writeTools from the same underlying project.  The next call to getOrOpen()
     * will fetch the program fresh from the on-disk project file, so any change that
     * was not actually saved will be lost.
     */
    private void reopenManager() throws Exception {
        programManager.closeAll();
        programManager = new ProgramManager(ghidraProject);
        readTools = new ReadTools(programManager, 60);
        writeTools = new WriteTools(programManager, RulesEngine.load((File) null));
    }

    @Test
    void renameFunction_persistsAfterReopen() throws Exception {
        writeTools.renameFunction(json(
                "program", programName,
                "name_or_address", FN_MULTIPLY,
                "new_name", "multiply_persist_test"));

        reopenManager();

        ReadTools.SearchFunctionsResponse search =
                readTools.searchFunctions(programName, "multiply_persist_test", 10);
        assertTrue(functionNamesFromRefs(search.functions()).contains("multiply_persist_test"),
                "Renamed function must survive program close-and-reopen");
    }

    @Test
    void renameVariable_persistsAfterReopen() throws Exception {
        ReadTools.GetFunctionVariablesResponse before =
                readTools.getFunctionVariables(programName, FN_ADD);
        assertFalse(before.variables().isEmpty(), "add() must have at least one variable");
        String originalName = before.variables().get(0).name();

        writeTools.renameVariable(json(
                "program", programName,
                "name_or_address", FN_ADD,
                "variable_name", originalName,
                "new_name", "renamed_persist_var"));

        reopenManager();

        ReadTools.GetFunctionVariablesResponse after =
                readTools.getFunctionVariables(programName, FN_ADD);
        assertTrue(variableNames(after.variables()).contains("renamed_persist_var"),
                "Renamed variable must survive program close-and-reopen");
    }

    @Test
    void setFunctionPrototype_persistsAfterReopen() throws Exception {
        writeTools.setFunctionPrototype(json(
                "program", programName,
                "name_or_address", FN_COMPUTE,
                "return_type", "int",
                "parameters", parameterArray(
                        parameter("persist_x", "int"),
                        parameter("persist_y", "int"))));

        reopenManager();

        ReadTools.GetFunctionVariablesResponse vars =
                readTools.getFunctionVariables(programName, FN_COMPUTE);
        assertTrue(variableNames(vars.variables()).contains("persist_x") ||
                   variableNames(vars.variables()).contains("persist_y"),
                "Prototype parameter names must survive program close-and-reopen");
    }

    @Test
    void setParameterType_persistsAfterReopen() throws Exception {
        // Establish a known prototype first, then update one parameter's type.
        writeTools.setFunctionPrototype(json(
                "program", programName,
                "name_or_address", FN_COMPUTE,
                "return_type", "int",
                "parameters", parameterArray(
                        parameter("a", "int"),
                        parameter("b", "int"),
                        parameter("c", "int"))));

        writeTools.setParameterType(json(
                "program", programName,
                "name_or_address", FN_COMPUTE,
                "parameter_index", 0,
                "type_name", "int",
                "new_name", "param_persist"));

        reopenManager();

        ReadTools.GetFunctionVariablesResponse vars =
                readTools.getFunctionVariables(programName, FN_COMPUTE);
        assertTrue(variableNames(vars.variables()).contains("param_persist"),
                "Updated parameter name must survive program close-and-reopen");
    }

    @Test
    void createStruct_persistsAfterReopen() throws Exception {
        writeTools.createStruct(json(
                "program", programName,
                "name", "PersistStruct",
                "size", 8,
                "category", "/mcp"));

        reopenManager();

        ReadTools.GetStructLayoutResponse layout =
                readTools.getStructLayout(programName, "PersistStruct");
        assertNotNull(layout, "Created struct must be retrievable after program close-and-reopen");
        assertEquals(8, layout.size());
    }

    @Test
    void addStructField_persistsAfterReopen() throws Exception {
        writeTools.createStruct(json(
                "program", programName,
                "name", "PersistFieldStruct",
                "size", 8,
                "category", "/mcp"));
        writeTools.addStructField(json(
                "program", programName,
                "struct_name", "PersistFieldStruct",
                "field_name", "persist_field",
                "type_name", "int"));

        reopenManager();

        ReadTools.GetStructLayoutResponse layout =
                readTools.getStructLayout(programName, "PersistFieldStruct");
        assertTrue(structFieldNames(layout.fields()).contains("persist_field"),
                "Added struct field must survive program close-and-reopen");
    }

    @Test
    void removeStructField_persistsAfterReopen() throws Exception {
        writeTools.createStruct(json(
                "program", programName,
                "name", "RemovePersistStruct",
                "size", 8,
                "category", "/mcp"));
        writeTools.addStructField(json(
                "program", programName,
                "struct_name", "RemovePersistStruct",
                "field_name", "field_to_remove",
                "type_name", "int"));
        writeTools.addStructField(json(
                "program", programName,
                "struct_name", "RemovePersistStruct",
                "field_name", "field_to_keep",
                "type_name", "int"));

        writeTools.removeStructField(json(
                "program", programName,
                "struct_name", "RemovePersistStruct",
                "field_name", "field_to_remove"));

        reopenManager();

        ReadTools.GetStructLayoutResponse layout =
                readTools.getStructLayout(programName, "RemovePersistStruct");
        assertFalse(structFieldNames(layout.fields()).contains("field_to_remove"),
                "Removed field must still be absent after program close-and-reopen");
        assertTrue(structFieldNames(layout.fields()).contains("field_to_keep"),
                "Retained field must still be present after program close-and-reopen");
    }

    @Test
    void replaceStructField_persistsAfterReopen() throws Exception {
        writeTools.createStruct(json(
                "program", programName,
                "name", "ReplacePersistStruct",
                "size", 8,
                "category", "/mcp"));
        writeTools.addStructField(json(
                "program", programName,
                "struct_name", "ReplacePersistStruct",
                "field_name", "original_field",
                "type_name", "int"));

        writeTools.replaceStructField(json(
                "program", programName,
                "struct_name", "ReplacePersistStruct",
                "field_name", "original_field",
                "type_name", "byte",
                "new_name", "replaced_persist_field"));

        reopenManager();

        ReadTools.GetStructLayoutResponse layout =
                readTools.getStructLayout(programName, "ReplacePersistStruct");
        StructField replaced = requireStructField(layout.fields(), "replaced_persist_field");
        assertEquals("byte", replaced.type(),
                "Replaced struct field type must survive program close-and-reopen");
    }

    @Test
    void setComment_persistsAfterReopen() throws Exception {
        Address addAddress = functionAddress(
                readTools.searchFunctions(programName, "", 200).functions(), FN_ADD);
        String commentText = "Persistence test comment";

        writeTools.setComment(json(
                "program", programName,
                "address", withHexPrefix(addAddress),
                "comment", commentText,
                "type", "PRE"));

        reopenManager();

        Program program = programManager.getOrOpen(programName);
        CodeUnit codeUnit = program.getListing().getCodeUnitAt(addAddress);
        assertNotNull(codeUnit);
        assertEquals(commentText, codeUnit.getComment(CommentType.PRE),
                "Comment must survive program close-and-reopen");
    }

    // -------------------------------------------------------------------------
    // ScriptTool – 4 routes
    // -------------------------------------------------------------------------

    @Test
    void listScripts_returnsScriptList() throws Exception {
        ScriptTool.ListScriptsResponse response = scriptTool.listScripts(false);
        assertNotNull(response.scripts());
        assertEquals(response.scripts().size(), response.count());
    }

    @Test
    void listScripts_mcpOnly_doesNotContainUserScript() throws Exception {
        // Add a user (non-MCP) script, then verify mcp_only=true excludes it
        String scriptClassName = "McpFilterTest" + UUID.randomUUID().toString().replace("-", "");
        Path tmpDir = Files.createTempDirectory("mcp-test-filter");
        Path tmpScript = tmpDir.resolve(scriptClassName + ".java");
        Files.writeString(tmpScript,
                "import ghidra.app.script.GhidraScript;\n" +
                "public class " + scriptClassName + " extends GhidraScript {\n" +
                "    @Override public void run() throws Exception {}\n" +
                "}\n",
                StandardCharsets.UTF_8);

        ScriptTool.AddScriptResponse added = scriptTool.addScript(json("file_path", tmpScript.toString()));
        assertTrue(added.success());
        try {
            ScriptTool.ListScriptsResponse mcpOnly = scriptTool.listScripts(true);
            assertFalse(mcpOnly.scripts().contains(added.filename()),
                    "mcp_only list must NOT contain user-added script: " + added.filename());

            // unfiltered list must contain it
            ScriptTool.ListScriptsResponse all = scriptTool.listScripts(false);
            assertTrue(all.scripts().contains(added.filename()),
                    "unfiltered list must contain user-added script: " + added.filename());
        } finally {
            scriptTool.deleteScript(json("filename", added.filename()));
        }
    }

    @Test
    void addScript_copiesScriptToUserDirectory() throws Exception {
        String scriptClassName = "AddScriptTest" + UUID.randomUUID().toString().replace("-", "");
        Path sourceDir = Files.createTempDirectory("ghidra-mcp-ng-script-add");
        Path sourceScript = sourceDir.resolve(scriptClassName + ".java");
        Files.writeString(sourceScript,
                "import ghidra.app.script.GhidraScript;\n" +
                "public class " + scriptClassName + " extends GhidraScript {\n" +
                "    @Override\n" +
                "    public void run() throws Exception {}\n" +
                "}\n",
                StandardCharsets.UTF_8);

        int beforeCount = scriptTool.listScripts(false).count();
        ScriptTool.AddScriptResponse response = scriptTool.addScript(json(
                "file_path", sourceScript.toString()));
        assertTrue(response.success());
        assertTrue(Files.exists(sourceScript), "addScript should copy (not move) the source file");

        ScriptTool.ListScriptsResponse after = scriptTool.listScripts(false);
        assertTrue(after.scripts().contains(response.filename()));
        assertTrue(after.count() >= beforeCount);

        // cleanup
        scriptTool.deleteScript(json("filename", response.filename()));
    }

    @Test
    void addScript_nonExistentFile_throwsIllegalArgument() throws Exception {
        assertThrows(IllegalArgumentException.class,
                () -> scriptTool.addScript(json("file_path", "/nonexistent/NoSuchScript.java")));
    }

    @Test
    void runScript_executesScriptAndCapturesOutput() throws Exception {
        String scriptClassName = "RunScriptTest" + UUID.randomUUID().toString().replace("-", "");
        Path sourceDir = Files.createTempDirectory("ghidra-mcp-ng-script-run");
        Path sourceScript = sourceDir.resolve(scriptClassName + ".java");
        Files.writeString(sourceScript,
                "import ghidra.app.script.GhidraScript;\n" +
                "public class " + scriptClassName + " extends GhidraScript {\n" +
                "    @Override\n" +
                "    public void run() throws Exception {\n" +
                "        println(\"MCP_MANAGED_SCRIPT_SENTINEL\");\n" +
                "    }\n" +
                "}\n",
                StandardCharsets.UTF_8);

        ScriptTool.AddScriptResponse added = scriptTool.addScript(json(
                "file_path", sourceScript.toString()));
        assertTrue(added.success());

        ScriptTool.RunScriptResponse run = scriptTool.runScript(json(
                "program", programName,
                "filename", added.filename()));
        assertTrue(run.success());
        assertTrue(run.output().contains("MCP_MANAGED_SCRIPT_SENTINEL"));

        // validation: path-traversal filename must be rejected
        IllegalArgumentException invalidFilename = assertThrows(
                IllegalArgumentException.class,
                () -> scriptTool.runScript(json(
                        "program", programName,
                        "filename", "nested/path/script.java")));
        assertTrue(invalidFilename.getMessage().contains("plain filename returned by list_scripts"));

        // cleanup
        scriptTool.deleteScript(json("filename", added.filename()));
    }

    @Test
    void runScript_nonExistentScript_throwsIllegalArgument() throws Exception {
        assertThrows(IllegalArgumentException.class,
                () -> scriptTool.runScript(json(
                        "program", programName,
                        "filename", "NonExistentScript_xyz_99999.java")));
    }

    /**
     * Reproduces the bug from ghidra_bug.md: a script that manually opens a Ghidra
     * transaction via {@code currentProgram.startTransaction()} and then throws without
     * calling {@code endTransaction()} leaves the program database in a locked state.
     *
     * <p>After such a crash, every subsequent MCP call against the same program was
     * failing with "Transaction has not been started" / "No transaction is open". The fix
     * is in {@code ProgramManager.withProgramLock}: after the action completes (whether
     * normally or exceptionally) it detects and terminates any leftover transaction before
     * releasing the lock, so the next caller always starts from a clean state.
     */
    @Test
    void runScript_leakedTransaction_doesNotLockSubsequentCalls() throws Exception {
        // Build a script that opens a nested transaction then throws without ending it.
        String scriptClassName = "LeakTxTest" + UUID.randomUUID().toString().replace("-", "");
        Path sourceDir = Files.createTempDirectory("ghidra-mcp-ng-leak-tx");
        Path sourceScript = sourceDir.resolve(scriptClassName + ".java");
        Files.writeString(sourceScript,
                "import ghidra.app.script.GhidraScript;\n" +
                "public class " + scriptClassName + " extends GhidraScript {\n" +
                "    @Override\n" +
                "    public void run() throws Exception {\n" +
                        // Open an extra nested transaction on top of the one GhidraScript opens
                "        int txId = currentProgram.startTransaction(\"leaked-tx\");\n" +
                        // Intentionally do NOT call endTransaction — simulate a crash
                "        throw new RuntimeException(\"simulated script crash\");\n" +
                "    }\n" +
                "}\n",
                StandardCharsets.UTF_8);

        ScriptTool.AddScriptResponse added = scriptTool.addScript(json(
                "file_path", sourceScript.toString()));
        try {
            // The script should fail — that's expected.
            assertThrows(Exception.class, () -> scriptTool.runScript(json(
                    "program", programName,
                    "filename", added.filename())));

            // The critical assertion: the program must be fully operational afterwards.
            // A write operation through withTransaction is the strongest probe — if any
            // transaction is still open (leaked) it will fail when trying to start a new one.
            WriteTools.RenameFunctionResponse rename = writeTools.renameFunction(json(
                    "program", programName,
                    "name_or_address", FN_ADD,
                    "new_name", FN_ADD + "_afterLeakTest"));
            assertTrue(rename.success(),
                    "renameFunction must succeed after a script that leaked a transaction");

            // Restore original name so later tests are unaffected.
            writeTools.renameFunction(json(
                    "program", programName,
                    "name_or_address", FN_ADD + "_afterLeakTest",
                    "new_name", FN_ADD));
        } finally {
            scriptTool.deleteScript(json("filename", added.filename()));
        }
    }

    @Test
    void deleteScript_removesScriptFromList() throws Exception {
        String scriptClassName = "DeleteScriptTest" + UUID.randomUUID().toString().replace("-", "");
        Path sourceDir = Files.createTempDirectory("ghidra-mcp-ng-script-del");
        Path sourceScript = sourceDir.resolve(scriptClassName + ".java");
        Files.writeString(sourceScript,
                "import ghidra.app.script.GhidraScript;\n" +
                "public class " + scriptClassName + " extends GhidraScript {\n" +
                "    @Override\n" +
                "    public void run() throws Exception {}\n" +
                "}\n",
                StandardCharsets.UTF_8);

        ScriptTool.AddScriptResponse added = scriptTool.addScript(json(
                "file_path", sourceScript.toString()));
        assertTrue(added.success());
        assertTrue(scriptTool.listScripts(false).scripts().contains(added.filename()));

        ScriptTool.DeleteScriptResponse deleted = scriptTool.deleteScript(json(
                "filename", added.filename()));
        assertTrue(deleted.success());

        assertFalse(scriptTool.listScripts(false).scripts().contains(added.filename()));
    }

    @Test
    void deleteScript_nonExistentScript_throwsIllegalArgument() throws Exception {
        assertThrows(IllegalArgumentException.class,
                () -> scriptTool.deleteScript(json("filename", "NonExistentScript_xyz_99999.java")));
    }

    // -------------------------------------------------------------------------
    // Extension-provided scripts (ghidra_scripts/)
    // -------------------------------------------------------------------------

    /**
     * Discovers all scripts shipped with the extension from the {@code ghidra_scripts/}
     * directory. Returns Arguments pairs: (filename, sourcePath).
     */
    static Stream<Arguments> providedScripts() throws Exception {
        Path projectRoot = Path.of(System.getProperty("user.dir"));
        List<Arguments> args = new ArrayList<>();

        Path ghidraScriptsDir = projectRoot.resolve("ghidra_scripts");
        if (Files.isDirectory(ghidraScriptsDir)) {
            try (Stream<Path> walk = Files.walk(ghidraScriptsDir, 1)) {
                walk.filter(p -> p.toString().endsWith(".java"))
                    .sorted()
                    .forEach(p -> args.add(Arguments.of(p.getFileName().toString(), p)));
            }
        }

        return args.stream();
    }

    /**
     * Broad smoke-test: every provided script must compile and return a JSON help object
     * with {@code "help": true} and at least one {@code "arguments"} entry when invoked
     * with no arguments. All scripts are pre-registered as system bundles in {@code @BeforeAll},
     * matching production behaviour when the extension is installed.
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("providedScripts")
    void allProvidedScripts_compileAndReturnHelpWithNoArgs(
            String filename, Path sourcePath) throws Exception {
        assertTrue(Files.exists(sourcePath), "Script source must exist on disk: " + sourcePath);

        ScriptTool.RunScriptResponse result = scriptTool.runScript(json(
                "program", programName,
                "filename", filename));
        assertTrue(result.success(), "Script must execute without error: " + filename);

        JsonObject output = parseJsonOutput(result.output());
        assertTrue(output.has("help"),
                filename + ": no-arg invocation must return JSON with 'help' field. Output was:\n"
                + result.output());
        assertTrue(output.get("help").getAsBoolean(),
                filename + ": 'help' field must be true");
        assertTrue(output.has("arguments") && output.getAsJsonArray("arguments").size() > 0,
                filename + ": help JSON must list at least one argument");
    }

    @Test
    void listScripts_mcpOnly_containsBundledScripts() throws Exception {
        ScriptTool.ListScriptsResponse response = scriptTool.listScripts(true);
        assertTrue(response.scripts().contains("AuditFunction.java"),
                "MCP script list must contain AuditFunction.java");
        assertEquals(response.scripts().size(), response.count());
    }

    @Test
    void getScriptDescription_mcpScript_isFlaggedAsMcp() throws Exception {
        ScriptTool.ScriptDescriptionResponse desc =
                scriptTool.getScriptDescription("AuditFunction.java");
        assertEquals("AuditFunction.java", desc.filename());
        assertTrue(desc.is_mcp_script(), "AuditFunction.java must be flagged as an MCP script");
        assertNotNull(desc.description());
        assertFalse(desc.description().isBlank(), "MCP script must have a non-blank description");
    }

    @Test
    void getScriptDescription_userScript_isNotFlaggedAsMcp() throws Exception {
        String scriptClassName = "UserDescTest" + UUID.randomUUID().toString().replace("-", "");
        Path tmpDir = Files.createTempDirectory("mcp-test-desc");
        Path tmpScript = tmpDir.resolve(scriptClassName + ".java");
        Files.writeString(tmpScript,
                "// @description A user-added script\n" +
                "import ghidra.app.script.GhidraScript;\n" +
                "public class " + scriptClassName + " extends GhidraScript {\n" +
                "    @Override public void run() throws Exception {}\n" +
                "}\n",
                StandardCharsets.UTF_8);

        ScriptTool.AddScriptResponse added = scriptTool.addScript(json("file_path", tmpScript.toString()));
        assertTrue(added.success());
        try {
            ScriptTool.ScriptDescriptionResponse desc =
                    scriptTool.getScriptDescription(added.filename());
            assertEquals(added.filename(), desc.filename());
            assertFalse(desc.is_mcp_script(), "User-added script must NOT be flagged as an MCP script");
        } finally {
            scriptTool.deleteScript(json("filename", added.filename()));
        }
    }

    @Test
    void getScriptDescription_nonExistentScript_throwsIllegalArgument() throws Exception {
        assertThrows(IllegalArgumentException.class,
                () -> scriptTool.getScriptDescription("NonExistentScript_xyz_99999.java"));
    }

    @Test
    void auditFunction_noArgs_returnsHelpJson() throws Exception {
        ScriptTool.RunScriptResponse result = scriptTool.runScript(json(
                "program", programName,
                "filename", "AuditFunction.java"));
        assertTrue(result.success());
        JsonObject output = parseJsonOutput(result.output());
        assertTrue(output.has("help"), "Help response must contain 'help' field");
        assertTrue(output.get("help").getAsBoolean());
        assertTrue(output.has("arguments"), "Help response must list arguments");
        assertTrue(output.getAsJsonArray("arguments").size() > 0);
    }

    @Test
    void auditFunction_knownFunction_returnsAuditResult() throws Exception {
        ScriptTool.RunScriptResponse result = scriptTool.runScript(json(
                "program", programName,
                "filename", "AuditFunction.java",
                "args", array("add")));
        assertTrue(result.success());
        JsonObject output = parseJsonOutput(result.output());
        assertEquals("add", output.get("name").getAsString());
        assertTrue(output.has("address"));
        assertTrue(output.has("signature"));
        assertTrue(output.has("is_thunk"));
        assertTrue(output.has("calling_convention"));
        assertTrue(output.has("callers"));
        assertTrue(output.has("callees"));
        assertTrue(output.has("xref_count"));
        assertTrue(output.has("reversing_status"),
                "Audit result must include a reversing_status array");
        assertTrue(output.getAsJsonArray("reversing_status") != null);
    }

    @Test
    void auditFunction_functionWithCallers_reportsCallGraph() throws Exception {
        // 'add' is called by both compute and multiply in the fixture
        ScriptTool.RunScriptResponse result = scriptTool.runScript(json(
                "program", programName,
                "filename", "AuditFunction.java",
                "args", array(FN_ADD)));
        assertTrue(result.success());
        JsonObject output = parseJsonOutput(result.output());
        JsonArray callers = output.getAsJsonArray("callers");
        assertTrue(callers.size() >= 1,
                "add() must have at least one caller (compute or multiply)");
        assertTrue(output.get("xref_count").getAsInt() >= 1);

        // verify specific expected callers are present
        Set<String> callerNames = new HashSet<>();
        for (int i = 0; i < callers.size(); i++) {
            callerNames.add(callers.get(i).getAsJsonObject().get("name").getAsString());
        }
        assertTrue(callerNames.contains(FN_COMPUTE) || callerNames.contains(FN_MULTIPLY),
                "add() must be called by compute or multiply in the fixture; got: " + callerNames);
    }

    @Test
    void auditFunction_unknownFunction_returnsErrorJson() throws Exception {
        ScriptTool.RunScriptResponse result = scriptTool.runScript(json(
                "program", programName,
                "filename", "AuditFunction.java",
                "args", array("no_such_function_xyz_99999")));
        assertTrue(result.success(), "Script itself should succeed even if function is not found");
        JsonObject output = parseJsonOutput(result.output());
        assertTrue(output.has("error"), "Output must contain 'error' field for unknown function");
    }

    @Test
    void auditProgram_noArgs_returnsHelpJson() throws Exception {
        ScriptTool.RunScriptResponse result = scriptTool.runScript(json(
                "program", programName,
                "filename", "AuditProgram.java"));
        assertTrue(result.success(), "AuditProgram must run without error");
        JsonObject output = parseJsonOutput(result.output());
        assertTrue(output.has("help"), "No-arg invocation must return JSON with 'help' field");
        assertTrue(output.get("help").getAsBoolean(), "'help' field must be true");
        assertTrue(output.has("arguments"), "Help JSON must include 'arguments'");
        assertTrue(output.has("example"), "Help JSON must include 'example'");
    }

    @Test
    void auditProgram_withN_returnsAuditResult() throws Exception {
        ScriptTool.RunScriptResponse result = scriptTool.runScript(json(
                "program", programName,
                "filename", "AuditProgram.java",
                "args", array("5")));
        assertTrue(result.success(), "AuditProgram must run without error");
        JsonObject output = parseJsonOutput(result.output());

        // Top-level shape
        assertTrue(output.has("program"),        "Result must contain 'program'");
        assertTrue(output.has("statistics"),     "Result must contain 'statistics'");
        assertTrue(output.has("top_incomplete"), "Result must contain 'top_incomplete'");

        // Statistics — only lightweight fields present
        JsonObject stats = output.getAsJsonObject("statistics");
        assertTrue(stats.has("total_functions"),   "stats must have total_functions");
        assertTrue(stats.has("thunks"),            "stats must have thunks");
        assertTrue(stats.has("unnamed_functions"), "stats must have unnamed_functions");
        assertFalse(stats.has("named_functions"),      "stats must NOT have named_functions");
        assertFalse(stats.has("incomplete_functions"), "stats must NOT have incomplete_functions");
        assertFalse(stats.has("complete_functions"),   "stats must NOT have complete_functions");
        assertFalse(stats.has("completion_pct"),       "stats must NOT have completion_pct");

        int total  = stats.get("total_functions").getAsInt();
        int thunks = stats.get("thunks").getAsInt();
        assertTrue(total > 0,       "total_functions must be > 0 for the test fixture");
        assertTrue(thunks <= total, "thunks must not exceed total");

        // top_incomplete — at most N entries, no rank or score fields
        JsonArray top = output.getAsJsonArray("top_incomplete");
        assertTrue(top.size() <= 5, "top_incomplete must contain at most 5 entries when N=5");
        for (int i = 0; i < top.size(); i++) {
            JsonObject entry = top.get(i).getAsJsonObject();
            assertFalse(entry.has("rank"),  "entry must NOT have 'rank'");
            assertFalse(entry.has("score"), "entry must NOT have 'score'");
            assertTrue(entry.has("name"),         "entry must have 'name'");
            assertTrue(entry.has("address"),      "entry must have 'address'");
            assertTrue(entry.has("xref_count"),   "entry must have 'xref_count'");
            assertTrue(entry.has("callee_count"), "entry must have 'callee_count'");
            assertTrue(entry.has("issues"),       "entry must have 'issues'");
            assertTrue(entry.getAsJsonArray("issues").size() > 0,
                    "incomplete function must have at least one issue code");
            assertTrue(entry.get("address").getAsString().startsWith("0x"),
                    "address must be 0x-prefixed hex");
        }
    }

    @Test
    void auditProgram_invalidN_returnsErrorJson() throws Exception {
        ScriptTool.RunScriptResponse result = scriptTool.runScript(json(
                "program", programName,
                "filename", "AuditProgram.java",
                "args", array("not_a_number")));
        assertTrue(result.success(), "Script must not throw — bad N should produce error JSON");
        JsonObject output = parseJsonOutput(result.output());
        assertTrue(output.has("error"), "Invalid N must produce error JSON with 'error' field");
        assertTrue(output.get("error").getAsString().contains("not_a_number"),
                "Error must mention the offending argument");
    }

    /**
     * PropagateFunctionSignatures.java lives in the extension's ghidra_scripts/ directory
     * because it requires FunctionID module classes (ghidra.feature.fid.*).
     */
    @Test
    void propagateFunctionSignatures_noArgs_returnsHelpJson() throws Exception {
        Path source = Path.of(System.getProperty("user.dir"), "ghidra_scripts",
                "PropagateFunctionSignatures.java");
        assertTrue(Files.exists(source),
                "PropagateFunctionSignatures.java must exist in ghidra_scripts/: " + source);

        ScriptTool.RunScriptResponse result = scriptTool.runScript(json(
                "program", programName,
                "filename", "PropagateFunctionSignatures.java"));
        assertTrue(result.success());
        JsonObject output = parseJsonOutput(result.output());
        assertTrue(output.has("help"), "Help response must contain 'help' field");
        assertTrue(output.get("help").getAsBoolean());
        assertTrue(output.has("arguments"), "Help response must list arguments");
        assertTrue(output.has("example"), "Help response must include usage example");
    }

    @Test
    void propagateFunctionSignatures_populatesFromSourceAndReportsMissingTarget() throws Exception {
        Path source = Path.of(System.getProperty("user.dir"), "ghidra_scripts",
                "PropagateFunctionSignatures.java");
        assertTrue(Files.exists(source),
                "PropagateFunctionSignatures.java must exist in ghidra_scripts/: " + source);

        // Create a temp path where the .fidb will be written (must not exist beforehand)
        Path fidbPath = Files.createTempFile("mcp-fid-test", ".fidb");
        Files.delete(fidbPath);
        try {
            ScriptTool.RunScriptResponse result = scriptTool.runScript(json(
                    "program", programName,
                    "filename", "PropagateFunctionSignatures.java",
                    "args", array(
                            fidbPath.toString(),   // fidb_path
                            programName,           // source_programs: populate from test fixture
                            "nonexistent_xyz",     // target_programs: no such program in project
                            "MCPTestLib")));        // library_name

            assertTrue(result.success());
            JsonObject output = parseJsonOutput(result.output());
            assertEquals(fidbPath.toString(), output.get("fidb_path").getAsString());

            // Phase 1 should have run and processed the fixture program
            JsonObject phase1 = output.getAsJsonObject("phase1");
            assertFalse(phase1.get("skipped").getAsBoolean());
            JsonArray p1Programs = phase1.getAsJsonArray("programs");
            assertEquals(1, p1Programs.size());
            JsonObject p1Entry = p1Programs.get(0).getAsJsonObject();
            assertEquals(programName, p1Entry.get("name").getAsString());
            assertFalse(p1Entry.has("error"),
                    "Phase 1 should not have an error for the test fixture: " + p1Entry);

            // Phase 2 should report the non-existent target as missing
            JsonArray p2Programs = output.getAsJsonObject("phase2").getAsJsonArray("programs");
            assertEquals(1, p2Programs.size());
            JsonObject p2Entry = p2Programs.get(0).getAsJsonObject();
            assertEquals("nonexistent_xyz", p2Entry.get("name").getAsString());
            assertTrue(p2Entry.has("error"), "Phase 2 must report error for missing target program");
        } finally {
            Files.deleteIfExists(fidbPath);
        }
    }

    // -------------------------------------------------------------------------
    // Built-in primitive type resolution
    // -------------------------------------------------------------------------

    /**
     * Every primitive listed in the error-message docs must be accepted by addStructField
     * without throwing. This guards against regressions where built-in types are not found
     * because they live in BuiltInDataTypeManager rather than the program's DataTypeManager.
     */
    @ParameterizedTest(name = "addStructField accepts built-in type: {0}")
    @MethodSource("builtInFieldTypeNames")
    void addStructField_acceptsBuiltInType(String typeName) {
        String structName = "BuiltinTypeTest_" + typeName.replace("*", "Ptr");
        writeTools.createStruct(json(
                "program", programName,
                "name", structName,
                "size", 16,
                "category", "/mcp_builtin_test"));

        WriteTools.AddStructFieldResponse response = writeTools.addStructField(json(
                "program", programName,
                "struct_name", structName,
                "field_name", "field_0",
                "type_name", typeName));
        assertTrue(response.success(),
                "addStructField must accept built-in type '" + typeName + "'");
    }

    /**
     * Every primitive listed in the error-message docs must be accepted by
     * setFunctionPrototype as a return type and as a parameter type.
     */
    @ParameterizedTest(name = "setFunctionPrototype accepts built-in type: {0}")
    @MethodSource("builtInTypeNames")
    void setFunctionPrototype_acceptsBuiltInReturnType(String typeName) {
        // void is not valid as a parameter type but is valid as a return type
        WriteTools.SetFunctionPrototypeResponse response = writeTools.setFunctionPrototype(json(
                "program", programName,
                "name_or_address", FN_ADD,
                "return_type", typeName,
                "parameters", new JsonArray()));
        assertTrue(response.success(),
                "setFunctionPrototype must accept built-in return type '" + typeName + "'");
    }

    /** Pointer-to-built-in type (e.g. "uint*") must resolve correctly. */
    @Test
    void addStructField_acceptsPointerToBuiltInType() {
        writeTools.createStruct(json(
                "program", programName,
                "name", "BuiltinPtrTest",
                "size", 16,
                "category", "/mcp_builtin_test"));

        // "uint*" uses uint which is not present in the C fixture's DWARF info, ensuring
        // the test exercises the BuiltInDataTypeManager fallback path.
        WriteTools.AddStructFieldResponse response = writeTools.addStructField(json(
                "program", programName,
                "struct_name", "BuiltinPtrTest",
                "field_name", "p_uint",
                "type_name", "uint*"));
        assertTrue(response.success(), "addStructField must accept 'uint*' (pointer to built-in)");
    }

    /** Array-of-built-in type (e.g. "uint[4]") must resolve correctly. */
    @Test
    void addStructField_acceptsArrayOfBuiltInType() {
        writeTools.createStruct(json(
                "program", programName,
                "name", "BuiltinArrayTest",
                "size", 16,
                "category", "/mcp_builtin_test"));

        // "uint[4]" uses uint which is not present in the C fixture's DWARF info.
        WriteTools.AddStructFieldResponse response = writeTools.addStructField(json(
                "program", programName,
                "struct_name", "BuiltinArrayTest",
                "field_name", "data",
                "type_name", "uint[4]"));
        assertTrue(response.success(), "addStructField must accept 'uint[4]' (array of built-in)");
    }

    /** The standalone "pointer" type (generic void pointer) must resolve. */
    @Test
    void addStructField_acceptsStandalonePointerType() {
        writeTools.createStruct(json(
                "program", programName,
                "name", "BuiltinStandalonePointerTest",
                "size", 16,
                "category", "/mcp_builtin_test"));

        WriteTools.AddStructFieldResponse response = writeTools.addStructField(json(
                "program", programName,
                "struct_name", "BuiltinStandalonePointerTest",
                "field_name", "generic_ptr",
                "type_name", "pointer"));
        assertTrue(response.success(), "addStructField must accept 'pointer' (generic pointer type)");
    }

    /**
     * searchDataTypes must include built-in types such as Ghidra's "dword".
     * Before the fix, the search only covered the program's DataTypeManager. On programs
     * without debug symbols (e.g. raw binary dumps) this returned 0 results for any
     * primitive. The GCC test fixture happens to have many built-ins pre-populated via
     * auto-analysis, so these tests verify correct behaviour on both kinds of program.
     */
    @Test
    void searchDataTypes_includesBuiltInTypes() {
        // "dword" is a Ghidra built-in type that is never present in a C ELF program's
        // DataTypeManager (which only has types from DWARF/GCC), so it reliably tests
        // whether the search covers BuiltInDataTypeManager.
        ReadTools.SearchDataTypesResponse result =
                readTools.searchDataTypes(programName, "dword", 50);
        assertTrue(result.count() > 0,
                "searchDataTypes('dword') must return at least one result (built-in 'dword' type)");
        assertTrue(result.data_types().stream().anyMatch(dt -> dt.name().equals("dword")),
                "searchDataTypes('dword') must include the exact built-in 'dword' type");
    }

    @Test
    void searchDataTypes_emptyQueryIncludesBuiltInTypes() {
        ReadTools.SearchDataTypesResponse all =
                readTools.searchDataTypes(programName, "", 500);
        // "dword" and "word" are Ghidra-specific built-ins absent from C DWARF info.
        assertTrue(all.data_types().stream().anyMatch(dt -> dt.name().equals("dword")),
                "searchDataTypes with empty query must include built-in 'dword'");
        assertTrue(all.data_types().stream().anyMatch(dt -> dt.name().equals("word")),
                "searchDataTypes with empty query must include built-in 'word'");
    }

    static Stream<Arguments> builtInTypeNames() {
        return Stream.of("int", "uint", "long", "ulong", "byte", "short", "ushort",
                "float", "double", "bool", "char", "void")
                .map(Arguments::of);
    }

    /** Built-in types valid as struct field types (excludes void, which has no fixed size). */
    static Stream<Arguments> builtInFieldTypeNames() {
        return Stream.of("int", "uint", "long", "ulong", "byte", "short", "ushort",
                "float", "double", "bool", "char")
                .map(Arguments::of);
    }

    // -------------------------------------------------------------------------
    // Private infrastructure (unchanged)
    // -------------------------------------------------------------------------

    private static Path compileFixtureBinary() throws Exception {
        Path source = Path.of(System.getProperty("user.dir"), "tests", "fixture", "test_target.c");
        if (!Files.exists(source)) {
            throw new IllegalStateException("Missing integration fixture source: " + source);
        }

        Path buildDir = Files.createTempDirectory("ghidra-mcp-ng-java-fixture");
        Path binary = buildDir.resolve("test_target_java_it");

        Process process;
        try {
            process = new ProcessBuilder(
                    "gcc",
                    "-O0",
                    source.toString(),
                    "-o",
                    binary.toString())
                    .redirectErrorStream(true)
                    .start();
        } catch (IOException e) {
            throw new IllegalStateException("gcc is required for Java integration tests", e);
        }

        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new IllegalStateException("gcc failed to build integration fixture: " + output);
        }
        return binary;
    }

    /**
     * Compiles a minimal ELF binary (distinct from the main fixture) used by
     * {@code importBinary} tests — it must not already be present in the test project.
     */
    private static Path compileMinimalBinary() throws Exception {
        Path buildDir = Files.createTempDirectory("ghidra-mcp-ng-java-import-test");
        Path source = buildDir.resolve("import_test.c");
        Files.writeString(source, "int main() { return 42; }\n", StandardCharsets.UTF_8);
        Path binary = buildDir.resolve("import_test");

        Process process;
        try {
            process = new ProcessBuilder("gcc", "-O0", source.toString(), "-o", binary.toString())
                    .redirectErrorStream(true)
                    .start();
        } catch (IOException e) {
            throw new IllegalStateException("gcc is required for Java integration tests", e);
        }
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new IllegalStateException("gcc failed to build import test binary: " + output);
        }
        return binary;
    }

    private static JsonObject json(Object... pairs) {
        if (pairs.length % 2 != 0) {
            throw new IllegalArgumentException("json helper expects key/value pairs");
        }
        JsonObject object = new JsonObject();
        for (int i = 0; i < pairs.length; i += 2) {
            String key = (String) pairs[i];
            Object value = pairs[i + 1];
            if (value == null) {
                object.add(key, JsonNull.INSTANCE);
            } else if (value instanceof String stringValue) {
                object.addProperty(key, stringValue);
            } else if (value instanceof Number numberValue) {
                object.addProperty(key, numberValue);
            } else if (value instanceof Boolean booleanValue) {
                object.addProperty(key, booleanValue);
            } else if (value instanceof JsonElement jsonElement) {
                object.add(key, jsonElement);
            } else {
                throw new IllegalArgumentException("Unsupported JSON value type: " + value.getClass());
            }
        }
        return object;
    }

    private static JsonArray array(String... values) {
        JsonArray array = new JsonArray();
        for (String value : values) {
            array.add(value);
        }
        return array;
    }

    private static JsonObject parameter(String name, String type) {
        return json("name", name, "type", type);
    }

    private static JsonArray parameterArray(JsonObject... params) {
        JsonArray array = new JsonArray();
        for (JsonObject param : params) {
            array.add(param);
        }
        return array;
    }

    private static Set<String> functionNamesFromRefs(Collection<FunctionRef> functions) {
        Set<String> names = new HashSet<>();
        for (FunctionRef function : functions) {
            names.add(function.name());
        }
        return names;
    }

    private static Set<String> variableNames(Collection<VariableEntry> variables) {
        Set<String> names = new HashSet<>();
        for (VariableEntry variable : variables) {
            names.add(variable.name());
        }
        return names;
    }

    private static Set<String> structFieldNames(Collection<StructField> fields) {
        Set<String> names = new HashSet<>();
        for (StructField field : fields) {
            names.add(field.name());
        }
        return names;
    }

    private static StructField requireStructField(Collection<StructField> fields, String name) {
        for (StructField field : fields) {
            if (name.equals(field.name())) {
                return field;
            }
        }
        throw new AssertionError("Struct field not found: " + name);
    }

    private static Set<String> stringValues(Collection<String> values) {
        return new HashSet<>(values);
    }

    private static boolean anyEndsWith(Collection<String> values, String suffix) {
        for (String value : values) {
            if (value.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }

    private static Address functionAddress(Collection<FunctionRef> functions, String name) {
        for (FunctionRef function : functions) {
            if (name.equals(function.name())) {
                return function.address();
            }
        }
        throw new IllegalArgumentException("Function not found in result: " + name);
    }

    private static boolean allStringEntriesHaveValues(Collection<StringEntry> strings) {
        for (StringEntry stringEntry : strings) {
            if (stringEntry.value() == null || stringEntry.value().isBlank()) {
                return false;
            }
        }
        return true;
    }

    private static String withHexPrefix(Address address) {
        return "0x" + address.toString();
    }

    /**
     * Extracts the first well-formed JSON object from script output, which may include
     * progress lines printed before the final JSON result.
     */
    private static JsonObject parseJsonOutput(String output) {
        // Scripts may emit progress messages before the JSON; find where the JSON block starts
        for (String line : output.split("\n")) {
            if (line.stripLeading().startsWith("{")) {
                int start = output.indexOf(line);
                return JsonParser.parseString(output.substring(start).trim()).getAsJsonObject();
            }
        }
        throw new AssertionError("No JSON block found in script output:\n" + output);
    }
}
