package com.ghidramcpng.rules;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Unit tests for {@link RulesEngine} and {@link RulesConfig}.
 *
 * These tests verify engine mechanics — that configured patterns are compiled and applied,
 * violations carry the right message, and edge cases are handled correctly.
 * They do NOT test specific naming conventions (those are user configuration in rules.yaml).
 *
 * No Ghidra installation required.
 */
class RulesEngineTest {

    // -----------------------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------------------

    private static RulesEngine fromYaml(String yaml) throws IOException {
        Path tmp = Files.createTempFile("rules_test_", ".yaml");
        try {
            Files.writeString(tmp, yaml, StandardCharsets.UTF_8);
            return RulesEngine.load(tmp.toFile());
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    private static RulesEngine engine(String fieldType, String pattern, String message) {
        RulesConfig cfg = new RulesConfig();
        RulesConfig.FieldRule rule = new RulesConfig.FieldRule();
        rule.setPattern(pattern);
        rule.setMessage(message);
        cfg.setNaming(java.util.Map.of(fieldType, rule));
        return new RulesEngine(cfg);
    }

    // -----------------------------------------------------------------------------------
    // Pattern application
    // -----------------------------------------------------------------------------------

    @Test
    @DisplayName("Name matching the configured pattern passes")
    void matchingName_passes() {
        var eng = engine("my_field", "^[a-z]+$", "lowercase only");
        assertDoesNotThrow(() -> eng.validate("my_field", "hello"));
        assertDoesNotThrow(() -> eng.validate("my_field", "world"));
    }

    @Test
    @DisplayName("Name not matching the configured pattern throws NamingRuleViolation")
    void nonMatchingName_throwsViolation() {
        var eng = engine("my_field", "^[a-z]+$", "lowercase only");
        assertThrows(NamingRuleViolation.class, () -> eng.validate("my_field", "Hello"));
        assertThrows(NamingRuleViolation.class, () -> eng.validate("my_field", "123"));
    }

    @Test
    @DisplayName("Violation exception contains the offending name and configured message")
    void violation_containsNameAndMessage() {
        var eng = engine("my_field", "^[a-z]+$", "Must be lowercase");
        NamingRuleViolation ex = assertThrows(NamingRuleViolation.class,
                () -> eng.validate("my_field", "BadName"));
        assertTrue(ex.getMessage().contains("BadName"), "Should contain offending name");
        assertTrue(ex.getMessage().contains("Must be lowercase"), "Should contain configured message");
    }

    @Test
    @DisplayName("Pattern is applied as a full match, not a substring search")
    void pattern_isFullMatch() {
        var eng = engine("my_field", "^[a-z]+$", null);
        // Partial matches must not pass
        assertThrows(NamingRuleViolation.class, () -> eng.validate("my_field", "abc123"));
        assertThrows(NamingRuleViolation.class, () -> eng.validate("my_field", "123abc"));
        assertDoesNotThrow(() -> eng.validate("my_field", "abc"));
    }

    @Test
    @DisplayName("Rules for different field types are independent")
    void multipleFieldTypes_areIndependent() throws IOException {
        String yaml = "naming:\n" +
                      "  function_name:\n" +
                      "    pattern: \"^a_.*$\"\n" +
                      "    message: \"must start with a_\"\n" +
                      "  variable_name:\n" +
                      "    pattern: \"^b_.*$\"\n" +
                      "    message: \"must start with b_\"\n";
        RulesEngine eng = fromYaml(yaml);

        assertDoesNotThrow(() -> eng.validate("function_name", "a_foo"));
        assertDoesNotThrow(() -> eng.validate("variable_name", "b_bar"));
        assertThrows(NamingRuleViolation.class, () -> eng.validate("function_name", "b_foo"));
        assertThrows(NamingRuleViolation.class, () -> eng.validate("variable_name", "a_bar"));
    }

    // -----------------------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------------------

    @Test
    @DisplayName("No rule configured for field type — silently passes")
    void noRuleForFieldType_passes() {
        var eng = engine("known_field", "^[a-z]+$", null);
        assertDoesNotThrow(() -> eng.validate("unknown_field", "ANYTHING_AT_ALL"));
    }

    @Test
    @DisplayName("Null and blank names are silently ignored")
    void nullAndBlankName_ignored() {
        var eng = engine("my_field", "^[a-z]+$", null);
        assertDoesNotThrow(() -> eng.validate("my_field", null));
        assertDoesNotThrow(() -> eng.validate("my_field", ""));
        assertDoesNotThrow(() -> eng.validate("my_field", "   "));
    }

    @Test
    @DisplayName("Invalid regex in config throws IllegalArgumentException at construction time")
    void invalidRegex_throwsAtConstruction() {
        RulesConfig cfg = new RulesConfig();
        RulesConfig.FieldRule rule = new RulesConfig.FieldRule();
        rule.setPattern("[invalid(regex");
        cfg.setNaming(java.util.Map.of("my_field", rule));
        assertThrows(IllegalArgumentException.class, () -> new RulesEngine(cfg));
    }

    // -----------------------------------------------------------------------------------
    // YAML loading
    // -----------------------------------------------------------------------------------

    @Test
    @DisplayName("YAML file is parsed and rule is applied correctly")
    void yamlLoading_ruleApplied() throws IOException {
        String yaml = "naming:\n" +
                      "  function_name:\n" +
                      "    pattern: \"^pfx_[a-z]+$\"\n" +
                      "    message: \"Must start with pfx_\"\n";
        RulesEngine eng = fromYaml(yaml);

        assertDoesNotThrow(() -> eng.validate("function_name", "pfx_foo"));
        NamingRuleViolation ex = assertThrows(NamingRuleViolation.class,
                () -> eng.validate("function_name", "nopfx"));
        assertTrue(ex.getMessage().contains("Must start with pfx_"));
    }

    @Test
    @DisplayName("Empty YAML produces a permissive engine")
    void emptyYaml_permissive() throws IOException {
        RulesEngine eng = fromYaml("");
        assertDoesNotThrow(() -> eng.validate("any_field", "anything"));
    }

    @Test
    @DisplayName("Null file produces a permissive engine")
    void nullFile_permissive() throws IOException {
        RulesEngine eng = RulesEngine.load((File) null);
        assertDoesNotThrow(() -> eng.validate("any_field", "anything"));
    }

    @Test
    @DisplayName("Missing file produces a permissive engine")
    void missingFile_permissive() throws IOException {
        RulesEngine eng = RulesEngine.load(new File("/nonexistent/path/rules.yaml"));
        assertDoesNotThrow(() -> eng.validate("any_field", "anything"));
    }

    // -----------------------------------------------------------------------------------
    // Timeout config
    // -----------------------------------------------------------------------------------

    @Test
    @DisplayName("Decompile timeout defaults to 60 seconds when not configured")
    void decompileTimeout_default() throws IOException {
        RulesEngine eng = fromYaml("");
        assertEquals(60, eng.getDecompileTimeoutSeconds());
    }

    @Test
    @DisplayName("Decompile timeout is read from YAML")
    void decompileTimeout_fromYaml() throws IOException {
        RulesEngine eng = fromYaml("timeouts:\n  decompile_seconds: 15\n");
        assertEquals(15, eng.getDecompileTimeoutSeconds());
    }

    @Test
    @DisplayName("Non-positive decompile timeout is rejected")
    void decompileTimeout_invalid() throws IOException {
        RulesEngine eng = fromYaml("timeouts:\n  decompile_seconds: 0\n");
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                eng::getDecompileTimeoutSeconds);
        assertTrue(ex.getMessage().contains("timeouts.decompile_seconds"));
    }

    // -----------------------------------------------------------------------------------
    // Import validation — min_directory_depth
    // -----------------------------------------------------------------------------------

    private static RulesEngine engineWithImport(Integer minDepth, String requireChildPath)
            throws IOException {
        StringBuilder yaml = new StringBuilder();
        yaml.append("import:\n");
        if (minDepth != null)        yaml.append("  min_directory_depth: ").append(minDepth).append("\n");
        if (requireChildPath != null) yaml.append("  require_child_path: \"").append(requireChildPath).append("\"\n");
        return fromYaml(yaml.toString());
    }

    @Test
    @DisplayName("min_directory_depth=0 allows root project_dir")
    void minDepth0_allowsRoot() throws IOException {
        RulesEngine eng = engineWithImport(0, null);
        assertDoesNotThrow(() -> eng.validateImport("/some/file.exe", null));
        assertDoesNotThrow(() -> eng.validateImport("/some/file.exe", "/"));
        assertDoesNotThrow(() -> eng.validateImport("/some/file.exe", ""));
    }

    @Test
    @DisplayName("min_directory_depth=1 rejects root, accepts one-level dir")
    void minDepth1_rejectsRoot_acceptsOneLevel() throws IOException {
        RulesEngine eng = engineWithImport(1, null);
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> eng.validateImport("/some/file.exe", "/"));
        assertTrue(ex.getMessage().contains("min_directory_depth"),
                "Error should mention the config key");
        assertTrue(ex.getMessage().contains("depth 0"),
                "Error should state the supplied depth");
        assertDoesNotThrow(() -> eng.validateImport("/some/file.exe", "binaries"));
        assertDoesNotThrow(() -> eng.validateImport("/some/file.exe", "binaries/sub"));
    }

    @Test
    @DisplayName("min_directory_depth=2 requires at least two path components")
    void minDepth2_requiresTwoComponents() throws IOException {
        RulesEngine eng = engineWithImport(2, null);
        assertThrows(IllegalArgumentException.class,
                () -> eng.validateImport("/f.exe", "binaries"));
        assertDoesNotThrow(() -> eng.validateImport("/f.exe", "binaries/sub"));
        assertDoesNotThrow(() -> eng.validateImport("/f.exe", "binaries/sub/deep"));
    }

    // -----------------------------------------------------------------------------------
    // Import validation — require_child_path
    // -----------------------------------------------------------------------------------

    @Test
    @DisplayName("require_child_path: file outside prefix is rejected")
    void requireChildPath_fileOutsidePrefix_rejected() throws IOException {
        RulesEngine eng = engineWithImport(0, "/a/");
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> eng.validateImport("/other/hello/bin/moo.exe", "hello/bin"));
        assertTrue(ex.getMessage().contains("require_child_path"),
                "Error should mention the config key");
        assertTrue(ex.getMessage().contains("/other/hello/bin/moo.exe"),
                "Error should echo the supplied file path");
    }

    @Test
    @DisplayName("require_child_path: correct project_dir passes")
    void requireChildPath_correctProjectDir_passes() throws IOException {
        RulesEngine eng = engineWithImport(0, "/a/");
        assertDoesNotThrow(() -> eng.validateImport("/a/hello/bin/moo.exe", "hello/bin"));
    }

    @Test
    @DisplayName("require_child_path: wrong project_dir is rejected with expected value in message")
    void requireChildPath_wrongProjectDir_rejectedWithHint() throws IOException {
        RulesEngine eng = engineWithImport(0, "/a/");
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> eng.validateImport("/a/hello/bin/moo.exe", "wrong/dir"));
        assertTrue(ex.getMessage().contains("hello/bin"),
                "Error should tell the user the expected project_dir");
    }

    @Test
    @DisplayName("require_child_path: file directly in prefix dir requires root project_dir")
    void requireChildPath_fileDirectlyInPrefix_requiresRoot() throws IOException {
        RulesEngine eng = engineWithImport(0, "/a/");
        assertDoesNotThrow(() -> eng.validateImport("/a/moo.exe", "/"));
        assertDoesNotThrow(() -> eng.validateImport("/a/moo.exe", ""));
        assertThrows(IllegalArgumentException.class,
                () -> eng.validateImport("/a/moo.exe", "hello"));
    }

    @Test
    @DisplayName("require_child_path: prefix without trailing slash is accepted in config")
    void requireChildPath_prefixWithoutTrailingSlash_accepted() throws IOException {
        RulesEngine eng = engineWithImport(0, "/a");
        assertDoesNotThrow(() -> eng.validateImport("/a/hello/bin/moo.exe", "hello/bin"));
    }

    // -----------------------------------------------------------------------------------
    // YAML error reporting
    // -----------------------------------------------------------------------------------

    @Test
    @DisplayName("Unknown YAML keys are rejected with a clear error")
    void unknownYamlKey_rejectedClearly() throws IOException {
        String yaml = "naming:\n" +
                      "  function_name:\n" +
                      "    pattern: \"^[a-z]+$\"\n" +
                      "    message: \"lowercase\"\n" +
                      "    unsupported_key: \"^FUN_\"\n";
        Path tmp = Files.createTempFile("rules_test_", ".yaml");
        try {
            Files.writeString(tmp, yaml, StandardCharsets.UTF_8);
            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                    () -> RulesEngine.load(tmp.toFile()));
            assertTrue(ex.getMessage().contains("unsupported_key"),
                    "Error must name the offending key. Got: " + ex.getMessage());
            assertTrue(ex.getMessage().toLowerCase().contains("rules file"),
                    "Error must mention 'rules file'. Got: " + ex.getMessage());
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    // -----------------------------------------------------------------------------------
    // Comment rules
    // -----------------------------------------------------------------------------------

    private static final java.util.function.IntSupplier NO_AUTO_NAMED = () -> 0;

    private static final String COMMENT_YAML =
            "comments:\n" +
            "  PLATE:\n" +
            "    max_length: 30\n" +
            "    require_named_function: true\n" +
            "    max_auto_named_variables: 2\n" +
            "    message: \"Rename it, do not describe it.\"\n";

    @Test
    @DisplayName("No comments section configured lets every comment through")
    void noCommentRules_permitsAnything() {
        var eng = new RulesEngine(new RulesConfig());
        assertFalse(eng.hasCommentRules());
        assertDoesNotThrow(() -> eng.validateComment(
                "PLATE", "x".repeat(4000), "FUN_00401000", () -> 99));
    }

    @Test
    @DisplayName("A comment type with no rule is unaffected by another type's rule")
    void unconfiguredCommentType_passes() throws IOException {
        var eng = fromYaml(COMMENT_YAML);
        assertDoesNotThrow(() -> eng.validateComment(
                "EOL", "x".repeat(500), "FUN_00401000", () -> 99));
    }

    @Test
    @DisplayName("Comment over max_length is rejected, naming both lengths")
    void commentTooLong_rejected() throws IOException {
        var eng = fromYaml(COMMENT_YAML);
        var ex = assertThrows(NamingRuleViolation.class, () -> eng.validateComment(
                "PLATE", "x".repeat(31), "maybe_init", NO_AUTO_NAMED));
        assertTrue(ex.getMessage().contains("31"), ex.getMessage());
        assertTrue(ex.getMessage().contains("30"), ex.getMessage());
        assertTrue(ex.getMessage().contains("Rename it, do not describe it."),
                "Configured message must be appended. Got: " + ex.getMessage());
    }

    @Test
    @DisplayName("Comment at exactly max_length passes")
    void commentAtLimit_passes() throws IOException {
        var eng = fromYaml(COMMENT_YAML);
        assertDoesNotThrow(() -> eng.validateComment(
                "PLATE", "x".repeat(30), "maybe_init", NO_AUTO_NAMED));
    }

    @Test
    @DisplayName("require_named_function rejects a comment inside a FUN_-named function")
    void autoNamedFunction_rejected() throws IOException {
        var eng = fromYaml(COMMENT_YAML);
        var ex = assertThrows(NamingRuleViolation.class, () -> eng.validateComment(
                "PLATE", "short", "FUN_00401000", NO_AUTO_NAMED));
        assertTrue(ex.getMessage().contains("FUN_00401000"), ex.getMessage());
        assertTrue(ex.getMessage().contains("rename_function"),
                "Message must name the exact next call. Got: " + ex.getMessage());
    }

    @Test
    @DisplayName("require_named_function accepts a function a person has named")
    void namedFunction_passes() throws IOException {
        var eng = fromYaml(COMMENT_YAML);
        assertDoesNotThrow(() -> eng.validateComment(
                "PLATE", "short", "maybe_board_init", NO_AUTO_NAMED));
    }

    @Test
    @DisplayName("Comment on data (no enclosing function) skips the function-state rules")
    void noEnclosingFunction_skipsFunctionRules() throws IOException {
        var eng = fromYaml(COMMENT_YAML);
        assertDoesNotThrow(() -> eng.validateComment("PLATE", "short", null, () -> 99));
    }

    @Test
    @DisplayName("max_auto_named_variables rejects over the limit and points at the fix")
    void tooManyAutoNamedVariables_rejected() throws IOException {
        var eng = fromYaml(COMMENT_YAML);
        var ex = assertThrows(NamingRuleViolation.class, () -> eng.validateComment(
                "PLATE", "short", "maybe_init", () -> 3));
        assertTrue(ex.getMessage().contains("3"), ex.getMessage());
        assertTrue(ex.getMessage().contains("get_function_variables"), ex.getMessage());
        assertDoesNotThrow(() -> eng.validateComment(
                "PLATE", "short", "maybe_init", () -> 2));
    }

    @Test
    @DisplayName("The variable count is not computed unless a rule needs it")
    void variableCount_notComputedWhenUnused() throws IOException {
        var eng = fromYaml(
                "comments:\n" +
                "  PLATE:\n" +
                "    max_length: 30\n");
        assertDoesNotThrow(() -> eng.validateComment("PLATE", "short", "FUN_00401000",
                () -> { throw new AssertionError("counted variables for a max_length-only rule"); }));
    }

    @Test
    @DisplayName("Clearing a comment is always allowed")
    void blankComment_alwaysPasses() throws IOException {
        var eng = fromYaml(COMMENT_YAML);
        assertDoesNotThrow(() -> eng.validateComment("PLATE", "", "FUN_00401000", () -> 99));
        assertDoesNotThrow(() -> eng.validateComment("PLATE", null, "FUN_00401000", () -> 99));
    }

    @Test
    @DisplayName("Auto-generated name detection covers Ghidra's own spellings only")
    void autoGeneratedNameDetection() {
        assertTrue(RulesEngine.isAutoGeneratedFunctionName("FUN_00401000"));
        assertTrue(RulesEngine.isAutoGeneratedFunctionName("SUB_00401000"));
        assertTrue(RulesEngine.isAutoGeneratedFunctionName("thunk_FUN_00401000"));
        assertFalse(RulesEngine.isAutoGeneratedFunctionName("maybe_init"));
        assertFalse(RulesEngine.isAutoGeneratedFunctionName("main"));
        assertFalse(RulesEngine.isAutoGeneratedFunctionName(null));

        assertTrue(RulesEngine.isAutoGeneratedVariableName("local_2c"));
        assertTrue(RulesEngine.isAutoGeneratedVariableName("param_1"));
        assertFalse(RulesEngine.isAutoGeneratedVariableName("maybe_count"));
        assertFalse(RulesEngine.isAutoGeneratedVariableName(null));
    }

    // -----------------------------------------------------------------------------------
    // Known key sets
    // -----------------------------------------------------------------------------------

    @Test
    @DisplayName("label_name and global_name are accepted and applied independently")
    void labelAndGlobalRules_areIndependent() throws IOException {
        String yaml = "naming:\n" +
                      "  label_name:\n" +
                      "    pattern: \"^lbl_.*$\"\n" +
                      "    message: \"labels start with lbl_\"\n" +
                      "  global_name:\n" +
                      "    pattern: \"^g_.*$\"\n" +
                      "    message: \"globals start with g_\"\n";
        RulesEngine eng = fromYaml(yaml);

        assertDoesNotThrow(() -> eng.validate("label_name", "lbl_reset_vector"));
        assertDoesNotThrow(() -> eng.validate("global_name", "g_tick_count"));
        assertThrows(NamingRuleViolation.class, () -> eng.validate("label_name", "g_tick_count"));
        assertThrows(NamingRuleViolation.class, () -> eng.validate("global_name", "lbl_reset_vector"));
        // A function_name rule must not leak onto either of them.
        assertDoesNotThrow(() -> eng.validate("function_name", "UART0_CTRL"));
    }

    @Test
    @DisplayName("An unknown naming key is rejected and every valid key is listed")
    void unknownNamingKey_rejectedWithTheValidKeys() throws IOException {
        String yaml = "naming:\n" +
                      "  lable_name:\n" +
                      "    pattern: \"^lbl_.*$\"\n";
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> fromYaml(yaml));
        assertTrue(ex.getMessage().contains("lable_name"),
                "Error must name the offending key. Got: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("label_name") && ex.getMessage().contains("variable_name"),
                "Error must list the keys that exist. Got: " + ex.getMessage());
    }

    @Test
    @DisplayName("An unknown comment type is rejected rather than silently ignored")
    void unknownCommentType_rejected() throws IOException {
        String yaml = "comments:\n" +
                      "  PLATE_COMMENT:\n" +
                      "    max_length: 100\n";
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> fromYaml(yaml));
        assertTrue(ex.getMessage().contains("PLATE_COMMENT"),
                "Error must name the offending key. Got: " + ex.getMessage());
        assertTrue(ex.getMessage().contains("PLATE"),
                "Error must list the valid comment types. Got: " + ex.getMessage());
    }

    @Test
    @DisplayName("Every key a write tool validates is in KNOWN_NAMING_FIELDS")
    void knownNamingFields_coversEveryValidatedKey() {
        // The list is what rules.yaml is checked against; if a tool ever validates a key that is
        // not here, that key becomes unconfigurable — the rule would be rejected at startup.
        assertEquals(
                java.util.List.of("function_name", "variable_name", "struct_name",
                        "struct_field_name", "label_name", "global_name"),
                RulesEngine.KNOWN_NAMING_FIELDS);
    }

    // -----------------------------------------------------------------------------------
    // reads.max_without_write — the read budget
    // -----------------------------------------------------------------------------------

    private static RulesEngine budget(int max, boolean allowIgnore, String message) {
        RulesConfig cfg = new RulesConfig();
        RulesConfig.Reads reads = new RulesConfig.Reads();
        reads.setMax_without_write(max);
        reads.setAllow_ignore(allowIgnore);
        reads.setMessage(message);
        cfg.setReads(reads);
        return new RulesEngine(cfg);
    }

    @Test
    @DisplayName("No reads section means an unlimited budget")
    void readBudget_unconfigured_neverRefuses() {
        var eng = new RulesEngine(new RulesConfig());
        assertEquals(0, eng.getMaxReadsWithoutWrite());
        for (int i = 0; i < 100; i++) {
            assertDoesNotThrow(() -> eng.noteBudgetedRead("decompile_function"));
        }
    }

    @Test
    @DisplayName("max_without_write: 0 disables the budget explicitly")
    void readBudget_zero_neverRefuses() {
        var eng = budget(0, false, null);
        for (int i = 0; i < 100; i++) {
            assertDoesNotThrow(() -> eng.noteBudgetedRead("get_disassembly"));
        }
    }

    @Test
    @DisplayName("allow_ignore: false refuses every read until a write clears the budget")
    void readBudget_forcing_staysExhaustedUntilWrite() {
        var eng = budget(2, false, null);
        assertDoesNotThrow(() -> eng.noteBudgetedRead("decompile_function"));
        assertDoesNotThrow(() -> eng.noteBudgetedRead("decompile_function"));

        // Exhausted, and it stays exhausted — repeating does not wear the refusal down.
        assertThrows(NamingRuleViolation.class, () -> eng.noteBudgetedRead("decompile_function"));
        assertThrows(NamingRuleViolation.class, () -> eng.noteBudgetedRead("decompile_function"));
        assertThrows(NamingRuleViolation.class, () -> eng.noteBudgetedRead("get_disassembly"));

        eng.noteRecordedWrite();
        assertDoesNotThrow(() -> eng.noteBudgetedRead("decompile_function"));
        assertDoesNotThrow(() -> eng.noteBudgetedRead("decompile_function"));
        assertThrows(NamingRuleViolation.class, () -> eng.noteBudgetedRead("decompile_function"));
    }

    @Test
    @DisplayName("allow_ignore: true resets the budget as the error is raised")
    void readBudget_ignorable_resetsOnRefusal() {
        var eng = budget(2, true, null);
        assertDoesNotThrow(() -> eng.noteBudgetedRead("decompile_function"));
        assertDoesNotThrow(() -> eng.noteBudgetedRead("decompile_function"));
        assertThrows(NamingRuleViolation.class, () -> eng.noteBudgetedRead("decompile_function"));

        // The refusal itself was the reset, so a full budget is available again with no write.
        assertDoesNotThrow(() -> eng.noteBudgetedRead("decompile_function"));
        assertDoesNotThrow(() -> eng.noteBudgetedRead("decompile_function"));
        assertThrows(NamingRuleViolation.class, () -> eng.noteBudgetedRead("decompile_function"));
    }

    @Test
    @DisplayName("A configured message is the whole error — nothing is added to it")
    void readBudget_configuredMessage_isUsedVerbatim() {
        String configured = "Project rule: name it before you read on.";
        var eng = budget(3, false, configured);
        for (int i = 0; i < 3; i++) eng.noteBudgetedRead("decompile_function");

        var ex = assertThrows(NamingRuleViolation.class,
                () -> eng.noteBudgetedRead("decompile_function"));
        assertEquals("read_budget", ex.getFieldType());
        assertEquals("decompile_function", ex.getOffendingName());
        assertEquals(configured, ex.getMessage(),
                "The project's own wording must reach the agent unaltered");
    }

    @Test
    @DisplayName("allow_ignore does not change the configured message either")
    void readBudget_configuredMessage_isUsedVerbatimWhenIgnorable() {
        String configured = "Write something down first.";
        var eng = budget(1, true, configured);
        eng.noteBudgetedRead("get_disassembly");
        var ex = assertThrows(NamingRuleViolation.class,
                () -> eng.noteBudgetedRead("get_disassembly"));
        assertEquals(configured, ex.getMessage());
    }

    @Test
    @DisplayName("With no configured message the built-in diagnostic states the limit and the fix")
    void readBudget_withoutMessage_fallsBackToTheBuiltInDiagnostic() {
        var eng = budget(3, false, null);
        for (int i = 0; i < 3; i++) eng.noteBudgetedRead("decompile_function");

        var ex = assertThrows(NamingRuleViolation.class,
                () -> eng.noteBudgetedRead("decompile_function"));
        assertTrue(ex.getMessage().contains("reads.max_without_write"), ex.getMessage());
        assertTrue(ex.getMessage().contains("3"), ex.getMessage());
        assertTrue(ex.getMessage().contains("rename_function"), ex.getMessage());
        assertTrue(ex.getMessage().contains("set_comment does not clear this budget"), ex.getMessage());
    }

    @Test
    @DisplayName("The reads section is read from YAML")
    void readBudget_parsesFromYaml() throws IOException {
        var eng = fromYaml("reads:\n" +
                           "  max_without_write: 4\n" +
                           "  allow_ignore: true\n" +
                           "  message: write it down\n");
        assertEquals(4, eng.getMaxReadsWithoutWrite());
        assertTrue(eng.isReadBudgetIgnorable());
        for (int i = 0; i < 4; i++) eng.noteBudgetedRead("decompile_function");
        var ex = assertThrows(NamingRuleViolation.class,
                () -> eng.noteBudgetedRead("decompile_function"));
        assertEquals("write it down", ex.getMessage());
    }

    @Test
    @DisplayName("A negative max_without_write is rejected rather than treated as disabled")
    void readBudget_negative_isRejected() throws IOException {
        var eng = fromYaml("reads:\n  max_without_write: -1\n");
        var ex = assertThrows(IllegalArgumentException.class, eng::getMaxReadsWithoutWrite);
        assertTrue(ex.getMessage().contains("reads.max_without_write"), ex.getMessage());
    }

    @Test
    @DisplayName("A misspelled key under reads: is rejected at load")
    void readBudget_unknownKey_isRejected() {
        var ex = assertThrows(IllegalArgumentException.class,
                () -> fromYaml("reads:\n  max_without_writes: 5\n"));
        assertTrue(ex.getMessage().contains("max_without_writes"),
                "Error must name the offending key. Got: " + ex.getMessage());
    }

    @Test
    @DisplayName("The shipped rules.yaml loads cleanly")
    void shippedRulesYaml_loads() throws IOException {
        File shipped = new File("rules.yaml");
        assumeTrue(shipped.exists(), "rules.yaml not present in the working directory");
        assertDoesNotThrow(() -> RulesEngine.load(shipped));
    }
}


