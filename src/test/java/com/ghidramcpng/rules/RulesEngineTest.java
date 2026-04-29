package com.ghidramcpng.rules;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

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
                      "  type_a:\n" +
                      "    pattern: \"^a_.*$\"\n" +
                      "    message: \"must start with a_\"\n" +
                      "  type_b:\n" +
                      "    pattern: \"^b_.*$\"\n" +
                      "    message: \"must start with b_\"\n";
        RulesEngine eng = fromYaml(yaml);

        assertDoesNotThrow(() -> eng.validate("type_a", "a_foo"));
        assertDoesNotThrow(() -> eng.validate("type_b", "b_bar"));
        assertThrows(NamingRuleViolation.class, () -> eng.validate("type_a", "b_foo"));
        assertThrows(NamingRuleViolation.class, () -> eng.validate("type_b", "a_bar"));
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
                      "  my_field:\n" +
                      "    pattern: \"^pfx_[a-z]+$\"\n" +
                      "    message: \"Must start with pfx_\"\n";
        RulesEngine eng = fromYaml(yaml);

        assertDoesNotThrow(() -> eng.validate("my_field", "pfx_foo"));
        NamingRuleViolation ex = assertThrows(NamingRuleViolation.class,
                () -> eng.validate("my_field", "nopfx"));
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
}


