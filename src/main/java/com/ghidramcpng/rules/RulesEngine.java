package com.ghidramcpng.rules;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Validates proposed names against the rules in rules.yaml.
 *
 * Loaded once at startup; the server must be restarted to reload the YAML.
 *
 * Validation flow for {@code validate(fieldType, name)}:
 * <ol>
 *   <li>If no rule exists for {@code fieldType}, silently pass.</li>
 *   <li>If the name does NOT fully match {@code pattern}, throw {@link NamingRuleViolation}.</li>
 * </ol>
 */
public class RulesEngine {

    private static final int DEFAULT_DECOMPILE_TIMEOUT_SECONDS = 60;

    private final RulesConfig config;
    private final Map<String, Pattern> patterns = new HashMap<>();

    /**
     * Build a RulesEngine from raw config (useful for tests providing an in-memory config).
     */
    public RulesEngine(RulesConfig config) {
        this.config = config;
        for (Map.Entry<String, RulesConfig.FieldRule> entry : config.getNaming().entrySet()) {
            String fieldType = entry.getKey();
            RulesConfig.FieldRule rule = entry.getValue();
            try {
                if (rule.getPattern() != null && !rule.getPattern().isBlank()) {
                    patterns.put(fieldType, Pattern.compile(rule.getPattern()));
                }
            } catch (PatternSyntaxException e) {
                throw new IllegalArgumentException(
                        "Invalid regex in rules for field '" + fieldType + "': " + e.getMessage(), e);
            }
        }
    }

    /**
     * Load a {@link RulesEngine} from a YAML file. Returns an engine with no rules if the
     * file is null or does not exist (permissive fallback).
     *
     * <p>Unknown YAML keys are <strong>rejected loudly</strong> rather than silently
     * dropped, so users get a clear error pointing at the offending key instead of
     * mysteriously-disabled rules.
     */
    public static RulesEngine load(File file) throws IOException {
        if (file == null || !file.exists()) {
            return new RulesEngine(new RulesConfig());
        }
        LoaderOptions loaderOptions = new LoaderOptions();
        loaderOptions.setTagInspector(tag ->
                tag.startsWith("tag:yaml.org,2002:"));  // allow only YAML built-in types
        Yaml yaml = new Yaml(new Constructor(RulesConfig.class, loaderOptions));
        try (InputStream in = new FileInputStream(file)) {
            RulesConfig config = yaml.load(in);
            if (config == null) config = new RulesConfig();
            return new RulesEngine(config);
        } catch (org.yaml.snakeyaml.error.YAMLException e) {
            StringBuilder details = new StringBuilder();
            if (e.getMessage() != null) details.append(e.getMessage());
            for (Throwable cause = e.getCause(); cause != null; cause = cause.getCause()) {
                if (cause.getMessage() != null && details.indexOf(cause.getMessage()) < 0) {
                    details.append("; ").append(cause.getMessage());
                }
            }
            String detailStr = details.toString().replaceAll("\\s+", " ").trim();
            throw new IllegalArgumentException(
                    "Failed to parse rules file '" + file + "': " + detailStr +
                    ". Check the file for typos or unsupported options.", e);
        } catch (PatternSyntaxException e) {
            throw new IllegalArgumentException(
                    "Invalid regex in rules file '" + file + "': " + e.getMessage(), e);
        }
    }

    /**
     * Validate {@code name} for {@code fieldType} (e.g. "function_name", "variable_name").
     *
     * @throws NamingRuleViolation if the name fails the configured rule
     */
    public void validate(String fieldType, String name) {
        if (name == null || name.isBlank()) return; // nothing to validate

        Pattern rule = patterns.get(fieldType);
        if (rule == null) return; // no rule configured for this field type

        if (!rule.matcher(name).matches()) {
            RulesConfig.FieldRule fr = config.getNaming().get(fieldType);
            String msg = fr.getMessage() != null ? fr.getMessage().trim()
                    : "Name '" + name + "' does not match required pattern for " + fieldType;
            throw new NamingRuleViolation(fieldType, name,
                    msg + "\n  Offending name: '" + name + "'");
        }
    }

    /** Returns true if no rules are configured (completely permissive). */
    public boolean isEmpty() {
        return patterns.isEmpty();
    }

    /**
     * Validates the {@code project_dir} and {@code filePath} combination against the
     * {@code import} section of rules.yaml:
     *
     * <ul>
     *   <li>{@code min_directory_depth} — {@code project_dir} must contain at least
     *       this many path components (0 = root is allowed).</li>
     *   <li>{@code require_child_path} — when set, {@code filePath} must start with
     *       the configured prefix, and {@code project_dir} must equal the relative
     *       parent directory of the file after stripping that prefix.</li>
     * </ul>
     *
     * @param filePath   absolute path to the binary being imported (may be null/blank
     *                   when the caller is still building the request)
     * @param projectDir project directory path as supplied by the caller (may be null,
     *                   treated as root)
     * @throws IllegalArgumentException if either constraint is violated
     */
    public void validateImport(String filePath, String projectDir) {
        RulesConfig.Import importCfg = config.getImports();
        if (importCfg == null) return;

        // Normalise projectDir: strip leading/trailing slashes, collapse empty
        String dir = (projectDir == null || projectDir.isBlank()) ? "" : projectDir.trim();
        // Remove surrounding slashes for component counting, but keep for messages
        String stripped = dir.replaceAll("^/+", "").replaceAll("/+$", "");

        // --- min_directory_depth ---
        int minDepth = importCfg.getMin_directory_depth() != null
                ? importCfg.getMin_directory_depth() : 0;
        if (minDepth > 0) {
            int depth = stripped.isEmpty() ? 0
                    : (int) stripped.chars().filter(c -> c == '/').count() + 1;
            if (depth < minDepth) {
                String example = "binaries" + "/sub".repeat(minDepth - 1);
                throw new IllegalArgumentException(
                        "import_binary requires a project_dir at least " + minDepth +
                        " level" + (minDepth == 1 ? "" : "s") + " deep " +
                        "(configured via import.min_directory_depth in rules.yaml). " +
                        "The supplied project_dir '" + (dir.isEmpty() ? "/" : dir) + "' has depth " + depth + ". " +
                        "Example of a valid project_dir: '" + example + "'.");
            }
        }

        // --- require_child_path ---
        String requiredPrefix = importCfg.getRequire_child_path();
        if (requiredPrefix != null && !requiredPrefix.isBlank()) {
            if (filePath == null || filePath.isBlank()) return; // nothing to check yet

            // Normalise prefix: ensure it ends with /
            String prefix = requiredPrefix.endsWith("/") ? requiredPrefix : requiredPrefix + "/";

            if (!filePath.startsWith(prefix)) {
                throw new IllegalArgumentException(
                        "import_binary: the file path '" + filePath + "' must be located under '" +
                        prefix + "' (configured via import.require_child_path in rules.yaml). " +
                        "Move the binary under that directory or update the rules.yaml to match your layout.");
            }

            // Derive the expected project_dir: parent dir of file, relative to prefix
            java.io.File f = new java.io.File(filePath);
            String parentPath = f.getParent() != null ? f.getParent() : "";
            // Strip the prefix from the parent to get the expected relative dir
            String relativeDir;
            if (parentPath.startsWith(prefix)) {
                relativeDir = parentPath.substring(prefix.length())
                        .replaceAll("^/+", "").replaceAll("/+$", "");
            } else if (parentPath.equals(prefix.replaceAll("/+$", ""))) {
                // Parent equals the prefix without the trailing slash — file is directly in prefix dir
                relativeDir = "";
            } else {
                relativeDir = "";
            }

            if (!stripped.equals(relativeDir)) {
                String expected = relativeDir.isEmpty() ? "/" : relativeDir;
                throw new IllegalArgumentException(
                        "import_binary: when importing '" + filePath + "' with require_child_path='" +
                        requiredPrefix + "', the project_dir must be '" + expected + "' " +
                        "(the path of the file relative to the required prefix, excluding the filename). " +
                        "You supplied '" + (dir.isEmpty() ? "/" : dir) + "'.");
            }
        }
    }

    public int getDecompileTimeoutSeconds() {
        RulesConfig.Timeouts timeouts = config.getTimeouts();
        if (timeouts == null || timeouts.getDecompile_seconds() == null) {
            return DEFAULT_DECOMPILE_TIMEOUT_SECONDS;
        }
        int configured = timeouts.getDecompile_seconds();
        if (configured <= 0) {
            throw new IllegalArgumentException(
                    "Invalid value for timeouts.decompile_seconds in rules.yaml: " + configured + ". " +
                    "The timeout must be a positive integer number of seconds.");
        }
        return configured;
    }
}
