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

    /**
     * Every {@code naming:} key a write tool actually asks for. A key outside this set can only
     * be a typo, and a typo here fails silently — {@link #validate} passes when no rule is
     * configured — so the rule would appear to be in force while enforcing nothing.
     */
    public static final java.util.List<String> KNOWN_NAMING_FIELDS = java.util.List.of(
            "function_name", "variable_name", "struct_name", "struct_field_name",
            "label_name", "global_name");

    /** Every comment type {@code set_comment} accepts; the {@code comments:} keys. */
    public static final java.util.List<String> KNOWN_COMMENT_TYPES = java.util.List.of(
            "PRE", "POST", "EOL", "PLATE", "REPEATABLE");

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
            // Only the file is checked, not the constructor: a rules.yaml is human input where a
            // typo must be loud, while the RulesConfig constructor is a programmatic API that
            // tests and callers may legitimately drive with any field type.
            rejectUnknownKeys(file, "naming", config.getNaming().keySet(), KNOWN_NAMING_FIELDS);
            rejectUnknownKeys(file, "comments", config.getComments().keySet(), KNOWN_COMMENT_TYPES);
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

    private static void rejectUnknownKeys(File file, String section,
            java.util.Collection<String> provided, java.util.List<String> known) {
        for (String key : provided) {
            if (known.contains(key)) {
                continue;
            }
            StringBuilder message = new StringBuilder()
                    .append("Unknown key '").append(key).append("' under '").append(section)
                    .append(":' in rules file '").append(file).append("'. ")
                    .append("Valid keys: ").append(String.join(", ", known)).append(".");
            String suggestion = com.ghidramcpng.mcp.ApiSupport.suggestClosest(key, known);
            if (suggestion != null) {
                message.append(" Did you mean '").append(suggestion).append("'?");
            }
            throw new IllegalArgumentException(message.toString());
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

    // -----------------------------------------------------------------------------------
    // reads.max_without_write — the read budget
    // -----------------------------------------------------------------------------------

    /**
     * The read tools that spend the budget. Both hand the agent a function's contents, which is
     * exactly the point at which it learns something worth writing down. Every other read tool
     * (searches, xrefs, listings) is navigation — it locates the next thing to look at rather
     * than producing a finding, so charging it would only push the agent to navigate less.
     */
    public static final java.util.List<String> BUDGETED_READ_TOOLS =
            java.util.List.of("decompile_function", "get_disassembly");

    /**
     * Reads charged since the last recorded write. Server-wide rather than per-program: the
     * budget describes the agent's habit, and an agent that alternates between two programs is
     * still one agent that has written nothing down.
     */
    private int readsSinceWrite = 0;

    private final Object readBudgetLock = new Object();

    /** The configured budget, or 0 when {@code reads.max_without_write} is unset/disabled. */
    public int getMaxReadsWithoutWrite() {
        RulesConfig.Reads reads = config.getReads();
        if (reads == null || reads.getMax_without_write() == null) {
            return 0;
        }
        int configured = reads.getMax_without_write();
        if (configured < 0) {
            throw new IllegalArgumentException(
                    "Invalid value for reads.max_without_write in rules.yaml: " + configured + ". " +
                    "The budget must be 0 (disabled) or a positive number of reads.");
        }
        return configured;
    }

    /** True when a spent budget only warns: {@code reads.allow_ignore} resets it as it fires. */
    public boolean isReadBudgetIgnorable() {
        RulesConfig.Reads reads = config.getReads();
        return reads != null && Boolean.TRUE.equals(reads.getAllow_ignore());
    }

    /**
     * Charge one budgeted read, called by the tools in {@link #BUDGETED_READ_TOOLS} once their
     * arguments have resolved and before they do the work.
     *
     * <p>When {@code reads.allow_ignore} is true the budget is reset as the error is raised, so
     * the refusal is advisory: repeating the call succeeds and the error returns one budget
     * later. When it is false the budget stays spent and every further read is refused until
     * {@link #noteRecordedWrite()} clears it.
     *
     * @throws NamingRuleViolation if the budget is exhausted
     */
    public void noteBudgetedRead(String toolName) {
        int max = getMaxReadsWithoutWrite();
        if (max <= 0) return;

        boolean allowIgnore = isReadBudgetIgnorable();
        synchronized (readBudgetLock) {
            if (readsSinceWrite < max) {
                readsSinceWrite++;
                return;
            }
            // Reset before throwing, so the read that was refused is not also charged.
            if (allowIgnore) readsSinceWrite = 0;
        }
        throw readBudgetViolation(toolName, max);
    }

    /**
     * Clear the budget: a write tool has just recorded a finding. Called on the success path of
     * the writes that persist analysis — names, types, prototypes, structs.
     */
    public void noteRecordedWrite() {
        synchronized (readBudgetLock) {
            readsSinceWrite = 0;
        }
    }

    /**
     * The whole diagnostic when {@code reads.message} is unset. A configured message replaces
     * this outright — it is the project's own wording, and appending to it would put words the
     * project did not write in front of the agent.
     */
    private static String defaultReadBudgetMessage(int max) {
        return "Read budget exhausted: " + max + " " + String.join("/", BUDGETED_READ_TOOLS) +
                (max == 1 ? " call has run" : " calls have run") +
                " since the last recorded write, which is the limit set by " +
                "reads.max_without_write in rules.yaml. Write down what you have already found " +
                "before reading more — any of rename_function, set_variable, set_global, " +
                "create_label, set_function_prototype, set_parameter_type, create_struct, " +
                "add_struct_field, remove_struct_field or replace_struct_field clears the budget, " +
                "and several can be batched with batch_tool_call. " +
                "set_comment does not clear this budget; prose is what the budget exists to stop " +
                "substituting for names and types.";
    }

    private NamingRuleViolation readBudgetViolation(String toolName, int max) {
        String configured = config.getReads().getMessage();
        String message = (configured == null || configured.isBlank())
                ? defaultReadBudgetMessage(max)
                : configured.trim();
        return new NamingRuleViolation("read_budget", toolName, message);
    }

    /**
     * Names Ghidra generates itself for a function it found but nobody has identified.
     * Not configurable: these are Ghidra's own conventions, not a project preference.
     */
    private static final Pattern AUTO_FUNCTION_NAME =
            Pattern.compile("^(FUN_|SUB_|thunk_FUN_).*");

    /**
     * Names Ghidra generates itself for a listing variable nobody has identified.
     * Decompiler-invented registers ({@code uVar7}) never reach the listing, so only the
     * stack/parameter spellings are matched here — see {@link #countAutoNamedVariables}
     * callers for what that means in practice.
     */
    private static final Pattern AUTO_VARIABLE_NAME =
            Pattern.compile("^(local_|param_|unaff_|in_|extraout_).*");

    /** True if {@code name} is one Ghidra invented rather than one a person chose. */
    public static boolean isAutoGeneratedFunctionName(String name) {
        return name != null && AUTO_FUNCTION_NAME.matcher(name).matches();
    }

    /** True if {@code name} is one Ghidra invented rather than one a person chose. */
    public static boolean isAutoGeneratedVariableName(String name) {
        return name != null && AUTO_VARIABLE_NAME.matcher(name).matches();
    }

    /** True if any {@code comments:} rule is configured; lets callers skip the lookups below. */
    public boolean hasCommentRules() {
        return !config.getComments().isEmpty();
    }

    /**
     * Validate a comment against the {@code comments:} section of rules.yaml.
     *
     * <p>The caller supplies the surrounding facts rather than a {@code Program}, so this class
     * stays free of Ghidra types. {@code autoNamedVariableCount} is a supplier because only the
     * {@code max_auto_named_variables} rule needs it and walking the listing is wasted work
     * otherwise.
     *
     * @param commentType            comment type, already upper-cased (PRE, PLATE, …)
     * @param comment                the comment text about to be written
     * @param containingFunctionName name of the function containing the target address, or null
     *                               when the address is not inside one
     * @param autoNamedVariableCount how many of that function's listing variables are still
     *                               auto-named; not consulted unless a rule needs it
     * @throws NamingRuleViolation if the comment fails the configured rule
     */
    public void validateComment(String commentType, String comment,
            String containingFunctionName, java.util.function.IntSupplier autoNamedVariableCount) {
        RulesConfig.CommentRule rule = config.getComments().get(commentType);
        if (rule == null) return;
        // Clearing a comment is always allowed — it can only reduce what the rule objects to.
        if (comment == null || comment.isBlank()) return;

        if (rule.getMax_length() != null && comment.length() > rule.getMax_length()) {
            throw violation(commentType, rule,
                    "This " + commentType + " comment is " + comment.length() + " characters; the limit is " +
                    rule.getMax_length() + ".");
        }

        // Both remaining rules are about the state of the enclosing function, so a comment on
        // data (no enclosing function) is out of their scope entirely.
        if (containingFunctionName == null) return;

        if (Boolean.TRUE.equals(rule.getRequire_named_function())
                && isAutoGeneratedFunctionName(containingFunctionName)) {
            throw violation(commentType, rule,
                    "Function '" + containingFunctionName + "' still has its auto-generated name, so a " +
                    commentType + " comment is the only record of what you found. " +
                    "Call rename_function on '" + containingFunctionName + "' first.");
        }

        if (rule.getMax_auto_named_variables() != null) {
            int autoNamed = autoNamedVariableCount.getAsInt();
            if (autoNamed > rule.getMax_auto_named_variables()) {
                throw violation(commentType, rule,
                        "Function '" + containingFunctionName + "' still has " + autoNamed +
                        " auto-named variables; the limit for a " + commentType + " comment is " +
                        rule.getMax_auto_named_variables() + ". " +
                        "Call get_function_variables on '" + containingFunctionName + "' to see them, " +
                        "then set_variable (batch them with batch_tool_call).");
            }
        }
    }

    private static NamingRuleViolation violation(String commentType, RulesConfig.CommentRule rule,
            String detail) {
        String configured = rule.getMessage() != null ? rule.getMessage().trim() : null;
        return new NamingRuleViolation("comment_" + commentType.toLowerCase(), commentType,
                configured == null ? detail : detail + "\n  " + configured);
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
