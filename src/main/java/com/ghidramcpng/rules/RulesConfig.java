package com.ghidramcpng.rules;

import java.util.HashMap;
import java.util.Map;

/**
 * Parsed representation of rules.yaml.
 *
 * Designed for SnakeYAML 2.x automatic bean mapping — all fields must have
 * public no-arg constructors and JavaBean-style getters/setters.
 *
 * YAML structure:
 * <pre>
 * naming:
 *   function_name:
 *     pattern: "^(maybe_|likely_|guess_)..."
 *     message: "..."
 * </pre>
 */
public class RulesConfig {

    private Map<String, FieldRule> naming = new HashMap<>();
    private Map<String, CommentRule> comments = new HashMap<>();
    private Timeouts timeouts = new Timeouts();
    private Import imports = new Import();

    public Map<String, FieldRule> getNaming() {
        return naming;
    }

    public void setNaming(Map<String, FieldRule> naming) {
        this.naming = naming != null ? naming : new HashMap<>();
    }

    public Map<String, CommentRule> getComments() {
        return comments;
    }

    public void setComments(Map<String, CommentRule> comments) {
        this.comments = comments != null ? comments : new HashMap<>();
    }

    public Timeouts getTimeouts() {
        return timeouts;
    }

    public void setTimeouts(Timeouts timeouts) {
        this.timeouts = timeouts != null ? timeouts : new Timeouts();
    }

    public Import getImports() {
        return imports;
    }

    /** YAML key is "import" — SnakeYAML maps it via setImports(). */
    public void setImport(Import imports) {
        this.imports = imports != null ? imports : new Import();
    }

    /** Configuration for a single named field type (e.g. "function_name"). */
    public static class FieldRule {

        /** Java regex that the name must fully match (Pattern.matches). */
        private String pattern;

        /** Human-readable error message shown when the rule is violated. */
        private String message;

        public String getPattern() {
            return pattern;
        }

        public void setPattern(String pattern) {
            this.pattern = pattern;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }
    }

    /**
     * Constraints on one comment type (PRE, POST, EOL, PLATE, REPEATABLE).
     *
     * <p>All three constraints are independent and all are off unless set, so a project that
     * wants none of this simply omits the {@code comments:} section. They exist because a
     * comment is one cheap unvalidated call while naming is N validated ones, and an agent
     * follows that gradient — writing the analysis as prose and leaving {@code local_2c} behind.
     */
    public static class CommentRule {

        /** Maximum comment length, tightening the global 4096-char cap. */
        private Integer max_length;

        /**
         * When true, reject a comment on an address inside a function whose name is still
         * Ghidra's auto-generated one. Encodes "name it before you describe it" directly,
         * rather than approximating it with a length cap that many short comments defeat.
         */
        private Boolean require_named_function = false;

        /**
         * When set, reject a comment on a function that still has more than this many
         * auto-named variables in the listing.
         */
        private Integer max_auto_named_variables;

        /** Error message shown when any of the above is violated. */
        private String message;

        public Integer getMax_length() {
            return max_length;
        }

        public void setMax_length(Integer max_length) {
            this.max_length = max_length;
        }

        public Boolean getRequire_named_function() {
            return require_named_function;
        }

        public void setRequire_named_function(Boolean require_named_function) {
            this.require_named_function = require_named_function != null && require_named_function;
        }

        public Integer getMax_auto_named_variables() {
            return max_auto_named_variables;
        }

        public void setMax_auto_named_variables(Integer max_auto_named_variables) {
            this.max_auto_named_variables = max_auto_named_variables;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }
    }

    /** Timeout settings for long-running Ghidra operations. */
    public static class Timeouts {

        /** Maximum time to wait for one decompilation attempt, in seconds. */
        private Integer decompile_seconds = 60;

        public Integer getDecompile_seconds() {
            return decompile_seconds;
        }

        public void setDecompile_seconds(Integer decompile_seconds) {
            this.decompile_seconds = decompile_seconds;
        }
    }

    /** Settings that govern the import_binary tool. */
    public static class Import {

        /**
         * Minimum number of path components required in the project_dir supplied to
         * import_binary. 0 means the project root ("/") is permitted. 1 requires at
         * least one sub-folder (e.g. "binaries"), 2 requires two levels, etc.
         */
        private Integer min_directory_depth = 0;

        /**
         * When set, the absolute file path supplied to import_binary must start with
         * this prefix, and the project_dir must equal the relative directory path of
         * the file after stripping this prefix.
         *
         * Example: require_child_path: /a/
         *   Importing /a/hello/bin/moo.exe  → project_dir must be "hello/bin"
         */
        private String require_child_path = null;

        public Integer getMin_directory_depth() {
            return min_directory_depth;
        }

        public void setMin_directory_depth(Integer min_directory_depth) {
            this.min_directory_depth = min_directory_depth != null ? min_directory_depth : 0;
        }

        public String getRequire_child_path() {
            return require_child_path;
        }

        public void setRequire_child_path(String require_child_path) {
            this.require_child_path = (require_child_path == null || require_child_path.isBlank())
                    ? null : require_child_path;
        }
    }

    /** Returns true if no naming rules are configured. */
    public boolean isEmpty() {
        return naming.isEmpty();
    }
}
