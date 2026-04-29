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
    private Timeouts timeouts = new Timeouts();
    private Import imports = new Import();

    public Map<String, FieldRule> getNaming() {
        return naming;
    }

    public void setNaming(Map<String, FieldRule> naming) {
        this.naming = naming != null ? naming : new HashMap<>();
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
