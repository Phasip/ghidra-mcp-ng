package com.ghidramcpng.rules;

/**
 * Thrown when a proposed name violates a naming rule defined in rules.yaml.
 *
 * This is a RuntimeException so tool handlers can throw it without wrapping,
 * and the MCP server converts it to an isError=true tool response.
 */
public class NamingRuleViolation extends RuntimeException {

    private final String fieldType;
    private final String offendingName;

    public NamingRuleViolation(String fieldType, String offendingName, String message) {
        super(message);
        this.fieldType = fieldType;
        this.offendingName = offendingName;
    }

    /** The rule category that was violated, e.g. "function_name". */
    public String getFieldType() {
        return fieldType;
    }

    /** The name that did not match the rule. */
    public String getOffendingName() {
        return offendingName;
    }
}
