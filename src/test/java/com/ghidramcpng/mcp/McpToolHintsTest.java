package com.ghidramcpng.mcp;

import com.ghidramcpng.tools.ReadTools;
import com.ghidramcpng.tools.ScriptTool;
import com.ghidramcpng.tools.WriteTools;
import io.swagger.v3.jaxrs2.Reader;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Guards the hint tables against drift. They name tools by string, so a renamed or deleted tool
 * leaves an entry that silently stops applying — the bridge would go on publishing a derived
 * default and nothing would fail. These tests are the thing that fails.
 */
class McpToolHintsTest {

    private static Map<String, Operation> operations;
    private static Map<String, String> methods;

    @BeforeAll
    static void readSpec() {
        OpenAPI spec = new Reader(new OpenAPI())
                .read(Set.of(ReadTools.class, WriteTools.class, ScriptTool.class));
        McpToolHints.apply(spec);

        operations = new HashMap<>();
        methods = new HashMap<>();
        for (PathItem pathItem : spec.getPaths().values()) {
            pathItem.readOperationsMap().forEach((method, operation) -> {
                operations.put(operation.getOperationId(), operation);
                methods.put(operation.getOperationId(), method.name().toLowerCase());
            });
        }
    }

    @Test
    void everyNamedToolStillExists() {
        Set<String> missing = new TreeSet<>(McpToolHints.namedTools());
        missing.removeAll(operations.keySet());
        assertTrue(missing.isEmpty(),
                "hint tables name tools that no longer exist: " + missing);
    }

    @Test
    void noReadToolIsGivenAWriteToolsHints() {
        // destructive/idempotent/open_world all follow from the method for a GET; naming one
        // here means the table and the derivation disagree about what the tool does.
        for (String tool : McpToolHints.writeOnlyTools()) {
            assertEquals("post", methods.get(tool),
                    tool + " is a read tool — its hints are derived, not declared");
        }
    }

    @Test
    void onlyNamedToolsCarryTheExtension() {
        Set<String> annotated = new TreeSet<>();
        operations.forEach((id, operation) -> {
            if (operation.getExtensions() != null && operation.getExtensions().containsKey("x-mcp")) {
                annotated.add(id);
            }
        });
        assertEquals(McpToolHints.namedTools(), annotated);
    }

    @Test
    void everyTimeoutIsLongerThanTheBridgeDefault() {
        // A shorter one would be a slower tool asking to be cut off sooner, which is never
        // the intent — the table exists for the tools that outlast the default.
        for (String tool : McpToolHints.namedTools()) {
            Object hints = operations.get(tool).getExtensions().get("x-mcp");
            Object seconds = ((Map<?, ?>) hints).get("timeout_seconds");
            if (seconds != null) {
                assertTrue(((Number) seconds).intValue() > 120,
                        tool + " declares a timeout no longer than the default");
            }
        }
    }

    @Test
    void theSlowToolsAllDeclareATimeout() {
        // Full auto-analysis and script runs are the calls that blow past any default; leaving
        // one of them off the table is how an agent gets told the server is unreachable.
        for (String tool : Set.of("analyze_program", "import_binary", "run_script")) {
            Object hints = operations.get(tool).getExtensions().get("x-mcp");
            assertNotNull(hints, tool + " must declare how long it may run");
            assertNotNull(((Map<?, ?>) hints).get("timeout_seconds"),
                    tool + " must declare how long it may run");
        }
    }

    @Test
    void theToolsThatReachOutsideTheProjectSaySo() {
        for (String tool : Set.of("add_script", "import_binary", "run_script")) {
            Map<?, ?> hints = (Map<?, ?>) operations.get(tool).getExtensions().get("x-mcp");
            assertEquals(Boolean.TRUE, hints.get("open_world"),
                    tool + " reads a host path or runs host code");
        }
    }

    @Test
    void applyIsSafeBeforeTheSpecHasBeenRead() {
        // /openapi.json is served from a context that may not have read yet
        assertDoesNotThrow(() -> McpToolHints.apply(new OpenAPI()));
        assertDoesNotThrow(() -> McpToolHints.apply(null));
    }
}
