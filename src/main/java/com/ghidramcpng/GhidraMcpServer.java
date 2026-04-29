package com.ghidramcpng;

import com.ghidramcpng.mcp.HttpApiServer;
import com.ghidramcpng.program.ProgramManager;
import com.ghidramcpng.rules.RulesEngine;
import com.ghidramcpng.tools.ReadTools;
import com.ghidramcpng.tools.ScriptTool;
import com.ghidramcpng.tools.WriteTools;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;

import java.io.File;
import java.util.Arrays;
import java.util.Iterator;
import java.util.concurrent.CountDownLatch;

/**
 * Main entry point for the {@code ghidra-mcp-ng} HTTP server.
 *
 * <p>Implements {@link GhidraLaunchable} so it can be started with Ghidra's
 * {@code support/launch.sh} script via {@code start.py}:
 *
 * <pre>
 *   ./start.py --ghidra /path/to/ghidra --project /path/to/MyProject [--rules rules.yaml]
 * </pre>
 *
 * <p>The server exposes an HTTP REST API on {@code 127.0.0.1:<port>} (default 8192).
 * A separate Python bridge can translate the HTTP schema into stdio MCP tools.
 *
 * <h3>CLI arguments</h3>
 * <dl>
 *   <dt>{@code --project <path>}</dt>
 *   <dd>Required. Path to Ghidra project directory (contains {@code <name>.rep}).</dd>
 *   <dt>{@code --rules <path>}</dt>
 *   <dd>Optional. Path to server YAML. If omitted, naming rules are disabled and
 *       default timeout settings are used. The file must exist — a missing path is an error.</dd>
 *   <dt>{@code --port <n>}</dt>
 *   <dd>Optional. HTTP port (default 8192). Binds to 127.0.0.1 only.</dd>
 * </dl>
 */
public class GhidraMcpServer implements GhidraLaunchable {

    @Override
    public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {

        // Parse arguments

        String projectPath = null;
        String rulesPath = null;
        int port = 8192;

        Iterator<String> it = Arrays.asList(args).iterator();
        while (it.hasNext()) {
            String arg = it.next();
            switch (arg) {
                case "--project":
                    if (!it.hasNext()) die("--project requires a path argument");
                    projectPath = it.next();
                    break;
                case "--rules":
                    if (!it.hasNext()) die("--rules requires a path argument");
                    rulesPath = it.next();
                    break;
                case "--port":
                    if (!it.hasNext()) die("--port requires a number argument");
                    try {
                        port = Integer.parseInt(it.next());
                    } catch (NumberFormatException e) {
                        die("--port must be a valid port number (1-65535)");
                    }
                    break;
                default:
                    System.err.println("[ghidra-mcp-ng] WARNING: unknown argument ignored: " + arg);
            }
        }

        if (projectPath == null) {
            die("Required argument --project <path> is missing.\n" +
                "Usage: ./start.py --ghidra <ghidra_path> --project <project_path> [--rules FILE] [--port PORT]");
        }

        // Resolve project directory

        File projectDir = new File(projectPath).getCanonicalFile();
        String projectName = projectDir.getName();
        String projectParent = projectDir.getParent();

        if (projectParent == null) {
            die("Cannot determine parent directory of project path: " + projectPath);
        }

        // Initialise Ghidra

        System.err.println("[ghidra-mcp-ng] Initialising Ghidra application ...");
        HeadlessGhidraApplicationConfiguration config =
                new HeadlessGhidraApplicationConfiguration();
        config.setInitializeLogging(false);
        Application.initializeApplication(layout, config);

        // Script support: acquireBundleHostReference() initialises the OSGi BundleHost
        // (null until called), required for Java script execution.
        System.err.println("[ghidra-mcp-ng] Initialising script support ...");
        GhidraScriptUtil.acquireBundleHostReference();

        // Open project

        System.err.println("[ghidra-mcp-ng] Opening project: " + projectDir);
        GhidraProject ghidraProject =
                GhidraProject.openProject(projectParent, projectName, false);

        // Load naming rules

        RulesEngine rules;
        if (rulesPath == null) {
            rules = RulesEngine.load(null);
            System.err.printf("[ghidra-mcp-ng] No rules file supplied — naming rules disabled, decompile timeout defaulting to %d second(s)%n",
                    rules.getDecompileTimeoutSeconds());
        } else {
            File rulesFile = new File(rulesPath).getCanonicalFile();
            if (!rulesFile.exists()) {
                die("Rules file not found: " + rulesFile + "\n" +
                    "Pass a valid path or omit --rules to disable naming rules.");
            }
            try {
                rules = RulesEngine.load(rulesFile);
            } catch (IllegalArgumentException e) {
                die(e.getMessage());
                return; // unreachable; keeps the compiler happy about `rules`
            }
            System.err.printf("[ghidra-mcp-ng] Loaded server config from: %s (decompile timeout: %d second(s))%n",
                    rulesFile, rules.getDecompileTimeoutSeconds());
        }

        // Register tools

        ProgramManager mgr = new ProgramManager(ghidraProject);
        ReadTools readTools = new ReadTools(mgr, rules.getDecompileTimeoutSeconds());
        WriteTools writeTools = new WriteTools(mgr, rules);
        ScriptTool scriptTool = new ScriptTool(mgr);

        System.err.printf("[ghidra-mcp-ng] %d HTTP tool endpoints available%n",
            ReadTools.TOOL_COUNT + WriteTools.TOOL_COUNT + ScriptTool.TOOL_COUNT);

        // Start HTTP server

        final int finalPort = port;
        HttpApiServer httpServer = new HttpApiServer(port, readTools, writeTools, scriptTool);

        CountDownLatch shutdown = new CountDownLatch(1);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.err.println("[ghidra-mcp-ng] Shutdown signal received, stopping ...");
            httpServer.stop();
            mgr.closeAll();
            GhidraScriptUtil.releaseBundleHostReference();
            try { ghidraProject.close(); } catch (Exception e) {
                System.err.println("[ghidra-mcp-ng] Warning: failed to close Ghidra project: " + e);
            }
            shutdown.countDown();
        }, "mcp-shutdown"));

        httpServer.start();
        System.err.printf("[ghidra-mcp-ng] Ready. Connect with: python bridge.py --url http://127.0.0.1:%d%n",
                finalPort);

        // Block until SIGTERM / SIGINT
        try {
            shutdown.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // -----------------------------------------------------------------------------------

    private static void die(String message) {
        System.err.println("[ghidra-mcp-ng] ERROR: " + message);
        System.exit(1);
    }
}
