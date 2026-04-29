package com.ghidramcpng.program;

import ghidra.base.project.GhidraProject;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.TransactionInfo;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Manages programs opened from a Ghidra project.
 *
 * Programs are opened lazily (on first request) and kept open for the lifetime of the
 * server unless explicitly closed. Every write operation goes through
 * {@link #withTransaction(Program, String, ThrowingRunnable)} which opens a Ghidra
 * transaction and auto-saves on success.
 *
 * <p>A single {@code Object} instance acts as the Ghidra domain-object consumer for
 * reference counting — {@code program.release(consumer)} is called on shutdown.
 */
public class ProgramManager {

    /** Functional interface equivalent to {@link Runnable} that may throw checked exceptions. */
    @FunctionalInterface
    public interface ThrowingRunnable {
        void run() throws Exception;
    }

    private final ghidra.base.project.GhidraProject ghidraProject;
    private final Object consumer = new Object();
    private final Map<String, Program> openPrograms = new ConcurrentHashMap<>();
    private final Map<Program, ReentrantLock> transactionLocks = new ConcurrentHashMap<>();

    public ProgramManager(ghidra.base.project.GhidraProject ghidraProject) {
        this.ghidraProject = ghidraProject;
        // Shutdown is handled by the server-level hook in GhidraMcpServer, which also
        // stops the HTTP server and releases the script runtime before calling closeAll().
    }

    // -----------------------------------------------------------------------------------
    // Program access
    // -----------------------------------------------------------------------------------

    /**
     * Returns an already-open program or opens it from the project by name.
     *
     * <p>Matching is exact and case-sensitive — pass the program name exactly as
     * returned by {@code list_project_files}.
     *
     * @param programName name as provided by the MCP client
     * @throws IllegalArgumentException if the program cannot be found in the project
     */
    public Program getOrOpen(String programName) throws Exception {
        if (programName == null || programName.isBlank()) {
            throw new IllegalArgumentException("Program name must not be empty");
        }

        // Serialize open-or-cache to prevent TOCTOU: two concurrent callers for
        // the same program could otherwise both miss the cache and open it twice,
        // leaking one consumer reference.
        synchronized (openPrograms) {
            Program cached = findCached(programName);
            if (cached != null) return cached;

            DomainFile domainFile =
                    findDomainFile(ghidraProject.getProject().getProjectData().getRootFolder(), programName);
            if (domainFile == null) {
                List<String> available = listProjectFiles();
                String msg;
                if (available.size() <= 10) {
                    msg = "Invalid program '" + programName + "'. Valid options: " + available;
                } else {
                    msg = "Invalid program '" + programName + "'. " +
                          "Use list_project_files to see all " + available.size() + " available programs.";
                }
                throw new IllegalArgumentException(msg);
            }

            Object obj = domainFile.getDomainObject(consumer, true, false, TaskMonitor.DUMMY);
            if (!(obj instanceof Program)) {
                ((ghidra.framework.model.DomainObject) obj).release(consumer);
                throw new IllegalArgumentException(
                        "'" + programName + "' is not a Program (found: " +
                        obj.getClass().getSimpleName() + ")");
            }
            Program program = (Program) obj;

            // Auto-analyze programs that were imported manually (e.g. via the Ghidra GUI)
            // without running analysis. Without this, every read/write tool would operate
            // on an unanalyzed binary and produce incomplete or missing results.
            if (!program.getOptions(Program.PROGRAM_INFO).getBoolean(Program.ANALYZED_OPTION_NAME, false)) {
                analyzeProgramBlocking(program);
                ghidraProject.save(program);
            }

            openPrograms.put(domainFile.getName(), program);
            return program;
        }
    }

    private Program findCached(String name) {
        return openPrograms.get(name);
    }

    /**
     * Imports a binary file into the project, runs full auto-analysis, saves it,
     * and returns the program name for immediate use with {@link #getOrOpen(String)}.
     *
     * @param filePath   absolute path to the binary file on disk
     * @param projectDir project folder path (e.g. {@code "hello/bin"} or {@code "/"} for root).
     *                   The folder is created automatically if it does not yet exist.
     * @return the program name as registered in the Ghidra project
     * @throws IllegalArgumentException if the file does not exist
     * @throws Exception if import or analysis fails
     */
    public String importBinary(String filePath, String projectDir) throws Exception {
        java.io.File file = new java.io.File(filePath);
        if (!file.isFile()) {
            throw new IllegalArgumentException(
                    "File not found: '" + filePath + "'. Provide an absolute path to an existing binary file.");
        }

        Program imported = ghidraProject.importProgram(file);
        if (imported == null) {
            throw new RuntimeException(
                    "Ghidra could not auto-detect the format of '" + file.getName() + "'. " +
                    "The file may be corrupted, empty, or in an unsupported format.");
        }

        // Block until auto-analysis fully completes so no MCP tool ever sees an
        // imported-but-still-analyzing program.
        analyzeProgramBlocking(imported);

        // Resolve destination folder — create intermediate directories as needed.
        String folderPath = normalizeFolderPath(projectDir);
        ensureFolderExists(folderPath);

        // importProgram() returns a proxy file with no saved location; saveAs establishes one.
        ghidraProject.saveAs(imported, folderPath, imported.getName(), true);
        return imported.getName();
    }

    /**
     * Normalises a caller-supplied project directory to an absolute Ghidra folder path.
     * Null / blank → root ("/"). Strips trailing slashes; ensures a leading slash.
     */
    private static String normalizeFolderPath(String projectDir) {
        if (projectDir == null || projectDir.isBlank()) return "/";
        String p = projectDir.trim().replaceAll("/+$", "");
        return p.startsWith("/") ? p : "/" + p;
    }

    /**
     * Runs full auto-analysis on an already-open program and blocks until completion.
     * Use this when a program was imported into the project outside the MCP server
     * (e.g. via the Ghidra GUI) without auto-analysis having run, or when a re-analysis
     * is desired after large structural changes.
     *
     * <p>Acquires the per-program lock for the duration so concurrent write tools wait.
     * Auto-analysis manages its own internal Ghidra transactions, so this method does
     * NOT open one of its own.
     */
    public void analyzeProgram(Program program) throws Exception {
        ReentrantLock lock = transactionLocks.computeIfAbsent(program, p -> new ReentrantLock());
        if (!lock.tryLock(300, TimeUnit.SECONDS)) {
            throw new RuntimeException("Timed out waiting for program lock on '" +
                    program.getName() + "' after 300s");
        }
        try {
            abortLeakedTransaction(program, "leftover transaction from a previous run");
            analyzeProgramBlocking(program);
            // Save the analysis results so subsequent server restarts see the analyzed program.
            program.getDomainFile().save(TaskMonitor.DUMMY);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Runs full auto-analysis and blocks until completion.
     *
     * GhidraProject.analyze() ultimately delegates to AutoAnalysisManager.startAnalysis(),
     * whose implementation may hand work off and return before analysis is fully complete.
     * For MCP we need a stronger guarantee: once a program is returned from open/import,
     * no caller should ever observe it in a partially analyzed state.
     */
    private static void analyzeProgramBlocking(Program program) {
        AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
        analysisManager.initializeOptions();
        analysisManager.reAnalyzeAll(null);
        analysisManager.waitForAnalysis(null, TaskMonitor.DUMMY);
    }

    /**
     * Creates every component of {@code folderPath} that does not yet exist in the project.
     * {@code folderPath} must be an absolute Ghidra path starting with "/".
     */
    private void ensureFolderExists(String folderPath) throws Exception {
        if ("/".equals(folderPath)) return; // root always exists

        ghidra.framework.model.DomainFolder current =
                ghidraProject.getProject().getProjectData().getRootFolder();

        // Walk each component, creating missing sub-folders one level at a time.
        String[] parts = folderPath.replaceAll("^/+", "").split("/");
        for (String part : parts) {
            if (part.isEmpty()) continue;
            ghidra.framework.model.DomainFolder child = current.getFolder(part);
            if (child == null) {
                child = current.createFolder(part);
            }
            current = child;
        }
    }

    // -----------------------------------------------------------------------------------
    // Transaction + save
    // -----------------------------------------------------------------------------------

    /**
     * Execute {@code action} while holding the per-program lock, without opening a Ghidra
     * transaction. Use this to serialize operations (e.g. script execution) that manage their
     * own transactions internally, so they cannot run concurrently with
     * {@link #withTransaction} calls on the same program.
     */
    public <T> T withProgramLock(Program program, java.util.concurrent.Callable<T> action)
            throws Exception {
        ReentrantLock lock = transactionLocks.computeIfAbsent(program, p -> new ReentrantLock());
        if (!lock.tryLock(300, TimeUnit.SECONDS)) {
            throw new RuntimeException("Timed out waiting for program lock on '" +
                    program.getName() + "' after 300s");
        }
        try {
            // Defensive pre-check: a previous (poorly-written) script may have left a
            // Ghidra transaction open. Roll it back so this run starts clean.
            abortLeakedTransaction(program, "leftover transaction from a previous run");

            boolean actionSucceeded = false;
            try {
                T result = action.call();
                actionSucceeded = true;
                return result;
            } finally {
                TransactionInfo leftover = program.getCurrentTransactionInfo();
                if (leftover != null) {
                    String desc = leftover.getDescription();
                    try {
                        program.forceLock(true, "ng: aborting leaked transaction '" + desc + "'");
                        program.unlock();
                    } catch (Exception ignored) {
                        // Best effort; original error (if any) is more important to surface.
                    }
                    if (actionSucceeded) {
                        // Action returned normally but left a transaction open — surface so the
                        // user knows their script is buggy instead of silently swallowing it.
                        throw new IllegalStateException(
                                "Script left Ghidra transaction '" + desc + "' open. It has been " +
                                "rolled back and any partial changes were discarded. Wrap " +
                                "startTransaction()/endTransaction() in try/finally so the " +
                                "transaction always closes, or use GhidraScript built-ins which " +
                                "manage transactions for you.");
                    }
                    // If the action threw, the original exception is propagating — don't shadow it.
                }
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * If a Ghidra transaction is still open on {@code program} (i.e. leaked from a previous
     * caller — typically a script that threw mid-transaction), force-rollback. No-op if no
     * transaction is active.
     */
    private static void abortLeakedTransaction(Program program, String reason) {
        TransactionInfo info = program.getCurrentTransactionInfo();
        if (info != null) {
            try {
                program.forceLock(true, "ng: " + reason + " ('" + info.getDescription() + "')");
                program.unlock();
            } catch (Exception ignored) {
                // Best effort — if even forceLock fails, the next caller will surface a clearer error.
            }
        }
    }

    /**
     * Execute {@code action} inside a Ghidra transaction on {@code program}. On success the
     * program is saved to the project. On failure the transaction is rolled back.
     *
     * <p>A per-program lock serializes concurrent callers so that a second write blocks
     * rather than failing with "Unable to lock due to active transaction".
     */
    public void withTransaction(Program program, String description, ThrowingRunnable action)
            throws Exception {
        ReentrantLock lock = transactionLocks.computeIfAbsent(program, p -> new ReentrantLock());
        if (!lock.tryLock(300, TimeUnit.SECONDS)) {
            throw new RuntimeException("Timed out waiting for transaction lock on '" +
                    program.getName() + "' after 300s");
        }
        try {
            // Defensive pre-check: a poorly-behaved script run earlier may have leaked a
            // Ghidra transaction. Roll it back so we don't hit "Unable to lock due to active
            // transaction" on save() below.
            abortLeakedTransaction(program, "leftover transaction from a previous run");

            int txId = program.startTransaction(description);
            boolean success = false;
            try {
                action.run();
                success = true;
            } finally {
                program.endTransaction(txId, success);
            }
            if (success) {
                program.getDomainFile().save(TaskMonitor.DUMMY);
            }
        } finally {
            lock.unlock();
        }
    }

    // -----------------------------------------------------------------------------------
    // Project enumeration
    // -----------------------------------------------------------------------------------

    /** Lists all domain-file pathnames in the project (recursive). */
    public List<String> listProjectFiles() {
        List<String> result = new ArrayList<>();
        collectFiles(ghidraProject.getProject().getProjectData().getRootFolder(), result);
        return result;
    }

    private void collectFiles(DomainFolder root, List<String> result) {
        // Iterative to prevent StackOverflowError on deeply nested project structures.
        Deque<DomainFolder> stack = new ArrayDeque<>();
        stack.push(root);
        while (!stack.isEmpty()) {
            DomainFolder folder = stack.pop();
            for (DomainFile f : folder.getFiles()) {
                result.add(f.getPathname());
            }
            for (DomainFolder sub : folder.getFolders()) {
                stack.push(sub);
            }
        }
    }

    /** Names of currently open programs (for internal lifecycle tracking). */
    List<String> listOpenPrograms() {
        return new ArrayList<>(openPrograms.keySet());
    }

    // -----------------------------------------------------------------------------------
    // Domain-file lookup
    // -----------------------------------------------------------------------------------

    /**
     * Find a domain file by name in the folder tree. Matches on exact filename or
     * full pathname (e.g. {@code /folder/mylib.so}). Both comparisons are case-sensitive.
     */
    public DomainFile findDomainFile(DomainFolder folder, String name) {
        for (DomainFile f : folder.getFiles()) {
            if (f.getName().equals(name) || f.getPathname().equals(name)) {
                return f;
            }
        }
        for (DomainFolder sub : folder.getFolders()) {
            DomainFile found = findDomainFile(sub, name);
            if (found != null) return found;
        }
        return null;
    }

    // -----------------------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------------------

    /** Release all open programs. Called by the server-level shutdown hook. */
    public void closeAll() {
        synchronized (openPrograms) {
            for (Program p : new ArrayList<>(openPrograms.values())) {
                try {
                    p.release(consumer);
                } catch (RuntimeException e) {
                    System.err.println("[ghidra-mcp-ng] Warning: failed to release program '" + p.getName() + "': " + e);
                }
            }
            openPrograms.clear();
        }
    }

    public Project getProject() {
        return ghidraProject.getProject();
    }
}
