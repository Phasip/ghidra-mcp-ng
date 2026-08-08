package com.ghidramcpng.program;

import ghidra.base.project.GhidraProject;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.TransactionInfo;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
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
     * @throws IllegalArgumentException if the program cannot be found, the name is
     *         ambiguous, or the program has not been analyzed
     */
    public Program getOrOpen(String programName) throws Exception {
        return getOrOpen(programName, true);
    }

    /**
     * Opens a program that is allowed to be unanalyzed. Only {@code analyze_program} should
     * use this — every other tool needs an analyzed program, and opening one for analysis is
     * the single case that cannot require analysis to have happened already.
     */
    public Program getOrOpenForAnalysis(String programName) throws Exception {
        return getOrOpen(programName, false);
    }

    private Program getOrOpen(String programName, boolean requireAnalyzed) throws Exception {
        if (programName == null || programName.isBlank()) {
            throw new IllegalArgumentException("Program name must not be empty");
        }

        // Serialize open-or-cache to prevent TOCTOU: two concurrent callers for
        // the same program could otherwise both miss the cache and open it twice,
        // leaking one consumer reference.
        synchronized (openPrograms) {
            // Fast path for the pathname spelling, which is what list_project_files
            // returns and therefore what callers normally pass.
            Program cached = openPrograms.get(programName);
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

            // findDomainFile accepts either the bare filename or the full pathname, but the
            // cache is keyed on the pathname alone. A caller using the filename spelling
            // therefore only reaches the cache after resolution; without this second lookup
            // the program would be re-opened on every such call, adding a consumer reference
            // each time.
            cached = openPrograms.get(domainFile.getPathname());
            if (cached != null) return cached;

            Object obj = domainFile.getDomainObject(consumer, true, false, TaskMonitor.DUMMY);
            if (!(obj instanceof Program)) {
                ((ghidra.framework.model.DomainObject) obj).release(consumer);
                throw new IllegalArgumentException(
                        "'" + programName + "' is not a Program (found: " +
                        obj.getClass().getSimpleName() + ")");
            }
            Program program = (Program) obj;

            // Opening a program must not silently analyze it. Analysis is a long, mutating
            // operation that already has its own tool, and running it from here meant a read
            // could block for minutes, or — if it failed — leave the program uncached so that
            // every later request, reads included, retried and failed the same way.
            // Report it instead and let the caller run analysis deliberately.
            if (requireAnalyzed && !GhidraProgramUtilities.isAnalyzed(program)) {
                program.release(consumer);
                throw new IllegalArgumentException(
                        "Program '" + domainFile.getPathname() + "' has not been analyzed. " +
                        "Run analyze_program on it first — an unanalyzed program has few or no " +
                        "functions defined, so reads return incomplete results.");
            }

            openPrograms.put(domainFile.getPathname(), program);
            return program;
        }
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
     * The transaction is opened by {@link #analyzeProgramBlocking(Program)}.
     */
    public void analyzeProgram(Program program) throws Exception {
        ReentrantLock lock = transactionLocks.computeIfAbsent(program, p -> new ReentrantLock());
        if (!lock.tryLock(300, TimeUnit.SECONDS)) {
            throw new RuntimeException("Timed out waiting for program lock on '" +
                    program.getName() + "' after 300s");
        }
        try {
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
     *
     * <p>The analyzers run on the calling thread and write to the program — reAnalyzeAll
     * resets analysis state, and analyzers such as ARM's FunctionStartAnalyzer write context
     * registers — so a transaction must be open for the duration. Without one the first
     * writing analyzer throws "Transaction has not been started".
     */
    private static void analyzeProgramBlocking(Program program) {
        int txId = program.startTransaction("Auto-analysis");
        boolean success = false;
        try {
            AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
            analysisManager.initializeOptions();
            analysisManager.reAnalyzeAll(null);
            analysisManager.waitForAnalysis(null, TaskMonitor.DUMMY);
            success = true;
        } finally {
            program.endTransaction(txId, success);
        }
        // Neither AutoAnalysisManager nor GhidraProject.analyze() records that analysis ran;
        // only markProgramAnalyzed does. Callers gate on that flag, so leaving it unset means
        // analysis is attempted again on every access. (It opens its own transaction.)
        GhidraProgramUtilities.markProgramAnalyzed(program);
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
     *
     * <p>On success the program is saved, matching {@link #withTransaction}. A GhidraScript's
     * own transaction commits to the in-memory database but never writes the domain file, so
     * without this a successful script's work — a memory map, a batch of applied types — would
     * survive only until the server stopped.
     */
    public <T> T withProgramLock(Program program, java.util.concurrent.Callable<T> action)
            throws Exception {
        ReentrantLock lock = transactionLocks.computeIfAbsent(program, p -> new ReentrantLock());
        if (!lock.tryLock(300, TimeUnit.SECONDS)) {
            throw new RuntimeException("Timed out waiting for program lock on '" +
                    program.getName() + "' after 300s");
        }
        try {
            boolean actionSucceeded = false;
            T result;
            try {
                result = action.call();
                actionSucceeded = true;
            } finally {
                TransactionInfo leftover = program.getCurrentTransactionInfo();
                if (leftover != null) {
                    String desc = leftover.getDescription();
                    drainLeakedEntries(program, "aborting leaked transaction '" + desc + "'");
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

            // Reached only when the action returned normally and left no transaction open.
            if (program.isChanged()) {
                try {
                    program.getDomainFile().save(TaskMonitor.DUMMY);
                } catch (Exception e) {
                    throw new RuntimeException("The operation succeeded but saving '" +
                            program.getName() + "' failed: " + e.getMessage() +
                            ". Its changes exist in memory only and will be lost when the " +
                            "server stops.", e);
                }
            }
            return result;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Drain any open sub-transaction entries that a GhidraScript leaked by calling
     * {@code currentProgram.startTransaction()} without a matching {@code endTransaction()}.
     *
     * <h3>Why this is needed</h3>
     * <p>GhidraScript wraps {@code run()} in its own transaction (entry #0). Scripts may
     * legally open additional sub-transaction entries; {@code GhidraScript.end(true)} only
     * closes entry #0. If the script throws mid-run, those extra entries remain open
     * ({@code activeEntries > 0}), so Ghidra never sets {@code transaction = null} and the
     * program is effectively stuck: any subsequent {@code startTransaction()} either fails
     * or opens a new entry in the dead transaction.
     *
     * <h3>The drain algorithm</h3>
     * <p>Ghidra uses an ID scheme: each entry added to the active
     * {@code DomainObjectDBTransaction} gets ID {@code baseId + list_index}. We add a
     * sentinel "drain" entry (getting the next available ID&nbsp;=&nbsp;R), immediately end
     * it with {@code commit=false} to mark the transaction as ABORTED, then walk backwards
     * ending the N leaked entries at IDs R&#8209;1, R&#8209;2, …, R&#8209;N. When
     * {@code activeEntries} reaches zero Ghidra's own code runs the ABORTED cleanup path
     * (closes the DB transaction, invalidates caches, sets {@code transaction = null}) — no
     * reflection needed.
     *
     * <h3>Fallback</h3>
     * <p>If the drain fails (e.g. a previous run already called {@code forceLock} and set
     * {@code transactionTerminated = true}), we fall back to {@code forceLock} + {@code unlock}.
     * This leaves {@code transaction} non-null internally, so the NEXT call to this method
     * (in the pre-action safety-net of the following {@code withProgramLock} invocation) will
     * encounter that state — at which point {@code getCurrentTransactionInfo()} still returns
     * non-null and we attempt the drain again (which will fail again via
     * {@code TerminatedTransactionException}). In this degenerate case the program remains
     * unusable, which is the correct behaviour: something went badly wrong and the operator
     * should restart the server to reload the program from disk.
     */
    private static void drainLeakedEntries(Program program, String context) {
        TransactionInfo info = program.getCurrentTransactionInfo();
        if (info == null) return;

        List<String> leaked = info.getOpenSubTransactions();
        int N = leaked.size();
        if (N == 0) return;

        try {
            // Add a sentinel entry BEFORE the first endTransaction so we have a known anchor
            // ID (R). This is safe because transactionTerminated is still false here — forceLock
            // has not been called yet.
            int R = program.startTransaction("_ng_tx_drain (" + context + ")");
            // End the sentinel with commit=false. This marks the transaction as ABORTED at the
            // domain level. activeEntries drops from N+1 to N; since N > 0 the ABORTED cleanup
            // path does not fire yet (getStatus() returns NOT_DONE_BUT_ABORTED).
            program.endTransaction(R, false);
            // End leaked entries newest-first. Each ID is R-i (i=1..N). When the last one
            // (activeEntries reaches 0) is ended, getStatus() returns ABORTED and Ghidra's
            // own cleanup runs: DB transaction closed, caches invalidated, transaction = null.
            for (int i = 1; i <= N; i++) {
                try {
                    program.endTransaction(R - i, false);
                } catch (Exception ignored) {
                    // Entry already ended somehow; keep going to drive activeEntries to 0.
                }
            }
        } catch (Exception drainFailed) {
            // transactionTerminated was already true (forceLock ran previously). Fall back to
            // forceLock, which at least terminates the DB transaction even if it cannot null
            // out the internal transaction reference.
            try {
                program.forceLock(true,
                        "ng: drain failed (" + context + "), force-terminating '" +
                        info.getDescription() + "'");
                program.unlock();
            } catch (Exception ignored) {
                System.err.println("[ghidra-mcp-ng] WARNING: forceLock fallback also failed during " +
                        context + " — program '" + program.getName() + "' may be unusable: " + ignored);
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

    /** Pathnames of currently open programs (for internal lifecycle tracking). */
    List<String> listOpenPrograms() {
        return new ArrayList<>(openPrograms.keySet());
    }

    // -----------------------------------------------------------------------------------
    // Domain-file lookup
    // -----------------------------------------------------------------------------------

    /**
     * Find a domain file by name in the folder tree. Matches on exact filename or
     * full pathname (e.g. {@code /folder/mylib.so}). Both comparisons are case-sensitive.
     *
     * <p>A pathname is unique within a project, but a bare filename can occur in several
     * folders. Rather than silently picking one, an ambiguous filename is rejected so the
     * caller can disambiguate — guessing here would write to the wrong program.
     *
     * @return the single matching file, or null if nothing matches
     * @throws IllegalArgumentException if more than one file matches
     */
    public DomainFile findDomainFile(DomainFolder folder, String name) {
        List<DomainFile> matches = new ArrayList<>();
        // Iterative to prevent StackOverflowError on deeply nested project structures.
        Deque<DomainFolder> stack = new ArrayDeque<>();
        stack.push(folder);
        while (!stack.isEmpty()) {
            DomainFolder current = stack.pop();
            for (DomainFile f : current.getFiles()) {
                // A Ghidra file name cannot contain '/', so a query is either a pathname
                // or a filename — never both, and the two cases cannot collide.
                if (f.getName().equals(name) || f.getPathname().equals(name)) {
                    matches.add(f);
                }
            }
            for (DomainFolder sub : current.getFolders()) {
                stack.push(sub);
            }
        }

        if (matches.isEmpty()) return null;
        if (matches.size() == 1) return matches.get(0);

        List<String> pathnames = new ArrayList<>();
        for (DomainFile f : matches) {
            pathnames.add(f.getPathname());
        }
        pathnames.sort(Comparator.naturalOrder());
        throw new IllegalArgumentException(
                "Ambiguous program '" + name + "' — " + matches.size() + " files share that name: " +
                pathnames + ". Pass the full pathname as returned by list_project_files.");
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
