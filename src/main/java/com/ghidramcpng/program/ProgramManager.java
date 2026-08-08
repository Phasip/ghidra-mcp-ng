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
     *
     * <p>On failure the program is {@linkplain #evict evicted}. A script that threw, or that
     * returned while still holding a transaction, leaves the in-memory database in a state
     * nothing can reliably repair; discarding it is reliable, and everything the script
     * completed before that point is already on disk.
     */
    public <T> T withProgramLock(Program program, java.util.concurrent.Callable<T> action)
            throws Exception {
        ReentrantLock lock = transactionLocks.computeIfAbsent(program, p -> new ReentrantLock());
        if (!lock.tryLock(300, TimeUnit.SECONDS)) {
            throw new RuntimeException("Timed out waiting for program lock on '" +
                    program.getName() + "' after 300s");
        }
        try {
            T result;
            try {
                result = action.call();
            } catch (Exception | Error e) {
                // A script that threw leaves the program in an unknown partial state — possibly
                // with a transaction it opened still open. Discard the in-memory copy rather than
                // trying to repair it; the next call reopens from disk, where everything that
                // completed successfully has already been saved.
                evict(program, "script failed: " + e);
                throw e;
            }

            TransactionInfo leftover = program.getCurrentTransactionInfo();
            if (leftover != null) {
                // Returned normally but left a transaction open. Its changes were never committed
                // and cannot be, so the in-memory program is unusable — discard it, and say so,
                // rather than silently swallowing a buggy script.
                //
                // Name the leaked sub-transactions, not the enclosing one: the enclosing
                // transaction is the one GhidraScript opens around run() and is named after the
                // script, whereas each sub-transaction carries the description passed to the
                // startTransaction() call that actually leaked.
                List<String> leaked = leftover.getOpenSubTransactions();
                String open = leaked.isEmpty() ? "'" + leftover.getDescription() + "'" : leaked.toString();
                evict(program, "script left transaction(s) open: " + open);
                throw new IllegalStateException(
                        "Script returned with Ghidra transaction(s) still open: " + open +
                        ". The program has been closed and will be reloaded from disk on the next " +
                        "call, discarding this run's uncommitted changes. Wrap " +
                        "startTransaction()/endTransaction() in try/finally so the transaction " +
                        "always closes, or use GhidraScript built-ins which manage transactions " +
                        "for you.");
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
     * Drop a program from the cache and close it, so the next {@link #getOrOpen} reloads it
     * from the project database on disk.
     *
     * <p>This is the recovery path for a program whose in-memory transaction state is broken —
     * most often a GhidraScript that opened a transaction with
     * {@code currentProgram.startTransaction()} and threw before ending it. GhidraScript wraps
     * {@code run()} in its own transaction and {@code end(true)} closes only that one, so the
     * leaked entries keep {@code activeEntries > 0}: Ghidra never clears the transaction and
     * every later {@code startTransaction()} on that program fails. Repairing that state in
     * place means reconstructing Ghidra's internal transaction IDs and hoping; closing the
     * program discards it outright and always works.
     *
     * <p>Nothing durable is lost. Every write tool saves inside {@link #withTransaction}, and a
     * successful script saves at the end of {@link #withProgramLock}, so eviction discards only
     * the uncommitted changes of the run that just failed — exactly the state worth throwing
     * away. Closing with a transaction still open is safe: Ghidra's close path aborts it and
     * disposes the buffers.
     *
     * <p>A caller that resolved this {@code Program} before eviction and is still using it will
     * see "program is closed" errors. That is a recoverable per-call failure — its next
     * {@code getOrOpen} returns the fresh instance — and it is the price of not leaving a
     * permanently wedged program cached for the life of the server.
     *
     * @param program the program to discard; ignored if it is not currently cached
     * @param reason  short description of what went wrong, for the server log
     */
    public void evict(Program program, String reason) {
        boolean wasCached;
        synchronized (openPrograms) {
            // Removing by identity: the cache is keyed on pathname, and the caller has a
            // Program, not a name. Guarding on the removal also makes eviction idempotent —
            // releasing a consumer twice throws.
            wasCached = openPrograms.values().removeIf(p -> p == program);
        }
        transactionLocks.remove(program);
        if (!wasCached) return;

        String name = program.getDomainFile().getPathname();
        try {
            program.release(consumer);
        } catch (RuntimeException e) {
            System.err.println("[ghidra-mcp-ng] WARNING: failed to close evicted program '" +
                    name + "': " + e);
        }
        System.err.println("[ghidra-mcp-ng] Evicted '" + name +
                "'; it will be reloaded from disk on the next call. Reason: " + reason);
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
            } catch (Exception | Error e) {
                // A rolled-back write leaves a healthy program, so most failures here are just
                // reported. But if the program's own transaction state is broken — a terminated
                // transaction, or one still open after ours was closed — nothing this or any
                // later call does can succeed against it, so discard it instead of leaving a
                // dead program cached.
                if (program.hasTerminatedTransaction() || program.getCurrentTransactionInfo() != null) {
                    evict(program, "unusable transaction state after '" + description + "': " + e);
                }
                throw e;
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
