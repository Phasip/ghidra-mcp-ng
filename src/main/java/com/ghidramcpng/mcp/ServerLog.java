package com.ghidramcpng.mcp;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.UUID;

/**
 * Records the full detail of an unexpected server-side failure to a rotating log file, and
 * hands back a short id the HTTP response can quote.
 *
 * <p>The API returns only {@code getMessage()} to the caller, which is the right amount of
 * detail for an agent trying to correct its own call but useless for diagnosing a genuine
 * server bug. The stack trace previously went only to the server's stderr, which in practice
 * belongs to whatever terminal launched it — a bug report could not include it without
 * restarting shared infrastructure on a guess. With this, an error response carries an
 * {@code error_id} and the operator (or the agent, via {@code /health}'s {@code log_file})
 * can pull the matching entry out of the log.
 *
 * <p>Writes are best-effort: if the log cannot be written the id is still allocated and the
 * entry falls back to stderr, so the response is never blocked by a logging failure.
 */
public final class ServerLog {

    /** Rotate once the current file passes this size, keeping one previous generation. */
    private static final long MAX_BYTES = 4 * 1024 * 1024;

    private static volatile Path file;

    private ServerLog() {}

    /**
     * Directs the log at {@code path}, creating parent directories as needed. Until this is
     * called, entries go to stderr only.
     *
     * @throws IOException if the file cannot be created — the caller decides whether that is
     *         fatal or merely worth a warning
     */
    public static void init(Path path) throws IOException {
        Path absolute = path.toAbsolutePath();
        Path parent = absolute.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        // Touch it now rather than on the first failure, so a bad path is reported at startup
        // instead of in the middle of diagnosing something else.
        Files.write(absolute, new byte[0], StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        file = absolute;
    }

    /** The active log file, or null if logging to file is not configured. */
    public static Path getFile() {
        return file;
    }

    /**
     * Records {@code error} with its full stack trace and returns the id to quote back to the
     * caller. Always returns an id, even if nothing could be written.
     *
     * @param context short description of what was being handled, e.g. {@code "POST /tool/run_script"}
     */
    public static String record(String context, Throwable error) {
        String errorId = UUID.randomUUID().toString().substring(0, 8);

        StringWriter stack = new StringWriter();
        error.printStackTrace(new PrintWriter(stack));

        String entry = Instant.now() + " [" + errorId + "] " + context + "\n" + stack + "\n";

        if (!append(entry)) {
            System.err.print("[ghidra-mcp-ng] " + entry);
        }
        return errorId;
    }

    /** @return true if the entry reached the log file. */
    private static synchronized boolean append(String entry) {
        Path target = file;
        if (target == null) return false;
        try {
            rotateIfFull(target);
            Files.writeString(target, entry, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            return true;
        } catch (IOException e) {
            System.err.println("[ghidra-mcp-ng] WARNING: could not write to log file " +
                    target + ": " + e);
            return false;
        }
    }

    private static void rotateIfFull(Path target) throws IOException {
        if (!Files.exists(target) || Files.size(target) < MAX_BYTES) return;
        Files.move(target, target.resolveSibling(target.getFileName() + ".1"),
                StandardCopyOption.REPLACE_EXISTING);
    }
}
