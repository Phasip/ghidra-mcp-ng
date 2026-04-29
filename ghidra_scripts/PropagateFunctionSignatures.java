// Populates a Ghidra Function ID (FID) database from a set of already-reversed "source" programs
// and then applies the resulting name signatures to a set of "target" programs.
//
// This is the recommended workflow for propagating function names from a fully-reversed
// library to binaries that statically link the same library.
//
// Usage (via run_script):
//   { "program": "<any_open_program>", "filename": "PropagateFunctionSignatures.java",
//     "args": ["<fidb_path>", "<source_programs>", "<target_programs>"] }
//
// Arguments:
//   args[0]  fidb_path        - Absolute path to the .fidb file (created if it does not exist).
//   args[1]  source_programs  - Comma-separated program names to populate the database from.
//                               Use "NONE" to skip Phase 1 and only apply an existing .fidb.
//   args[2]  target_programs  - Comma-separated program names to apply FID names to.
//                               Use "*" to apply to every program in the project.
//   args[3]  library_name     - (Optional) Library label stored in the .fidb. Defaults to "MCP_FID_Library".
//
// When called with no args the script prints a JSON help object and exits.
//
// Output: a single JSON object written to println() — captured in run_script's "output" field.
//   {
//     "fidb_path": string,
//     "phase1": { "skipped": boolean, "programs": [ { "name", "added", "excluded", "error" } ] },
//     "phase2": { "programs": [ { "name", "applied", "error" } ] }
//   }
//
// @category GhidraTools

import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.*;
import ghidra.feature.fid.service.*;
import ghidra.framework.model.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.database.ProgramContentHandler;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.symbol.SourceType;

import java.io.File;
import java.util.*;

public class PropagateFunctionSignatures extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length < 3 || args[0].isBlank()) {
            printHelp();
            return;
        }

        String fidbPath     = args[0].trim();
        String sourcesArg   = args[1].trim();
        String targetsArg   = args[2].trim();
        String libraryName  = args.length > 3 && !args[3].isBlank() ? args[3].trim() : "MCP_FID_Library";

        boolean skipPhase1 = sourcesArg.equalsIgnoreCase("NONE") || sourcesArg.isEmpty();
        List<String> sourceNames = skipPhase1 ? List.of() : splitNames(sourcesArg);

        boolean allTargets = targetsArg.equals("*");
        List<String> targetNames = allTargets ? List.of() : splitNames(targetsArg);

        JsonObject result = new JsonObject();
        result.addProperty("fidb_path", fidbPath);

        FidService service = new FidService();
        FidFileManager fidFileManager = FidFileManager.getInstance();
        File fidbFile = new File(fidbPath);
        DomainFolder root = state.getProject().getProjectData().getRootFolder();

        // -------------------------------------------------------------------------
        // Phase 1: Populate FID database from source programs
        // -------------------------------------------------------------------------
        JsonObject phase1 = new JsonObject();
        result.add("phase1", phase1);

        if (skipPhase1) {
            phase1.addProperty("skipped", true);
            println("Phase 1: Skipped (using existing .fidb)");
        } else {
            phase1.addProperty("skipped", false);
            JsonArray phase1Programs = new JsonArray();
            phase1.add("programs", phase1Programs);

            if (!fidbFile.exists()) {
                fidFileManager.createNewFidDatabase(fidbFile);
                println("Phase 1: Created new .fidb at " + fidbPath);
            }

            FidFile fidFile = fidFileManager.addUserFidFile(fidbFile);
            fidFile.setActive(true);
            FidDB fidDb = fidFile.getFidDB(true);

            try {
                // Use the language from the first source program found
                LanguageID langId = detectLanguage(root, sourceNames);

                for (String progName : sourceNames) {
                    JsonObject entry = new JsonObject();
                    entry.addProperty("name", progName);
                    DomainFile df = searchFolder(root, progName);
                    if (df == null) {
                        entry.addProperty("error", "not found in project");
                        phase1Programs.add(entry);
                        println("  SKIP (not found): " + progName);
                        continue;
                    }
                    try {
                        List<DomainFile> programs = List.of(df);
                        FidPopulateResult popResult = service.createNewLibraryFromPrograms(
                            fidDb, libraryName, "1.0", progName, programs,
                            null, langId, null, null, monitor);
                        if (popResult != null) {
                            entry.addProperty("added", popResult.getTotalAdded());
                            entry.addProperty("excluded", popResult.getTotalExcluded());
                            println("  " + progName + ": added=" + popResult.getTotalAdded() +
                                    " excluded=" + popResult.getTotalExcluded());
                        }
                    } catch (Exception e) {
                        entry.addProperty("error", e.getMessage());
                        println("  ERROR on " + progName + ": " + e.getMessage());
                    }
                    phase1Programs.add(entry);
                }
                fidDb.saveDatabase("Saving FID database", monitor);
                println("Phase 1: Saved .fidb");
            } finally {
                fidDb.close();
            }
        }

        // -------------------------------------------------------------------------
        // Phase 2: Apply FID to target programs
        // -------------------------------------------------------------------------
        JsonObject phase2 = new JsonObject();
        result.add("phase2", phase2);
        JsonArray phase2Programs = new JsonArray();
        phase2.add("programs", phase2Programs);

        println("Phase 2: Applying FID names...");

        // Ensure the .fidb is registered and active
        FidFile fidFile = fidFileManager.addUserFidFile(fidbFile);
        fidFile.setActive(true);

        // Resolve target list (all programs if "*")
        List<String> resolvedTargets = allTargets
                ? collectAllProgramNames(root)
                : targetNames;

        FidQueryService queryService = fidFileManager.openFidQueryService(
                currentProgram.getLanguage(), false);
        try {
            for (String progName : resolvedTargets) {
                JsonObject entry = new JsonObject();
                entry.addProperty("name", progName);
                DomainFile df = searchFolder(root, progName);
                if (df == null) {
                    entry.addProperty("error", "not found in project");
                    phase2Programs.add(entry);
                    continue;
                }
                DomainObject domObj = null;
                try {
                    domObj = df.getDomainObject(this, true, false, monitor);
                    if (!(domObj instanceof Program)) {
                        entry.addProperty("error", "not a Program");
                        phase2Programs.add(entry);
                        continue;
                    }
                    Program prog = (Program) domObj;
                    List<FidSearchResult> results = service.processProgram(
                            prog, queryService, 0.5f, monitor);

                    int applied = 0;
                    if (results != null) {
                        int tx = prog.startTransaction("FID names");
                        try {
                            for (FidSearchResult r : results) {
                                if (r.function == null || r.matches == null || r.matches.isEmpty()) continue;
                                FidMatch best = r.matches.get(0);
                                String name = best.getFunctionRecord().getName();
                                if (name == null || name.startsWith("FUN_") ||
                                        name.startsWith("Catch@") || name.startsWith("Unwind@") ||
                                        name.startsWith("_$")) continue;
                                try {
                                    r.function.setName(name, SourceType.ANALYSIS);
                                    applied++;
                                } catch (Exception ignored) {}
                            }
                        } finally {
                            prog.endTransaction(tx, true);
                        }
                    }
                    prog.save("FID names applied", monitor);
                    entry.addProperty("applied", applied);
                    println("  " + progName + ": applied " + applied + " names");
                } catch (Exception e) {
                    entry.addProperty("error", e.getMessage());
                    println("  ERROR on " + progName + ": " + e.getMessage());
                } finally {
                    if (domObj != null) domObj.release(this);
                }
                phase2Programs.add(entry);
            }
        } finally {
            queryService.close();
        }

        println("Done.");
        println(new GsonBuilder().setPrettyPrinting().create().toJson(result));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private LanguageID detectLanguage(DomainFolder root, List<String> names) throws Exception {
        for (String name : names) {
            DomainFile df = searchFolder(root, name);
            if (df == null) continue;
            DomainObject domObj = null;
            try {
                domObj = df.getDomainObject(this, false, false, monitor);
                if (domObj instanceof Program) {
                    return ((Program) domObj).getLanguageID();
                }
            } finally {
                if (domObj != null) domObj.release(this);
            }
        }
        // Fall back to the current program's language
        return currentProgram.getLanguageID();
    }

    private List<String> collectAllProgramNames(DomainFolder folder) throws CancelledException {
        List<String> names = new ArrayList<>();
        collectNames(folder, names);
        return names;
    }

    private void collectNames(DomainFolder folder, List<String> out) throws CancelledException {
        for (DomainFile f : folder.getFiles()) {
            monitor.checkCancelled();
            if (ProgramContentHandler.PROGRAM_CONTENT_TYPE.equals(f.getContentType())) {
                out.add(f.getName());
            }
        }
        for (DomainFolder sub : folder.getFolders()) {
            monitor.checkCancelled();
            collectNames(sub, out);
        }
    }

    private DomainFile searchFolder(DomainFolder folder, String name) throws CancelledException {
        for (DomainFile f : folder.getFiles()) {
            monitor.checkCancelled();
            if (f.getName().equals(name) &&
                    ProgramContentHandler.PROGRAM_CONTENT_TYPE.equals(f.getContentType())) {
                return f;
            }
        }
        for (DomainFolder sub : folder.getFolders()) {
            monitor.checkCancelled();
            DomainFile found = searchFolder(sub, name);
            if (found != null) return found;
        }
        return null;
    }

    private static List<String> splitNames(String csv) {
        List<String> names = new ArrayList<>();
        for (String s : csv.split(",")) {
            String t = s.trim();
            if (!t.isEmpty()) names.add(t);
        }
        return names;
    }

    private void printHelp() {
        JsonObject help = new JsonObject();
        help.addProperty("help", true);
        help.addProperty("script", "PropagateFunctionSignatures.java");
        help.addProperty("description",
                "Builds a Ghidra Function ID (FID) database from reversed 'source' programs " +
                "(Phase 1) then applies the resulting name signatures to 'target' programs (Phase 2). " +
                "Use this to propagate function names from a fully-reversed library to binaries " +
                "that statically link the same library.");

        JsonArray arguments = new JsonArray();
        addArg(arguments, "fidb_path",       "Absolute path to the .fidb file (created if it does not exist)", true);
        addArg(arguments, "source_programs", "Comma-separated program names to populate the database from. Use 'NONE' to skip Phase 1 and only apply an existing .fidb", true);
        addArg(arguments, "target_programs", "Comma-separated target program names, or '*' to apply to every program in the project", true);
        addArg(arguments, "library_name",    "Label stored in the .fidb (optional, defaults to 'MCP_FID_Library')", false);
        help.add("arguments", arguments);

        JsonObject example = new JsonObject();
        example.addProperty("program", "mylib.dll");
        example.addProperty("filename", "PropagateFunctionSignatures.java");
        JsonArray exArgs = new JsonArray();
        exArgs.add("/home/user/project/mylib.fidb");
        exArgs.add("mylib_reversed.dll,mylib_debug.dll");
        exArgs.add("target1.exe,target2.exe");
        exArgs.add("MyLib_v1");
        example.add("args", exArgs);
        help.add("example", example);

        println(new GsonBuilder().setPrettyPrinting().create().toJson(help));
    }

    private static void addArg(JsonArray arr, String name, String desc, boolean required) {
        JsonObject o = new JsonObject();
        o.addProperty("name", name);
        o.addProperty("description", desc);
        o.addProperty("required", required);
        arr.add(o);
    }
}
