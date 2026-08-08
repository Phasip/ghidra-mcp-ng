# ghidra-mcp-ng — improvement plan

Written 2026-08-08 from an audit of the two field bug logs plus a read of the current source.
Sections are marked DONE as they land; §6 carries the running order.

Source material:

- `~/projects/<project-a>/ghidra/ghidra-mcp-issues.md` (2026-08-08, newest, unhandled)
- `~/projects/<project-b>/ghidra-mcp-issues.md` (2026-07-31 → 2026-08-08)

Related deliverables written outside this repo in the same session:

- `~/SKILLS/REVERSING.md` — consolidated reversing methodology (old copy at
  `REVERSING.md.bak-2026-08-08`; project D's copy was byte-identical to the old base, and the project A
  copy byte-identical to project B's, so all four projects can point at the one file).
- `~/.claude/skills/reversing/SKILL.md` — user-level operational skill (connect,
  parameter names, gotchas, scripting rules, known-broken list).

---

## 0. Audit result — every logged issue is still open

Checked against source, not dates. Nothing in either log has been fixed.

| # | Issue | Evidence in source |
|---|---|---|
| 1 | Auto-analysis runs with no transaction | `ProgramManager.java:197-202` |
| 2 | Sticky wedge — even reads fail, never clears | `ProgramManager.java:102-107` |
| 3 | `analyze_program` tool unusable | `ProgramManager.java:174-187` — no transaction |
| 4 | `import_binary` can't import a headerless blob | no `language_id` in `ImportBinaryRequest` |
| 5 | `create_label` / `rename_global` validated as `function_name` | `WriteTools.java:152, 183` |
| 6 | Query-param names diverge between tools | `ReadTools.java:686` (`filter`), `:408` (`item_count`), `:462` (`instructions`) |
| 7 | `get_xrefs_to` / `get_xrefs_from` have no `limit` / `offset` | `ReadTools.java:839, 884` |
| 8 | `set_function_prototype` uses `{name,type}`, `add_struct_field` uses `type_name` | `WriteTools.java:225-226` vs `:377` |
| 9 | README documents `GET /tools` + `POST /call` | `README.md:104-105` — neither route exists |
| 10 | 404 surfaces as `"Internal error: HTTP 404 Not Found"` (a 500) | `HttpApiServer.java:303-308` maps all `Throwable` to 500 |
| 11 | C99 type spellings (`uint32_t`) rejected | by design; no stdint aliases in `findDataType` |
| 12 | `add_script` snapshots; `run_script` silently runs the stale copy | `ScriptTool.java:166` copies, `:191` resolves without an mtime check |
| 13 | No server-side log file — stack traces unrecoverable | mapper keeps only `getMessage()` |
| 14 | `search_defined_strings` `count` is page size, cap of 1000 undocumented | `ReadTools.java:693` |

Fixed elsewhere, for the record: the `launch.sh` missing-vmargs invocation is correct in the
`ghidra-<project-b>` skill but **still broken** in `projects/<project-c>/.claude/skills/ghidra-<project-c>/SKILL.md:31`
(5 positionals instead of 6).

Stale docs outside this repo: `~/SKILLS/fmt_string_lookup.md`, `library_fidb_workflow.md` and
`debug_log_bulk_naming.md` all reference `search_memory_strings` and `analyze_function_complete`,
which do not exist in the current tool surface.

---

## 1. The transaction wedge — root cause

The field reports treat "No transaction is open" as mysterious. It is not. There are **two** bugs
and they multiply. Bug B is not in either log.

### Bug A — a write hidden inside a read path, with a self-perpetuating gate

`ProgramManager.java:197`:

```java
private static void analyzeProgramBlocking(Program program) {
    AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
    analysisManager.initializeOptions();
    analysisManager.reAnalyzeAll(null);
    analysisManager.waitForAnalysis(null, TaskMonitor.DUMMY);   // no transaction open
}
```

Analyzers run on the calling thread with no transaction. Any analyzer that writes throws — on ARM,
`FunctionStartAnalyzer` writes the TMode context register, which is why ARM/Thumb images trigger it
so reliably.

`getOrOpen` calls it at line 103, gated on the `Analyzed` program option:

```java
if (!program.getOptions(Program.PROGRAM_INFO).getBoolean(Program.ANALYZED_OPTION_NAME, false)) {
    analyzeProgramBlocking(program);   // throws
    ghidraProject.save(program);       // never reached
}
openPrograms.put(domainFile.getName(), program);   // never reached either
```

The flag is only set as a side effect of analysis *completing*. It throws → flag stays false →
program never cached → next call retries → throws again. Forever. And because `getOrOpen` runs
before any tool's own logic, **read-only endpoints fail too**. Recovery today is a server restart.

Diagnostic signature, worth recording: server-level tools (`/health`, `check_connection`,
`list_project_files`) keep working normally while every tool touching the program fails
identically. Argument validation also still works, because it runs before the handler touches the
`Program`.

### Bug B — the cache key never matches the lookup key

```java
Program cached = findCached(programName);            // caller's spelling
...
openPrograms.put(domainFile.getName(), program);     // "firmware.elf"
```

`findDomainFile` matches on **name or pathname**, but `openPrograms` is keyed on `getName()` only.
Meanwhile `listProjectFiles()` returns `f.getPathname()` — so **the tool that tells the agent what
to pass returns the exact form that can never hit the cache.**

Consequences on every call that uses the pathname form (`/firmware.elf`):

- the domain file is re-resolved and `getDomainObject(consumer, …)` called again, adding a
  duplicate consumer reference each time (a slow leak; the same `ProgramDB` instance comes back, so
  the per-program lock still works);
- **the analyze gate at line 102 is re-evaluated on every single request.**

### How the two combine — the project A timeline explained

The project A server ran fine for hours, then wedged mid-session. That is fully explained: the flag was
`true` (analysis had been saved earlier), so Bug B was only costing a redundant reopen. Then
`SetLanguage.java` called `Program.setLanguage()`, which resets analysis state and clears
the analysed flag. From that instant every request re-entered Bug A and the server was wedged for
good — including `run_script`, which had been the documented escape hatch for the sibling
`analyze_program` bug.

### Why the current mitigation is the wrong shape

`drainLeakedEntries` (`ProgramManager.java:305-346`) is a ~40-line post-mortem repair that
reconstructs Ghidra's internal transaction IDs from `baseId + list_index` arithmetic and drives
`activeEntries` to zero to trigger Ghidra's own ABORTED cleanup. Its own doc comment concedes the
`forceLock` fallback leaves the program permanently unusable and the operator should restart.

It repairs a mutated shared object in place. **Repair is unreliable; discard is reliable.** And it
does not address Bug A at all — that is a *missing* transaction, not a leaked one, so the drain
never fires for it.

---

## 2. Proposed changes — transactions and program lifecycle

Ordered by leverage. (1) alone removes the entire reported failure class.

### 2.1 Stop analysing from a read path — **DONE 2026-08-08**

Implemented as a rejection, not a transacted auto-analysis. Note §2.3 had to land first: with
`analyze_program` still broken, rejecting unanalyzed programs would have pointed callers at a tool
that could not work. Program opening is now split — `getOrOpen` requires an analyzed program,
`getOrOpenForAnalysis` is used only by `analyze_program`.

Two findings from implementing it, both worth keeping:

- `GhidraProject.analyze()` does **not** mark the program analyzed. Only
  `GhidraProgramUtilities.markProgramAnalyzed` does, and nothing in the analysis path calls it.
  This confirms the project B log's "both halves are required" from first-hand source reading
  (`Base-src.zip`, `GhidraProject.java:534`, `GhidraProgramUtilities.java:85`).
- The missing transaction breaks **x86 too**, not only ARM. Reverting the fix, the test fails with
  `db.NoTransactionException` from the *GCC Exception Handlers* analyzer on the plain x86 fixture.
  The field reports pinned it on ARM's TMode-writing `FunctionStartAnalyzer`, which made it look
  more architecture-specific than it is.


`getOrOpen` is a read that performs a hidden, unrecoverable write. Per design principle 3 (never
silently accept or fix — reject with a specific, actionable error), the correct behaviour is not to
analyse silently but to refuse:

```
Program 'firmware.elf' has not been analyzed. Run analyze_program first.
```

That deletes Bug A outright, converts an unrecoverable wedge into a one-line self-correcting error,
and removes a multi-minute surprise from what the agent thinks is a cheap read.

If auto-analysis must stay: wrap it in `program.startTransaction(...)` / `endTransaction` in
try/finally, **and** set `ANALYZED_OPTION_NAME` in the finally so a failure cannot loop. Both halves
are required — the project B log documents that the flag must be set explicitly or `getOrOpen`
retries regardless.

Effort: small. Risk: low. Behaviour change: a GUI-imported, never-analysed program now errors
instead of silently analysing — which is the intended teaching signal.

### 2.2 Fix the cache key — **DONE 2026-08-08**

Key `openPrograms` on `domainFile.getPathname()` and register `getName()` as an alias, or normalise
the caller's spelling before both the lookup and the store. Kills the repeated reopens and the
consumer-reference leak, and stops the analyze gate re-firing per request.

Effort: trivial. Risk: none. **Worth doing even if nothing else here is.**

Implemented as a two-stage lookup rather than an alias map: the fast path tries the caller's
spelling directly (the pathname, which is what `list_project_files` returns), and on a miss the
resolved `domainFile.getPathname()` is looked up again before opening. The filename spelling
therefore costs an in-memory folder walk but never a re-open. No alias map means no divergence
from `findDomainFile`'s own tree-order resolution when two folders hold the same filename.

Covered by `ToolResourceIntegrationTest.getOrOpen_filenameAndPathnameSpellingsShareOneCacheEntry`,
which asserts both spellings return the same instance *and* that the consumer-reference count does
not grow — verified to fail against the pre-fix code and pass after. Note the existing suite passes
the bare-filename spelling throughout, so it exercises the resolved path on every test.

Known limitation left alone deliberately: `findDomainFile` resolves an ambiguous bare filename
(the same name in two folders, e.g. project B's `/Tool.exe` and `/tool/Tool.exe`) to
whichever comes first in tree order. Rejecting that with an "ambiguous, use the full path" error
would fit design principle 3 and is worth doing, but it is a separate behaviour change.

### 2.3 Make `analyze_program` work — **DONE 2026-08-08**

`analyzeProgram()` (`:174`) takes the per-program lock but deliberately opens no transaction, on a
stated assumption that auto-analysis manages its own. That assumption is wrong for the first call in
the chain: `reAnalyzeAll(null)` writes to the program. Wrap the `reAnalyzeAll` + `waitForAnalysis`
pair in a transaction, or route it through `withTransaction`.

Effort: trivial. Removes the reason projects write `Analyze.java`-style workaround scripts.

### 2.4 Eviction instead of drain — **see §3 before implementing**

Add `ProgramManager.evict(Program)`: remove from `openPrograms`, `release(consumer)`, drop the
`transactionLocks` entry. Call it on the failure path only — a script that threw, a script that left
a transaction open, or any call that failed with a transaction-state exception.

The next `getOrOpen` reopens from the project database on disk with a clean transaction stack.
Recovery goes from "restart the server" to "the next call is clean", and it replaces the ID-arithmetic
drain with a handful of lines.

**Precondition: §3.2 must land first.** Do not enable eviction before the `withProgramLock` save gap
is closed.

### 2.5 `run_script` transaction mode

Add an optional `transaction` field: `"auto"` (default — today's behaviour, `GhidraScript.execute()`
holds a transaction for the whole of `run()`) and `"none"` (drive `run()` outside a transaction).

This removes the `end(true)` / `start()` hack that every `setLanguage`-style script currently has to
carry, and which is easy to get wrong in a way that wedges the program. An option on an existing
tool, per design principle 9.

### 2.6 Log the actual exception server-side

`ApiExceptionMapper` (`HttpApiServer.java:303`) keeps only `getMessage()`. The project A session could not
file a proper bug report because the stack trace went only to a pty owned by another process, and
the reporter (correctly) would not restart shared infrastructure on a guess.

Log the full stack to a rotating file and return an `error_id` in the JSON envelope so a report can
quote it. Also: map `WebApplicationException` to its own status so a 404 stops reading as
`"Internal error"` (issue #10).

---

## 3. Does eviction lose analysis and naming work?

Raised as a blocking concern, and it splits three ways. Two are already safe; one is a real gap that
must be closed first.

### 3.1 Names, types and structs are already safe

Every write tool goes through `withTransaction`, which saves on success
(`ProgramManager.java:371-373`):

```java
if (success) {
    program.getDomainFile().save(TaskMonitor.DUMMY);
}
```

So every `rename_function`, `rename_variable`, `set_function_prototype`, `create_struct`,
`add_struct_field`, `create_label` and `set_comment` is committed to the `.gpr` on disk **before the
HTTP response returns**. Eviction drops an in-memory handle; it cannot touch anything already on
disk. Reopening reads it all back.

### 3.2 Script results are **not** currently safe — fix before enabling eviction

`withProgramLock` (`ProgramManager.java:236-270`) has **no save call**. It takes the lock, runs the
action, checks for a leaked transaction, unlocks. `GhidraScript.execute()`'s `end(true)` commits to
the in-memory `ProgramDB` but does not save the `DomainFile`.

So a *successful* script's work — a memory map, 63 peripheral instances, an applied `symbols.csv` —
currently sits unsaved in memory and would be lost on eviction. (Note this contradicts the project A
issues log, which states "`withProgramLock`/`withTransaction` already persist on the way out". That
is true of `withTransaction` and false of `withProgramLock`.)

This is a latent bug independent of eviction: any server crash or restart loses it too. The fix is
one line — save at the end of a successful `withProgramLock`, mirroring `withTransaction`. With that
in place, eviction loses only the changes of the run that just *failed*, which is exactly the state
worth discarding.

### 3.3 Reopening is not re-analysis

`ANALYZED_OPTION_NAME` lives in the program's options and is persisted with the database, so a
reopened program is still analysed and `getOrOpen` will not re-run analysis. (Under §2.1 it would
not analyse at all.) The cost of a reopen is a database handle plus lazy paging and a cold
decompiler cache — seconds, not the multi-minute analysis pass.

### 3.4 Scope

Evict on the failure path only, never routinely. A healthy program stays cached for the server's
lifetime exactly as today.

**Summary:** with §3.2 landed, eviction costs at most the failed run's own partial changes. Given
that a failed `run_script` already leaves the program in a documented unknown-partial state
(memory-block creations surviving a throw), discarding that is an improvement, not a loss.

---

## 4. Plate comments crowding out naming

The recurring field failure: an agent decompiles a function, understands it, writes a
multi-paragraph PLATE comment, leaves every identifier as `local_2c` / `uVar7`, and moves on.
Nothing propagates and the next session re-derives it. Documented as user feedback in
`ghidra-naming-over-plate.md` (2026-07-21) and re-flagged 2026-07-16 in
`ghidra-persist-findings.md`.

**Mechanical cause:** a plate comment is *one* call that accepts arbitrary prose and is never
rejected; naming is *N* calls that are each validated and can fail. The incentive gradient points at
the plate. A ban alone does not fix that — it displaces the prose into PRE comments.

Three changes, in leverage order:

### 4.1 Make naming batchable (highest leverage)

Let `rename_variable` accept an array of `{current_name, new_name}` applied in one transaction.
Renaming 14 locals is currently 14 round-trips against one call for a plate. The project B session
log reached the same conclusion independently ("individual calls are 10-50× slower and burn MCP
round trips"). An extension of an existing tool, per principle 9. **You cannot close the cheap wrong
path without opening a cheap right one.**

### 4.2 Per-type comment caps in `rules.yaml`

Fits the existing architecture exactly — a `comments:` map alongside `naming:`, reusing
`RulesEngine`, `NamingRuleViolation` and the 400 path, configurable per project. Note
`MAX_COMMENT_LENGTH` (4096) already exists as a hard cap; this is a configurable per-type tightening
with a custom message.

```yaml
comments:
  PLATE:
    max_length: 300
    message: >
      Plate comments are a 1-2 line pointer, not the analysis. Record what you found by
      renaming: rename_function, rename_variable, set_function_prototype, create_struct.
      If it does not fit in 300 chars it belongs in names and types, not a comment.
  EOL:
    max_length: 120
```

### 4.3 A precondition rule, not a length rule (the sharp one)

Length caps are gameable — many short plates beat one long one. What actually correlates with the
failure is *a comment written on a function that is still auto-named*.

Reject a `PLATE` on a function whose name still matches `^(FUN_|SUB_|thunk_FUN_)`, with a message
naming the exact next call. Optionally extend to locals: reject when more than N variables still
match `^(local_|uVar|iVar|puVar|param_)\d+`, with a message pointing at `get_function_variables`.
This encodes the intended ordering directly instead of approximating it by size.

### 4.4 What not to do

**Do not ban PLATE outright.** Plates are legitimately right for a role summary, a caveat the names
cannot carry, a pointer to the durable write-up, or a bit/pin map with no natural home in a type —
e.g. project A's `maybe_board_gpio_init`, which carries a full pin-group-to-consumer map. A hard ban
blocks good comments and pushes the prose into PRE.

All three rules should be configurable and default-off per project, since project A deliberately diverges
(see §5.2).

---

## 5. Consistency and documentation

### 5.1 Parameter-name divergence (principle 1)

Four separate round-trips were lost to this in one session. Breaking changes are cheap here
(principle 3) — rename outright, no aliases:

| Tool | Today | Should be |
|---|---|---|
| `search_defined_strings` | `filter` | `query` (matches `search_functions`, `search_data_types`) |
| `read_data` | `item_count` | keep, but reconcile with `instructions` below |
| `get_disassembly` | `instructions` | `limit` (matches every other list/search tool) |
| `set_function_prototype` `parameters[]` | `{name, type}` | `{name, type_name}` (matches `add_struct_field`, `set_parameter_type`) |
| `get_xrefs_to` / `get_xrefs_from` | no cap | add `limit` + `truncated`, matching the other list tools |

Also: `count` in list responses is the returned page size, not a grand total. Either add a `total`
or document the convention once and apply it everywhere.

### 5.2 Naming rules on labels and globals

`rename_global` (`WriteTools.java:152`) and `create_label` (`:183`) both validate against the
`function_name` rule, so every data label must carry `maybe_`/`likely_`/`guess_`.

That is wrong for **recovered** names. CMSIS peripheral names and their register fields are datasheet
facts, not inferences — `UART0->CTRL` is strictly more readable than
`likely_UART0->maybe_CTRL_0x18`. Project A worked around it by applying those from
GhidraScripts, which bypass the rules engine entirely — i.e. the rule is being routed around rather
than obeyed, which is the worst outcome.

Add distinct `label_name` / `global_name` rule keys so a project can permit plain recovered names
without dropping to scripts. The prefixes stay mandatory on functions.

### 5.3 Docs

- `README.md:104-105` — replace the fictional `GET /tools` / `POST /call` table with the real
  surface (`/health`, `/schema`, `/openapi.json`, `GET|POST /tool/<operationId>`). Working this out
  from source cost a reported ~15 minutes at session start.
- Document the per-tool `limit` caps in `TOOLS.md` (1000 on `search_defined_strings` /
  `search_functions`, 2000 on the byte/instruction/constant searches, 5000 on `list_globals`).
- Document that `add_script` **snapshots** the file (issue #12), or better: have `run_script` compare
  mtime/hash against the registered source and re-copy or warn. The current failure mode is a
  plausible success response running old code.
- Fix `projects/<project-c>/.claude/skills/ghidra-<project-c>/SKILL.md:31` — 5 positionals, missing the empty
  vmargs slot.

### 5.4 Smaller items

- `import_binary`: add optional `language_id` / `base_address` and use `BinaryLoader` with an
  explicit `LanguageCompilerSpecPair`, so a headerless image does not need a bespoke script
  (issue #4).
- `findDataType`: alias the `<stdint.h>` spellings (`uint32_t` → `uint`, etc.). Every prototype typed
  from a datasheet or header currently costs one guaranteed round-trip (issue #11).
- `run_script`'s "no args = help" convention makes a genuinely zero-argument script need a dummy
  argument. Either drop the convention or document it in `TOOLS.md` as a script-authoring
  requirement.

---

## 6. Suggested order of work

Each step is independently shippable.

1. ~~**§2.2** cache key~~ — **done**, plus `findDomainFile` now rejects an ambiguous filename.
2. ~~**§2.3** transact `analyze_program`~~ — **done.** Swapped ahead of §2.1: rejecting unanalyzed
   programs while `analyze_program` was still broken would have left no way out.
3. ~~**§2.1** remove auto-analysis from `getOrOpen`~~ — **done.**
4. **§3.2** save at the end of a successful `withProgramLock` — a latent data-loss bug in its own
   right, and the precondition for step 5.
5. **§2.4** eviction on the failure path; then delete `drainLeakedEntries`.
6. **§2.6** server-side log file + `error_id`; map 404 to 404.
7. **§4.1** batch `rename_variable`; then **§4.2** / **§4.3** comment rules.
8. **§5.1** parameter renames + `TOOLS.md` regeneration; **§5.3** README.
9. **§5.2** `label_name` / `global_name` rule keys.
10. **§5.4** the remaining small items.

Per the repo's definition of done, each change needs integration tests covering the happy path *and*
the error path, `make tools-docs` regenerated, and `gradle buildExtension` run before `pytest` — the
pytest fixture installs the newest `dist/*.zip` and does not rebuild.
