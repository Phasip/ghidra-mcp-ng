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

### 2.4 Eviction instead of drain — **DONE 2026-08-08**

Added `ProgramManager.evict(Program, reason)`: remove from `openPrograms`, `release(consumer)`, drop
the `transactionLocks` entry. Called on the failure path only — a script that threw, a script that
returned while still holding a transaction, and (in `withTransaction`) a program whose own
transaction state is broken. `drainLeakedEntries` and its ID arithmetic are deleted.

Confirmed from Ghidra source that closing mid-transaction is safe, which the whole approach rests on:
`DomainObjectAdapterDB.close()` → `transactionMgr.close()` only checks `lockCount` (set by
`forceLock`/`lock`, not by transactions) and `DomainObjectTransactionManager.doClose()` is a no-op;
`DBHandle.close()` then disposes the buffer manager unconditionally, discarding uncommitted changes.

Two things worth recording:

- Removal is by identity (`values().removeIf(p -> p == program)`), because the cache is keyed on
  pathname and callers hold a `Program`. Guarding the release on that removal also makes eviction
  idempotent — `release` throws on an unknown consumer.
- The "returned with a transaction open" error now reports
  `TransactionInfo.getOpenSubTransactions()`, not `getDescription()`. The enclosing transaction is
  the one `GhidraScript` opens around `run()` and is named after the script class, so the original
  message named the script rather than the leaking call. The first version of the test caught this.

Accepted trade-off: a concurrent caller that resolved the `Program` before eviction sees
"program is closed" on that one call. That is recoverable — its next `getOrOpen` returns the fresh
instance — and it is strictly better than leaving a permanently wedged program cached.

Covered by `runScript_failure_evictsProgramButKeepsSavedWork` (fresh instance afterwards, work saved
before the crash survives) and `runScript_returnsWithTransactionOpen_reportsItAndEvicts` (message
names the leaked transaction, program reopens usable). Both plus the pre-existing
`runScript_leakedTransaction_doesNotLockSubsequentCalls` verified to fail with `evict` stubbed out.

### 2.5 `run_script` transaction mode — **NOT IMPLEMENTABLE as specified; documented instead 2026-08-08**

The proposal was an optional `transaction` field: `"auto"` (default — today's behaviour,
`GhidraScript.execute()` holds a transaction for the whole of `run()`) and `"none"` (drive `run()`
outside a transaction), removing the `end(true)` / `start()` hack that every `setLanguage`-style
script carries.

**`"none"` cannot be built on Ghidra's public API.** The transaction is opened by
`GhidraScript.executeNormal()`, which is `private` and does exactly `start(); run(); end(true)`.
Its only caller, `doExecute`, is also `private`, and `run()` itself is `protected abstract` — so a
non-subclass in another package has no way to reach it. Driving `run()` directly would mean
reflecting into private members *and* re-implementing `doExecute`'s setup
(`loadVariablesFromState`, `loadPropertiesFile`, the writer/monitor/state assignment,
`updateStateFromVariables`, `doCleanup`), half of which is private too. That is a hack that breaks
on any Ghidra update and fails by silently skipping setup — strictly worse than the two-line
workaround it replaces.

What was done instead: `run_script`'s summary now states the mechanism outright — Ghidra holds a
transaction around `run()`, a script must not open an outer one, an operation that manages its own
transaction must be bracketed by `end(true)` / `start()`, and returning with an extra transaction
open evicts the program. The guesswork was the real cost; §2.4 already turned the failure from a
permanent wedge into an evict-and-reopen.

Worth revisiting only if Ghidra ever exposes an execute-without-transaction entry point.

### 2.6 Log the actual exception server-side — **DONE 2026-08-08**

`ApiExceptionMapper` (`HttpApiServer.java:303`) keeps only `getMessage()`. The project A session could not
file a proper bug report because the stack trace went only to a pty owned by another process, and
the reporter (correctly) would not restart shared infrastructure on a guess.

Log the full stack to a rotating file and return an `error_id` in the JSON envelope so a report can
quote it. Also: map `WebApplicationException` to its own status so a 404 stops reading as
`"Internal error"` (issue #10).

Implemented as `mcp/ServerLog.java` (rotating at 4 MB, one previous generation kept) plus a
three-way split in the mapper: a rejected argument stays a 400 with the message alone; a
`WebApplicationException` keeps its own status; anything else is logged and the response carries
`error_id`. Writing is best-effort — if the file cannot be opened the id is still allocated and the
entry falls back to stderr, so logging can never block a response.

Decisions worth keeping:

- The log is **per project** (`~/.ghidra-mcp-ng/<project>.log`, `--log` to override), not shared.
  Two servers interleaving into one file makes it useless exactly when two projects are in play.
- `GET /health` reports the active path as `log_file`. Without that, an `error_id` is only useful to
  whoever already knows where the server writes — which is the same gap that made the project A trace
  unreachable in the first place.
- A 404 on this server means one thing: a tool name that does not exist. It now says so and names
  the closest real tool, reusing `UnknownQueryParamFilter`'s levenshtein "did you mean" — moved to
  `ApiSupport` rather than duplicated. The tool-name list comes from `ToolHelpers.listEndpoints`,
  reflection-derived for the same reason `countEndpoints` is (`countEndpoints` is now its size).
- 405 falls out of the same change: a GET on a POST-only tool used to read as an internal error.

Covered by `tests/test_integration.py::TestErrorReporting` — 404 with suggestion, 404 on a
non-tool path, 405, `log_file` in `/health`, and an `error_id` that appears exactly once in the log
next to the stack trace. All five verified to fail against the previous `HttpApiServer`.

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

### 3.2 Script results are **not** currently safe — fix before enabling eviction — **DONE 2026-08-08**

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

### 4.1 Make naming batchable (highest leverage) — **DONE 2026-08-08**

Renaming 14 locals is currently 14 round-trips against one call for a plate. The project B session
log reached the same conclusion independently ("individual calls are 10-50× slower and burn MCP
round trips"). **You cannot close the cheap wrong path without opening a cheap right one.**

The plan said "let `rename_variable` accept an array". That was wrong, and the correction is the
main thing worth recording: **`batch_tool_call` already exists as the generic batching idiom** — it
was merely read-only by construction (`BATCH_ALLOWLIST`, plus a doc comment asserting write tools
"may take transactions or run for a long time"). An array parameter on `rename_variable` would have
been a *second* batching idiom for one tool, and the same argument would then have applied to
`rename_function`, `rename_global`, `set_comment` and `set_parameter_type` in turn. That is exactly
what principle 1 forbids. Widening the existing tool was the smaller and more consistent change.

Implemented by allowlisting the eleven write tools that make one short, self-contained edit and
dispatching them from `dispatchBatchTool`. Points worth keeping:

- Dispatch for a write is a one-liner (`writeTools.renameFunction(args)`) because write tools take
  the `JsonObject` body verbatim — a batch item *is* the standalone request body. The read tools
  each need their query params unpacked; the write half has no second spelling of any parameter to
  drift out of sync. `ReadTools` gained a `WriteTools` constructor argument for this; there is no
  cycle, and `GhidraMcpServer` just constructs `WriteTools` first.
- **Each item keeps its own transaction and its own save.** Batching removes round-trips, not
  durability, so a batch is exactly N standalone calls with one HTTP hop — including on the failure
  path, where the eviction logic in `withTransaction` re-resolves the program for the next item via
  its own `openProgram`. One transaction for the whole batch was rejected: it would have meant
  either restructuring every write tool to opt out of `runTransaction`, or an all-or-nothing rollback
  that discards thirteen good renames because the fourteenth name was taken.
- A failed item does not abandon the rest, and the response gained `failed` (count of `ok=false`).
  Without it a partial failure is invisible at a glance in a 14-item result list, and a rename the
  agent believes landed but did not is precisely the failure this section exists to prevent.
- `analyze_program` and `import_binary` join `run_script` as deliberately not batchable — minutes
  per call, once per program. They get their own reason (`NOT_BATCHABLE` map) rather than the
  generic "not allowlisted", per coding standard 1.

Covered by `tests/test_integration.py::TestBatchedWrites`: batched rename round-trip, partial
failure (bad item reported, good item still applied and observable), batched `set_comment`, and both
rejection paths.

### 4.2 Per-type comment caps in `rules.yaml` — **DONE 2026-08-08** (with §4.3)

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

### 4.3 A precondition rule, not a length rule (the sharp one) — **DONE 2026-08-08**

Length caps are gameable — many short plates beat one long one. What actually correlates with the
failure is *a comment written on a function that is still auto-named*.

Reject a `PLATE` on a function whose name still matches `^(FUN_|SUB_|thunk_FUN_)`, with a message
naming the exact next call. Optionally extend to locals: reject when more than N variables still
match the decompiler's default spellings, with a message pointing at `get_function_variables`.
This encodes the intended ordering directly instead of approximating it by size.

**Both landed as one `comments:` section**, keyed by comment type alongside `naming:`, reusing
`RulesEngine` / `NamingRuleViolation` / the 400 path exactly as predicted. Keys: `max_length`,
`require_named_function`, `max_auto_named_variables`, `message`. Every constraint is off unless
set, so an absent section (or no `--rules`) leaves `set_comment` unconstrained.

Findings worth keeping:

- **The variable rule cannot see what the field reports complain about most.** `uVar7`, `iVar3`,
  `puVar2` are the *decompiler's* inventions and live only in its view — they never reach the
  listing, so `Function.getAllVariables()` cannot count them. Reading them means a decompile on
  every `set_comment` call, which is far too expensive for a guard rail. The rule therefore counts
  listing variables only (`local_`, `param_`, `unaff_`, `in_`, `extraout_`), which is the bulk of
  what an unanalysed function carries but *not* all of it. The plan's proposed regex
  (`^(local_|uVar|iVar|puVar|param_)\d+`) implied otherwise; it would have silently matched nothing
  for three of its five alternatives.
- `RulesEngine` stays free of Ghidra types: `set_comment` passes the enclosing function's *name*,
  and the variable count as an `IntSupplier` so the listing walk never runs for a `max_length`-only
  rule. Covered by a test that throws from the supplier if it is consulted.
- Address resolution moved ahead of `runTransaction` in `set_comment` — the rules need the
  enclosing function, and per coding standard 5 that lookup belongs outside the transaction anyway.
  A rejected comment is now provably never written (asserted in the test).
- The auto-name patterns (`FUN_`/`SUB_`/`thunk_FUN_`) are deliberately **not** configurable. They
  are Ghidra's own conventions, not a project preference, and a knob there is one more thing to get
  wrong.
- Comments on data (no enclosing function) are subject to `max_length` alone; clearing a comment is
  always allowed, since it can only reduce what the rule objects to.

Covered by 11 new `RulesEngineTest` cases (engine mechanics, message content, the laziness
guarantee) plus 4 in `ToolResourceIntegrationTest` that drive the real `set_comment` against the
fixture — including one that renames a function to `FUN_<addr>` to recreate the state the rule
exists to catch, since the fixture is compiled with symbols and has nothing auto-named. The
variable-count test derives its threshold from the fixture and `assumeTrue`s rather than silently
passing if the analyzer ever stops recovering auto-named locals.

Note the live pytest server runs without `--rules`, so the Python suite deliberately covers none of
this; enforcement lives in the two Java suites.

### 4.4 What not to do

**Do not ban PLATE outright.** Plates are legitimately right for a role summary, a caveat the names
cannot carry, a pointer to the durable write-up, or a bit/pin map with no natural home in a type —
e.g. project A's `maybe_board_gpio_init`, which carries a full pin-group-to-consumer map. A hard ban
blocks good comments and pushes the prose into PRE.

All three rules should be configurable and default-off per project, since project A deliberately diverges
(see §5.2).

---

## 5. Consistency and documentation

### 5.1 Parameter-name divergence (principle 1) — **DONE 2026-08-08**

Four separate round-trips were lost to this in one session. Breaking changes are cheap here
(principle 3) — renamed outright, no aliases:

| Tool | Was | Now |
|---|---|---|
| `search_defined_strings` | `filter` | `query` (matches `search_functions`, `search_data_types`) |
| `read_data` | `item_count` | **unchanged** — see below |
| `get_disassembly` | `instructions` | `limit` (matches every other list/search tool) |
| `set_function_prototype` `parameters[]` | `{name, type}` | `{name, type_name}` (matches `add_struct_field`, `set_parameter_type`) |
| `get_xrefs_to` / `get_xrefs_from` | no cap | `limit` (default 500, max 5000) + `truncated` |

`item_count` stays as it is. It is not a page size — it pairs with `item_size` to describe the
*shape* of a fixed read (`item_size * item_count` bytes, capped at 64 KiB), so spelling it `limit`
would make it look like a truncation knob when it is a required part of the request. The divergence
in the audit table was a misreading.

Decisions worth keeping:

- **Renaming a parameter is only half the fix; the other half is what the old spelling now does.**
  `filter` and `instructions` were already handled — `UnknownQueryParamFilter` rejects any
  undeclared query param — so they self-correct. `parameters[].type` did **not**: it lived inside a
  JSON body object that nothing validated, so the old spelling read only as
  "'parameters[0].type_name' is required", saying nothing about the key actually sent. Added
  `rejectUnknownParameterFields`, mirroring `UnknownQueryParamFilter` for that nested object.
  A misspelled key now names itself and its intended field.
- The first attempt at that hint scanned the object for a key that `suggestClosest` maps onto the
  missing field. It fired on `name` — `suggestClosest` accepts on substring, and `type_name`
  contains `name` — and pointed the caller at a key that was already correct. Rejecting *unknown*
  keys is the right shape; suggesting a replacement for a *present* key is not.
- `get_disassembly`'s `limit` now goes through `requireLimit` like every other list tool, which
  means `limit=0` is accepted (returns an empty window) where the old `requirePositive` rejected it.
  Consistency with the neighbours was worth more than the extra rejection.
- Xref `truncated` is computed *after* the ref-type and address-range filters, so it means
  "a matching xref was dropped" and never "the page happened to fill exactly". `search_bytes` and
  `search_instructions` use the looser `hits.size() >= limit`; the precise form costs nothing here.
- `indirect_calls` is deliberately not subject to `limit` — it is inferred from the full reference
  set, not paged from it. Said so in its `@Schema`.

On `count`: documented the convention rather than adding a `total`, since a true total means a full
scan on every call. Every `count` that a `limit` can bound now carries a `@Schema` saying it is the
size of the returned page, and every `limit` names its own cap (1000 / 500 / 2000 / 5000) so
`TOOLS.md` carries them — the caps were previously discoverable only by exceeding one.

**Silent truncation — DONE 2026-08-09.** `search_functions`, `search_data_types` and
`search_defined_strings` had a `limit` but no `truncated` flag, so a result of exactly `limit` items
was indistinguishable from a complete one. Fixed the same way the xref tools were, and the sweep
turned up more than the three the audit named:

| Tool | Was | Now |
|---|---|---|
| `search_functions` | no flag | precise `truncated` |
| `search_data_types` | no flag | precise `truncated` |
| `search_defined_strings` | no flag | precise `truncated` |
| `search_constant_references` | no flag | precise `truncated` |
| `search_bytes` | `count >= limit` | precise `truncated` |
| `search_instructions` | `count >= limit` | precise `truncated` |
| `list_globals` | `count >= limit` | precise `truncated` |

Points worth keeping:

- **The loose form `count >= limit` is a *false positive*, not a missing flag**, and that is the
  worse of the two failures the audit lumped together. A silently truncated page at least looks
  complete; a page that lies about being truncated sends the agent back for a second call that
  returns the identical result, which is exactly the round-trip cost §5.1 exists to remove. So the
  three tools that already carried a flag needed the same change as the four that carried none.
- Precise means the limit is checked **after** every filter and after `search_defined_strings`'
  offset skip, so `truncated` means "a matching item past this page was dropped". `search_bytes` is
  the one that cannot do it inline — `scanBlockForPattern` fills a list to a cap — so it scans for
  `limit + 1` hits and drops the extra. The extra scan only runs to completion when the match count
  is exactly `limit`, which is the one case where the answer matters.
- `search_data_types` reads two managers in sequence (the program's, then built-ins). Once the first
  overflows the page the second is skipped entirely rather than walked to rediscover the same
  overflow — `Collections.emptyIterator()` keeps that a data decision rather than a second branch.
- Not given a flag, deliberately: `list_exports` / `list_imports` / `list_data_type_categories`
  (no `limit` — they return everything, and say so), `get_function_callees` (no `limit`), and
  `read_data`'s `item_count` (a read shape, not a page — see above).

Covered by `TestPaginationTruncation`, parametrised over all seven plus `get_xrefs_to` as the
already-correct control: it derives the true match count from a max-limit query, then asserts a page
of exactly that size reports `truncated: false` and a page one shorter reports `true`. Plus
`test_search_defined_strings_paging_terminates`, which pages by `offset` to a final untruncated page
— the only tool where `truncated` and `offset` interact. Verified against the pre-fix build: 12 of
the 17 new cases fail, and the 5 that pass are precisely the ones where the loose form already
agreed (the short-page direction, and both `get_xrefs_to` cases).

### 5.2 Naming rules on labels and globals — **DONE 2026-08-08**

`rename_global` (`WriteTools.java:152`) and `create_label` (`:183`) both validated against the
`function_name` rule, so every data label had to carry `maybe_`/`likely_`/`guess_`.

That is wrong for **recovered** names. CMSIS peripheral names and their register fields are datasheet
facts, not inferences — `UART0->CTRL` is strictly more readable than
`likely_UART0->maybe_CTRL_0x18`. Project A worked around it by applying those from
GhidraScripts, which bypass the rules engine entirely — i.e. the rule was being routed around rather
than obeyed, which is the worst outcome.

Added `label_name` and `global_name`. The prefixes stay mandatory on functions; the shipped
`rules.yaml` leaves both new keys unset (= unconstrained) with commented-out examples and the
reasoning inline.

Points worth keeping:

- **The change's own risk is silence.** `validate` passes when no rule is configured, so pointing
  these two tools at new keys silently drops enforcement for any project whose `rules.yaml` only
  defines `function_name`. Nothing can infer that project's intent — but the same silence was
  already a standing trap: `naming:` is a free-form map, so a project that wrote `label_name` before
  today got no rule and no error. So `RulesEngine.load` now rejects any key outside
  `KNOWN_NAMING_FIELDS` / `KNOWN_COMMENT_TYPES`, with the usual `suggestClosest` "did you mean".
  A typo'd rule can no longer look configured while enforcing nothing.
- **The file is validated; the constructor is not.** `RulesConfig` is a programmatic API that tests
  legitimately drive with invented field types, and `validate(fieldType, …)` stays generic. Only
  `load(File)` — human input — is checked. Two existing `RulesEngineTest` cases used `my_field` /
  `type_a` through the YAML path and now use real keys, which is what they should have exercised.
- `create_label` and `rename_global` had **no test coverage at all** in either suite before this.
  They now have three: the function rule provably does not reach a label, each new key is enforced
  end-to-end, and a rejected label is not written. Plus a `KNOWN_NAMING_FIELDS` guard test — a tool
  validating a key missing from that list would make the key unconfigurable, since `rules.yaml`
  would then reject it at startup.

### 5.3 Docs — **README and caps DONE 2026-08-08**

- ~~`README.md:104-105` — the fictional `GET /tools` / `POST /call` table~~ — **done.** Replaced
  with the real surface (`/health`, `/schema`, `/openapi.json`, `GET|POST /tool/<operationId>`),
  the response envelope, the `error_id`/`log_file` path, and a worked `curl` for each verb. Says
  outright that there is no dispatcher endpoint, since that is the wrong model the old table taught.
- ~~Document the per-tool `limit` caps in `TOOLS.md`~~ — **done**, in the `@Parameter` descriptions
  so the generator picks them up (1000 `search_functions`/`search_defined_strings`, 500
  `search_data_types`, 2000 the byte/instruction/constant searches and `get_disassembly`, 5000
  `list_globals` and the xref tools).
- ~~`add_script` **snapshots** the file~~ — **done 2026-08-09** (issue #12). `add_script` now records
  the source path in a sidecar next to the copy, and `run_script` re-copies whenever the source's
  contents differ. An edit needs no second `add_script`. See below.
- Fix `projects/<project-c>/.claude/skills/ghidra-<project-c>/SKILL.md:31` — 5 positionals, missing the empty
  vmargs slot. (Outside this repo.)

One generator change came with this: `scripts/generate_tools_docs.py` rendered a nested request
object as a bare `object`, so `set_function_prototype`'s `parameters` documented its element keys
nowhere in `TOOLS.md` — the exact information the `{name, type}` → `{name, type_name}` rename makes
load-bearing. It now renders `array of object {name, type_name}`. (The MCP bridge was never
affected; `bridge.py` resolves item `$ref`s and passed the nested shape through all along.)

### 5.4 Smaller items — **DONE 2026-08-08**

- **`import_binary` takes optional `language_id` / `base_address`** (issue #4). The plan said to
  select `BinaryLoader` explicitly; that turned out to be unnecessary and slightly wrong.
  `GhidraProject.importProgram(file, language, compilerSpec)` runs loader detection *constrained to
  loaders that support the language*, so a headerless blob lands on `BinaryLoader` (the only one
  that claims it) while an ELF with a language override still goes through `ElfLoader` and keeps its
  sections. Forcing `BinaryLoader` would have thrown the ELF's structure away. One parameter, right
  in both cases, no new mode flag.
  - `base_address` is applied **before** analysis, via `setImageBase` in its own raw transaction —
    not `withTransaction`, because the imported program has no saved `DomainFile` yet (still the
    import proxy; `saveAs` has not run) and `withTransaction` saves on the way out. Relocating after
    analysis would leave every recovered pointer and function address pointing at the old base.
  - An unresolvable `language_id` names the closest real id via `suggestClosest` over
    `getLanguageDescriptions`. No tool lists language ids, so without that it is a dead end.
- **`findDataType` accepts the `<stdint.h>` spellings** (issue #11) — `int8_t`…`int64_t`,
  `uint8_t`…`uint64_t`, plus `size_t`/`ssize_t`/`intptr_t`/`uintptr_t`/`ptrdiff_t` at the program's
  pointer width. The plan's "`uint32_t` → `uint`" mapping is not safe as written: Ghidra's `uint`
  takes its width from the program's data organisation, so the alias would be a *rename*, not a
  width guarantee. Resolution instead goes through `AbstractIntegerDataType.getSignedDataType(n)` /
  `getUnsignedDataType(n)`, which return the program's generic spelling when the widths agree and a
  fixed-size builtin (`dword`) when they do not — so the result is never the wrong width. The alias
  runs only after every real lookup has failed, so a program that defines its own `uint32_t` (from
  DWARF) always wins, and `uint24_t` still errors rather than being coerced.
- **`run_script`'s "no args = help" convention is documented, not enforced.** Worth stating plainly
  because the old summary read as though the server implemented it: it does not. `run_script` passes
  an empty argument list and the *bundled scripts* choose to print their argument list instead of
  running. So a script that genuinely takes no arguments should just run — no dummy argument needed,
  as long as its author does not copy the convention. Said so in the `run_script` and
  `get_script_description` summaries, which is what `TOOLS.md` is generated from.

### 5.5 `add_script` staleness — **DONE 2026-08-09**

Issue #12, the last in-repo item. `add_script` copied the file into Ghidra's user script directory
and forgot where it came from, so an edited script ran its old snapshot and returned
`{"ok": true, "success": true}` — a response indistinguishable from a correct run. Documenting the
snapshot (§5.3) made it predictable but left the trap in place.

`add_script` now writes a sidecar next to the copy (`<filename>.mcp-source`, holding the absolute
source path) and `run_script` reconciles the two before running. `delete_script` removes it.

Decisions worth keeping:

- **Re-copy, don't reject.** Design principle 3 says reject rather than guess, but a stale copy is
  not invalid input — the filename is valid and unambiguous. `add_script` names a source file, and
  the copy is an implementation detail of getting it where Ghidra can compile it, so "run the
  current contents of the file you registered" is the tool's meaning, not a guess about it.
  Rejecting would also mean the agent's only recovery is to call `add_script` again with the same
  argument, which is a round-trip that carries no information.
- **The response says which copy ran**, because a silent refresh would swap one invisible behaviour
  for another. `source_state` is one of `current` / `refreshed` / `source_missing` /
  `no_registered_source`, alongside `source_path`. `source_missing` is deliberately not an error —
  the last registered copy is still the best available, and adding from a temp file that is later
  cleaned up is a normal workflow — but it must not report as `current`.
- **Comparison is by content, not mtime.** The file is a few KB, and mtime is the field most likely
  to differ for reasons unrelated to the script changing (a copy, a checkout, a clock skew).
- The sidecar suffix matches no `GhidraScriptProvider` extension, so `list_scripts`
  (`isSupportedScriptName`) and Ghidra's own scanner both ignore it without a special case.
- **Ghidra does recompile after the re-copy** — the one real risk in the design, since a cached
  compiled class would have made the whole thing a no-op. `Files.copy` bumps the mtime and
  `GhidraSourceBundle` picks it up. Proved by the test asserting the new sentinel appears in the
  output *and* the old one does not.
- One adjacent trap fixed while here: `add_script` now **rejects a filename that collides with a
  bundled script**. `resolveScript` prefers the extension's own directory, so the copy would have
  succeeded and then never been what `run_script` ran — the same "plausible success, different
  code" failure this section is about.

Covered by five cases in `tests/test_integration.py::TestScript`: the edit round-trip (before →
`current`, edit → `refreshed` with new output, again → `current`), a deleted source, a bundled
script reporting `no_registered_source`, the bundled-name rejection, and delete-then-re-add from a
new path. All five verified to fail against the previous `ScriptTool`.

Note `source_path` is **absent**, not null, when there is no registered source: `GsonProvider` omits
nulls API-wide, and `source_state` already carries the whole answer.

---

## 6. Suggested order of work

Each step is independently shippable.

1. ~~**§2.2** cache key~~ — **done**, plus `findDomainFile` now rejects an ambiguous filename.
2. ~~**§2.3** transact `analyze_program`~~ — **done.** Swapped ahead of §2.1: rejecting unanalyzed
   programs while `analyze_program` was still broken would have left no way out.
3. ~~**§2.1** remove auto-analysis from `getOrOpen`~~ — **done.**
4. ~~**§3.2** save at the end of a successful `withProgramLock`~~ — **done.** Covered by
   `runScript_changesPersistAfterReopen`, verified to fail without the save.
5. ~~**§2.4** eviction on the failure path; then delete `drainLeakedEntries`~~ — **done.**
6. ~~**§2.6** server-side log file + `error_id`; map 404 to 404~~ — **done.** 405 came with it.
7. ~~**§4.1** batch `rename_variable`~~ — **done**, but as a widening of `batch_tool_call` rather
   than an array parameter on `rename_variable`; see the section for why.
8. ~~**§4.2** / **§4.3** comment rules~~ — **done**, as one `comments:` section carrying both the
   length caps and the precondition rules.
9. ~~**§5.1** parameter renames + `TOOLS.md` regeneration; **§5.3** README~~ — **done.** The
   `limit` caps and the `count`-is-a-page-size convention landed with it; `read_data`'s
   `item_count` was left alone (it is a read shape, not a page size).
10. ~~**§5.2** `label_name` / `global_name` rule keys~~ — **done.** Unknown `naming:`/`comments:`
    keys are now rejected at load, which is what makes adding keys safe.
11. ~~**§5.4** the remaining small items~~ — **done.**

**After step 11 — the plan is complete.** All 14 audited issues in §0 are closed, as is §2.5 (not
implementable on Ghidra's public API, documented instead). One deliberate partial: issue #7 asked
for `limit` *and* `offset` on the xref tools and only `limit` landed, because paging a reference set
by offset means re-walking it per page. `truncated` plus the `ref_types` / address-range filters
cover the case it was reported for; add `offset` only if a real program produces more than 5000
matching xrefs to one address after filtering.

- **§2.5** — closed as not implementable; see the section. `run_script` documents the transaction
  contract instead, and the `end(true)` / `start()` bracket stays the way to run a
  `setLanguage`-style operation.
- ~~**§5.1 leftover** — silent truncation~~ — **done 2026-08-09.** Seven tools, four of which had no
  flag and three of which had a false-positive one; see §5.1.
- ~~**§5.3 leftover** — `add_script` snapshots and `run_script` runs the stale copy~~ — **done
  2026-08-09** as §5.5: the source path is registered and re-copied on change, and the run reports
  which copy it ran.
- ~~**Outside this repo**~~ — **done 2026-08-09**, and it grew once the in-repo work landed:
  - `projects/<project-c>/.claude/skills/ghidra-<project-c>/SKILL.md` — the empty vmargs slot, with the same
    explanatory comment the working `ghidra-<project-b>` copy carries.
  - `~/SKILLS/fmt_string_lookup.md`, `library_fidb_workflow.md`, `debug_log_bulk_naming.md` —
    `search_memory_strings` → `search_defined_strings` (plus `search_bytes` for text Ghidra has not
    defined as data, which is what the old tool was actually being used for), and
    `analyze_function_complete` → `decompile_function` + `get_function_info`.
  - `~/.claude/skills/reversing/SKILL.md` — **this was the one that mattered.** Not on the original
    list, but every item in its "known-broken" section was fixed by this work, so the skill was
    actively telling agents to route around things that now work: run analysis from a script,
    re-`add_script` before every run, avoid C99 type names, apply labels from a GhidraScript to
    bypass the rules engine. Left alone it would have kept the workarounds alive after the bugs
    were gone — which is worse than the bugs, since a bypass hides the write from every check. Its
    parameter table (mostly obsolete after §5.1), the "read-only tools only" claim about
    `batch_tool_call` (wrong since §4.1), and the pagination advice (`truncated` now, not "page
    until you get a short page") were updated with it.
  - Both field logs (project A, project B) — fixed entries marked in their headings and summarised
    under `## Resolved`, since the skill tells agents to read those logs first and they still said
    "Open / blocking". The two things the project B log asserted that turned out to be wrong are
    recorded there too.

Per the repo's definition of done, each change needs integration tests covering the happy path *and*
the error path, `make tools-docs` regenerated, and `gradle buildExtension` run before `pytest` — the
pytest fixture installs the newest `dist/*.zip` and does not rebuild.
