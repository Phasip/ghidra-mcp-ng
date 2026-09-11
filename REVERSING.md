# Reversing methodology

A tested methodology for reverse engineering a program to the point of understanding it. It is
the reasoning companion to `TOOLS.md`: that file says what the tools do, this one says what to do
with them. The naming conventions `rules.yaml` enforces are defined here.

Reversing is an iterative process and it is very easy to get sidetracked. **Re-read this guide
periodically during a long session** — the failure mode is not ignorance of the method, it is
drift away from it once the code starts looking interesting.

Use separate context windows (subagents) for bulk pre-reversing sweeps — enumerating exports,
batch-decompiling hundreds of functions, grepping a vendored source tree. Bring back conclusions,
not dumps. The main session's context is for the reasoning, not the raw material. Work with one
agent at a time to save tokens.

---

## 0. The Golden Rule

**Rename and create structs the moment you identify something. Not later. Later never comes.**

Deferred naming is not a stylistic problem, it is a correctness problem:

- The next function you decompile still shows `FUN_10001234`, so you lose the context you just
  built and re-derive it.
- The decompiler cannot propagate what you know. A named, typed function improves every caller
  and callee automatically; a note in chat improves nothing.
- The debt compounds faster than you can pay it down.
- **The act of naming verifies the understanding.** If you cannot pick a name, you have not
  actually understood the function — you have only read it.

Findings left in prose are lost to the next session. Findings written into the program database
persist. Treat "I understood it" as the *middle* of the work, never the end.

Concretely, after every function you look at, before moving to the next one:
`rename_function` → `set_variable` on everything you understood → `set_function_prototype` →
`create_struct` / `add_struct_field` if a layout emerged.

### Cadence: it's both a method and a deliverable — name/type/struct before the next read

Naming, typing and struct creation are all both: they're how you **hold state while you work**
(a method), and they're also the actual output this process must leave behind (a deliverable).
The failure mode is treating them as only the second — deferring to "once I've found the
answer" — which drops the first. **Rule: every function you decompile gets renamed, its
parameters/locals get named and typed, and any layout that emerged gets a struct — all before
you call `decompile_function` on the next one.** Don't queue understanding as "do later"; apply
the `guess_`/`maybe_`/`likely_` name and the type or struct the moment you have a one-line reason
for it, and upgrade the prefix later if warranted. Tells you've drifted: a PLATE comment growing
past a couple of lines, or a mental backlog of "things I understand but haven't touched."

This applies mid-hop too. Chasing a thread across binaries, you'll pass through functions you may
later decide were a wrong turn — name and type them anyway, on first understanding. A rename or
retype is free and reversible; a branch abandoned *without* one is the finding most likely to be
lost, since nothing then marks you were there.

---

## 1. Naming conventions

Names must distinguish what was **inferred** from what was **recovered**. Three prefixes:

| Prefix | Use when |
|---|---|
| `guess_<name>` | Quick label. Not investigated, but almost certainly this. |
| `maybe_<name>` | Strong reversing evidence supports the name. **The common case.** |
| `likely_<name>` | Unambiguous from context — a log string inside the function, a known API's argument, an exact match against published library source, a vector-table slot. |

Struct fields: **`maybe_<guessedName>_0x<offsetInStruct>`** (e.g. `maybe_size_0x8`). The offset
suffix makes an accidental layout shift obvious at a glance.

`main`, `entry`, `_start` are permitted bare.

### The one exception: recovered names are not inferred names

The prefixes exist to mark inference. **A name taken from a datasheet, a vendor header, or
published library source is not an inference and should be written plain.**

- Hardware registers and peripheral instances: `UART0`, `UART0->CTRL`, `GPIO1->OUT`.
- Vendor/library type names: `UART_TypeDef`, `GPIO_InitTypeDef`.

`UART0->CTRL` is strictly more readable than `likely_UART0->maybe_CTRL_0x18`, and readability is
the entire point. `rules.yaml` leaves `label_name` and `global_name` unconstrained for exactly
this reason, so apply recovered names with `create_label` / `set_global` through the normal
tools. Do **not** route around the rules engine with a GhidraScript to write a name the rules
would reject — that hides the write from every check the server performs.

The *functions* keep their prefixes regardless — even when RTTI or a library match confirms the
class name, the function's behaviour is still inferred.

---

## 2. Naming and types are the documentation. Comments are the last 5%.

A reader who opens the decompiled function must be able to understand it **from the identifiers
alone**.

> **A multi-paragraph PLATE comment on a function whose variables are still `local_2c` and
> `uVar7` is not documentation. It is a confession that the analysis was never persisted.**

This is the single most repeated failure in practice: an agent decompiles a function, understands
it, writes a beautiful 40-line plate comment explaining it, leaves every identifier
auto-generated, and moves on. The next session opens the same function and sees `FUN_100e2880`
with a wall of prose. Nothing propagated. Nothing typed. The decompiler learned nothing.

**Order of preference for recording any finding:**

1. `rename_function`
2. `set_variable` — arguments *and* locals, name and type in one call
3. `set_function_prototype` / `set_parameter_type` — return type and parameter types
4. `create_struct` / `add_struct_field` — layouts
5. `create_label` / `set_global` — data tables, globals
6. *…then* a terse `set_comment`

A PLATE comment is legitimately for:

- a one- or two-line summary of the function's role,
- a caveat the names can't carry ("this is the authority on the header layout — re-derive before
  trusting the docs"),
- a pointer to the durable write-up (the project's lab notebook or results document),
- a bit map or pin map that genuinely has no home in a type.

If your comment is explaining *what the function does*, that meaning belongs in the names. Rewrite
it as names and delete the paragraph.

Long-form analysis goes in the project's markdown, not the program database. The program database
holds names, types, structures, and pointers to the markdown.

---

## 3. Practical heuristics

### Treat naming as semantic reconstruction

Compilation strips identifiers and most semantic hints. Reversing is largely the act of
**reintroducing meaning**. Decompilers reconstruct control flow and approximate high-level
constructs, but identifiers and context must be inferred from usage patterns, data access and
call relationships.

### Use strings and log messages as intent hints

Log strings, debug strings, error messages, protocol markers and format strings point directly at
what the nearby code does. Find the string, follow its xrefs, name the referencing function.

Format strings are especially valuable in tool binaries: a literal like `"WRITE %s AT %lxH\n"`
tells you exactly what a function emits before you have decompiled a line of it.

A funnelled logging wrapper is a naming multiplier — once you find it, every caller's nearby
format string proposes a `guess_` name for an otherwise anonymous function. Script that sweep in
dry-run first, review the proposals, then apply.

### Use imports and exports as anchors

External APIs imply purpose (file I/O, sockets, crypto). Exported functions are the externally
visible feature set. Tracing callers of exports and callees of imports unwinds the internals
around those interfaces fast.

Runtime-resolution APIs (`LoadLibraryA`/`GetProcAddress` and their equivalents) reveal
dependencies absent from the import table — and the name string passed to the resolver tells you
precisely what capability is being loaded.

### Identify libraries — then read them instead of reversing them

Programmers reuse open-source code heavily. Identifying a library (usually via its strings) and
downloading the matching source converts hundreds of functions from "to reverse" to "to match".

**Confirm the identification before you lean on it.** What settles a library ID is an exact
constant match with meaning — a status-flag argument whose literal value *is* that library's
named constant for the flag — or a verbatim dispatch structure. Not a vibe about coding style.
An identification that only rhymes is a guess wearing a uniform.

Once it holds, the library's names are *recovered* rather than inferred (§1), and the struct
layouts in its headers are the layouts to create — take them from the header, do not re-infer
them from the code.

### Infer struct layouts early — constructors first

Repeated pointer offsets are struct fields. When several functions touch the same offsets off one
pointer, define the structure.

**Decompile the constructor / init routine before any method.** Constructors initialize fields in
address order and expose the layout more completely than anything else, and the argument to
`malloc` / `operator new` gives you the total size for free.

In C++ binaries, **always create the vtable struct too**, not just the object struct. A
`maybe_Foo_vtable` with one named function-pointer field per slot, applied at the vtable's
address, makes every indirect call site display the method name. That is at least as valuable as
the object struct.

### RTTI is free information in MSVC binaries

MSVC C++ binaries carry RTTI type descriptors containing mangled class names as strings. Search
for `??_R` / `?AV` early in any MSVC DLL — it hands you the class hierarchy with no guesswork.

### Follow data rather than instructions

Tracing where a key object is created, mutated and consumed exposes subsystem boundaries faster
than following control flow. In polymorphic C++, follow the vtable: identify the concrete class
from the vtable address, find that class's implementation, trace it.

### Related functions cluster

Compilers and linkers place related code together. Find one `std::string` function and its
neighbours are probably `std::string` too. The same holds for driver families and library
translation units.

### Use call relationships for context

A function's behaviour clarifies from: who calls it, what it calls, which APIs it touches.

**For large functions (300+ instructions), call `get_function_callees` *before* decompiling.** The
call tree frequently reveals the purpose without reading a single line of the body.

### Let types propagate

Introducing types for structures, arguments and return values improves the decompiler's output for
everything that touches them. This cascades. Applying a struct to one global improves every
function that reads that global, for free.

Calling convention matters: applying `__cdecl` where the binary uses `__thiscall` or `__stdcall`
gives you the wrong parameter count and a missing `this`. Verify from the prologue / `ECX` usage
before you set a prototype.

### Negative results are findings — write them down

"Searched for magic `X` as bytes in all binaries: 0 hits, in every encoding, with controls" is a
real, expensive result. Record it prominently or the next session (or the next you) will spend the
same hours re-running it. Inline comments in the project's sweep scripts are a good home for an
explicit "zero hits in ALL binaries — do not repeat" marker.

When a constant is genuinely absent as a literal, consider before concluding: emitted byte-by-byte
through a format string; assembled at runtime from field values; present in a *different* binary
(dynamically loaded library, separate tool); or not a magic at all — field values that happen to
look like ASCII.

And keep tool-binary behaviour separate from the content it produces. A build tool that
*generates* a firmware byte does not *contain* that byte.

---

## 4. Embedded / bare-metal firmware

A stripped MCU image needs setup work before the methodology above pays off. Do it first, from
scripts, and make the scripts idempotent and re-runnable.

1. **Get the language right.** Ghidra's ELF loader may pick a broader variant than the part
   (e.g. `ARM:LE:32:v8` for a Cortex-M core). A too-broad language lets ARM-mode decoding consume
   data gaps as bogus instructions. Retarget to the exact core (`ARM:LE:32:Cortex`) and force
   redisassembly.
2. **Fix the memory map.** Name the flash regions; mark erased regions; add peripheral, bit-band
   and private-peripheral-bus regions as **volatile**. Critically: a `PT_LOAD` with `filesz=0,
   memsz=N` (`.bss` + heap) is materialised by the loader as an *initialised, read-only* zero
   block, which lets the decompiler constant-fold every global read to `0`. Replace it with a
   plain uninitialised read/write block or every conclusion downstream is wrong.
3. **Type the vector table.** It pins handler names for free — an IRQ slot is a `likely_` grade
   anchor. Count the slots against the part's IRQ count; the table's end is usually exactly where
   the reset stub begins, which validates the whole layout.
4. **Place peripheral structs.** Define register structs per peripheral and put a named, typed
   instance at every base. Every MMIO access in the program then reads as `UART0->CTRL` instead
   of `*(uint *)0x40021018`. Take the bases and field offsets from the vendor's headers rather
   than inferring them from the code.
5. **Then analyse**, then apply any symbols recovered from other channels (string carving, a
   symbol CSV, a bootloader dump).

Finding the hardware-touching code afterwards: sweep xrefs to every peripheral base **and to each
individual field offset**. A base-address-only xref search misses field-offset accesses, which is
precisely where bit-bang GPIO code lives.

---

## 5. Binary protocol reversing

The parser in the binary is the specification. Everything below is read out of it statically.

### Infer record structure from length-prefixed patterns

Common shape:

```
[0x00] magic / start marker   (u32 or u16)
[0x04] total message length   (u32)
[0x08] records:
         [+0x00] type_flags   (type_id is often the low N bits of this word)
         [+0x04] record_size  (usually includes the record header itself)
         [+0x08] payload
```

Cross-reference the *size field read* to find the record dispatcher. That dispatcher's switch or
if-chain is the protocol command table.

### Use string anchors to find command handlers

Command-name strings (`"CONNECT"`, `"GetStatus"`, `"AT+OPEN"`) sit near dispatch tables or serve
as hash-map keys. One string's xrefs usually lead straight to the handler or to a table entry that
points at it.

### Trace type_id constants back to their assignment

Have a numeric command code? Search it as a scalar constant. The function that stores or compares
it is the builder or the dispatcher for that message type.

---

## 6. Verification discipline

Confident-but-false claims are the standard failure mode of a long reversing session. Guard
against it:

- **A plate comment is not evidence.** If a Ghidra comment and a project document disagree,
  investigate — do not assume either is right. Most such contradictions turn out to be the
  *comment* being stale; some turn out to be a misidentified function, such as a plate naming the
  top-level server loop sitting on the per-request handler one level below it. Fix whichever is
  wrong, in the same pass.
- **Re-derive from the decompiled code, not from prose about the decompiled code.**
- **Reversing depth is not the same as a working result.** A beautifully named codec still does
  not mean the file decodes. Decide what would settle the question before you start, and do not
  call it solved until that says so.
- **When a finding changes, update every place that asserts it in the same pass**: the Ghidra
  annotation, the lab notebook / results document, and any script or header that encodes the same
  claim. They drift apart otherwise, and a stale duplicate is worse than no document.

---

## 7. Suggested workflow

1. Identify entry points and high-level anchors: exports, `main`/reset path, RTTI class names,
   vector-table slots.
2. **Search prior findings before running any new sweep** — the program database itself (existing
   `maybe_`/`likely_` names and comments), the project's scripts and their inline comments
   (including recorded negative results), and the lab notebook. Re-running a known-empty search is
   the most common way to waste an hour.
3. For firmware: do the §4 setup (language, memory map, vector table, peripheral types) first.
4. Inspect imports, exports, strings and runtime-resolved library calls to locate the interesting
   subsystems.
5. Identify third-party libraries; obtain their source; verify mechanically; match rather than
   reverse.
6. Decompile constructors/init routines first; define structs (and vtable structs) from them.
7. Rename functions, arguments and locals as you go, with the right prefix. Set prototypes.
8. Apply and propagate types. Re-read the decompilation after applying — earlier output is stale.
9. Trace key data structures across the program to find subsystem boundaries.
10. Use call graphs and xrefs to refine.
11. Iterate. Keep cleaning up decompiled code for the whole session, not just at the start.

---

## 8. Anti-patterns

1. **Analysing without naming.** The default failure. Name before moving on.
2. **A long plate comment instead of renames.** See §2. The plate is the last 5%, never the deliverable.
3. **Reading decompiler output without re-decompiling after a rename/retype** — you will read
   stale results and draw conclusions from them.
4. **Skipping the constructor** — you will build the struct wrong, twice.
5. **Skipping the vtable struct** — every indirect call site stays unreadable.
6. **The wrong calling convention** — silently wrong parameter counts and a missing `this`.
7. **Writing to the wrong program.** In a multi-binary project every call needs an explicit
   `program=`; a rename against the wrong binary succeeds silently and corrupts the wrong database.
8. **Concluding a constant is absent** from a literal byte search without considering the other
   encodings in §3.
9. **Confusing a build tool's behaviour with the content it produces.**
10. **Assuming an RTTI-confirmed class name exempts a function from the `maybe_` prefix** — the
    class is recovered, the function's behaviour is still inferred.
11. **Bulk-renaming over existing names.** A batch script that does not check current names will
    overwrite correct work from previous sessions. Check first; never clobber a `likely_`.
12. **Deriving a frame/entry count from the distance between index entries.** In multi-region
    layouts that stride spans other data and is always wrong.
13. **Deferring naming/typing/structs to a wrap-up pass.** They're a deliverable *and* a
    method — skipping the method half loses state mid-session. See §0.
14. **Withholding a rename or type because a branch might get abandoned.** Backwards — an
    untouched abandoned branch is the finding most likely to vanish.

---

## 9. Log tooling problems where the next session will find them

When the reversing toolchain misbehaves — an endpoint errors, truncates, returns stale output,
mangles an edit, or forces an awkward workaround — record it in the project's
`ghidra-mcp-issues.md` as a dated entry: **what you called → what went wrong → the workaround**.
Mark entries resolved when confirmed fixed rather than deleting them.

Keep that file for *tooling*. Findings about the target go in the lab notebook / results
documents.

Two specific things worth capturing every time, because they are what a bug report actually needs:
the exact request, and whether the operation had partially succeeded despite the error. A 500 does
not mean nothing happened.

---

## Mental model

```
improve readability
→ decompile function
→→ recover structures and types
→→ interpret behaviour
→→ refine names and relationships
→→ decompile related functions
```

The top priority is always naming functions, their arguments, their argument and return types, and
the structs around them. That improves readability drastically for everything else, because the
decompiler reuses it.

## Final note

As the code becomes clearer, the architecture and intent gradually emerge. Even when the code
*seems* clear, keep naming and keep defining structs — that is what verifies the understanding is
real, and what makes the next session cheaper than this one.

Continue to clean up the decompiled code throughout your whole working session.
