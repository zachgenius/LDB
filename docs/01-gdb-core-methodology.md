# GDB Core Methodology — Deep Analysis

> Source under study: `/Users/zach/Downloads/gdb-17.1` (GDB 17.1, ~240 MB)
> Purpose: Extract the timeless design ideas that make GDB the de-facto live debugger and core-dump analyzer, so LDB can adopt them, modernize them, or knowingly skip them.

This document is the foundational research for **LDB**, an LLM/Agent-first universal debugger. It reads GDB as a *codebase* — not as a manual — and identifies the architectural decisions that have survived 35 years of language churn, OS evolution, and hardware diversification.

---

## 1. The 10 Cross-Cutting Methodologies

These are the principles that show up *everywhere* in the GDB source. If you don't reproduce these, you don't have a debugger; you have a process inspector.

| # | Methodology | One-line statement |
|---|---|---|
| 1 | **Everything is a target** | Live process, core dump, simulator, replay log, remote stub — all expose the same `target_ops` vtable. |
| 2 | **Resume / Wait / Handle is the universal loop** | `target.resume() → target.wait() → handle_inferior_event()` is the only way execution moves forward. |
| 3 | **Stratum stack composes capabilities** | Targets compose like middleware: file < process < thread < record < arch < debug. Each layer can intercept. |
| 4 | **Breakpoints are the universal control primitive** | step / next / finish / until / catch / longjmp-resume — all decompose into "set an internal bp, resume, wait, check FSM." |
| 5 | **DWARF is the source of truth** | Variable locations, frame layout, line tables, types — all derived from DWARF (or its equivalent on Win/Mach). |
| 6 | **Values abstract over location** | A `value` is `(type, location, availability)` — register, memory, computed-by-DWARF-expression, optimized-out, unavailable. |
| 7 | **Frame unwinding via pluggable sniffers** | Each unwinder (DWARF CFI, prologue analysis, sigtramp, jit, python) gets first refusal. First match wins. |
| 8 | **`ui_out` separates structured emission from rendering** | One command implementation emits to CLI text, MI records, JSON, or anything else by swapping the `ui_out` subclass. |
| 9 | **Observers decouple subsystems** | `gdb::observers::normal_stop.notify(...)` lets MI, Python, TUI, DAP, logging all react without knowing each other. |
| 10 | **Push computation to the target via agent expressions** | Conditional breakpoints, tracepoints, and watchpoint side-conditions compile to a portable bytecode the stub evaluates in-process. |

The rest of this document is the evidence for these claims, organized by subsystem.

---

## 2. Execution Control

### 2.1 Target abstraction (`gdb/target.h`, `gdb/target.c`)

A `target_ops` is a virtual class with ~200 methods. Each running inferior owns a *stack* of these, ordered by stratum:

```
debug_stratum     ← instrumentation wrapper (logging, replay)
arch_stratum      ← architecture overrides
record_stratum    ← record / replay (record-full, record-btrace)
thread_stratum    ← thread control
process_stratum   ← live execution OR core file (peer types)
file_stratum      ← executable + shared libraries on disk
dummy_stratum     ← always-present no-op floor
```

Operations walk *down* the stack until one returns success. The classical example is `xfer_partial(object, rw, buf, offset, len)` — a single mega-method handling memory, registers, threads, libraries, auxv, target-description XML, etc. Layered targets either intercept (record-replay returning logged contents) or pass through (`beneath()->xfer_partial(...)`).

**Why a stack and not a single object?** Composition. You can push `record-btrace` on top of a live `linux-nat` target and the lower layer is unaware: every memory read goes through the recorder first, which can serve replay state without ever touching the kernel.

**Legacy seam:** `xfer_partial` is a god-method. A clean redesign splits it into typed RPCs (`read_memory`, `read_registers`, `read_aux_vector`, …).

### 2.2 Inferior / thread / program-space (`gdb/inferior.h`, `gdb/gdbthread.h`, `gdb/progspace.h`)

Three orthogonal containers:

- **program_space** — one per executable image. Holds objfiles, shared library list, address space layout. Forked children share the parent's progspace until `exec()`.
- **inferior** — one per debugged entity (a Linux process, a remote target, a core file). Owns the target stack, thread list, control state.
- **thread_info** — per-thread state, including the *thread FSM* (see §2.4) and per-thread breakpoints (`step_resume_breakpoint`, `longjmp_resume_breakpoint`).

GDB can hold *multiple inferiors at once*, e.g. a local process and a remote MCU. Each has its own target stack. This is the thing that makes "switch to inferior 2 and look at core_b" work.

### 2.3 Resume / Wait / Handle (`gdb/infrun.c`, 10,838 lines)

This is the heart. The whole file is a giant state machine with one entry point:

```
proceed()                    ← user command "continue", "step", etc.
  → set up step-resume breakpoint(s)
  → set thread state to RESUMED
  → target->resume(ptid, step, signal)
  → wait_for_inferior() loops:
       ws = target->wait(ptid, &waitstatus, opts)
       handle_inferior_event(ws):
         switch (ws.kind) {
           STOPPED, SIGNALLED, EXITED,
           FORKED, VFORKED, EXECD, CLONED,
           SYSCALL_ENTRY, SYSCALL_RETURN,
           NO_HISTORY, NO_RESUMED, ...
         }
         → consult thread_fsm: should we report or continue silently?
```

Higher-level commands (`step`, `next`, `finish`, `until`) all *decompose* into:
1. Insert a strategic internal breakpoint (`bp_step_resume`, `bp_longjmp_resume`, `bp_finish`).
2. Resume.
3. On stop, ask the FSM `should_stop()`.
4. If yes → report; if no → adjust internal bps and loop.

**This is methodology #4.** GDB does not have separate kernel paths for step / next / finish. They are all "set a bp and run."

### 2.4 Thread FSM (`gdb/thread-fsm.h`)

Each thread carries `std::unique_ptr<thread_fsm>` representing its current command intent: `step_command_fsm`, `finish_fsm`, `until_break_fsm`, `call_thread_fsm` (for `call foo()`). The FSM's `should_stop(ecs)` decides whether the user-visible stop fires. This decouples stepping logic from the event handler — you can write a new "step until X" command by writing a new FSM, no change to `handle_inferior_event`.

### 2.5 Linux native target (`gdb/linux-nat.c`, `gdb/nat/linux-ptrace.c`)

ptrace is gnarly. The driver handles:
- `PTRACE_ATTACH`, `PTRACE_CONT`, `PTRACE_SINGLESTEP`, `PTRACE_GETREGSET`, `PTRACE_PEEKTEXT/POKETEXT`, `PTRACE_GETSIGINFO`, `PTRACE_GETEVENTMSG`.
- Distinguishing real SIGTRAPs (breakpoint) from kernel-injected ones (fork/exec/clone events) via `siginfo.si_code`.
- The SIGSTOP dance: to halt a running thread, send `tkill(tid, SIGSTOP)`, wait for the kernel to report it, *consume* it (never deliver to inferior).
- `PTRACE_O_TRACECLONE/FORK/VFORK/EXEC/EXIT/SYSGOOD` so events are reported as stops with a distinguishable kind, not raw signals.
- `/proc/PID/mem` for fast memory access (bypasses the per-word ptrace overhead).

**Modernization:** Linux 5.3+ has `pidfd`, `process_vm_readv/writev`, `ptrace(PTRACE_GETREGSET, NT_X86_XSTATE)`. A new debugger should target these directly and treat ptrace as a reluctant fallback.

### 2.6 Displaced stepping (`gdb/displaced-stepping.c`)

The classic problem: to single-step over a live software breakpoint, you must (a) remove it, (b) step, (c) reinsert. In non-stop mode this is racy — another thread can hit the same address while the bp is gone.

Solution: copy the instruction to a scratch slot, fix up PC-relative operands, single-step in the scratch slot, then continue. The breakpoint at the original PC is never touched.

This is essential for non-stop mode and for any debugger that wants to be safe under concurrency.

### 2.7 Reverse execution (`gdb/record-full.c`, `gdb/record-btrace.c`)

Two modes, both implemented as a stratum that *wraps* the process target:

- **record-full** — software, every memory write and register change is logged. 2–100× slowdown. Works everywhere.
- **record-btrace** — leverages Intel PT / ARM ETM. Hardware logs branches; replay recomputes everything from binary + branch trace. Near-zero overhead, but state is read-only.

Reverse-step / reverse-continue are just `wait()` calls that walk the recorded log instead of forward execution. From above the stratum stack, the rest of GDB doesn't know it's replaying.

### 2.8 Remote serial protocol (`gdb/remote.c`, `gdbserver/`)

RSP is a text protocol with packets like `g` (read all regs), `m addr,len` (read memory), `Z0 addr,kind` (insert sw bp), `vCont;c:1;s:2` (per-thread continue/step), `T05thread:p1.1;` (stop reply). Checksum-protected, ACK/NAK-driven, designed in 1987 to work over 9600 baud.

What it *gives you architecturally* is a clean wire-format separation between "the debugger" and "the thing controlling the debuggee." You can:
- Run the stub on an MCU with 32 KB of RAM (gdbserver builds this small).
- Tunnel over SSH, USB, JTAG, network.
- Have *multiple* clients speak it (rr, lldb, IDEs all do).

**For LDB this is the most important interoperability surface.** Speaking RSP means every tool that already speaks it (gdbserver, OpenOCD, QEMU, rr, Renode, probe-rs) is a backend you don't have to port.

### 2.9 Core dump (`gdb/corelow.c`)

A core file is a `target_ops` at `process_stratum`. `wait()` returns a synthetic stopped event; `resume()` errors. Memory is served from BFD-parsed core segments. Registers come from `NT_PRSTATUS` notes. Symbols are loaded from the executable referenced in `NT_AUXV` or `NT_FILE`. Build-IDs in the core are matched against `/usr/lib/debug/.build-id/...` for separate-debug-info.

The elegance: *the same stack-unwind, value-evaluation, pretty-print code paths run on cores and live processes*. Only `resume()` and `wait()` differ.

---

## 3. Symbol & Debug Info

### 3.1 BFD as the binary parser (`bfd/`)

GDB does not parse ELF, Mach-O, PE, COFF, a.out, XCOFF, or any other format. It calls into `libbfd`, which exposes:
- Section enumeration (`abfd->sections`).
- Symbol table extraction (`asymbol`).
- Relocations.
- `.gnu_debuglink` and `.note.gnu.build-id` for separate debug info.

BFD stops at "binary structure"; everything semantic (types, scopes, line numbers) is DWARF, parsed by GDB itself.

**For LDB:** keep using BFD (or the LLVM equivalent — `llvm::object`). Don't write your own ELF parser.

### 3.2 Object/symbol/block hierarchy

```
objfile          ← one loaded binary
  compunit_symtab  ← one compilation unit
    blockvector
      block        ← lexical scope (function body, namespace, …)
        symbol     ← function | var | type | label
  msymtab          ← minimal symbols (from ELF symbol table only)
```

**Minimal symbols** are critical: they're the names you can resolve *before* DWARF is parsed. They make `b malloc` work on a stripped libc. Full symbols are expanded *lazily* per CU.

### 3.3 DWARF reader (`gdb/dwarf2/`)

The largest single subsystem. `gdb/dwarf2/read.c` is 19,869 lines. It evolved through three indexing strategies:

1. **`.gdb_index`** (DWARF 4 era) — pre-built hash table written at link time. Fast load, brittle.
2. **`.debug_names`** (DWARF 5) — standardized version of the same idea.
3. **Cooked index** (GDB 11+) — built at startup, sharded across worker threads, persisted to `~/.cache/gdb`. No external tooling required.

The cooked index is the modern answer to "GDB takes 30 seconds to start on a 1 GB binary." A worker thread pool walks each CU, recording (name, kind, language, DIE offset) without parsing types. When a name is queried, the matching CU is expanded on demand.

**For LDB:** adopt this approach. Sharded parallel indexing + persistent cache + lazy CU expansion is non-negotiable for binaries over 100 MB.

### 3.4 Line tables (`gdb/symtab.c::find_pc_line`)

DWARF `.debug_line` is a compressed state machine producing `(addr, file, line, col, is_stmt)` tuples. GDB binary-searches on PC. Prologue skipping (so `b main` lands *after* the function setup) is heuristic + DWARF `DW_AT_entry_pc` when available.

### 3.5 Type system (`gdb/gdbtypes.h`)

One `struct type` for every language: C, C++, Rust, Go, Ada, Fortran, D, Objective-C, OpenCL, Pascal, Modula-2. Differences are folded into `type_specific` and language-specific flags (Ada variant records, Fortran dynamic bounds, C++ vptr offsets).

### 3.6 Frame & unwinder (`gdb/frame.c`, `gdb/dwarf2/frame.c`)

A `frame_info` is a node in a linked list rooted at the *sentinel frame* (current registers). Each frame has:
- `frame_id = (PC, SP, special_addr)` — the identity that survives stop/restart.
- A pointer to its `frame_unwind` vtable: who created me, how do I find my caller's registers?

Unwinders are tried in order:
- **DWARF CFI** (`.eh_frame`, `.debug_frame`) — usually wins.
- **Prologue analysis** — disassemble the function prologue, infer where SP/FP/RA went.
- **Architecture-specific** — sigtramp, dummy frames for `call foo()`.
- **Python-registered** — for JIT, async runtimes, custom calling conventions.

First successful sniff produces the frame. **This sniffer-chain pattern is the right design.** It's how Rust async stacks, Go goroutines, V8 JIT frames, and Linux signal trampolines all get unwound by the same engine.

### 3.7 Expressions & values (`gdb/expression.h`, `gdb/value.h`, `gdb/eval.c`, `gdb/infcall.c`)

User types `print foo->bar.baz[i]`. GDB:
1. Parses with the language module's parser → `expression` (tree of `expr::operation` subclasses).
2. Walks the tree → produces a `value`.

A `value` is the key abstraction. It's *not* "the bytes of a variable." It's:
- `type` — what is it?
- `lval` — where does it live? `lval_memory`, `lval_register`, `lval_computed` (DWARF expression with a callback), `lval_internalvar`, or `not_lval`.
- `bits_available` — partial values from tracepoints / optimized-out fields are first-class.
- `lazy` — defer fetch until needed.

`call foo(args)` (`infcall.c`) is the wildest feature: GDB pushes a *dummy frame*, sets registers per the calling convention, points PC at the function, plants a special breakpoint at a "return-to-debugger" address, and resumes. When the breakpoint fires, it lifts the return value out of registers/memory, tears down the dummy frame, and hands the user a `value`. Handles longjmp-out via a sigsetjmp guard.

### 3.8 Language modules (`gdb/language.h`)

`struct language_defn` is the language plug-in. Each implements:
- Expression parser.
- Type printer.
- Value printer.
- Symbol-lookup scope rules (C: block→file→global; C++: ADL through namespaces; Ada: package hierarchy).
- Demangler.
- Primitive type registration.

15+ languages. New language ≈ 1 file + 1 yacc grammar.

---

## 4. Interfaces

### 4.1 `ui_out` — the most important pattern in GDB (`gdb/ui-out.h`)

A class with methods like `field_string("name", value)`, `begin(ui_out_type_tuple, "id")`, `table_header(...)`. Commands call these *without knowing the format*. Subclasses render:

- `cli_ui_out` → human text, aligned columns.
- `mi_ui_out` → MI records like `^done,threads=[{id="1",...}]`.
- (Hypothetical: `json_ui_out`, `proto_ui_out`.)

**This is methodology #8 and the single most LDB-relevant pattern.** It means *one command implementation can serve a CLI human, an MI client, a JSON-RPC LLM, and a Protobuf gRPC client simultaneously.* GDB built this by accident in pursuit of MI; we should build it on purpose for agent-first.

The current implementation has gaps an LLM-first design must fix:
- **No schema** — clients hardcode field names.
- **No streaming** — entire tables buffered.
- **No introspection** — you can't ask a command "what fields will you emit" before running it.

### 4.2 GDB/MI (`gdb/mi/*`)

Line-protocol: `[token]-cmd args\n` → `[token]^done,key=value,...\n` plus async `*stopped,...\n`. Every IDE wraps it. Failure modes:
- State explosion (varobj polling).
- Weak typing (everything is strings).
- Polling, not push.
- No backpressure / cancellation.
- Buffered, not streamed.

### 4.3 DAP (`gdb/python/lib/gdb/dap/*`)

Modern JSON-RPC layer, written in Python on top of the Python API. Strengths: standardized, capabilities-advertised, used by VS Code. Weaknesses: incomplete coverage, leaky abstraction (variable references are opaque ints), no GDB-unique features (agent expressions, tracepoints, frame filters).

### 4.4 Python API (`gdb/python/`, `gdb/python/lib/gdb/`)

The strongest extension surface. 51 C modules + 53 Python modules. Exposes `gdb.Inferior`, `gdb.Thread`, `gdb.Frame`, `gdb.Symbol`, `gdb.Type`, `gdb.Value`, `gdb.Breakpoint`, `gdb.Block`, `gdb.events.*`.

Extension points:
- **Pretty printers** — rewrite how a value displays.
- **Frame filters** — rewrite what a backtrace shows (essential for hiding async runtime infra).
- **Unwinders** — define new calling conventions.
- **xmethods** — override C++ methods at debug time (e.g., `std::shared_ptr::get()` without calling into the inferior).
- **Type printers** — humanize mangled names.
- **Custom commands & parameters** — first-class CLI extension.
- **Events** — `events.normal_stop`, `events.new_thread`, `events.breakpoint_modified`, ...

This is the substrate everything modern is built on, including DAP. **For LDB, the equivalent must exist on day one** — agents are extensions and need a stable extension API.

### 4.5 Agent expressions (`gdb/ax-*.c`)

Bytecode VM. Conditional breakpoints and tracepoint-collection expressions are compiled to bytecode and shipped to gdbserver, which evaluates them *in the target's address space* without round-tripping. A condition that fires once per million hits doesn't pay 999,999 round-trip costs.

**Methodology #10.** For LLM-first debugging this is even more valuable: the agent can ship a "watch this complex predicate" program to the target instead of polling.

### 4.6 Observers (`gdb/observable.h`)

40+ events: `normal_stop`, `signal_received`, `breakpoint_created/modified/deleted`, `new_thread`, `thread_exit`, `inferior_created`, `new_objfile`, `solib_loaded`, `target_resumed`, ...

Pure pub-sub. CLI, MI, Python, DAP, TUI, logging all subscribe. **This is how you decouple a debugger.** It's the substrate for any agent that needs to react to program state.

### 4.7 CLI command framework (`gdb/cli/*`)

`cmd_list_element` is a tree node: name, function, completer, help, sub-list pointer. Prefix commands (`set`, `show`, `info`, `maintenance`) are nodes whose children are looked up by the next token. The `set/show` pattern auto-pairs setters and getters from a typed `var_types` enum. Tab-completion is a separate function pointer per command.

---

## 5. What an LLM-First Reimplementation Should Keep, Replace, Skip

| Area | Keep | Replace | Skip |
|---|---|---|---|
| Target abstraction | The stratum stack and resume/wait/handle loop | Split `xfer_partial` into typed RPCs | — |
| Process control | ptrace as one driver | Default to `pidfd`, `process_vm_readv`, `perf_event_open` on Linux | Stabs, a.out |
| Breakpoint primitives | Sw bp + shadow contents; hw bp/wp; displaced stepping | — | `bp_shlib_event` and other historical types |
| Recording | The wrapping-stratum pattern | Use Intel PT / ARM ETM directly; integrate with `rr` for portability | record-full as default (too slow) |
| Remote protocol | Speak RSP for backend interop | Add a JSON/MsgPack/gRPC-over-RSP-tunnel for richer client side | — |
| BFD | Yes (stable, decades-tested) | — | — |
| DWARF | Cooked-index pattern, lazy CU expansion | Use `gimli` (Rust) or `llvm::DebugInfoDWARF` instead of GDB's reader | DWARF 1, stabs |
| Frame unwinding | Sniffer chain | Expose as a library with stable C ABI | — |
| Type system | Unified `type` w/ language-specific tail | — | — |
| Value abstraction | `(type, location, availability)` | Add native lazy iteration for huge containers | — |
| Expression eval | Tree-walking on parsed AST | Make AST a first-class data type accessible to agents | Opcode-walking variant |
| Language modules | Pluggable vtable | Add a "query language" that's language-independent for agent semantic queries | — |
| `ui_out` | The pattern | Add: schema-first, streaming, introspectable, with cancellation | The text-formatting bias |
| MI | The async records idea | Replace with JSON-RPC 2.0 / Protobuf | Field-name-as-API |
| DAP | Compatibility veneer | Extend to expose pretty printers, frame filters, agent expressions | — |
| Python API | The full extension surface | Add typed schemas, async generators, lazy iterators, sandboxed eval | — |
| Guile | — | — | Skip entirely |
| Agent expressions | The VM | Extend with type-reflection ops, versioned ABI, formal sandbox | — |
| Observers | Pub-sub | Add filtering, priority, backpressure, async handlers | — |
| Auto-load | Build-ID resolution | Add symbol-server (debuginfod) as a first-class backend | The `safe-path` user-prompt UX |

---

## 6. What's Missing in GDB for an Agent-First World

These are gaps no amount of porting fixes — they need new design.

1. **Schema-typed I/O.** Every response is a documented type; clients don't parse field names, they parse a schema. JSON-RPC 2.0 + JSON Schema, or Protobuf, is the floor.

2. **Streaming and cancellation.** A 1M-element array, a 10 MB memory window, a 50k-frame stack — chunked responses with resumption tokens, not "buffer the whole thing."

3. **View descriptors.** Don't make the agent issue 12 round-trips to inspect a frame. Let it issue one declarative query: *"frame 0, give me locals + args + types + source line + register snapshot, max array len 100, max string 1024."*

4. **Session model.** Checkpoints, named bookmarks, command history, replay-from-checkpoint, "remember what I observed last debugging session." Today this is improvised in `.gdbinit` and shell history.

5. **Semantic queries on the inferior.** "Find every live `MyClass` instance," "show the heap object graph rooted at `g_session`," "what threads are currently blocked on this mutex." These require type-walking + memory-walking + GC-style heap traversal. GDB has the primitives — Python `gdb.Type`, `gdb.Value`, memory-search — but no first-class operators.

6. **Bidirectional events to the agent.** WebSocket / gRPC stream where the debugger pushes interesting events to the LLM, not the LLM polling.

7. **Determinism guarantees.** Same binary + same input + same query → byte-identical output. Critical for caching, for reproducibility, for trust.

8. **Provenance.** Every value the agent sees should be tagged with where it came from (which CU, which DWARF location list entry, which register at which PC). When the agent reasons "x came from y, and y is wrong because z," it must be able to cite chain-of-custody.

9. **LLM-aware pretty printing.** Output that's *informative for an LLM*: include type names always, show enum tag-and-value, show pointers as `<type *>(0xaddr → "string preview")`, deterministic field ordering.

10. **Cost-aware queries.** The agent should know "this query will fetch 800 KB" before issuing it. Server reports estimated bytes / round-trips for each operation.

---

## 7. Reading-Map of GDB Source

For anyone implementing LDB, this is the order to read GDB:

1. **`gdb/target.h`** + **`gdb/target.c`** (target_ops, push/unpush, the stratum stack).
2. **`gdb/inferior.h`** + **`gdb/gdbthread.h`** + **`gdb/progspace.h`** (state model).
3. **`gdb/infrun.c`** (the resume/wait/handle loop, FSMs, longjmp, exec follow). Bring snacks; it's 10k lines.
4. **`gdb/breakpoint.h`** + **`gdb/breakpoint.c`** (shadow contents, bp_locations, bpstat).
5. **`gdb/displaced-stepping.c`** — small but critical.
6. **`gdb/linux-nat.c`** + **`gdb/nat/linux-ptrace.c`** (the actual driver).
7. **`gdb/remote.c`** + the gdbserver tree (the wire protocol).
8. **`gdb/corelow.c`** (target abstraction in its purest form).
9. **`gdb/dwarf2/read.c`** + **`gdb/dwarf2/cooked-index.c`** + **`gdb/dwarf2/frame.c`** (the symbol/unwind side).
10. **`gdb/frame.c`** + **`gdb/frame-unwind.c`** (sniffer chain).
11. **`gdb/value.c`** + **`gdb/eval.c`** + **`gdb/infcall.c`** (the value abstraction & inferior calls).
12. **`gdb/ui-out.h`** + **`gdb/cli-out.c`** + **`gdb/mi/mi-out.c`** (the structured-emission pattern).
13. **`gdb/observable.h`** (the event substrate).
14. **`gdb/python/python.c`** + **`gdb/python/py-value.c`** + **`gdb/python/py-frame.c`** (the extension surface).
15. **`gdb/ax-general.c`** + **`gdb/ax-gdb.c`** (the agent-expression VM).

---

## 8. The 8 Architectural Theses for LDB

Distilled from the above:

1. **Adopt the stratum-stack target model wholesale.** It's the right answer.
2. **The resume/wait/handle loop is not negotiable.** Build it once, build it well, never pretend you can skip it.
3. **Speak RSP at the southbound interface.** Every existing target stub becomes a backend.
4. **Build a schema-first northbound interface.** JSON-RPC 2.0 + JSON Schema, with streaming and cancellation. This is where MI failed.
5. **Reuse battle-tested libraries for the parts that took GDB 30 years.** BFD or `llvm::object`. `gimli` or `llvm::DebugInfoDWARF`. `libunwind` or DWARF CFI. Don't reinvent.
6. **Make the extension API the public API.** Agents are extensions. If your own MVP commands aren't built on the same API the agent uses, the agent is a second-class citizen.
7. **Push computation to the target via agent expressions.** This is GDB's most underused superpower; make it the default for predicates.
8. **Expose semantics, not just syntax.** Heap traversal, type-instance enumeration, mutex-graph queries, lock-order analysis — these are LLM force-multipliers and the differentiator from "GDB-but-with-a-chat-window."
